//! TLS 1.3 over TCP with certificates on both sides.
//!
//! Sessions are not resumed and no tickets are sent: every connection
//! authenticates from scratch, and an idle connection never has unsolicited
//! data waiting (which is how [`Conn::probe`] tells a dead peer from a quiet
//! one).

use crate::sock::{probe_fd, set_timeouts, tune_tcp};
use crate::{ClientSettings, Closer, Conn, Connector, Identity, Incoming, Listener, Prober};
use rustls::client::Resumption;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn err(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

fn certs(pem: &[u8], what: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let v: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem).collect();
    let v = v.map_err(|e| format!("{what}: {e}"))?;
    if v.is_empty() {
        return Err(format!("{what}: no certificate found"));
    }
    Ok(v)
}

fn roots(pem: &[u8]) -> Result<RootCertStore, String> {
    let mut r = RootCertStore::empty();
    for c in certs(pem, "CA")? {
        r.add(c).map_err(|e| format!("CA: {e}"))?;
    }
    Ok(r)
}

fn key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("private key: {e}"))
}

/// Pull the identity out of a client's certificate.
pub fn identity_of_cert(der: &[u8]) -> Identity {
    let fp = Sha256::digest(der);
    let fp: String = fp.iter().map(|b| format!("{b:02x}")).collect();
    let mut aliases = vec![format!("cert:sha256={fp}")];
    let mut name = None;
    if let Ok((_, c)) = x509_parser::parse_x509_certificate(der) {
        if let Some(cn) = c.subject().iter_common_name().next().and_then(|a| a.as_str().ok()) {
            name = Some(format!("cert:cn={cn}"));
        }
        if let Ok(Some(san)) = c.subject_alternative_name() {
            use x509_parser::extensions::GeneralName;
            for g in &san.value.general_names {
                match g {
                    GeneralName::DNSName(d) => aliases.push(format!("cert:san:dns={d}")),
                    GeneralName::RFC822Name(e) => aliases.push(format!("cert:san:email={e}")),
                    GeneralName::URI(u) => aliases.push(format!("cert:san:uri={u}")),
                    _ => {}
                }
            }
        }
    }
    let name = name.unwrap_or_else(|| aliases.first().cloned().unwrap());
    aliases.retain(|a| *a != name);
    Identity::with_aliases(name, aliases)
}

macro_rules! tls_conn {
    ($name:ident, $conn:ty) => {
        pub struct $name(StreamOwned<$conn, TcpStream>);

        impl Read for $name {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.0.read(b)
            }
        }
        impl Write for $name {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }
        impl Conn for $name {
            fn set_timeouts(&self, r: Option<Duration>, w: Option<Duration>) -> io::Result<()> {
                set_timeouts(&self.0.sock, r, w)
            }
            fn closer(&self) -> io::Result<Closer> {
                let s = self.0.sock.try_clone()?;
                Ok(Arc::new(move || {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }))
            }
            fn probe(&self) -> bool {
                probe_fd(self.0.sock.as_raw_fd())
            }
            fn prober(&self) -> Option<Prober> {
                let s = self.0.sock.try_clone().ok()?;
                Some(Arc::new(move || probe_fd(s.as_raw_fd())))
            }
        }
    };
}
tls_conn!(ClientStream, ClientConnection);
tls_conn!(ServerStream, ServerConnection);

// ---------------------------------------------------------------------
// client
// ---------------------------------------------------------------------

#[derive(Debug)]
pub struct TlsConnector {
    host: String,
    port: u16,
    name: ServerName<'static>,
    cfg: Arc<ClientConfig>,
    timeout: Duration,
}

impl TlsConnector {
    pub fn new(host: &str, port: u16, s: &ClientSettings) -> Result<TlsConnector, String> {
        let ca = s
            .ca_pem
            .as_deref()
            .ok_or("tcp:// needs the CA certificate that signed the daemon's (PKCS11_PROXY_TLS_CA)")?;
        let cert = s.cert_pem.as_deref().ok_or("tcp:// needs a client certificate (PKCS11_PROXY_TLS_CERT)")?;
        let k = s.key_pem.as_deref().ok_or("tcp:// needs the client's private key (PKCS11_PROXY_TLS_KEY)")?;
        let mut cfg = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots(ca)?)
            .with_client_auth_cert(certs(cert, "client certificate")?, key(k)?)
            .map_err(|e| format!("client certificate: {e}"))?;
        cfg.resumption = Resumption::disabled();
        cfg.enable_early_data = false;
        let name = s.server_name.clone().unwrap_or_else(|| host.to_string());
        let name = ServerName::try_from(name).map_err(|e| format!("server name: {e}"))?;
        Ok(TlsConnector {
            host: host.to_string(),
            port,
            name,
            cfg: Arc::new(cfg),
            timeout: s.connect_timeout.unwrap_or(Duration::from_secs(20)),
        })
    }
}

pub(crate) fn tcp_connect(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
    for a in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                tune_tcp(&s)?;
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

impl Connector for TlsConnector {
    fn connect(&self) -> io::Result<Box<dyn Conn>> {
        let mut tcp = tcp_connect(&self.host, self.port, self.timeout)?;
        set_timeouts(&tcp, Some(self.timeout), Some(self.timeout))?;
        let mut c = ClientConnection::new(self.cfg.clone(), self.name.clone()).map_err(|e| err(e.to_string()))?;
        while c.is_handshaking() {
            c.complete_io(&mut tcp)?;
        }
        Ok(Box::new(ClientStream(StreamOwned::new(c, tcp))))
    }
}

// ---------------------------------------------------------------------
// server
// ---------------------------------------------------------------------

pub struct TlsAcceptor {
    l: TcpListener,
    cfg: Arc<ServerConfig>,
    timeout: Duration,
}

impl TlsAcceptor {
    /// `ca_pem` is the CA whose client certificates are accepted; every client must present one.
    pub fn bind(
        addr: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
        ca_pem: &[u8],
        handshake_timeout: Duration,
    ) -> Result<TlsAcceptor, String> {
        let p = provider();
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots(ca_pem)?), p.clone())
            .build()
            .map_err(|e| format!("client CA: {e}"))?;
        let mut cfg = ServerConfig::builder_with_provider(p)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs(cert_pem, "server certificate")?, key(key_pem)?)
            .map_err(|e| format!("server certificate: {e}"))?;
        cfg.send_tls13_tickets = 0;
        cfg.session_storage = Arc::new(NoServerSessionStorage {});
        let l = TcpListener::bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
        Ok(TlsAcceptor { l, cfg: Arc::new(cfg), timeout: handshake_timeout })
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.l.local_addr()
    }
}

struct TlsIncoming {
    tcp: TcpStream,
    cfg: Arc<ServerConfig>,
    timeout: Duration,
}

impl Incoming for TlsIncoming {
    fn establish(self: Box<Self>) -> io::Result<(Box<dyn Conn>, Identity)> {
        let TlsIncoming { mut tcp, cfg, timeout } = *self;
        tune_tcp(&tcp)?;
        set_timeouts(&tcp, Some(timeout), Some(timeout))?;
        let mut c = ServerConnection::new(cfg).map_err(|e| err(e.to_string()))?;
        while c.is_handshaking() {
            c.complete_io(&mut tcp)?;
        }
        let id = c
            .peer_certificates()
            .and_then(|v| v.first())
            .map(|c| identity_of_cert(c.as_ref()))
            .ok_or_else(|| err("no client certificate"))?;
        set_timeouts(&tcp, None, None)?;
        Ok((Box::new(ServerStream(StreamOwned::new(c, tcp))), id))
    }
}

impl Listener for TlsAcceptor {
    fn accept(&self) -> io::Result<Box<dyn Incoming>> {
        let (tcp, _) = self.l.accept()?;
        Ok(Box::new(TlsIncoming { tcp, cfg: self.cfg.clone(), timeout: self.timeout }))
    }
    fn describe(&self) -> String {
        match self.l.local_addr() {
            Ok(a) => format!("tcp://{a} (TLS 1.3, client certificates)"),
            Err(_) => "tcp:// (TLS 1.3)".into(),
        }
    }
}
