//! TLS 1.2 with a pre-shared key, through the system OpenSSL (rustls has no
//! external PSKs). Only key exchanges that keep forward secrecy or, failing
//! that, an AEAD cipher are enabled. The secret must be at least 16 bytes.
//!
//! Key file format, one entry per line: `identity:hex-secret`. Lines starting
//! with `#` and blank lines are ignored.

use crate::sock::{probe_fd, set_timeouts, tune_tcp};
use crate::tls::tcp_connect;
use crate::{ClientSettings, Closer, Conn, Connector, Identity, Incoming, Listener, Prober};
use openssl::error::ErrorStack;
use openssl::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslStream, SslVersion};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MIN_SECRET: usize = 16;
const CIPHERS: &str = "ECDHE-PSK-CHACHA20-POLY1305:DHE-PSK-AES256-GCM-SHA384:PSK-AES256-GCM-SHA384";

fn hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// The secrets the daemon accepts, by identity.
#[derive(Debug, Clone, Default)]
pub struct PskKeys(HashMap<String, Vec<u8>>);

impl PskKeys {
    pub fn parse(text: &str) -> Result<PskKeys, String> {
        let mut m = HashMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (id, key) =
                line.split_once(':').ok_or_else(|| format!("line {}: expected identity:hex-secret", n + 1))?;
            let key = hex(key.trim()).ok_or_else(|| format!("line {}: the secret is not hex", n + 1))?;
            if key.len() < MIN_SECRET {
                return Err(format!("line {}: the secret must be at least {MIN_SECRET} bytes", n + 1));
            }
            if id.is_empty() || id.len() > 128 {
                return Err(format!("line {}: bad identity", n + 1));
            }
            if m.insert(id.to_string(), key).is_some() {
                return Err(format!("line {}: duplicate identity {id}", n + 1));
            }
        }
        if m.is_empty() {
            return Err("no keys".into());
        }
        Ok(PskKeys(m))
    }
}

/// Parse a client's PSK file: exactly one entry.
pub fn client_key_from_file(text: &str) -> Result<(String, Vec<u8>), String> {
    let k = PskKeys::parse(text)?;
    if k.0.len() != 1 {
        return Err("a client key file holds exactly one identity".into());
    }
    Ok(k.0.into_iter().next().unwrap())
}

pub struct PskStream(SslStream<TcpStream>);

impl Read for PskStream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}
impl Write for PskStream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl Conn for PskStream {
    fn set_timeouts(&self, r: Option<Duration>, w: Option<Duration>) -> io::Result<()> {
        set_timeouts(self.0.get_ref(), r, w)
    }
    fn closer(&self) -> io::Result<Closer> {
        let s = self.0.get_ref().try_clone()?;
        Ok(Arc::new(move || {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }))
    }
    fn probe(&self) -> bool {
        probe_fd(self.0.get_ref().as_raw_fd())
    }
    fn prober(&self) -> Option<Prober> {
        let s = self.0.get_ref().try_clone().ok()?;
        Some(Arc::new(move || probe_fd(s.as_raw_fd())))
    }
}

fn ossl(e: ErrorStack) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn base(builder: &mut SslContextBuilder) -> Result<(), ErrorStack> {
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_cipher_list(CIPHERS)?;
    builder.set_options(openssl::ssl::SslOptions::NO_TICKET | openssl::ssl::SslOptions::NO_COMPRESSION);
    Ok(())
}

// ---- client ----

#[derive(Debug)]
pub struct PskConnector {
    host: String,
    port: u16,
    ctx: SslContext,
    timeout: Duration,
}

impl PskConnector {
    pub fn new(host: &str, port: u16, s: &ClientSettings) -> Result<PskConnector, String> {
        let (identity, secret) = s.psk.clone().ok_or("psk:// needs a key (PKCS11_PROXY_TLS_PSK_FILE)")?;
        if secret.len() < MIN_SECRET {
            return Err(format!("the secret must be at least {MIN_SECRET} bytes"));
        }
        let mut b = SslContext::builder(SslMethod::tls_client()).map_err(|e| e.to_string())?;
        base(&mut b).map_err(|e| e.to_string())?;
        b.set_psk_client_callback(move |_ssl, _hint, id_out, secret_out| {
            let id = identity.as_bytes();
            // the identity goes out NUL-terminated
            if id.len() + 1 > id_out.len() || secret.len() > secret_out.len() {
                return Ok(0);
            }
            id_out[..id.len()].copy_from_slice(id);
            id_out[id.len()] = 0;
            secret_out[..secret.len()].copy_from_slice(&secret);
            Ok(secret.len())
        });
        Ok(PskConnector {
            host: host.to_string(),
            port,
            ctx: b.build(),
            timeout: s.connect_timeout.unwrap_or(Duration::from_secs(20)),
        })
    }
}

impl Connector for PskConnector {
    fn connect(&self) -> io::Result<Box<dyn Conn>> {
        let tcp = tcp_connect(&self.host, self.port, self.timeout)?;
        set_timeouts(&tcp, Some(self.timeout), Some(self.timeout))?;
        let ssl = Ssl::new(&self.ctx).map_err(ossl)?;
        let s = ssl.connect(tcp).map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;
        Ok(Box::new(PskStream(s)))
    }
}

// ---- server ----

pub struct PskAcceptor {
    l: TcpListener,
    ctx: SslContext,
    idx: openssl::ex_data::Index<Ssl, Arc<Mutex<Option<String>>>>,
    timeout: Duration,
}

impl PskAcceptor {
    pub fn bind(addr: &str, keys: PskKeys, handshake_timeout: Duration) -> Result<PskAcceptor, String> {
        let idx = Ssl::new_ex_index::<Arc<Mutex<Option<String>>>>().map_err(|e| e.to_string())?;
        let mut b = SslContext::builder(SslMethod::tls_server()).map_err(|e| e.to_string())?;
        base(&mut b).map_err(|e| e.to_string())?;
        b.set_psk_server_callback(move |ssl, identity, secret_out| {
            let Some(id) = identity.and_then(|i| std::str::from_utf8(i).ok()) else { return Ok(0) };
            let Some(key) = keys.0.get(id) else { return Ok(0) };
            if key.len() > secret_out.len() {
                return Ok(0);
            }
            if let Some(slot) = ssl.ex_data(idx) {
                *slot.lock().unwrap() = Some(id.to_string());
            }
            secret_out[..key.len()].copy_from_slice(key);
            Ok(key.len())
        });
        let l = TcpListener::bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
        Ok(PskAcceptor { l, ctx: b.build(), idx, timeout: handshake_timeout })
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.l.local_addr()
    }
}

struct PskIncoming {
    tcp: TcpStream,
    ctx: SslContext,
    idx: openssl::ex_data::Index<Ssl, Arc<Mutex<Option<String>>>>,
    timeout: Duration,
}

impl Incoming for PskIncoming {
    fn establish(self: Box<Self>) -> io::Result<(Box<dyn Conn>, Identity)> {
        let PskIncoming { tcp, ctx, idx, timeout } = *self;
        tune_tcp(&tcp)?;
        set_timeouts(&tcp, Some(timeout), Some(timeout))?;
        let slot = Arc::new(Mutex::new(None));
        let mut ssl = Ssl::new(&ctx).map_err(ossl)?;
        ssl.set_ex_data(idx, slot.clone());
        let s = ssl.accept(tcp).map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
        let id = slot
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "no psk identity"))?;
        set_timeouts(s.get_ref(), None, None)?;
        Ok((Box::new(PskStream(s)), Identity::new(format!("psk:{id}"))))
    }
}

impl Listener for PskAcceptor {
    fn accept(&self) -> io::Result<Box<dyn Incoming>> {
        let (tcp, _) = self.l.accept()?;
        Ok(Box::new(PskIncoming { tcp, ctx: self.ctx.clone(), idx: self.idx, timeout: self.timeout }))
    }
    fn describe(&self) -> String {
        match self.l.local_addr() {
            Ok(a) => format!("psk://{a} (TLS 1.2, pre-shared keys)"),
            Err(_) => "psk:// (TLS 1.2)".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_files() {
        let k = PskKeys::parse(
            "# comment\n\nalice:00112233445566778899aabbccddeeff\nbob:ffeeddccbbaa99887766554433221100\n",
        )
        .unwrap();
        assert_eq!(k.0.len(), 2);
        assert!(PskKeys::parse("alice:0011").is_err(), "too short");
        assert!(PskKeys::parse("alice:zz112233445566778899aabbccddeeff").is_err());
        assert!(PskKeys::parse("alice").is_err());
        assert!(PskKeys::parse("a:00112233445566778899aabbccddeeff\na:00112233445566778899aabbccddeeff").is_err());
        assert!(PskKeys::parse("# nothing").is_err());
        assert!(client_key_from_file("a:00112233445566778899aabbccddeeff").is_ok());
        assert!(client_key_from_file("a:00112233445566778899aabbccddeeff\nb:00112233445566778899aabbccddeeff").is_err());
    }
}
