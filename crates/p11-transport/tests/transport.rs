use p11_transport::tls::{TlsAcceptor, TlsConnector};
use p11_transport::unix::{UnixAcceptor, UnixConnector};
use p11_transport::{ClientSettings, Conn, Connector, Incoming, Listener};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use std::io::{Read, Write};
use std::time::Duration;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

struct Leaf {
    cert_pem: String,
    key_pem: String,
}

fn ca(name: &str) -> Ca {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    Ca { cert, key }
}

fn leaf(ca: &Ca, cn: &str, sans: &[&str]) -> Leaf {
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    for s in sans {
        p.subject_alt_names.push(match s.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName((*s).try_into().unwrap()),
        });
    }
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &ca.cert, &ca.key).unwrap();
    Leaf { cert_pem: cert.pem(), key_pem: key.serialize_pem() }
}

fn settings(ca: &Ca, client: &Leaf) -> ClientSettings {
    ClientSettings {
        ca_pem: Some(ca.cert.pem().into_bytes()),
        cert_pem: Some(client.cert_pem.clone().into_bytes()),
        key_pem: Some(client.key_pem.clone().into_bytes()),
        server_name: Some("localhost".into()),
        connect_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    }
}

/// Run one connection on a thread: establish, echo a line back.
fn echo_once(l: Box<dyn Listener>) -> (String, std::thread::JoinHandle<Result<String, String>>) {
    let d = l.describe();
    let t = std::thread::spawn(move || {
        let inc: Box<dyn Incoming> = l.accept().map_err(|e| e.to_string())?;
        let (mut c, id) = inc.establish().map_err(|e| e.to_string())?;
        let mut buf = [0u8; 5];
        c.read_exact(&mut buf).map_err(|e| e.to_string())?;
        c.write_all(&buf).map_err(|e| e.to_string())?;
        Ok(id.to_string())
    });
    (d, t)
}

#[test]
fn mutual_tls_and_identity() {
    let ca = ca("test ca");
    let server = leaf(&ca, "daemon", &["localhost", "127.0.0.1"]);
    let alice = leaf(&ca, "alice", &["alice.example.org"]);
    let acc = TlsAcceptor::bind(
        "127.0.0.1:0",
        server.cert_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca.cert.pem().as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    let port = acc.local_addr().unwrap().port();
    let (_d, t) = echo_once(Box::new(acc));

    let c = TlsConnector::new("127.0.0.1", port, &settings(&ca, &alice)).unwrap();
    let mut conn = c.connect().unwrap();
    assert!(conn.probe(), "an idle, healthy connection probes alive");
    conn.write_all(b"hello").unwrap();
    let mut back = [0u8; 5];
    conn.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"hello");
    assert_eq!(t.join().unwrap().unwrap(), "cert:cn=alice");
    // the server has gone: the connection reads as dead
    std::thread::sleep(Duration::from_millis(100));
    assert!(!conn.probe());
}

#[test]
fn identity_aliases_from_the_certificate() {
    let ca = ca("test ca");
    let alice = leaf(&ca, "alice", &["alice.example.org"]);
    let der = rustls_pemfile_der(&alice.cert_pem);
    let id = p11_transport::tls::identity_of_cert(&der);
    assert_eq!(id.name, "cert:cn=alice");
    assert!(id.matches("cert:san:dns=alice.example.org"));
    assert!(id.labels().any(|l| l.starts_with("cert:sha256=") && l.len() == "cert:sha256=".len() + 64));
}

fn rustls_pemfile_der(pem: &str) -> Vec<u8> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::from_pem_slice(pem.as_bytes()).unwrap().to_vec()
}

#[test]
fn clients_and_servers_from_the_wrong_ca_are_refused() {
    let ca1 = ca("ca one");
    let ca2 = ca("ca two");
    let server = leaf(&ca1, "daemon", &["localhost", "127.0.0.1"]);
    let good = leaf(&ca1, "alice", &[]);
    let stranger = leaf(&ca2, "mallory", &[]);
    let acc = TlsAcceptor::bind(
        "127.0.0.1:0",
        server.cert_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca1.cert.pem().as_bytes(),
        Duration::from_secs(5),
    )
    .unwrap();
    let port = acc.local_addr().unwrap().port();
    let acc = std::sync::Arc::new(acc);

    // a client certificate from another CA: the server refuses at the handshake
    let a = acc.clone();
    let t = std::thread::spawn(move || a.accept().unwrap().establish().map(|_| ()).map_err(|e| e.to_string()));
    let c = TlsConnector::new("127.0.0.1", port, &settings(&ca1, &stranger)).unwrap();
    let r = c.connect().and_then(|mut c| {
        // TLS 1.3 reports a rejected client certificate on the first read
        c.write_all(b"x")?;
        let mut b = [0u8; 1];
        c.read_exact(&mut b)
    });
    assert!(r.is_err());
    assert!(t.join().unwrap().is_err());

    // a client that trusts a different CA refuses the server
    let a = acc.clone();
    let t = std::thread::spawn(move || a.accept().unwrap().establish().map(|_| ()).map_err(|e| e.to_string()));
    let c = TlsConnector::new("127.0.0.1", port, &settings(&ca2, &good)).unwrap();
    assert!(c.connect().is_err());
    let _ = t.join().unwrap();

    // a certificate for a different name
    let a = acc.clone();
    let t = std::thread::spawn(move || a.accept().unwrap().establish().map(|_| ()).map_err(|e| e.to_string()));
    let mut s = settings(&ca1, &good);
    s.server_name = Some("elsewhere.example.org".into());
    let c = TlsConnector::new("127.0.0.1", port, &s).unwrap();
    assert!(c.connect().is_err());
    let _ = t.join().unwrap();

    // no client certificate configured
    let mut s = settings(&ca1, &good);
    s.cert_pem = None;
    assert!(TlsConnector::new("127.0.0.1", port, &s).is_err());
}

#[test]
fn a_silent_peer_cannot_hold_the_handshake_forever() {
    let ca = ca("test ca");
    let server = leaf(&ca, "daemon", &["localhost"]);
    let acc = TlsAcceptor::bind(
        "127.0.0.1:0",
        server.cert_pem.as_bytes(),
        server.key_pem.as_bytes(),
        ca.cert.pem().as_bytes(),
        Duration::from_millis(300),
    )
    .unwrap();
    let port = acc.local_addr().unwrap().port();
    let t = std::thread::spawn(move || acc.accept().unwrap().establish().map(|_| ()).map_err(|e| e.kind()));
    let _silent = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let started = std::time::Instant::now();
    assert!(t.join().unwrap().is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[cfg(feature = "psk")]
mod psk {
    use super::*;
    use p11_transport::psk::{PskAcceptor, PskConnector, PskKeys};

    const KEYS: &str = "alice:00112233445566778899aabbccddeeff\nbob:ffeeddccbbaa99887766554433221100\n";

    fn client(port: u16, id: &str, secret: &str) -> Result<PskConnector, String> {
        let s = ClientSettings {
            psk: Some((
                id.into(),
                (0..secret.len() / 2).map(|i| u8::from_str_radix(&secret[2 * i..2 * i + 2], 16).unwrap()).collect(),
            )),
            connect_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };
        PskConnector::new("127.0.0.1", port, &s)
    }

    #[test]
    fn psk_authenticates_by_secret() {
        let acc = PskAcceptor::bind("127.0.0.1:0", PskKeys::parse(KEYS).unwrap(), Duration::from_secs(5)).unwrap();
        let port = acc.local_addr().unwrap().port();
        let acc = std::sync::Arc::new(acc);

        let a = acc.clone();
        let t = std::thread::spawn(move || {
            let (mut c, id) = a.accept().unwrap().establish().map_err(|e| e.to_string())?;
            let mut b = [0u8; 5];
            c.read_exact(&mut b).map_err(|e| e.to_string())?;
            c.write_all(&b).map_err(|e| e.to_string())?;
            Ok::<_, String>(id.name)
        });
        let mut c = client(port, "bob", "ffeeddccbbaa99887766554433221100").unwrap().connect().unwrap();
        c.write_all(b"hello").unwrap();
        let mut b = [0u8; 5];
        c.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hello");
        assert_eq!(t.join().unwrap().unwrap(), "psk:bob");
        std::thread::sleep(Duration::from_millis(100));
        assert!(!c.probe());

        // the wrong secret
        let a = acc.clone();
        let t = std::thread::spawn(move || a.accept().unwrap().establish().map(|_| ()).map_err(|e| e.to_string()));
        assert!(client(port, "bob", "00112233445566778899aabbccddeeff").unwrap().connect().is_err());
        assert!(t.join().unwrap().is_err());

        // an identity the daemon doesn't know
        let a = acc.clone();
        let t = std::thread::spawn(move || a.accept().unwrap().establish().map(|_| ()).map_err(|e| e.to_string()));
        assert!(client(port, "eve", "00112233445566778899aabbccddeeff").unwrap().connect().is_err());
        assert!(t.join().unwrap().is_err());

        // a short secret is refused before it is used
        assert!(client(port, "bob", "0011").is_err());
    }
}

#[test]
fn unix_sockets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p11.sock");
    let acc = UnixAcceptor::bind(&path, None).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o660);
    }
    let (_d, t) = echo_once(Box::new(acc));
    let mut c = UnixConnector(path.clone()).connect().unwrap();
    c.write_all(b"hello").unwrap();
    let mut b = [0u8; 5];
    c.read_exact(&mut b).unwrap();
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc_getuid() };
    assert_eq!(t.join().unwrap().unwrap(), format!("unix:uid={uid}"));
    // the socket file goes away with the acceptor
    assert!(!path.exists());

    // a stale socket file is replaced; a regular file is left alone
    let stale = dir.path().join("stale.sock");
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
    assert!(stale.exists());
    UnixAcceptor::bind(&stale, Some(0o600)).unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    assert!(UnixAcceptor::bind(&file, None).is_err());
    assert!(file.exists());
    // a live listener is not stolen
    let live = dir.path().join("live.sock");
    let _keep = UnixAcceptor::bind(&live, None).unwrap();
    assert!(UnixAcceptor::bind(&live, None).is_err());
}

unsafe fn libc_getuid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    // SAFETY: getuid has no preconditions.
    unsafe { getuid() }
}
