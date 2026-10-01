//! Throwaway certificates for TLS tests.

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use std::path::{Path, PathBuf};

pub struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    pub pem: String,
}

#[derive(Debug, Clone)]
pub struct Leaf {
    pub cert_pem: String,
    pub key_pem: String,
}

impl Ca {
    pub fn new(name: &str) -> Ca {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        let pem = cert.pem();
        Ca { cert, key, pem }
    }

    /// A certificate with this common name and these DNS names / IP addresses.
    pub fn leaf(&self, cn: &str, sans: &[&str]) -> Leaf {
        let mut p = CertificateParams::new(vec![]).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        for s in sans {
            p.subject_alt_names.push(match s.parse::<std::net::IpAddr>() {
                Ok(ip) => SanType::IpAddress(ip),
                Err(_) => SanType::DnsName((*s).try_into().unwrap()),
            });
        }
        let key = KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, &self.cert, &self.key).unwrap();
        Leaf { cert_pem: cert.pem(), key_pem: key.serialize_pem() }
    }
}

impl Leaf {
    /// Write `<name>.pem` and `<name>.key` into `dir`.
    pub fn write(&self, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let c = dir.join(format!("{name}.pem"));
        let k = dir.join(format!("{name}.key"));
        std::fs::write(&c, &self.cert_pem).unwrap();
        std::fs::write(&k, &self.key_pem).unwrap();
        (c, k)
    }
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ca")
    }
}
