//! Client settings, from the environment and an optional configuration file.
//!
//! | variable | file key | meaning |
//! |---|---|---|
//! | `PKCS11_PROXY_SOCKET` | `socket` | `unix:///path`, `tcp://host:port` (TLS, certificates) or `psk://host:port` (required) |
//! | `PKCS11_PROXY_TLS_CA` | `ca` | PEM file: the CA that signed the daemon's certificate |
//! | `PKCS11_PROXY_TLS_CERT`, `PKCS11_PROXY_TLS_KEY` | `cert`, `key` | PEM files: this client's certificate chain and key |
//! | `PKCS11_PROXY_TLS_SERVER_NAME` | `server_name` | name to verify the daemon's certificate against (default: the host) |
//! | `PKCS11_PROXY_TLS_PSK_FILE` | `psk_file` | file with one `identity:hex-secret` line, for `psk://` |
//! | `PKCS11_PROXY_TIMEOUT` | `timeout` | seconds one call may take (default 300) |
//! | `PKCS11_PROXY_MAX_CONNECTIONS` | `max_connections` | connections kept open at once (default 16) |
//! | `PKCS11_PROXY_DEBUG` | | set to log connection problems to stderr |
//! | `PKCS11_PROXY_CONFIG` | | a TOML file with the keys above; variables override it |

use crate::core::CoreConfig;
use p11_transport::{ClientSettings, Connector, Endpoint};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

pub const ENV_SOCKET: &str = "PKCS11_PROXY_SOCKET";
pub const ENV_TIMEOUT: &str = "PKCS11_PROXY_TIMEOUT";
pub const ENV_CONFIG: &str = "PKCS11_PROXY_CONFIG";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct File {
    pub socket: Option<String>,
    pub ca: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub server_name: Option<String>,
    pub psk_file: Option<PathBuf>,
    pub timeout: Option<u64>,
    pub max_connections: Option<usize>,
}

/// The settings a process is configured with, before any connection is made.
#[derive(Debug, Default)]
pub struct Settings {
    pub socket: Option<String>,
    pub ca: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub server_name: Option<String>,
    pub psk_file: Option<PathBuf>,
    pub timeout: Option<u64>,
    pub max_connections: Option<usize>,
}

impl Settings {
    /// Read the file named by `PKCS11_PROXY_CONFIG` (if any), then let the
    /// environment override it.
    pub fn load(env: &dyn Fn(&str) -> Option<String>) -> Result<Settings, String> {
        let mut s = Settings::default();
        if let Some(p) = env(ENV_CONFIG) {
            let text = std::fs::read_to_string(&p).map_err(|e| format!("{ENV_CONFIG}: cannot read {p}: {e}"))?;
            let f: File = toml::from_str(&text).map_err(|e| format!("{p}: {e}"))?;
            s = Settings {
                socket: f.socket,
                ca: f.ca,
                cert: f.cert,
                key: f.key,
                server_name: f.server_name,
                psk_file: f.psk_file,
                timeout: f.timeout,
                max_connections: f.max_connections,
            };
        }
        let path = |name: &str| env(name).map(PathBuf::from);
        if let Some(v) = env(ENV_SOCKET) {
            s.socket = Some(v);
        }
        s.ca = path("PKCS11_PROXY_TLS_CA").or(s.ca);
        s.cert = path("PKCS11_PROXY_TLS_CERT").or(s.cert);
        s.key = path("PKCS11_PROXY_TLS_KEY").or(s.key);
        s.server_name = env("PKCS11_PROXY_TLS_SERVER_NAME").or(s.server_name);
        s.psk_file = path("PKCS11_PROXY_TLS_PSK_FILE").or(s.psk_file);
        if let Some(t) = env(ENV_TIMEOUT) {
            s.timeout = Some(t.parse().map_err(|_| format!("{ENV_TIMEOUT} must be a number of seconds"))?);
        }
        if let Some(t) = env("PKCS11_PROXY_MAX_CONNECTIONS") {
            s.max_connections =
                Some(t.parse().map_err(|_| "PKCS11_PROXY_MAX_CONNECTIONS must be a number".to_string())?);
        }
        Ok(s)
    }

    /// Build the connector and pool settings.
    pub fn build(self) -> Result<(Box<dyn Connector>, CoreConfig), String> {
        let spec = self.socket.ok_or_else(|| format!("{ENV_SOCKET} is not set"))?;
        let endpoint = Endpoint::parse(&spec)?;
        let mut cfg = CoreConfig::default();
        if let Some(t) = self.timeout {
            cfg.call_timeout = Duration::from_secs(t);
        }
        if let Some(n) = self.max_connections {
            cfg.max_conns = n.max(1);
        }
        let read = |name: &str, p: &Option<PathBuf>| -> Result<Option<Vec<u8>>, String> {
            match p {
                None => Ok(None),
                Some(p) => std::fs::read(p).map(Some).map_err(|e| format!("{name}: cannot read {}: {e}", p.display())),
            }
        };
        #[allow(unused_mut)]
        let mut s = ClientSettings {
            ca_pem: read("ca", &self.ca)?,
            cert_pem: read("cert", &self.cert)?,
            key_pem: read("key", &self.key)?,
            server_name: self.server_name,
            connect_timeout: Some(cfg.connect_timeout),
            ..Default::default()
        };
        #[cfg(feature = "psk")]
        if let Some(b) = read("psk_file", &self.psk_file)? {
            let text = String::from_utf8(b).map_err(|_| "the PSK file is not text".to_string())?;
            s.psk = Some(p11_transport::psk::client_key_from_file(&text).map_err(|e| format!("the PSK file: {e}"))?);
        }
        #[cfg(not(feature = "psk"))]
        let _ = &self.psk_file;
        Ok((p11_transport::client_connector(&endpoint, &s)?, cfg))
    }
}

pub fn from_env() -> Result<(Box<dyn Connector>, CoreConfig), String> {
    Settings::load(&|k| std::env::var(k).ok())?.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn file_then_environment() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("client.toml");
        std::fs::write(
            &f,
            "socket = \"unix:///from/file\"\ntimeout = 10\nmax_connections = 3\nserver_name = \"hsm\"\n",
        )
        .unwrap();
        let s = Settings::load(&env(&[(ENV_CONFIG, f.to_str().unwrap())])).unwrap();
        assert_eq!(
            (s.socket.as_deref(), s.timeout, s.max_connections, s.server_name.as_deref()),
            (Some("unix:///from/file"), Some(10), Some(3), Some("hsm"))
        );
        // the environment wins
        let s = Settings::load(&env(&[
            (ENV_CONFIG, f.to_str().unwrap()),
            (ENV_SOCKET, "unix:///from/env"),
            (ENV_TIMEOUT, "99"),
        ]))
        .unwrap();
        assert_eq!((s.socket.as_deref(), s.timeout), (Some("unix:///from/env"), Some(99)));
        // errors are reported, not ignored
        assert!(Settings::load(&env(&[(ENV_CONFIG, "/nonexistent/file")])).is_err());
        assert!(Settings::load(&env(&[(ENV_TIMEOUT, "soon")])).is_err());
        std::fs::write(&f, "sockett = 1\n").unwrap();
        assert!(Settings::load(&env(&[(ENV_CONFIG, f.to_str().unwrap())])).is_err(), "typos in the file are errors");
        assert!(Settings::default().build().is_err(), "no socket configured");
    }
}
