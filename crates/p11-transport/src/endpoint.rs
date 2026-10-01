use std::path::PathBuf;

/// Where the daemon listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Unix(PathBuf),
    /// TLS 1.3 with certificates.
    Tcp {
        host: String,
        port: u16,
    },
    /// TLS 1.2 with a pre-shared key.
    Psk {
        host: String,
        port: u16,
    },
    Stdio,
}

fn host_port(rest: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(r) = rest.strip_prefix('[') {
        r.split_once("]:").ok_or("expected [address]:port")?
    } else {
        rest.rsplit_once(':').ok_or("expected host:port")?
    };
    if host.is_empty() {
        return Err("missing host".into());
    }
    let port: u16 = port.parse().map_err(|_| "bad port".to_string())?;
    Ok((host.to_string(), port))
}

impl Endpoint {
    /// `unix:///path`, `tcp://host:port`, `tcp://[v6]:port`, `psk://host:port`, `stdio`.
    pub fn parse(s: &str) -> Result<Endpoint, String> {
        if s == "stdio" {
            return Ok(Endpoint::Stdio);
        }
        if let Some(p) = s.strip_prefix("unix://") {
            if p.is_empty() {
                return Err("unix:// needs a path".into());
            }
            return Ok(Endpoint::Unix(PathBuf::from(p)));
        }
        if let Some(r) = s.strip_prefix("tcp://") {
            let (host, port) = host_port(r)?;
            return Ok(Endpoint::Tcp { host, port });
        }
        if let Some(r) = s.strip_prefix("psk://") {
            let (host, port) = host_port(r)?;
            return Ok(Endpoint::Psk { host, port });
        }
        Err(format!("unsupported address {s:?}: use unix:///path, tcp://host:port (TLS), psk://host:port or stdio"))
    }
}

impl core::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Endpoint::Unix(p) => write!(f, "unix://{}", p.display()),
            Endpoint::Tcp { host, port } if host.contains(':') => write!(f, "tcp://[{host}]:{port}"),
            Endpoint::Tcp { host, port } => write!(f, "tcp://{host}:{port}"),
            Endpoint::Psk { host, port } if host.contains(':') => write!(f, "psk://[{host}]:{port}"),
            Endpoint::Psk { host, port } => write!(f, "psk://{host}:{port}"),
            Endpoint::Stdio => f.write_str("stdio"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert_eq!(Endpoint::parse("unix:///run/p11.sock").unwrap(), Endpoint::Unix("/run/p11.sock".into()));
        assert_eq!(
            Endpoint::parse("tcp://hsm.example.com:2345").unwrap(),
            Endpoint::Tcp { host: "hsm.example.com".into(), port: 2345 }
        );
        assert_eq!(Endpoint::parse("tcp://[::1]:2345").unwrap(), Endpoint::Tcp { host: "::1".into(), port: 2345 });
        assert_eq!(Endpoint::parse("psk://10.0.0.1:1").unwrap(), Endpoint::Psk { host: "10.0.0.1".into(), port: 1 });
        assert_eq!(Endpoint::parse("stdio").unwrap(), Endpoint::Stdio);
        for bad in ["tcp://host", "tcp://host:99999", "http://x:1", "unix://", "tcp://:80", "tcp://[::1]"] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(Endpoint::parse("tcp://[::1]:2345").unwrap().to_string(), "tcp://[::1]:2345");
    }
}
