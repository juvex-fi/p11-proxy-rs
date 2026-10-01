//! Transports.
//!
//! A [`Conn`] is a connected, blocking byte stream with timeouts; a
//! [`Connector`] makes them for the client library; a [`Listener`] accepts
//! them for the daemon and tells it who is on the other end ([`Identity`]).
//!
//! | scheme | what |
//! |---|---|
//! | `unix:///path` | a local socket; the peer's uid is its identity |
//! | `tcp://host:port` | TLS 1.3 over TCP with certificates on both sides |
//! | `psk://host:port` | TLS 1.2 with a pre-shared key (feature `psk`) |
//! | `stdio` | the daemon's stdin and stdout, for inetd-style launchers |
//!
//! There is no plaintext TCP.
#![allow(missing_debug_implementations)]

use std::fmt::Debug;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::Duration;

pub mod endpoint;
pub mod identity;
mod sock;
pub mod stdio;
pub mod tls;
pub mod unix;

#[cfg(feature = "psk")]
pub mod psk;

pub use endpoint::Endpoint;
pub use identity::Identity;

/// See [`Conn::closer`].
pub type Closer = Arc<dyn Fn() + Send + Sync>;

/// See [`Conn::prober`]: true while the peer is still there.
pub type Prober = Arc<dyn Fn() -> bool + Send + Sync>;

pub trait Conn: Read + Write + Send + 'static {
    /// Limit how long one read or write may block; `None` removes the limit.
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()>;
    /// A handle that can shut the connection down from another thread,
    /// waking anything blocked in a read or write on it.
    fn closer(&self) -> io::Result<Closer>;
    /// Whether the peer is still there, checked without blocking: an idle
    /// connection the peer closed reads as end of file. A connection with
    /// unexpected data pending is not usable either.
    fn probe(&self) -> bool {
        true
    }
    /// A handle that checks [`Conn::probe`] from another thread, so a call
    /// that blocks on something else (waiting for a slot event) can notice
    /// that its client has gone. `None` if the transport cannot say.
    fn prober(&self) -> Option<Prober> {
        None
    }
}

impl<T: Conn + ?Sized> Conn for Box<T> {
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> io::Result<()> {
        (**self).set_timeouts(read, write)
    }
    fn closer(&self) -> io::Result<Closer> {
        (**self).closer()
    }
    fn probe(&self) -> bool {
        (**self).probe()
    }
    fn prober(&self) -> Option<Prober> {
        (**self).prober()
    }
}

/// Makes connections to the daemon.
pub trait Connector: Send + Sync + Debug {
    fn connect(&self) -> io::Result<Box<dyn Conn>>;
}

/// A connection the daemon has accepted but whose handshake may not have
/// happened yet, so a slow peer can't stall the accept loop: call
/// [`Incoming::establish`] on the connection's own thread.
pub trait Incoming: Send {
    fn establish(self: Box<Self>) -> io::Result<(Box<dyn Conn>, Identity)>;
}

pub trait Listener: Send + Sync {
    /// Wait for the next connection.
    fn accept(&self) -> io::Result<Box<dyn Incoming>>;
    /// What this listens on, for logs.
    fn describe(&self) -> String;
}

/// Client-side settings for the TLS transports. All contents, not paths, so
/// callers decide where they come from.
#[derive(Debug, Clone, Default)]
pub struct ClientSettings {
    /// PEM: the CA that signed the daemon's certificate.
    pub ca_pem: Option<Vec<u8>>,
    /// PEM: this client's certificate chain and key.
    pub cert_pem: Option<Vec<u8>>,
    pub key_pem: Option<Vec<u8>>,
    /// The name to check the daemon's certificate against (default: the host).
    pub server_name: Option<String>,
    /// For `psk://`: identity and secret.
    pub psk: Option<(String, Vec<u8>)>,
    pub connect_timeout: Option<Duration>,
}

/// The connector a client uses for `endpoint`.
pub fn client_connector(endpoint: &Endpoint, s: &ClientSettings) -> Result<Box<dyn Connector>, String> {
    match endpoint {
        Endpoint::Unix(p) => Ok(Box::new(unix::UnixConnector(p.clone()))),
        Endpoint::Tcp { host, port } => Ok(Box::new(tls::TlsConnector::new(host, *port, s)?)),
        #[cfg(feature = "psk")]
        Endpoint::Psk { host, port } => Ok(Box::new(psk::PskConnector::new(host, *port, s)?)),
        #[cfg(not(feature = "psk"))]
        Endpoint::Psk { .. } => Err("this build has no TLS-PSK support (feature `psk`)".into()),
        Endpoint::Stdio => Err("stdio is for the daemon, not for clients".into()),
    }
}
