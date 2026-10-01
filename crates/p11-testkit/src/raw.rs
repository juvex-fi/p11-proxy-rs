//! A bare protocol client for tests: speaks frames and typed requests over a
//! local socket pair to a `Server` running on a thread.

use p11_daemon::{Identity, ServeError, Server};
use p11_wire::calls::{Request, Response, ResponseError};
use p11_wire::codec::{from_slice, to_vec};
use p11_wire::frame::*;
use p11_wire::handshake::*;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread::JoinHandle;

#[derive(Debug)]
pub struct RawClient {
    pub stream: UnixStream,
    pub token: Token,
    pub version: u16,
    next_id: u32,
    pub server_thread: Option<JoinHandle<Result<(), ServeError>>>,
}

/// What the daemon answered to the hello.
#[derive(Debug)]
pub enum Hi {
    Ack(HelloAck),
    Abort(AbortReason),
}

pub fn hello(join: Option<Token>) -> Hello {
    Hello {
        min_version: VERSION_MIN,
        max_version: VERSION_MAX,
        features: 0,
        join: join.is_some(),
        token: join.unwrap_or([0; TOKEN_LEN]),
        client: "testkit".into(),
    }
}

impl RawClient {
    /// Connect over a socket pair, serving the other end on a thread.
    pub fn connect(server: &Arc<Server>, identity: &str, join: Option<Token>) -> Result<RawClient, AbortReason> {
        let (a, b) = UnixStream::pair().unwrap();
        let s = server.clone();
        let id = Identity::new(identity);
        let t = std::thread::spawn(move || s.serve_conn(b, &id));
        let mut c = RawClient { stream: a, token: [0; TOKEN_LEN], version: 0, next_id: 1, server_thread: Some(t) };
        match c.exchange_hello(&hello(join)) {
            Hi::Ack(ack) => {
                c.token = ack.token;
                c.version = ack.version;
                Ok(c)
            }
            Hi::Abort(r) => Err(r),
        }
    }

    /// Wrap an already connected stream (the caller drives the handshake).
    pub fn from_stream(stream: UnixStream) -> RawClient {
        RawClient { stream, token: [0; TOKEN_LEN], version: 0, next_id: 1, server_thread: None }
    }

    pub fn exchange_hello(&mut self, h: &Hello) -> Hi {
        write_frame(&mut self.stream, Kind::Hello, &to_vec(h)).unwrap();
        let f = read_frame(&mut self.stream).unwrap();
        match f.kind {
            Kind::HelloAck => Hi::Ack(from_slice(&f.payload).unwrap()),
            Kind::Abort => Hi::Abort(from_slice(&f.payload).unwrap()),
            k => panic!("unexpected {k:?}"),
        }
    }

    /// Send a request and read its response.
    pub fn call(&mut self, req: &Request) -> (u64, Option<Response>) {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(&mut self.stream, Kind::Request, &build_request(id, req.call_id(), &req.encode_body())).unwrap();
        let f = read_frame(&mut self.stream).unwrap();
        assert_eq!(f.kind, Kind::Response);
        let (h, body) = parse_response(&f.payload).unwrap();
        assert_eq!(h.id, id);
        let resp = h.has_body.then(|| match Response::decode(req.call_id(), body) {
            Ok(r) => r,
            Err(ResponseError::Unknown) => panic!("unknown response"),
            Err(ResponseError::Malformed(e)) => panic!("malformed response: {e}"),
        });
        (h.rv, resp)
    }

    /// Close the connection and wait for the daemon's side to finish.
    pub fn close(mut self) -> Result<(), ServeError> {
        let t = self.server_thread.take().unwrap();
        drop(self.stream);
        t.join().unwrap()
    }
}

/// A `Connector` that serves each connection on a thread of this process.
#[derive(Debug, Clone)]
pub struct Loopback {
    pub server: Arc<Server>,
    pub identity: String,
}

impl p11_transport::Connector for Loopback {
    fn connect(&self) -> std::io::Result<Box<dyn p11_transport::Conn>> {
        let (a, b) = UnixStream::pair()?;
        let s = self.server.clone();
        let id = Identity::new(self.identity.clone());
        std::thread::spawn(move || {
            let _ = s.serve_conn(b, &id);
        });
        Ok(Box::new(a))
    }
}
