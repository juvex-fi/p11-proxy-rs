//! Accepting connections: the handshake, client contexts, and the request loop.

use crate::ctx::ClientCtx;
use crate::dispatch::handle_with;
use crate::policy::{Identity, Policy};
use p11_module::Backend;
use p11_wire::codec::{from_slice, to_vec};
use p11_wire::frame::*;
use p11_wire::handshake::*;
use p11_wire::WireError;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

/// Limits on what clients may hold.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Client contexts alive at once.
    pub max_contexts: usize,
    /// Pooled connections per context.
    pub max_conns_per_context: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_contexts: 256, max_conns_per_context: 32 }
    }
}

#[derive(Debug)]
pub enum ServeError {
    Wire(WireError),
    Refused(AbortReason),
}

impl core::fmt::Display for ServeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServeError::Wire(e) => write!(f, "{e}"),
            ServeError::Refused(r) => write!(f, "connection refused: {r:?}"),
        }
    }
}

impl std::error::Error for ServeError {}

impl From<WireError> for ServeError {
    fn from(e: WireError) -> Self {
        ServeError::Wire(e)
    }
}

/// Whether a request is a vendor-defined function call whose arguments include a secret (a PIN).
#[cfg(feature = "vendor")]
fn vendor_call_has_secret(call: u16, payload: &[u8]) -> bool {
    /// The bytes of a request before the call's own body: the request id and the call id.
    const REQUEST_HEAD: usize = 6;
    call == p11_wire::vendorfn::CALL_VENDOR
        && payload.get(REQUEST_HEAD..).is_some_and(|body| {
            p11_wire::vendorfn::request_name(body)
                .ok()
                .and_then(|n| p11_params::vendorfn::get(&n))
                .is_some_and(|d| d.has_secret())
        })
}

#[cfg(not(feature = "vendor"))]
fn vendor_call_has_secret(_call: u16, _payload: &[u8]) -> bool {
    false
}

pub struct Server {
    backend: Arc<dyn Backend>,
    policy: Policy,
    limits: Limits,
    name: String,
    /// Vendor-defined mechanisms announced to clients that ask for them.
    #[cfg(feature = "vendor")]
    vendor: VendorMechs,
    /// Vendor-defined functions announced to clients that ask for them.
    #[cfg(feature = "vendor")]
    vendor_fns: p11_wire::vendorfn::VendorFns,
    contexts: Mutex<HashMap<Token, Arc<ClientCtx>>>,
}

impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Server").field("name", &self.name).finish()
    }
}

fn new_token() -> Token {
    let mut t = [0u8; TOKEN_LEN];
    getrandom::fill(&mut t).expect("system randomness");
    t
}

impl Server {
    pub fn new(backend: Arc<dyn Backend>, policy: Policy, limits: Limits) -> Server {
        Server {
            backend,
            policy,
            limits,
            name: concat!("p11-daemon/", env!("CARGO_PKG_VERSION")).into(),
            #[cfg(feature = "vendor")]
            vendor: VendorMechs::default(),
            #[cfg(feature = "vendor")]
            vendor_fns: p11_wire::vendorfn::VendorFns::default(),
            contexts: Mutex::new(HashMap::new()),
        }
    }

    /// Announce these vendor-defined functions to every client that asks. The caller has installed
    /// them with `p11_params::vendorfn::set` for the daemon's own use.
    #[cfg(feature = "vendor")]
    pub fn with_vendor_functions(mut self, list: &[p11_wire::vendorfn::FnDesc]) -> Server {
        self.vendor_fns = p11_params::vendorfn::to_wire(list);
        self
    }

    /// Announce these vendor-defined mechanisms to every client that asks. The caller has
    /// installed them with `p11_params::vendor::set` for the daemon's own use.
    #[cfg(feature = "vendor")]
    pub fn with_vendor_mechanisms(
        mut self,
        list: &[p11_params::vendor::VendorMech],
        structs: &[p11_params::vendor::VendorStruct],
    ) -> Result<Server, String> {
        self.vendor = p11_params::vendor::to_wire(list, structs)?;
        Ok(self)
    }

    /// Client contexts currently alive.
    pub fn context_count(&self) -> usize {
        self.contexts.lock().unwrap().len()
    }

    fn attach(&self, hello: &Hello, identity: &Identity) -> Result<Arc<ClientCtx>, AbortReason> {
        let mut map = self.contexts.lock().unwrap();
        if hello.join {
            let ctx = map.get(&hello.token).ok_or(AbortReason::Protocol)?;
            if ctx.identity != *identity {
                return Err(AbortReason::Unauthorized);
            }
            if ctx.conns.load(Ordering::SeqCst) >= self.limits.max_conns_per_context {
                return Err(AbortReason::Busy);
            }
            ctx.conns.fetch_add(1, Ordering::SeqCst);
            return Ok(ctx.clone());
        }
        let rules = self.policy.rules_for(identity).ok_or(AbortReason::Unauthorized)?.clone();
        if map.len() >= self.limits.max_contexts {
            return Err(AbortReason::Busy);
        }
        let token = new_token();
        let ctx = Arc::new(ClientCtx::new(token, identity.clone(), rules));
        ctx.conns.store(1, Ordering::SeqCst);
        map.insert(token, ctx.clone());
        Ok(ctx)
    }

    fn detach(&self, ctx: &Arc<ClientCtx>) {
        let mut map = self.contexts.lock().unwrap();
        if ctx.conns.fetch_sub(1, Ordering::SeqCst) == 1 {
            debug!("{} went away with {} open sessions", ctx.identity, ctx.session_count());
            map.remove(&ctx.token);
            drop(map);
            // the last connection is gone: give back what the client left open
            ctx.close_sessions(&*self.backend, None);
        }
    }

    /// Serve one connection until the client hangs up or breaks the protocol.
    pub fn serve<S: Read + Write>(&self, stream: S, identity: &Identity) -> Result<(), ServeError> {
        self.serve_with(stream, identity, None)
    }

    /// [`Server::serve`] on a transport connection: calls that wait notice when the client leaves.
    pub fn serve_conn<C: p11_transport::Conn>(&self, conn: C, identity: &Identity) -> Result<(), ServeError> {
        let prober = conn.prober();
        self.serve_with(conn, identity, prober)
    }

    fn serve_with<S: Read + Write>(
        &self,
        mut stream: S,
        identity: &Identity,
        prober: Option<p11_transport::Prober>,
    ) -> Result<(), ServeError> {
        let mut reader = FrameReader::new();
        let f = reader.read(&mut stream)?;
        if f.kind != Kind::Hello {
            return self.abort(&mut stream, AbortReason::Protocol);
        }
        let hello: Hello = match from_slice(&f.payload) {
            Ok(h) => h,
            Err(_) => return self.abort(&mut stream, AbortReason::Protocol),
        };
        let Some(version) = negotiate(hello.min_version, hello.max_version) else {
            return self.abort(&mut stream, AbortReason::Version);
        };
        let ctx = match self.attach(&hello, identity) {
            Ok(c) => c,
            Err(r) => {
                info!("refusing {identity}: {r:?}");
                return self.abort(&mut stream, r);
            }
        };
        debug!("{identity} attached ({}, {})", hello.client, if hello.join { "joined" } else { "new context" });
        let (bits, frames) = self.vendor_announcement(hello.features);
        let ack = HelloAck { version, features: bits, token: ctx.token, server: self.name.clone() };
        let result = write_frame(&mut stream, Kind::HelloAck, &to_vec(&ack))
            .and_then(|_| frames.iter().try_for_each(|(kind, payload)| write_frame(&mut stream, *kind, payload)))
            .map_err(ServeError::from)
            .and_then(|_| self.request_loop(&mut stream, &mut reader, &ctx, prober.as_ref()));
        self.detach(&ctx);
        result
    }

    /// The feature bits for the `HelloAck` and the frames that follow it: the vendor-defined mechanisms and
    /// functions, each to a client that asked for them, and only if there are some.
    #[cfg(feature = "vendor")]
    fn vendor_announcement(&self, asked: u64) -> (u64, Vec<(Kind, Vec<u8>)>) {
        let mut bits = features::NONE;
        let mut frames = Vec::new();
        if asked & features::VENDOR_MECHANISMS != 0 && !self.vendor.0.is_empty() {
            bits |= features::VENDOR_MECHANISMS;
            frames.push((Kind::VendorMechanisms, to_vec(&self.vendor)));
        }
        if asked & features::VENDOR_FUNCTIONS != 0 && !self.vendor_fns.0.is_empty() {
            bits |= features::VENDOR_FUNCTIONS;
            frames.push((Kind::VendorFunctions, to_vec(&self.vendor_fns)));
        }
        (bits, frames)
    }

    /// Built without vendor support: nothing is announced, whatever the client asks.
    #[cfg(not(feature = "vendor"))]
    fn vendor_announcement(&self, _asked: u64) -> (u64, Vec<(Kind, Vec<u8>)>) {
        (features::NONE, Vec::new())
    }

    fn abort<S: Write>(&self, stream: &mut S, reason: AbortReason) -> Result<(), ServeError> {
        let _ = write_frame(stream, Kind::Abort, &to_vec(&reason));
        Err(ServeError::Refused(reason))
    }

    fn request_loop<S: Read + Write>(
        &self,
        stream: &mut S,
        reader: &mut FrameReader,
        ctx: &Arc<ClientCtx>,
        prober: Option<&p11_transport::Prober>,
    ) -> Result<(), ServeError> {
        let alive = || prober.is_none_or(|p| p());
        loop {
            let f = match reader.read(stream) {
                Ok(f) => f,
                // a clean hang-up between requests is the normal end
                Err(WireError::Io(std::io::ErrorKind::UnexpectedEof)) => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            if f.kind != Kind::Request {
                return self.abort(stream, AbortReason::Protocol);
            }
            let mut f = f;
            let (head, answer) = match parse_request(&f.payload) {
                Ok((head, body)) => {
                    let a = handle_with(ctx, &*self.backend, head.call, body, &alive);
                    (head, a)
                }
                Err(_) => return self.abort(stream, AbortReason::Protocol),
            };
            // the request may have carried a PIN
            if vendor_call_has_secret(head.call, &f.payload)
                || p11_wire::calls::call_info(head.call).is_some_and(|i| i.secret)
            {
                p11_wire::wipe_vec(&mut f.payload);
            }
            let (rv, resp) = match answer {
                Ok(a) => a,
                Err(_) => return self.abort(stream, AbortReason::Protocol),
            };
            write_frame(stream, Kind::Response, &build_response(head.id, rv, resp.as_deref()))?;
        }
    }
}
