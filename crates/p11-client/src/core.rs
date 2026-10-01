//! The connection pool and the request/response exchange.
//!
//! One `Core` is one client context in the daemon. Its first connection
//! creates the context; further connections join it, so calls from several
//! threads run in parallel and a blocking `C_WaitForSlotEvent` occupies one
//! connection instead of the whole library.

use p11_transport::{Closer, Conn, Connector};
use p11_types::*;
use p11_wire::calls::{Request, Response, ResponseError};
use p11_wire::codec::{from_slice, to_vec};
use p11_wire::frame::*;
use p11_wire::handshake::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// How long one call may take (blocking calls excepted).
    pub call_timeout: Duration,
    /// How long connecting and the handshake may take.
    pub connect_timeout: Duration,
    /// Most connections kept open at once.
    pub max_conns: usize,
    pub client_name: String,
}

impl Default for CoreConfig {
    fn default() -> Self {
        CoreConfig {
            call_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(20),
            max_conns: 16,
            client_name: format!("libp11-proxy/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

struct Link {
    conn: Box<dyn Conn>,
    reader: FrameReader,
    next_id: u32,
    uid: u64,
    /// The timeouts currently set on the connection, to avoid setting them again for every call.
    timeouts: Option<(Option<Duration>, Option<Duration>)>,
    idle_since: Instant,
}

impl Link {
    fn new(conn: Box<dyn Conn>, uid: u64) -> Link {
        Link { conn, reader: FrameReader::new(), next_id: 1, uid, timeouts: None, idle_since: Instant::now() }
    }
}

/// An idle connection is checked for a closed peer only if it has been idle at least this long.
const PROBE_AFTER: Duration = Duration::from_millis(500);

struct Pool {
    idle: Vec<Link>,
    total: usize,
    token: Token,
    /// Every live connection, in use or idle, so `shutdown` can reach them all.
    live: HashMap<u64, Closer>,
    next_uid: u64,
    /// The daemon no longer knows our context (it restarted, or dropped us).
    dead: bool,
}

pub struct Core {
    connector: Box<dyn Connector>,
    cfg: CoreConfig,
    pool: Mutex<Pool>,
    cv: Condvar,
    closed: AtomicBool,
    pub pid: u32,
}

impl core::fmt::Debug for Core {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Core").field("pid", &self.pid).finish()
    }
}

pub fn debug_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("PKCS11_PROXY_DEBUG").is_some())
}

macro_rules! dlog {
    ($($a:tt)*) => { if $crate::core::debug_enabled() { eprintln!("p11-proxy: {}", format!($($a)*)); } };
}
pub(crate) use dlog;

fn handshake(conn: &mut dyn Conn, cfg: &CoreConfig, join: Option<Token>) -> Result<HelloAck, CK_RV> {
    conn.set_timeouts(Some(cfg.connect_timeout), Some(cfg.connect_timeout)).map_err(|_| CKR_DEVICE_ERROR)?;
    let hello = Hello {
        min_version: VERSION_MIN,
        max_version: VERSION_MAX,
        features: VENDOR_FEATURES,
        join: join.is_some(),
        token: join.unwrap_or([0; TOKEN_LEN]),
        client: cfg.client_name.clone(),
    };
    let mut conn = conn;
    write_frame(&mut conn, Kind::Hello, &to_vec(&hello)).map_err(|e| {
        dlog!("sending hello failed: {e}");
        CKR_DEVICE_ERROR
    })?;
    let f = read_frame(&mut conn).map_err(|e| {
        dlog!("reading hello reply failed: {e}");
        CKR_DEVICE_ERROR
    })?;
    match f.kind {
        Kind::HelloAck => {
            let ack = from_slice::<HelloAck>(&f.payload).map_err(|_| CKR_DEVICE_ERROR)?;
            accept_vendor(&mut conn, &ack)?;
            Ok(ack)
        }
        Kind::Abort => {
            dlog!("daemon refused the connection: {:?}", from_slice::<AbortReason>(&f.payload));
            Err(CKR_DEVICE_ERROR)
        }
        _ => Err(CKR_DEVICE_ERROR),
    }
}

/// The features asked for in `Hello`: the daemon's vendor-defined mechanisms and functions.
#[cfg(feature = "vendor")]
const VENDOR_FEATURES: u64 = features::VENDOR_MECHANISMS | features::VENDOR_FUNCTIONS;
#[cfg(not(feature = "vendor"))]
const VENDOR_FEATURES: u64 = features::NONE;

/// Built without vendor support: nothing was asked for, so a daemon that announces something anyway
/// (and would follow it with frames this client does not expect) is not talking the protocol.
#[cfg(not(feature = "vendor"))]
fn accept_vendor(_conn: &mut &mut dyn Conn, ack: &HelloAck) -> Result<(), CK_RV> {
    if ack.features != features::NONE {
        dlog!("the daemon announced features that were not asked for");
        return Err(CKR_DEVICE_ERROR);
    }
    Ok(())
}

/// The daemon's vendor-defined mechanisms and functions, which follow the `HelloAck` when it says so;
/// a daemon without any means the library carries none. They are installed before any call is made.
#[cfg(feature = "vendor")]
fn accept_vendor(conn: &mut &mut dyn Conn, ack: &HelloAck) -> Result<(), CK_RV> {
    let mut expect = |kind: Kind, what: &str| -> Result<Vec<u8>, CK_RV> {
        let f = read_frame(conn).map_err(|e| {
            dlog!("reading the vendor {what} failed: {e}");
            CKR_DEVICE_ERROR
        })?;
        if f.kind != kind {
            dlog!("expected the vendor {what}, got {:?}", f.kind);
            return Err(CKR_DEVICE_ERROR);
        }
        Ok(f.payload)
    };
    let mechs = if ack.features & features::VENDOR_MECHANISMS != 0 {
        from_slice::<VendorMechs>(&expect(Kind::VendorMechanisms, "mechanisms")?).map_err(|_| CKR_DEVICE_ERROR)?
    } else {
        VendorMechs::default()
    };
    let fns = if ack.features & features::VENDOR_FUNCTIONS != 0 {
        from_slice::<p11_wire::vendorfn::VendorFns>(&expect(Kind::VendorFunctions, "functions")?)
            .map_err(|_| CKR_DEVICE_ERROR)?
    } else {
        p11_wire::vendorfn::VendorFns::default()
    };
    p11_params::vendor::set_from_wire(&mechs).map_err(|e| {
        dlog!("the daemon's vendor mechanisms are not acceptable: {e}");
        CKR_DEVICE_ERROR
    })?;
    p11_params::vendorfn::set_from_wire(&fns).map_err(|e| {
        dlog!("the daemon's vendor functions are not acceptable: {e}");
        CKR_DEVICE_ERROR
    })
}

impl Core {
    /// Connect the first connection, creating the client context in the daemon.
    pub fn open(connector: Box<dyn Connector>, cfg: CoreConfig) -> Result<Core, CK_RV> {
        let mut conn = connector.connect().map_err(|e| {
            dlog!("cannot connect: {e}");
            CKR_DEVICE_ERROR
        })?;
        let ack = handshake(&mut *conn, &cfg, None)?;
        let closer = conn.closer().map_err(|_| CKR_DEVICE_ERROR)?;
        Ok(Core {
            connector,
            cfg,
            pool: Mutex::new(Pool {
                idle: vec![Link::new(conn, 0)],
                total: 1,
                token: ack.token,
                live: HashMap::from([(0, closer)]),
                next_uid: 1,
                dead: false,
            }),
            cv: Condvar::new(),
            closed: AtomicBool::new(false),
            pid: std::process::id(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Pool> {
        self.pool.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn checkout(&self) -> Result<(Link, bool), CK_RV> {
        let mut p = self.lock();
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
            }
            if p.dead {
                return Err(CKR_DEVICE_ERROR);
            }
            if let Some(l) = p.idle.pop() {
                // an idle connection may have been closed by the peer or a middlebox
                if l.idle_since.elapsed() > PROBE_AFTER && !l.conn.probe() {
                    dlog!("dropping a connection the peer closed");
                    p.live.remove(&l.uid);
                    p.total -= 1;
                    continue;
                }
                return Ok((l, false));
            }
            if p.total < self.cfg.max_conns {
                p.total += 1;
                let token = p.token;
                let uid = p.next_uid;
                p.next_uid += 1;
                drop(p);
                return match self.dial(token, uid) {
                    Ok((l, closer)) => {
                        self.lock().live.insert(uid, closer);
                        if self.closed.load(Ordering::SeqCst) {
                            self.forget(&l);
                            return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
                        }
                        Ok((l, true))
                    }
                    Err(e) => {
                        let mut p = self.lock();
                        p.total -= 1;
                        if e == CKR_DEVICE_REMOVED {
                            p.dead = true;
                        }
                        self.cv.notify_one();
                        Err(if e == CKR_DEVICE_REMOVED { CKR_DEVICE_ERROR } else { e })
                    }
                };
            }
            p = self.cv.wait(p).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn forget(&self, l: &Link) {
        let mut p = self.lock();
        p.live.remove(&l.uid);
        p.total -= 1;
        self.cv.notify_one();
    }

    fn dial(&self, token: Token, uid: u64) -> Result<(Link, Closer), CK_RV> {
        let mut conn = self.connector.connect().map_err(|e| {
            dlog!("cannot connect: {e}");
            CKR_DEVICE_ERROR
        })?;
        match handshake(&mut *conn, &self.cfg, Some(token)) {
            Ok(_) => {
                let closer = conn.closer().map_err(|_| CKR_DEVICE_ERROR)?;
                Ok((Link::new(conn, uid), closer))
            }
            // the daemon has forgotten our context: everything we held is gone
            Err(_) => Err(CKR_DEVICE_REMOVED),
        }
    }

    fn checkin(&self, l: Link) {
        if self.closed.load(Ordering::SeqCst) {
            self.forget(&l);
            return;
        }
        let mut l = l;
        l.idle_since = Instant::now();
        let mut p = self.lock();
        p.idle.push(l);
        self.cv.notify_one();
    }

    fn discard(&self, l: Link) {
        self.forget(&l);
    }

    /// Send a request and wait for its response. `blocking` calls have no
    /// time limit (they wait for an external event).
    pub fn call(&self, req: &Request, blocking: bool) -> Result<(u64, Option<Response>), CK_RV> {
        let call = req.call_id();
        let body = req.encode_body();
        // a PIN in the encoded request is wiped once it has been sent (or the call has failed)
        let secret = p11_wire::calls::call_info(call).is_some_and(|i| i.secret);
        self.exchange(call, body, secret, blocking, |rv, has_body, body| {
            let out = if has_body {
                match Response::decode(call, body) {
                    Ok(r) => Some(r),
                    Err(ResponseError::Unknown) | Err(ResponseError::Malformed(_)) => return Err(CKR_DEVICE_ERROR),
                }
            } else {
                None
            };
            Ok((rv, out))
        })
    }

    /// Call a vendor-defined function: `body` is a [`p11_wire::vendorfn::VendorRequest`]; the answer is
    /// the function's `CK_RV` and the encoded reply, if it came with one.
    #[cfg(feature = "vendor")]
    pub fn call_vendor(&self, body: Vec<u8>, secret: bool) -> Result<(u64, Option<Vec<u8>>), CK_RV> {
        self.exchange(p11_wire::vendorfn::CALL_VENDOR, body, secret, false, |rv, has_body, b| {
            Ok((rv, has_body.then(|| b.to_vec())))
        })
    }

    /// Send one request on a pooled connection and read its response. `finish` turns the response body
    /// into the caller's value. A pooled connection that died while idle is replaced once.
    fn exchange<T>(
        &self,
        call: u16,
        mut body: Vec<u8>,
        secret: bool,
        blocking: bool,
        finish: impl FnOnce(u64, bool, &[u8]) -> Result<T, CK_RV>,
    ) -> Result<T, CK_RV> {
        let _wipe = WipeOnDrop(&mut body, secret);
        let body = &*_wipe.0;
        let mut retried = false;
        loop {
            let (mut link, fresh) = self.checkout()?;
            let id = link.next_id;
            link.next_id = link.next_id.wrapping_add(1);
            let rd = (!blocking).then_some(self.cfg.call_timeout);
            let want = (rd, Some(self.cfg.call_timeout));
            let sent = if link.timeouts == Some(want) {
                Ok(())
            } else {
                link.conn.set_timeouts(want.0, want.1).map(|_| link.timeouts = Some(want))
            }
            .map_err(p11_wire::WireError::from)
            .and_then(|_| {
                let mut payload = build_request(id, call, body);
                let r = write_frame(&mut link.conn, Kind::Request, &payload);
                if secret {
                    p11_wire::wipe_vec(&mut payload);
                }
                r
            });
            if let Err(e) = sent {
                dlog!("send failed: {e}");
                self.discard(link);
                // a pooled connection may have been closed while idle; nothing
                // was delivered, so it is safe to try once on a new one
                if !fresh && !retried {
                    retried = true;
                    continue;
                }
                return Err(self.io_error());
            }
            let got = link.reader.read(&mut link.conn);
            let f = match got {
                Ok(f) => f,
                Err(e) => {
                    dlog!("receive failed: {e}");
                    self.discard(link);
                    return Err(self.io_error());
                }
            };
            let parsed = if f.kind == Kind::Response { parse_response(&f.payload).ok() } else { None };
            let Some((head, body)) = parsed.filter(|(h, _)| h.id == id) else {
                dlog!("unexpected frame from the daemon");
                self.discard(link);
                return Err(CKR_DEVICE_ERROR);
            };
            let has_body = head.has_body;
            let rv = head.rv;
            self.checkin(link);
            return finish(rv, has_body, body);
        }
    }

    fn io_error(&self) -> CK_RV {
        if self.closed.load(Ordering::SeqCst) {
            CKR_CRYPTOKI_NOT_INITIALIZED
        } else {
            CKR_DEVICE_ERROR
        }
    }

    /// Close every connection. Calls in flight fail with
    /// `CKR_CRYPTOKI_NOT_INITIALIZED`.
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let closers: Vec<Closer> = {
            let mut p = self.lock();
            p.idle.clear();
            p.live.values().cloned().collect()
        };
        for c in closers {
            c();
        }
        self.cv.notify_all();
    }

    /// Drop the connections without telling the daemon or the peer: for a
    /// forked child, whose copies of the sockets belong to its parent.
    pub fn abandon(self) {
        let idle = std::mem::take(&mut self.lock().idle);
        for l in idle {
            std::mem::forget(l.conn);
        }
    }
}

/// Wipes the encoded request when it goes out of scope, if it carried a secret.
struct WipeOnDrop<'a>(&'a mut Vec<u8>, bool);

impl Drop for WipeOnDrop<'_> {
    fn drop(&mut self) {
        if self.1 {
            p11_wire::wipe_vec(self.0);
        }
    }
}
