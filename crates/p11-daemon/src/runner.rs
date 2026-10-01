//! Listeners, the accept loops and the per-connection threads.

use crate::config::Config;
use crate::policy::Identity;
use crate::server::Server;
use p11_module::Backend;
use p11_transport::unix::UnixAcceptor;
use p11_transport::{Closer, Endpoint, Listener};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Open the listeners the configuration asks for.
pub fn open_listeners(cfg: &Config) -> Result<Vec<Arc<dyn Listener>>, String> {
    let mut out: Vec<Arc<dyn Listener>> = Vec::new();
    let handshake = cfg.limits.handshake();
    for spec in &cfg.listen {
        let ep = Endpoint::parse(spec)?;
        match ep {
            Endpoint::Unix(p) => {
                let mode = cfg.unix.mode.as_ref().map(|m| m.get()).transpose()?;
                out.push(Arc::new(UnixAcceptor::bind(&p, mode).map_err(|e| format!("{spec}: {e}"))?));
            }
            Endpoint::Tcp { host, port } => {
                let rd = |name: &str, p: &Option<std::path::PathBuf>| -> Result<Vec<u8>, String> {
                    let p =
                        p.as_ref().ok_or_else(|| format!("{spec}: [tls] {name} is required for tcp:// listeners"))?;
                    std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
                };
                let cert = rd("cert", &cfg.tls.cert)?;
                let key = rd("key", &cfg.tls.key)?;
                let ca = rd("client_ca", &cfg.tls.client_ca)?;
                let addr = bind_addr(&host, port);
                out.push(Arc::new(p11_transport::tls::TlsAcceptor::bind(&addr, &cert, &key, &ca, handshake)?));
            }
            #[cfg(feature = "psk")]
            Endpoint::Psk { host, port } => {
                let p = cfg
                    .psk
                    .file
                    .as_ref()
                    .ok_or_else(|| format!("{spec}: [psk] file is required for psk:// listeners"))?;
                let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
                let keys = p11_transport::psk::PskKeys::parse(&text).map_err(|e| format!("{}: {e}", p.display()))?;
                out.push(Arc::new(p11_transport::psk::PskAcceptor::bind(&bind_addr(&host, port), keys, handshake)?));
            }
            #[cfg(not(feature = "psk"))]
            Endpoint::Psk { .. } => return Err(format!("{spec}: this build has no TLS-PSK support")),
            Endpoint::Stdio => out.push(Arc::new(p11_transport::stdio::StdioListener::new())),
        }
    }
    if out.is_empty() {
        return Err("nothing to listen on: give --listen or set `listen` in the configuration".into());
    }
    Ok(out)
}

fn bind_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

struct Shared {
    server: Arc<Server>,
    cfg: Config,
    shutting_down: AtomicBool,
    active: AtomicUsize,
    accepted: AtomicU64,
    next_id: AtomicU64,
    conns: Mutex<HashMap<u64, Closer>>,
}

/// A running daemon.
pub struct Daemon {
    shared: Arc<Shared>,
    listeners: Vec<Arc<dyn Listener>>,
}

impl Daemon {
    pub fn new(cfg: Config, backend: Arc<dyn Backend>, listeners: Vec<Arc<dyn Listener>>) -> Result<Daemon, String> {
        let policy = cfg.policy()?;
        let server = Server::new(backend, policy, cfg.limits.server_limits());
        #[cfg(feature = "vendor")]
        let server = server.with_vendor_mechanisms(&cfg.vendor_mechanisms, &cfg.vendor_structs)?.with_vendor_functions(
            &cfg.vendor_functions
                .iter()
                .map(p11_params::vendorfn::VendorFunction::desc)
                .collect::<Result<Vec<_>, _>>()?,
        );
        let server = Arc::new(server);
        Ok(Daemon {
            shared: Arc::new(Shared {
                server,
                cfg,
                shutting_down: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                accepted: AtomicU64::new(0),
                next_id: AtomicU64::new(1),
                conns: Mutex::new(HashMap::new()),
            }),
            listeners,
        })
    }

    /// What the daemon listens on.
    pub fn listening(&self) -> Vec<String> {
        self.listeners.iter().map(|l| l.describe()).collect()
    }

    /// Start accepting; returns at once, the work happens on threads.
    pub fn start(&self) {
        for l in &self.listeners {
            let l = l.clone();
            let sh = self.shared.clone();
            std::thread::Builder::new()
                .name("accept".into())
                .spawn(move || accept_loop(l, sh))
                .expect("spawn accept thread");
        }
    }

    /// Stop taking connections and close the ones open.
    pub fn shutdown(&self) {
        self.shared.shutting_down.store(true, Ordering::SeqCst);
        let closers: Vec<Closer> = self.shared.conns.lock().unwrap().values().cloned().collect();
        for c in closers {
            c();
        }
    }

    /// Connections accepted since the start (served or finished).
    pub fn accepted_connections(&self) -> u64 {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// Connections being served right now.
    pub fn active_connections(&self) -> usize {
        self.shared.active.load(Ordering::SeqCst)
    }

    /// Wait (up to `timeout`) for the connection threads to finish after [`Daemon::shutdown`].
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let end = std::time::Instant::now() + timeout;
        while self.active_connections() > 0 {
            if std::time::Instant::now() > end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }

    pub fn client_contexts(&self) -> usize {
        self.shared.server.context_count()
    }
}

fn accept_loop(l: Arc<dyn Listener>, sh: Arc<Shared>) {
    info!("listening on {}", l.describe());
    loop {
        let incoming = match l.accept() {
            Ok(i) => i,
            Err(e) => {
                if sh.shutting_down.load(Ordering::SeqCst) || e.kind() == std::io::ErrorKind::NotConnected {
                    return;
                }
                warn!("accept failed: {e}");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        if sh.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        if sh.active.fetch_add(1, Ordering::SeqCst) >= sh.cfg.limits.max_connections {
            sh.active.fetch_sub(1, Ordering::SeqCst);
            warn!("connection refused: {} connections are open", sh.cfg.limits.max_connections);
            continue; // dropping `incoming` closes it
        }
        sh.accepted.fetch_add(1, Ordering::SeqCst);
        let sh2 = sh.clone();
        let spawned = std::thread::Builder::new().name("conn".into()).spawn(move || {
            handle(incoming, &sh2);
            sh2.active.fetch_sub(1, Ordering::SeqCst);
        });
        if let Err(e) = spawned {
            sh.active.fetch_sub(1, Ordering::SeqCst);
            error!("cannot start a connection thread: {e}");
        }
    }
}

fn handle(incoming: Box<dyn p11_transport::Incoming>, sh: &Shared) {
    let (conn, id): (_, Identity) = match incoming.establish() {
        Ok(x) => x,
        Err(e) => {
            warn!("connection refused during the handshake: {e}");
            return;
        }
    };
    let id_num = sh.next_id.fetch_add(1, Ordering::SeqCst);
    if let Ok(c) = conn.closer() {
        sh.conns.lock().unwrap().insert(id_num, c);
    }
    let idle = sh.cfg.limits.idle();
    // a client that stops reading must not hold the thread forever
    let _ = conn.set_timeouts(idle, Some(idle.unwrap_or(Duration::from_secs(300))));
    debug!("connection {id_num} from {id}");
    match sh.server.serve_conn(conn, &id) {
        Ok(()) => debug!("connection {id_num} from {id} closed"),
        Err(e) => info!("connection {id_num} from {id} ended: {e}"),
    }
    sh.conns.lock().unwrap().remove(&id_num);
}
