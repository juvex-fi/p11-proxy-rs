//! p11-daemon: serves a PKCS#11 module to remote clients.

use clap::Parser;
use p11_daemon::config::{Config, ModeVal};
use p11_daemon::{runner, Daemon};
use p11_module::DlBackend;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Serve a PKCS#11 module to remote clients.
///
/// Clients connect with libp11-proxy. TCP connections use TLS 1.3 with
/// certificates on both sides (tcp://) or a pre-shared key (psk://); local
/// clients use a unix socket.
#[derive(Parser, Debug)]
#[command(name = "p11-daemon", version)]
struct Cli {
    /// The PKCS#11 module to serve (a shared library)
    module: Option<PathBuf>,

    /// Configuration file (TOML); options given here override it
    #[arg(short, long, env = "PKCS11_DAEMON_CONFIG")]
    config: Option<PathBuf>,

    /// Where to listen: unix:///path, tcp://host:port, psk://host:port or stdio (repeatable)
    #[arg(short, long, env = "PKCS11_DAEMON_SOCKET", value_delimiter = ' ')]
    listen: Vec<String>,

    /// Server certificate chain (PEM) for tcp:// listeners
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// Server private key (PEM)
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// CA (PEM) whose client certificates are accepted
    #[arg(long)]
    tls_client_ca: Option<PathBuf>,
    /// Pre-shared keys (identity:hex-secret per line) for psk:// listeners
    #[arg(long)]
    psk_file: Option<PathBuf>,

    /// Make one call at a time, for modules that are not thread safe
    #[arg(long)]
    serialize_module: bool,

    /// File mode of unix sockets (octal)
    #[arg(long)]
    unix_mode: Option<String>,

    /// Run as this user once the module is open and the sockets are bound
    #[arg(long)]
    drop_privs: Option<String>,

    /// Confine the process: auto (where supported), off, or require
    #[arg(long, env = "PKCS11_DAEMON_SANDBOX", value_parser = ["auto", "off", "require"])]
    sandbox: Option<String>,

    /// Check the configuration and exit
    #[arg(long)]
    check_config: bool,

    /// Log more (repeat for more)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn init_logging(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let default = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_env("PKCS11_DAEMON_LOG").unwrap_or_else(|_| EnvFilter::new(default));
    use std::io::IsTerminal;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .init();
}

fn effective_config(cli: &Cli) -> Result<Config, String> {
    let mut cfg = match &cli.config {
        Some(p) => Config::load(p)?,
        None => Config::default(),
    };
    if let Some(m) = &cli.module {
        cfg.module = Some(m.clone());
    }
    if !cli.listen.is_empty() {
        cfg.listen = cli.listen.iter().filter(|s| !s.is_empty()).cloned().collect();
    }
    if cli.tls_cert.is_some() {
        cfg.tls.cert = cli.tls_cert.clone();
    }
    if cli.tls_key.is_some() {
        cfg.tls.key = cli.tls_key.clone();
    }
    if cli.tls_client_ca.is_some() {
        cfg.tls.client_ca = cli.tls_client_ca.clone();
    }
    if cli.psk_file.is_some() {
        cfg.psk.file = cli.psk_file.clone();
    }
    cfg.serialize_module |= cli.serialize_module;
    if let Some(m) = &cli.unix_mode {
        cfg.unix.mode = Some(ModeVal::Str(m.clone()));
    }
    if cli.drop_privs.is_some() {
        cfg.drop_privileges = cli.drop_privs.clone();
    }
    if cli.sandbox.is_some() {
        cfg.sandbox.mode = cli.sandbox.clone();
    }
    Ok(cfg)
}

/// Block the shutdown signals in this thread (and so in every thread started
/// after), to be waited for with [`wait_for_signal`].
fn block_signals() {
    // SAFETY: plain sigset manipulation on a local set.
    unsafe {
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, core::ptr::null_mut());
    }
}

fn wait_for_signal() -> i32 {
    // SAFETY: sigwait on a local set of blocked signals.
    unsafe {
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        let mut sig = 0;
        libc::sigwait(&set, &mut sig);
        sig
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    let cfg = effective_config(&cli)?;
    let module =
        cfg.module.clone().ok_or("no PKCS#11 module given (positional argument or `module` in the configuration)")?;
    cfg.policy()?; // validate before opening anything
    #[cfg(feature = "vendor")]
    {
        p11_params::vendor::set(&cfg.vendor_mechanisms, &cfg.vendor_structs)?;
        p11_params::vendorfn::set_from_config(&cfg.vendor_functions)?;
    }
    if cli.check_config {
        println!("configuration ok");
        return Ok(());
    }
    block_signals();

    let backend = Arc::new(DlBackend::open(&module, cfg.serialize_module).map_err(|e| e.to_string())?);
    let (maj, min) = backend.interface_version();
    info!("loaded {} (PKCS#11 {maj}.{min})", module.display());
    let listeners = runner::open_listeners(&cfg)?;
    let stdio_only = cfg.listen.len() == 1 && cfg.listen[0] == "stdio";

    p11_daemon::sandbox::apply(&cfg).map_err(|e| format!("cannot confine the process: {e}"))?;

    let daemon = Daemon::new(cfg, backend.clone(), listeners)?;
    daemon.start();
    for l in daemon.listening() {
        info!("ready: {l}");
    }
    if stdio_only {
        // launched per connection: done when it is
        while daemon.accepted_connections() == 0 {
            std::thread::sleep(Duration::from_millis(20));
        }
        daemon.wait_idle(Duration::from_secs(86_400 * 365));
    } else {
        let sig = wait_for_signal();
        info!("signal {sig}: shutting down");
        daemon.shutdown();
        daemon.wait_idle(Duration::from_secs(5));
    }
    backend.finalize_module();
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if tracing::dispatcher::has_been_set() {
                error!("{e}");
            } else {
                eprintln!("p11-daemon: {e}");
            }
            ExitCode::FAILURE
        }
    }
}
