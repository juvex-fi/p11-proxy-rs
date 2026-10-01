//! Confining the daemon once it has opened the module and its sockets.

use crate::config::Config;
use p11_sandbox::{Applied, Mode, Options};
use tracing::info;

/// Drop privileges and confine the process as configured.
pub fn apply(cfg: &Config) -> Result<(), String> {
    if let Some(user) = &cfg.drop_privileges {
        p11_sandbox::drop_privileges(user)?;
        info!("running as {user}");
    }
    let mode = match cfg.sandbox.mode.as_deref() {
        Some(m) => Mode::parse(m)?,
        None => Mode::Auto,
    };
    let o = Options { mode, write_paths: cfg.sandbox.write_paths.clone(), debug: cfg.sandbox.debug };
    match p11_sandbox::apply(&o)? {
        Applied::Off => info!("sandbox: off"),
        Applied::Confined(what) => info!("sandbox: {what}"),
        Applied::Unsupported => info!("sandbox: not available on this platform"),
    }
    Ok(())
}
