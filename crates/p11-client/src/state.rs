//! The process-wide connection: created by `C_Initialize`, dropped by
//! `C_Finalize`, abandoned in a forked child.

use crate::core::Core;
use p11_types::*;
use std::sync::{Arc, RwLock};

static CORE: RwLock<Option<Arc<Core>>> = RwLock::new(None);

/// The connection, or the reason there isn't one.
pub fn current() -> Result<Arc<Core>, CK_RV> {
    let g = CORE.read().unwrap_or_else(|e| e.into_inner());
    match g.as_ref() {
        // After fork() the child inherits the state but not the right to use
        // the parent's connections: it must initialise again.
        Some(c) if c.pid == std::process::id() => Ok(c.clone()),
        _ => Err(CKR_CRYPTOKI_NOT_INITIALIZED),
    }
}

/// Install a freshly opened connection.
pub fn install(core: Core) -> Result<(), CK_RV> {
    let mut g = CORE.write().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = g.as_ref() {
        if old.pid == std::process::id() {
            return Err(CKR_CRYPTOKI_ALREADY_INITIALIZED);
        }
    }
    if let Some(old) = g.take() {
        // a forked child's inheritance: forget it without touching the sockets
        if let Ok(c) = Arc::try_unwrap(old) {
            c.abandon();
        }
    }
    *g = Some(Arc::new(core));
    Ok(())
}

/// Remove and return the connection.
pub fn take() -> Result<Arc<Core>, CK_RV> {
    let mut g = CORE.write().unwrap_or_else(|e| e.into_inner());
    match g.take() {
        Some(c) if c.pid == std::process::id() => Ok(c),
        Some(c) => {
            if let Ok(c) = Arc::try_unwrap(c) {
                c.abandon();
            }
            Err(CKR_CRYPTOKI_NOT_INITIALIZED)
        }
        None => Err(CKR_CRYPTOKI_NOT_INITIALIZED),
    }
}
