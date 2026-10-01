//! libp11-proxy: a PKCS#11 module whose every call goes to a remote
//! `p11-daemon`.
//!
//! The exported symbols are the standard PKCS#11 ones. Most of them are
//! generated from `api.idl` (see `p11-idl`): each captures its arguments from
//! the caller's memory into wire values, sends them, and writes the answer
//! back. Nothing here trusts the daemon's answer to be well-formed.

pub mod config;
pub mod core;
pub mod exports;
pub mod rt;
pub mod state;
#[cfg(feature = "vendor")]
pub mod vendor;

mod generated {
    // Every unsafe block here forwards the application's pointers to a helper under
    // the contract stated in the entry point's doc comment.
    #![allow(clippy::all, clippy::undocumented_unsafe_blocks, unused_imports, unused_variables)]
    include!(concat!(env!("OUT_DIR"), "/stubs.rs"));
}
mod tables {
    #![allow(clippy::all, unused_imports)]
    include!(concat!(env!("OUT_DIR"), "/tables.rs"));
}

pub use exports::*;
pub use generated::*;
#[cfg(feature = "vendor")]
pub use vendor::*;

#[doc(hidden)]
pub mod testing {
    //! Installing a connection built by a test instead of from the environment.
    use super::*;
    use p11_types::CK_RV;

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Holds the process-wide connection for one test; dropping it finalises.
    #[derive(Debug)]
    pub struct Session {
        _g: std::sync::MutexGuard<'static, ()>,
    }

    /// Connect through `connector` and run `C_Initialize`'s work. Tests share
    /// one process-wide connection, so they take turns.
    pub fn install(connector: Box<dyn p11_transport::Connector>, cfg: core::CoreConfig) -> Result<Session, CK_RV> {
        let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if state::current().is_ok() {
            // a previous test left the library initialised
            // SAFETY: null reserved pointer.
            unsafe { C_Finalize(std::ptr::null_mut()) };
        }
        exports::initialize_with(core::Core::open(connector, cfg)?)?;
        Ok(Session { _g: g })
    }

    impl Drop for Session {
        fn drop(&mut self) {
            // SAFETY: null reserved pointer.
            unsafe { C_Finalize(std::ptr::null_mut()) };
        }
    }
}
