//! The daemon: serves a PKCS#11 module to remote clients.
//!
//! Layers, top to bottom: [`server`] (handshake, client contexts, request
//! loop), [`dispatch`] (policy, handle translation, the calls that need the
//! daemon's own state), then a [`p11_module::Backend`]. The transport that
//! produced the byte stream lives elsewhere; this crate only needs
//! `Read + Write` and an [`Identity`](policy::Identity).

#![allow(missing_debug_implementations)]

pub mod config;
pub mod ctx;
pub mod dispatch;
pub mod policy;
pub mod runner;
pub mod sandbox;
pub mod server;
#[cfg(feature = "vendor")]
mod vendorfn;

mod xlate {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/xlate.rs"));
}

pub use config::Config;
pub use ctx::ClientCtx;
pub use policy::{Identity, Policy, Rules};
pub use runner::Daemon;
pub use server::{Limits, ServeError, Server};
