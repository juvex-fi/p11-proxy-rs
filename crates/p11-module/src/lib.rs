//! The provider side of the proxy.
//!
//! [`Backend`] has one method per PKCS#11 call, taking and returning the wire
//! request and response types, so a provider is testable without a network or
//! a C compiler. [`DlBackend`] is the real thing: it loads a PKCS#11 module
//! and calls it. The mock provider in `p11-testkit` implements the same
//! trait.

use p11_types::*;

pub mod dlrt;
mod loader;

pub use loader::{DlBackend, LoadError};

/// The result of one call: the `CK_RV`, and the outputs when there are any
/// to report (see [`dlrt::wants_body`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Reply<T> {
    pub rv: u64,
    pub resp: Option<T>,
}

impl<T> Reply<T> {
    pub fn ok(resp: T) -> Self {
        Reply { rv: CKR_OK as u64, resp: Some(resp) }
    }
    /// Success with nothing to report.
    pub fn done() -> Self {
        Reply { rv: CKR_OK as u64, resp: None }
    }
    pub fn err(rv: CK_RV) -> Self {
        Reply { rv: rv as u64, resp: None }
    }
}

mod backend {
    #![allow(clippy::all, unused_imports)]
    include!(concat!(env!("OUT_DIR"), "/backend.rs"));
}
pub use backend::{dispatch, Backend};

mod dl_impl {
    #![allow(clippy::all, unused_imports, missing_debug_implementations)]
    include!(concat!(env!("OUT_DIR"), "/dl.rs"));
}
pub use dl_impl::Fns;
