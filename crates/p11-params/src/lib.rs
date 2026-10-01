//! C-side structures <-> wire values. This crate contains the unsafe pointer
//! work for both ends: the client reads the caller's memory and writes the
//! answers back; the daemon rebuilds the structures in its own memory for
//! the module. Nothing from a peer is ever used as a pointer.

pub mod arena;
pub mod attrs;
pub mod conv;
pub mod desc;
pub mod descs;
#[cfg(feature = "vendor")]
pub mod layout;
pub mod mech;
mod mechtab;
#[cfg(feature = "vendor")]
pub mod vendor;
#[cfg(feature = "vendor")]
pub mod vendorfn;
