//! The p11-proxy wire format.
//!
//! This crate has no unsafe code and does no network I/O; it turns bytes from
//! an untrusted peer into checked values, and values into bytes. See
//! `docs/PROTOCOL.md` for the specification.
#![forbid(unsafe_code)]

pub mod attr;
pub mod calls {
    //! One request and one response type per call, generated from `api.idl`.
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/calls.rs"));

    /// The call table as Markdown (for docs/PROTOCOL.md).
    pub const CALL_TABLE_MARKDOWN: &str = include_str!(concat!(env!("OUT_DIR"), "/table.md"));

    /// Example messages for every call (golden vectors, fuzzer seeds).
    #[allow(unused_imports)]
    pub mod samples {
        include!(concat!(env!("OUT_DIR"), "/samples.rs"));
    }

    /// A request whose call id is not one this version knows, or whose body is malformed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RequestError {
        Unknown,
        Malformed(super::WireError),
    }
    /// The same for a response.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ResponseError {
        Unknown,
        Malformed(super::WireError),
    }
}
pub mod codec;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod limits;
pub mod secret;
pub mod structs;
pub mod tree;
pub mod vendorfn;

pub use codec::{from_slice, to_vec, Decode, Encode, MinSize, Reader, Seq, U64s, Writer};
pub use error::{Result, WireError};
pub use secret::{wipe, wipe_vec, Secret};
pub use tree::Node;
