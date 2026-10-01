//! The API description of p11-proxy and the generators that turn it into
//! Rust source: wire messages, the backend trait and its dlopen
//! implementation, the client's C entry points, and the daemon's handle
//! translation. Each consumer crate runs the generator it needs from
//! `build.rs`, so the description in `src/api.idl` is the only place a call
//! is written down.
//!
//! # Kinds
//!
//! | kind | C parameters | request field | response field |
//! |---|---|---|---|
//! | `slot`, `session`, `object`, `u64` | one `CK_ULONG` | `u64` | |
//! | `bool` | `CK_BBOOL` | `bool` | |
//! | `bytes` | pointer, length | `Vec<u8>` | |
//! | `optbytes` | pointer (may be NULL), length | `Option<Vec<u8>>` | |
//! | `label` | 32-byte string | `[u8; 32]` | |
//! | `cstr` | NUL-terminated string | `Vec<u8>` | |
//! | `mech` | `CK_MECHANISM_PTR` | `Mech` | `Option<Node>` (members the module filled in) |
//! | `attrs` | template pointer, count | `Template` | |
//! | `msgparam` | parameter pointer, length | `MsgParam` | `Option<Node>` |
//! | `o_bytes` | buffer, length pointer | `OutSpec` | `OutBytes` |
//! | `o_fixed` | buffer, length | `u64` | `Vec<u8>` |
//! | `o_u64s` | array, count pointer | `OutSpec` | `OutU64s` |
//! | `o_handles` | array, max, count pointer | `u64` | `U64s` |
//! | `o_u64`, `o_object`, `o_session` | `CK_ULONG_PTR` | | `u64` |
//! | `o_info` and kin | pointer to the structure | | the structure |
//! | `attrs_query` | template pointer, count | `Seq<Query>` | `Seq<Reply>` |
//! | `asyncdata` | `CK_ASYNC_DATA_PTR` | `AsyncIn` | `AsyncOut` |

mod gen_backend;
mod gen_client;
mod gen_wire;
mod gen_xlate;
pub mod model;

pub use model::{snake, Api, Arg, Call, Kind, Since};

/// Rust source for the sample messages (`p11-wire`, feature `samples`).
pub fn samples_source() -> String {
    gen_wire::samples(&Api::embedded())
}

/// The call table as Markdown, for `docs/PROTOCOL.md`.
pub fn calls_markdown() -> String {
    Api::embedded().markdown()
}

/// Rust source for the wire messages (`p11-wire`).
pub fn wire_source() -> String {
    gen_wire::generate(&Api::embedded())
}

/// Path of the description, for `cargo:rerun-if-changed`.
pub const API_IDL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/api.idl");

/// Rust source for the `Backend` trait and `dispatch` (`p11-module`).
pub fn backend_trait_source() -> String {
    gen_backend::trait_source(&Api::embedded())
}

/// Rust source for `Fns` and the dlopen implementation of `Backend` (`p11-module`).
pub fn dl_source() -> String {
    gen_backend::dl_source(&Api::embedded())
}

/// Rust source for the daemon's handle translation (`p11-daemon`).
pub fn xlate_source() -> String {
    gen_xlate::generate(&Api::embedded())
}

/// Rust source for the client's C entry points (`p11-client`).
pub fn client_source() -> String {
    gen_client::generate(&Api::embedded())
}

/// Rust source for the client's function-list tables (`p11-client`).
pub fn client_tables_source() -> String {
    gen_client::tables(&Api::embedded())
}
