//! Running the same PKCS#11 script against different modules and comparing
//! what they say.

#![allow(
    clippy::undocumented_unsafe_blocks,
    unsafe_op_in_unsafe_fn,
    clippy::op_ref,
    clippy::unnecessary_to_owned,
    clippy::manual_c_str_literals
)]

pub mod mechs;
mod module;
pub mod scenario;

pub use module::Module;

/// What a run printed: one line per step, free of anything that legitimately
/// differs between runs (handles, random bytes, timestamps).
#[derive(Debug, Default, Clone)]
pub struct Transcript(pub Vec<String>);

impl Transcript {
    pub fn line(&mut self, label: &str, detail: impl AsRef<str>) {
        let d = detail.as_ref();
        self.0.push(if d.is_empty() { label.to_string() } else { format!("{label}: {d}") });
    }
    pub fn render(&self) -> String {
        self.0.join("\n") + "\n"
    }
}

/// The name of a return value, or its number.
pub fn rvn(rv: p11_types::CK_RV) -> String {
    p11_types::rv_name(rv).map(|s| s.to_string()).unwrap_or_else(|| format!("0x{rv:x}"))
}
