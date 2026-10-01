//! PKCS#11 v3.2 C types and constants.
//!
//! `generated.rs` is produced by `regen.sh` (bindgen) from the vendored OASIS
//! headers and committed, so a normal build needs no libclang. Constants are
//! all `CK_ULONG`, matching how the headers use them; bindgen's own layout
//! tests come with the file and check every struct against the C compiler's
//! layout.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::all)]
#![allow(unsafe_op_in_unsafe_fn)]

mod generated;
mod names;
pub use generated::*;

/// The PKCS#11 `CK_RV` as a Rust integer.
pub type Rv = CK_ULONG;

/// Cryptoki structures use `CK_ULONG` for handles, flags and lengths. This
/// crate targets LP64 Unix, where that is 64 bits; the wire protocol is
/// 64-bit regardless, so a narrower `CK_ULONG` would still work but is
/// rejected here to keep every conversion lossless.
const _: () = assert!(core::mem::size_of::<CK_ULONG>() == 8, "LP64 only");

// Parameters without pointers travel as the bytes of the C structure (see
// docs/PROTOCOL.md), which assumes both ends have the same byte order.
#[cfg(target_endian = "big")]
compile_error!("big-endian targets are not supported");

fn lookup(table: &[(&str, CK_ULONG)], name: &str) -> Option<CK_ULONG> {
    table.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// `CKM_AES_GCM` to its value.
pub fn mechanism_by_name(name: &str) -> Option<CK_ULONG> {
    lookup(names::MECHANISMS, name)
}

/// `CKA_LABEL` to its value.
pub fn attribute_by_name(name: &str) -> Option<CK_ULONG> {
    lookup(names::ATTRIBUTES, name)
}

/// The name of a return value (`CKR_OK`), if it has one.
pub fn rv_name(rv: CK_ULONG) -> Option<&'static str> {
    names::RETURN_VALUES.iter().find(|(_, v)| *v == rv).map(|(n, _)| *n)
}

/// Every mechanism name in the header with its value (aliases included).
pub fn all_mechanisms() -> &'static [(&'static str, CK_ULONG)] {
    names::MECHANISMS
}

/// The name of a mechanism, for logs.
pub fn mechanism_name(m: CK_ULONG) -> Option<&'static str> {
    names::MECHANISMS.iter().find(|(_, v)| *v == m).map(|(n, _)| *n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_values() {
        assert_eq!(CKR_OK, 0);
        assert_eq!(CKR_BUFFER_TOO_SMALL, 0x150);
        assert_eq!(CKM_AES_GCM, 0x1087);
        assert_eq!(CKA_CLASS, 0);
        assert_eq!(CK_UNAVAILABLE_INFORMATION, u64::MAX as CK_ULONG);
        assert_eq!(CKM_VENDOR_DEFINED, 0x8000_0000);
        assert_eq!(CKM_ML_DSA, 0x1d);
    }

    #[test]
    fn names() {
        assert_eq!(mechanism_by_name("CKM_AES_GCM"), Some(CKM_AES_GCM));
        assert_eq!(attribute_by_name("CKA_EXTRACTABLE"), Some(CKA_EXTRACTABLE));
        assert_eq!(rv_name(CKR_BUFFER_TOO_SMALL), Some("CKR_BUFFER_TOO_SMALL"));
        assert_eq!(mechanism_by_name("CKM_NOPE"), None);
    }

    #[test]
    fn function_list_shapes() {
        // 3.2 function list has the 3.0 members after the 2.40 ones.
        assert!(core::mem::size_of::<CK_FUNCTION_LIST_3_0>() > core::mem::size_of::<CK_FUNCTION_LIST>());
        assert_eq!(core::mem::size_of::<CK_VERSION>(), 2);
    }
}
