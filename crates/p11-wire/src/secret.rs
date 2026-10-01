//! Bytes that must not linger or leak: PINs and user names.
//!
//! A [`Secret`] is zeroed when it is dropped and prints as its length only, so
//! logging a request never shows a PIN. It does not stop the operating system
//! from swapping the page out, or a copy made by a caller that took the bytes
//! with [`Secret::expose`]; it removes the easy ways a PIN ends up somewhere it
//! shouldn't.

use crate::codec::{Decode, Encode, Reader, Writer};
use crate::error::Result;
use zeroize::Zeroize;

/// Overwrite `b` with zeros in a way the compiler may not remove.
pub fn wipe(b: &mut [u8]) {
    b.zeroize();
}

/// [`wipe`] including the spare capacity, then empty the vector.
pub fn wipe_vec(v: &mut Vec<u8>) {
    v.zeroize();
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(v: Vec<u8>) -> Secret {
        Secret(v)
    }
    /// The bytes, for the one place that must hand them on.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Secret {
    fn from(v: Vec<u8>) -> Secret {
        Secret(v)
    }
}

impl From<&[u8]> for Secret {
    fn from(v: &[u8]) -> Secret {
        Secret(v.to_vec())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret(<{} bytes>)", self.0.len())
    }
}

impl Encode for Secret {
    fn encode(&self, w: &mut Writer) {
        w.bytes(&self.0)
    }
}

impl Decode for Secret {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Secret(r.bytes_ref()?.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_slice, to_vec};

    #[test]
    fn debug_shows_no_bytes() {
        let s = Secret::from(&b"1234"[..]);
        assert_eq!(format!("{s:?}"), "Secret(<4 bytes>)");
        assert_eq!(format!("{:?}", Some(s)), "Some(Secret(<4 bytes>))");
    }

    #[test]
    fn same_encoding_as_a_byte_string() {
        let s = Secret::from(&b"1234"[..]);
        assert_eq!(to_vec(&s), to_vec(&b"1234".to_vec()));
        assert_eq!(from_slice::<Secret>(&to_vec(&s)).unwrap(), s);
    }

    #[test]
    fn wiping() {
        let mut v = vec![7u8; 10];
        v.truncate(4);
        wipe_vec(&mut v);
        assert!(v.is_empty());
        let mut a = [1u8, 2, 3];
        wipe(&mut a);
        assert_eq!(a, [0, 0, 0]);
    }
}
