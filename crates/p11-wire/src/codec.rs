//! Primitive encoding. Everything is big endian and fixed width: no padding,
//! no native `long`, no platform-dependent sizes.
//!
//! - `u8`, `u16`, `u32`, `u64`: that many bytes, big endian
//! - `bool`: one byte, 0 or 1 (anything else is rejected)
//! - byte string: `u32` length, bytes
//! - array: `u32` count, elements
//! - `Option<T>`: one presence byte (0 or 1), then the value if present

use crate::error::{Result, WireError};
use crate::limits::{MAX_ARRAY, MAX_BYTES};

#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_capacity(n: usize) -> Self {
        Writer { buf: Vec::with_capacity(n) }
    }
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn bool(&mut self, v: bool) {
        self.buf.push(v as u8);
    }
    /// Raw bytes with no length prefix (fixed-size fields).
    pub fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    /// A length-prefixed byte string. The caller guarantees the length fits
    /// the limits; the decoder enforces them regardless.
    pub fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
    }
    pub fn count(&mut self, n: usize) {
        self.u32(n as u32);
    }
}

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    /// Fail unless the whole input was consumed.
    pub fn finish(self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(WireError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::BadTag),
        }
    }
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    /// A length-prefixed byte string, borrowed from the input.
    pub fn bytes_ref(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > MAX_BYTES {
            return Err(WireError::TooLarge);
        }
        self.take(n)
    }
    /// An element count for a following array, checked against `max` and
    /// against the bytes left (each element takes at least `min_elem` bytes),
    /// so a claimed count can never exceed what the input could hold.
    pub fn count(&mut self, max: usize, min_elem: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(WireError::TooLarge);
        }
        if min_elem > 0 && n > self.remaining() / min_elem {
            return Err(WireError::Truncated);
        }
        Ok(n)
    }
}

/// A type that can write itself.
pub trait Encode {
    fn encode(&self, w: &mut Writer);
}

/// A type that can read itself from untrusted input.
pub trait Decode: Sized {
    fn decode(r: &mut Reader<'_>) -> Result<Self>;
}

/// Encode a value into a fresh buffer.
pub fn to_vec<T: Encode + ?Sized>(v: &T) -> Vec<u8> {
    let mut w = Writer::new();
    v.encode(&mut w);
    w.into_vec()
}

/// Decode a value and require that the input is used up.
pub fn from_slice<T: Decode>(b: &[u8]) -> Result<T> {
    let mut r = Reader::new(b);
    let v = T::decode(&mut r)?;
    r.finish()?;
    Ok(v)
}

macro_rules! prim {
    ($t:ty, $put:ident, $get:ident) => {
        impl Encode for $t {
            fn encode(&self, w: &mut Writer) {
                w.$put(*self)
            }
        }
        impl Decode for $t {
            fn decode(r: &mut Reader<'_>) -> Result<Self> {
                r.$get()
            }
        }
    };
}
prim!(u8, u8, u8);
prim!(u16, u16, u16);
prim!(u32, u32, u32);
prim!(u64, u64, u64);
prim!(bool, bool, bool);

impl Encode for Vec<u8> {
    fn encode(&self, w: &mut Writer) {
        w.bytes(self)
    }
}
impl Decode for Vec<u8> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(r.bytes_ref()?.to_vec())
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, w: &mut Writer) {
        w.raw(self)
    }
}
impl<const N: usize> Decode for [u8; N] {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        r.array::<N>()
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, w: &mut Writer) {
        match self {
            None => w.u8(0),
            Some(v) => {
                w.u8(1);
                v.encode(w)
            }
        }
    }
}
impl<T: Decode> Decode for Option<T> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(r)?)),
            _ => Err(WireError::BadTag),
        }
    }
}

/// Arrays of `u64` (slot ids, handles, mechanism types). Byte strings have
/// their own impl, so arrays of other records go through [`Seq`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct U64s(pub Vec<u64>);

impl Encode for U64s {
    fn encode(&self, w: &mut Writer) {
        w.count(self.0.len());
        for v in &self.0 {
            w.u64(*v);
        }
    }
}
impl Decode for U64s {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.count(MAX_ARRAY, 8)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(r.u64()?);
        }
        Ok(U64s(v))
    }
}

/// An array of records with a per-type element limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seq<T>(pub Vec<T>);

impl<T> Default for Seq<T> {
    fn default() -> Self {
        Seq(Vec::new())
    }
}
impl<T: Encode> Encode for Seq<T> {
    fn encode(&self, w: &mut Writer) {
        w.count(self.0.len());
        for v in &self.0 {
            v.encode(w);
        }
    }
}
/// Element types say how small they can be so `Seq` can bound the count.
pub trait MinSize {
    const MIN: usize;
    const MAX: usize = MAX_ARRAY;
}
impl<T: Decode + MinSize> Decode for Seq<T> {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.count(T::MAX, T::MIN)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(T::decode(r)?);
        }
        Ok(Seq(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn big_endian_layout() {
        let mut w = Writer::new();
        w.u16(0x0102);
        w.u32(0x03040506);
        w.u64(0x0708090a0b0c0d0e);
        w.bytes(&[0xaa, 0xbb]);
        assert_eq!(w.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0, 0, 0, 2, 0xaa, 0xbb]);
    }

    #[test]
    fn truncated_and_trailing() {
        assert_eq!(from_slice::<u32>(&[0, 0, 1]).unwrap_err(), WireError::Truncated);
        assert_eq!(from_slice::<u8>(&[1, 2]).unwrap_err(), WireError::Trailing);
        assert_eq!(from_slice::<bool>(&[2]).unwrap_err(), WireError::BadTag);
    }

    #[test]
    fn claimed_length_cannot_exceed_input() {
        // 4 GiB claimed, 0 bytes present: must fail without allocating.
        assert!(from_slice::<Vec<u8>>(&[0xff, 0xff, 0xff, 0xff]).is_err());
        assert_eq!(from_slice::<U64s>(&[0, 0, 0xff, 0xff]).unwrap_err(), WireError::Truncated);
        assert_eq!(from_slice::<U64s>(&[0xff, 0xff, 0xff, 0xff]).unwrap_err(), WireError::TooLarge);
    }

    proptest! {
        #[test]
        fn roundtrip_bytes(v in proptest::collection::vec(any::<u8>(), 0..300)) {
            prop_assert_eq!(from_slice::<Vec<u8>>(&to_vec(&v)).unwrap(), v);
        }
        #[test]
        fn roundtrip_u64s(v in proptest::collection::vec(any::<u64>(), 0..100)) {
            let s = U64s(v);
            prop_assert_eq!(from_slice::<U64s>(&to_vec(&s)).unwrap(), s);
        }
        #[test]
        fn roundtrip_opt(v in proptest::option::of(any::<u64>())) {
            prop_assert_eq!(from_slice::<Option<u64>>(&to_vec(&v)).unwrap(), v);
        }
        #[test]
        fn decoding_garbage_never_panics(b in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = from_slice::<U64s>(&b);
            let _ = from_slice::<Vec<u8>>(&b);
            let _ = from_slice::<Option<Vec<u8>>>(&b);
        }
    }
}
