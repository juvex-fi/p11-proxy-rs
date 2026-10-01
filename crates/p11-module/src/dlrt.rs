//! Helpers the generated `DlBackend` methods use: buffers the module writes
//! into, sized by the caller's request but never beyond the protocol limits.

use p11_types::*;
use p11_wire::limits::{MAX_ARRAY, MAX_BYTES};
use p11_wire::structs::{AsyncIn, AsyncOut, OutBytes, OutSpec, OutU64s};
use p11_wire::U64s;

pub use crate::Reply;

/// Pointer and length for an optional byte string (PINs may be NULL).
pub fn opt_bytes(b: &Option<Vec<u8>>) -> (CK_BYTE_PTR, CK_ULONG) {
    match b {
        None => (core::ptr::null_mut(), 0),
        Some(v) => (v.as_ptr() as CK_BYTE_PTR, v.len() as CK_ULONG),
    }
}

/// Pointer and length for an optional PIN or user name.
pub fn opt_secret(b: &Option<p11_wire::Secret>) -> (CK_BYTE_PTR, CK_ULONG) {
    match b {
        None => (core::ptr::null_mut(), 0),
        Some(v) => (v.expose().as_ptr() as CK_BYTE_PTR, v.len() as CK_ULONG),
    }
}

/// A NUL-terminated copy, or `None` if the string has an embedded NUL.
pub fn cstring(b: &[u8]) -> Option<Vec<u8>> {
    if b.contains(&0) {
        return None;
    }
    let mut v = b.to_vec();
    v.push(0);
    Some(v)
}

/// Whether a call that failed with `rv` still reports outputs (lengths of
/// attributes, the size a buffer needs).
pub fn wants_body(rv: u64) -> bool {
    matches!(rv as CK_ULONG, CKR_OK | CKR_BUFFER_TOO_SMALL | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID)
}

/// A byte output under the two-call convention.
#[derive(Debug)]
pub struct OutBuf {
    buf: Vec<u8>,
    supplied: bool,
    len: CK_ULONG,
}

impl OutBuf {
    pub fn new(spec: OutSpec) -> OutBuf {
        match spec {
            OutSpec::Length => OutBuf { buf: Vec::new(), supplied: false, len: 0 },
            OutSpec::Capacity(n) => {
                let n = (n as usize).min(MAX_BYTES);
                OutBuf { buf: vec![0; n], supplied: true, len: n as CK_ULONG }
            }
        }
    }
    pub fn ptr(&mut self) -> CK_BYTE_PTR {
        if self.supplied {
            self.buf.as_mut_ptr()
        } else {
            core::ptr::null_mut()
        }
    }
    pub fn len_ptr(&mut self) -> CK_ULONG_PTR {
        &mut self.len
    }
    pub fn finish(&self, rv: u64) -> OutBytes {
        let len = self.len as u64;
        let data = (self.supplied && rv as CK_ULONG == CKR_OK && (len as usize) <= self.buf.len())
            .then(|| self.buf[..len as usize].to_vec());
        OutBytes { len, data }
    }
}

/// An output of exactly the requested size (`C_GenerateRandom`).
#[derive(Debug)]
pub struct FixedBuf {
    buf: Vec<u8>,
}

impl FixedBuf {
    pub fn new(n: u64) -> Option<FixedBuf> {
        (n as usize <= MAX_BYTES && n <= MAX_BYTES as u64).then(|| FixedBuf { buf: vec![0; n as usize] })
    }
    pub fn ptr(&mut self) -> CK_BYTE_PTR {
        self.buf.as_mut_ptr()
    }
    pub fn len(&self) -> CK_ULONG {
        self.buf.len() as CK_ULONG
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
    pub fn finish(&self, rv: u64) -> Vec<u8> {
        if rv as CK_ULONG == CKR_OK {
            self.buf.clone()
        } else {
            Vec::new()
        }
    }
}

/// An array of `CK_ULONG` under the two-call convention.
#[derive(Debug)]
pub struct OutU64Buf {
    buf: Vec<CK_ULONG>,
    supplied: bool,
    len: CK_ULONG,
}

impl OutU64Buf {
    pub fn new(spec: OutSpec) -> OutU64Buf {
        match spec {
            OutSpec::Length => OutU64Buf { buf: Vec::new(), supplied: false, len: 0 },
            OutSpec::Capacity(n) => {
                let n = (n as usize).min(MAX_ARRAY);
                OutU64Buf { buf: vec![0; n], supplied: true, len: n as CK_ULONG }
            }
        }
    }
    pub fn ptr(&mut self) -> CK_ULONG_PTR {
        if self.supplied {
            self.buf.as_mut_ptr()
        } else {
            core::ptr::null_mut()
        }
    }
    pub fn len_ptr(&mut self) -> CK_ULONG_PTR {
        &mut self.len
    }
    pub fn finish(&self, rv: u64) -> OutU64s {
        let len = self.len as u64;
        let data = (self.supplied && rv as CK_ULONG == CKR_OK && (len as usize) <= self.buf.len())
            .then(|| U64s(self.buf[..len as usize].iter().map(|&x| x as u64).collect()));
        OutU64s { len, data }
    }
}

/// The handle buffer of `C_FindObjects`.
#[derive(Debug)]
pub struct HandleBuf {
    buf: Vec<CK_ULONG>,
    count: CK_ULONG,
}

impl HandleBuf {
    pub fn new(max: u64) -> HandleBuf {
        HandleBuf { buf: vec![0; (max as usize).min(MAX_ARRAY)], count: 0 }
    }
    pub fn ptr(&mut self) -> CK_ULONG_PTR {
        self.buf.as_mut_ptr()
    }
    pub fn max(&self) -> CK_ULONG {
        self.buf.len() as CK_ULONG
    }
    pub fn count_ptr(&mut self) -> CK_ULONG_PTR {
        &mut self.count
    }
    pub fn finish(&self, rv: u64) -> U64s {
        if rv as CK_ULONG != CKR_OK {
            return U64s(Vec::new());
        }
        let n = (self.count as usize).min(self.buf.len());
        U64s(self.buf[..n].iter().map(|&x| x as u64).collect())
    }
}

/// `CK_ASYNC_DATA` with a buffer of the size the caller offered.
#[derive(Debug)]
pub struct AsyncBuf {
    data: CK_ASYNC_DATA,
    buf: Vec<u8>,
    supplied: bool,
}

impl AsyncBuf {
    pub fn new(i: &AsyncIn) -> AsyncBuf {
        let (buf, supplied, len) = match i.value {
            OutSpec::Length => (Vec::new(), false, 0),
            OutSpec::Capacity(n) => {
                let n = (n as usize).min(MAX_BYTES);
                (vec![0u8; n], true, n)
            }
        };
        let mut a = AsyncBuf {
            data: CK_ASYNC_DATA {
                ulVersion: i.version as CK_ULONG,
                pValue: core::ptr::null_mut(),
                ulValue: len as CK_ULONG,
                hObject: 0,
                hAdditionalObject: 0,
            },
            buf,
            supplied,
        };
        if supplied {
            a.data.pValue = a.buf.as_mut_ptr();
        }
        a
    }
    pub fn as_mut_ptr(&mut self) -> CK_ASYNC_DATA_PTR {
        &mut self.data
    }
    pub fn finish(&self, rv: u64) -> AsyncOut {
        let len = self.data.ulValue as u64;
        let data = (self.supplied && rv as CK_ULONG == CKR_OK && (len as usize) <= self.buf.len())
            .then(|| self.buf[..len as usize].to_vec());
        AsyncOut {
            version: self.data.ulVersion as u64,
            value: OutBytes { len, data },
            object: self.data.hObject as u64,
            additional_object: self.data.hAdditionalObject as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_buf_modes() {
        let mut o = OutBuf::new(OutSpec::Length);
        assert!(o.ptr().is_null());
        let mut o = OutBuf::new(OutSpec::Capacity(4));
        assert!(!o.ptr().is_null());
        // SAFETY: len_ptr points into `o`.
        unsafe { *o.len_ptr() = 2 };
        o.buf[0] = 9;
        assert_eq!(o.finish(CKR_OK as u64).data, Some(vec![9, 0]));
        assert_eq!(o.finish(CKR_BUFFER_TOO_SMALL as u64).data, None);
        // a module claiming more than the buffer holds is not believed
        // SAFETY: len_ptr points into `o`.
        unsafe { *o.len_ptr() = 99 };
        assert_eq!(o.finish(CKR_OK as u64).data, None);
    }

    #[test]
    fn capacity_is_clamped() {
        let o = OutBuf::new(OutSpec::Capacity(u64::MAX));
        assert_eq!(o.buf.len(), MAX_BYTES);
        assert!(FixedBuf::new(u64::MAX).is_none());
        assert_eq!(HandleBuf::new(u64::MAX).max() as usize, MAX_ARRAY);
    }

    #[test]
    fn cstring_rejects_nul() {
        assert_eq!(cstring(b"ab"), Some(vec![b'a', b'b', 0]));
        assert_eq!(cstring(b"a\0b"), None);
    }
}
