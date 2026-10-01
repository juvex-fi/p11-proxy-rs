//! `CK_ATTRIBUTE` arrays <-> wire values.
//!
//! Client side: [`capture_template`], [`capture_query`], [`apply_replies`]
//! read and write the caller's memory. Daemon side: [`AttrBuf`] and
//! [`QueryBuf`] rebuild arrays in the daemon's own memory for the module.

use crate::arena::Arena;
use core::mem::size_of;
use p11_types::*;
use p11_wire::attr::{repr_of, Answer, Attr, AttrVal, Query, Reply, Repr, Slot};
use p11_wire::limits::{MAX_ATTRS, MAX_BYTES, MAX_DEPTH};

const SIZEOF_ATTR: usize = size_of::<CK_ATTRIBUTE>();
const ULONG: usize = size_of::<CK_ULONG>();

// ---------------------------------------------------------------------
// client side
// ---------------------------------------------------------------------

/// Read a caller's template.
///
/// # Safety
/// `ptr` must be null or point to `n` readable `CK_ATTRIBUTE`s whose
/// `pValue` members point to `ulValueLen` readable bytes (or are null), as
/// the PKCS#11 contract requires.
pub unsafe fn capture_template(ptr: *const CK_ATTRIBUTE, n: CK_ULONG) -> Result<Vec<Attr>, Rv> {
    // SAFETY: forwarded contract.
    unsafe { capture_template_at(ptr, n, 0) }
}

unsafe fn capture_template_at(ptr: *const CK_ATTRIBUTE, n: CK_ULONG, depth: usize) -> Result<Vec<Attr>, Rv> {
    if depth > MAX_DEPTH {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let n = n as usize;
    if n > MAX_ATTRS {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if n == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: the caller promised `n` readable elements.
    let src = unsafe { core::slice::from_raw_parts(ptr, n) };
    let mut out = Vec::with_capacity(n);
    for a in src {
        let ty = a.type_ as u64;
        if a.ulValueLen == CK_UNAVAILABLE_INFORMATION {
            out.push(Attr { ty, val: AttrVal::Unavailable });
            continue;
        }
        let len = a.ulValueLen as usize;
        if len > MAX_BYTES {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        if a.pValue.is_null() {
            if len != 0 {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            out.push(Attr { ty, val: AttrVal::Bytes(Vec::new()) });
            continue;
        }
        let val = match repr_of(ty) {
            Repr::Template => {
                if len % SIZEOF_ATTR != 0 {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID);
                }
                // SAFETY: the value of a template attribute is an array of `len / size` attributes.
                AttrVal::Nested(unsafe {
                    capture_template_at(a.pValue as *const CK_ATTRIBUTE, (len / SIZEOF_ATTR) as CK_ULONG, depth + 1)?
                })
            }
            Repr::Ulong if len == ULONG => {
                // SAFETY: `len` readable bytes.
                AttrVal::Ulong(unsafe { (a.pValue as *const CK_ULONG).read_unaligned() } as u64)
            }
            Repr::UlongArray if len % ULONG == 0 => {
                let p = a.pValue as *const u8;
                let mut v = Vec::with_capacity(len / ULONG);
                for i in 0..len / ULONG {
                    // SAFETY: within the `len` readable bytes.
                    v.push(unsafe { (p.add(i * ULONG) as *const CK_ULONG).read_unaligned() } as u64);
                }
                AttrVal::UlongArray(v)
            }
            _ => {
                // SAFETY: `len` readable bytes.
                AttrVal::Bytes(unsafe { core::slice::from_raw_parts(a.pValue as *const u8, len) }.to_vec())
            }
        };
        out.push(Attr { ty, val });
    }
    Ok(out)
}

/// Read the caller's template for `C_GetAttributeValue`: which attributes,
/// and how much room there is for each.
///
/// # Safety
/// As for [`capture_template`]; `pValue` members are only compared with null
/// here, but nested templates are followed.
pub unsafe fn capture_query(ptr: *const CK_ATTRIBUTE, n: CK_ULONG) -> Result<Vec<Query>, Rv> {
    // SAFETY: forwarded contract.
    unsafe { capture_query_at(ptr, n, 0) }
}

unsafe fn capture_query_at(ptr: *const CK_ATTRIBUTE, n: CK_ULONG, depth: usize) -> Result<Vec<Query>, Rv> {
    if depth > MAX_DEPTH {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let n = n as usize;
    if n > MAX_ATTRS {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if n == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: the caller promised `n` readable elements.
    let src = unsafe { core::slice::from_raw_parts(ptr, n) };
    let mut out = Vec::with_capacity(n);
    for a in src {
        let ty = a.type_ as u64;
        let slot = if a.pValue.is_null() {
            Slot::Length
        } else if repr_of(ty) == Repr::Template {
            let len = a.ulValueLen as usize;
            if len % SIZEOF_ATTR != 0 || len > MAX_ATTRS * SIZEOF_ATTR {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            // SAFETY: the buffer of a template attribute is an array of attributes.
            Slot::Nested(unsafe {
                capture_query_at(a.pValue as *const CK_ATTRIBUTE, (len / SIZEOF_ATTR) as CK_ULONG, depth + 1)?
            })
        } else {
            if a.ulValueLen as usize > MAX_BYTES {
                return Err(CKR_ATTRIBUTE_VALUE_INVALID);
            }
            Slot::Capacity(a.ulValueLen as u64)
        };
        out.push(Query { ty, slot });
    }
    Ok(out)
}

/// Write the daemon's answers into the caller's attribute array. The
/// answers are untrusted: types must match, and no value may exceed the room
/// the caller gave.
///
/// # Safety
/// As for [`capture_template`], and the `pValue` buffers must be writable
/// for their `ulValueLen` bytes.
pub unsafe fn apply_replies(replies: &[Reply], ptr: *mut CK_ATTRIBUTE, n: CK_ULONG) -> Result<(), Rv> {
    if replies.len() != n as usize {
        return Err(CKR_DEVICE_ERROR);
    }
    if n == 0 {
        return Ok(());
    }
    if ptr.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: the caller promised `n` writable elements.
    let dst = unsafe { core::slice::from_raw_parts_mut(ptr, n as usize) };
    for (a, r) in dst.iter_mut().zip(replies) {
        if a.type_ as u64 != r.ty {
            return Err(CKR_DEVICE_ERROR);
        }
        let cap = a.ulValueLen as usize;
        let put = |a: &mut CK_ATTRIBUTE, bytes: &[u8]| -> Result<(), Rv> {
            if a.pValue.is_null() || bytes.len() > cap {
                return Err(CKR_DEVICE_ERROR);
            }
            // SAFETY: the caller's buffer holds `cap >= bytes.len()` writable bytes.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), a.pValue as *mut u8, bytes.len()) };
            a.ulValueLen = bytes.len() as CK_ULONG;
            Ok(())
        };
        match &r.answer {
            Answer::Unavailable => a.ulValueLen = CK_UNAVAILABLE_INFORMATION,
            Answer::Length(l) => a.ulValueLen = *l as CK_ULONG,
            Answer::Bytes(b) => put(a, b)?,
            Answer::Ulong(v) => put(a, &(*v as CK_ULONG).to_ne_bytes())?,
            Answer::UlongArray(v) => {
                let mut bytes = Vec::with_capacity(v.len() * ULONG);
                for x in v {
                    bytes.extend_from_slice(&(*x as CK_ULONG).to_ne_bytes());
                }
                put(a, &bytes)?
            }
            Answer::Nested(inner) => {
                if a.pValue.is_null() || cap != inner.len() * SIZEOF_ATTR {
                    return Err(CKR_DEVICE_ERROR);
                }
                // SAFETY: the buffer is the caller's nested attribute array.
                unsafe { apply_replies(inner, a.pValue as *mut CK_ATTRIBUTE, inner.len() as CK_ULONG)? }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// daemon side
// ---------------------------------------------------------------------

/// A template rebuilt in the daemon's memory, for a call that reads it.
#[derive(Debug)]
pub struct AttrBuf {
    _arena: Arena,
    ptr: *mut CK_ATTRIBUTE,
    len: usize,
}

impl AttrBuf {
    pub fn build(attrs: &[Attr]) -> Result<AttrBuf, Rv> {
        let mut arena = Arena::new();
        let ptr = build_template(&mut arena, attrs, 0)?;
        Ok(AttrBuf { _arena: arena, ptr, len: attrs.len() })
    }
    pub fn as_mut_ptr(&mut self) -> CK_ATTRIBUTE_PTR {
        self.ptr
    }
    pub fn len(&self) -> CK_ULONG {
        self.len as CK_ULONG
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub(crate) fn build_template(arena: &mut Arena, attrs: &[Attr], depth: usize) -> Result<*mut CK_ATTRIBUTE, Rv> {
    if depth > MAX_DEPTH || attrs.len() > MAX_ATTRS {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let arr = arena.alloc_array::<CK_ATTRIBUTE>(attrs.len())?;
    for (i, a) in attrs.iter().enumerate() {
        let (p, l): (*mut u8, usize) = match &a.val {
            AttrVal::Unavailable => (core::ptr::null_mut(), usize::MAX),
            AttrVal::Bytes(b) if b.is_empty() => (core::ptr::null_mut(), 0),
            AttrVal::Bytes(b) => (arena.copy(b)?, b.len()),
            AttrVal::Ulong(v) => (arena.copy(&(*v as CK_ULONG).to_ne_bytes())?, ULONG),
            AttrVal::UlongArray(v) => {
                let mut bytes = Vec::with_capacity(v.len() * ULONG);
                for x in v {
                    bytes.extend_from_slice(&(*x as CK_ULONG).to_ne_bytes());
                }
                (arena.copy(&bytes)?, bytes.len())
            }
            AttrVal::Nested(n) => (build_template(arena, n, depth + 1)?.cast(), n.len() * SIZEOF_ATTR),
        };
        // SAFETY: `arr` has room for `attrs.len()` attributes and `i` is in range.
        unsafe {
            arr.add(i).write(CK_ATTRIBUTE {
                type_: a.ty as CK_ATTRIBUTE_TYPE,
                pValue: p.cast(),
                ulValueLen: if l == usize::MAX { CK_UNAVAILABLE_INFORMATION } else { l as CK_ULONG },
            });
        }
    }
    Ok(arr)
}

/// Buffers for `C_GetAttributeValue`, sized as the caller asked.
#[derive(Debug)]
pub struct QueryBuf {
    arena: Arena,
    ptr: *mut CK_ATTRIBUTE,
    shape: Vec<Query>,
    built: Vec<Built>,
}

/// Where `build_query` put each value. The module may overwrite the `pValue`
/// members it is handed (some do, in a nested template, pointing them
/// at their own storage); answers are read from these, never from the module's
/// pointers.
#[derive(Debug)]
struct Built {
    buf: *mut u8,
    inner: Vec<Built>,
}

impl QueryBuf {
    pub fn build(q: &[Query]) -> Result<QueryBuf, Rv> {
        let mut arena = Arena::new();
        let (ptr, built) = build_query(&mut arena, q, 0)?;
        Ok(QueryBuf { arena, ptr, shape: q.to_vec(), built })
    }
    pub fn as_mut_ptr(&mut self) -> CK_ATTRIBUTE_PTR {
        self.ptr
    }
    pub fn len(&self) -> CK_ULONG {
        self.shape.len() as CK_ULONG
    }
    pub fn is_empty(&self) -> bool {
        self.shape.is_empty()
    }

    /// Read back what the module wrote.
    pub fn finish(&self) -> Vec<Reply> {
        let _ = &self.arena;
        // SAFETY: `ptr` is the array `build_query` made for `shape`, still alive in the arena.
        unsafe { read_query(self.ptr, &self.shape, &self.built) }
    }
}

fn build_query(arena: &mut Arena, q: &[Query], depth: usize) -> Result<(*mut CK_ATTRIBUTE, Vec<Built>), Rv> {
    if depth > MAX_DEPTH || q.len() > MAX_ATTRS {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let arr = arena.alloc_array::<CK_ATTRIBUTE>(q.len())?;
    let mut built = Vec::with_capacity(q.len());
    for (i, x) in q.iter().enumerate() {
        let mut inner = Vec::new();
        let (p, l): (*mut u8, usize) = match &x.slot {
            Slot::Length => (core::ptr::null_mut(), 0),
            Slot::Capacity(n) => (arena.alloc(*n as usize)?, *n as usize),
            Slot::Nested(n) => {
                let (a, b) = build_query(arena, n, depth + 1)?;
                inner = b;
                (a.cast(), n.len() * SIZEOF_ATTR)
            }
        };
        built.push(Built { buf: p, inner });
        // SAFETY: in-range element of the array just allocated.
        unsafe {
            arr.add(i).write(CK_ATTRIBUTE {
                type_: x.ty as CK_ATTRIBUTE_TYPE,
                pValue: p.cast(),
                ulValueLen: l as CK_ULONG,
            });
        }
    }
    Ok((arr, built))
}

/// # Safety
/// `arr` must be the array built for `shape`, and `built` what `build_query` returned with it.
unsafe fn read_query(arr: *mut CK_ATTRIBUTE, shape: &[Query], built: &[Built]) -> Vec<Reply> {
    let mut out = Vec::with_capacity(shape.len());
    for (i, q) in shape.iter().enumerate() {
        // SAFETY: in range per the contract.
        let a = unsafe { &*arr.add(i) };
        let ans = if a.ulValueLen == CK_UNAVAILABLE_INFORMATION {
            Answer::Unavailable
        } else {
            match &q.slot {
                Slot::Length => Answer::Length(a.ulValueLen as u64),
                Slot::Capacity(cap) => {
                    let len = a.ulValueLen as u64;
                    if len > *cap {
                        // the module reports the size it needs
                        Answer::Length(len)
                    } else {
                        // SAFETY: the buffer holds `cap >= len` initialised (zeroed) bytes.
                        let b = unsafe { core::slice::from_raw_parts(built[i].buf as *const u8, len as usize) };
                        match repr_of(q.ty) {
                            Repr::Ulong if b.len() == ULONG => {
                                Answer::Ulong(CK_ULONG::from_ne_bytes(b.try_into().unwrap()) as u64)
                            }
                            Repr::UlongArray if b.len() % ULONG == 0 => Answer::UlongArray(
                                b.chunks_exact(ULONG)
                                    .map(|c| CK_ULONG::from_ne_bytes(c.try_into().unwrap()) as u64)
                                    .collect(),
                            ),
                            _ => Answer::Bytes(b.to_vec()),
                        }
                    }
                }
                Slot::Nested(inner) => {
                    // SAFETY: the nested array was built for `inner`.
                    Answer::Nested(unsafe { read_query(built[i].buf.cast(), inner, &built[i].inner) })
                }
            }
        };
        out.push(Reply { ty: q.ty, answer: ans });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(ty: u64, val: AttrVal) -> Attr {
        Attr { ty, val }
    }

    #[test]
    fn template_roundtrips_through_c_memory() {
        let tpl = vec![
            t(CKA_CLASS as u64, AttrVal::Ulong(CKO_SECRET_KEY as u64)),
            t(CKA_LABEL as u64, AttrVal::Bytes(b"key".to_vec())),
            t(CKA_TOKEN as u64, AttrVal::Bytes(vec![1])),
            t(CKA_VALUE as u64, AttrVal::Bytes(vec![])),
            t(CKA_ALLOWED_MECHANISMS as u64, AttrVal::UlongArray(vec![1, 2, 3])),
            t(
                CKA_WRAP_TEMPLATE as u64,
                AttrVal::Nested(vec![
                    t(CKA_CLASS as u64, AttrVal::Ulong(4)),
                    t(CKA_LABEL as u64, AttrVal::Bytes(b"x".to_vec())),
                ]),
            ),
            t(CKA_VALUE_LEN as u64, AttrVal::Unavailable),
        ];
        let mut buf = AttrBuf::build(&tpl).unwrap();
        // SAFETY: buf.ptr/len describe a valid array in buf's arena.
        let back = unsafe { capture_template(buf.as_mut_ptr(), buf.len()) }.unwrap();
        // an unavailable length stays unavailable; empty bytes stay empty
        assert_eq!(back, tpl);
    }

    #[test]
    fn hostile_templates_are_rejected() {
        let bad = CK_ATTRIBUTE { type_: CKA_LABEL, pValue: core::ptr::null_mut(), ulValueLen: 5 };
        // SAFETY: one valid attribute, null value with a length.
        assert_eq!(unsafe { capture_template(&bad, 1) }.unwrap_err(), CKR_ATTRIBUTE_VALUE_INVALID);
        // SAFETY: n == 0 never reads.
        assert!(unsafe { capture_template(core::ptr::null(), 0) }.unwrap().is_empty());
        // SAFETY: null with n > 0 is rejected before any read.
        assert_eq!(unsafe { capture_template(core::ptr::null(), 3) }.unwrap_err(), CKR_ARGUMENTS_BAD);
        // SAFETY: rejected on the count alone.
        assert_eq!(unsafe { capture_template(bad_ptr(), 1 << 40) }.unwrap_err(), CKR_ARGUMENTS_BAD);
    }

    fn bad_ptr() -> *const CK_ATTRIBUTE {
        core::ptr::NonNull::dangling().as_ptr()
    }

    #[test]
    fn query_flow() {
        // caller: length of label, 8 bytes for the class, a nested wrap template with room for one label
        let q = vec![
            Query { ty: CKA_LABEL as u64, slot: Slot::Length },
            Query { ty: CKA_CLASS as u64, slot: Slot::Capacity(8) },
            Query { ty: CKA_VALUE as u64, slot: Slot::Capacity(2) },
            Query {
                ty: CKA_WRAP_TEMPLATE as u64,
                slot: Slot::Nested(vec![Query { ty: CKA_LABEL as u64, slot: Slot::Capacity(4) }]),
            },
        ];
        let mut b = QueryBuf::build(&q).unwrap();
        // pretend to be the module
        let arr = b.as_mut_ptr();
        // SAFETY: arr points to 4 attributes built by QueryBuf.
        unsafe {
            (*arr).ulValueLen = 3;
            let cls = &mut *arr.add(1);
            (cls.pValue as *mut CK_ULONG).write(CKO_DATA);
            let val = &mut *arr.add(2);
            val.ulValueLen = 20; // needs 20, has 2
            let w = &mut *arr.add(3);
            let inner = w.pValue as *mut CK_ATTRIBUTE;
            let lab = &mut *inner;
            core::ptr::copy_nonoverlapping(b"abc".as_ptr(), lab.pValue as *mut u8, 3);
            lab.ulValueLen = 3;
        }
        let r = b.finish();
        assert_eq!(r[0].answer, Answer::Length(3));
        assert_eq!(r[1].answer, Answer::Ulong(CKO_DATA as u64));
        assert_eq!(r[2].answer, Answer::Length(20));
        assert_eq!(
            r[3].answer,
            Answer::Nested(vec![Reply { ty: CKA_LABEL as u64, answer: Answer::Bytes(b"abc".to_vec()) }])
        );

        // caller applies the replies to its own array
        let mut lab = [0u8; 4];
        let mut cls = [0u8; 8];
        let mut val = [0u8; 2];
        let mut inner = [CK_ATTRIBUTE { type_: CKA_LABEL, pValue: lab.as_mut_ptr().cast(), ulValueLen: 4 }];
        let mut mine = [
            CK_ATTRIBUTE { type_: CKA_LABEL, pValue: core::ptr::null_mut(), ulValueLen: 0 },
            CK_ATTRIBUTE { type_: CKA_CLASS, pValue: cls.as_mut_ptr().cast(), ulValueLen: 8 },
            CK_ATTRIBUTE { type_: CKA_VALUE, pValue: val.as_mut_ptr().cast(), ulValueLen: 2 },
            CK_ATTRIBUTE {
                type_: CKA_WRAP_TEMPLATE,
                pValue: inner.as_mut_ptr().cast(),
                ulValueLen: SIZEOF_ATTR as CK_ULONG,
            },
        ];
        // SAFETY: `mine` and its buffers are valid for the sizes declared.
        unsafe { apply_replies(&r, mine.as_mut_ptr(), 4) }.unwrap();
        assert_eq!(mine[0].ulValueLen, 3);
        assert_eq!(CK_ULONG::from_ne_bytes(cls), CKO_DATA);
        assert_eq!(mine[2].ulValueLen, 20);
        assert_eq!(&lab[..3], b"abc");
    }

    #[test]
    fn a_module_that_repoints_values_is_not_followed() {
        let q = vec![Query {
            ty: CKA_WRAP_TEMPLATE as u64,
            slot: Slot::Nested(vec![Query { ty: CKA_VALUE_LEN as u64, slot: Slot::Capacity(8) }]),
        }];
        let mut b = QueryBuf::build(&q).unwrap();
        let mut elsewhere = [0xAAu8; 8];
        // SAFETY: the array and its nested array were built by QueryBuf.
        unsafe {
            let inner = (*b.as_mut_ptr()).pValue as *mut CK_ATTRIBUTE;
            (*inner).pValue = elsewhere.as_mut_ptr().cast();
        }
        assert_eq!(
            b.finish()[0].answer,
            Answer::Nested(vec![Reply { ty: CKA_VALUE_LEN as u64, answer: Answer::Ulong(0) }])
        );
    }

    #[test]
    fn oversized_or_mismatched_replies_are_refused() {
        let mut small = [0u8; 2];
        let mut a = [CK_ATTRIBUTE { type_: CKA_VALUE, pValue: small.as_mut_ptr().cast(), ulValueLen: 2 }];
        let too_big = [Reply { ty: CKA_VALUE as u64, answer: Answer::Bytes(vec![0; 3]) }];
        // SAFETY: valid array and buffer.
        assert_eq!(unsafe { apply_replies(&too_big, a.as_mut_ptr(), 1) }.unwrap_err(), CKR_DEVICE_ERROR);
        let wrong_type = [Reply { ty: CKA_LABEL as u64, answer: Answer::Length(1) }];
        // SAFETY: as above.
        assert_eq!(unsafe { apply_replies(&wrong_type, a.as_mut_ptr(), 1) }.unwrap_err(), CKR_DEVICE_ERROR);
        // SAFETY: as above.
        assert_eq!(unsafe { apply_replies(&[], a.as_mut_ptr(), 1) }.unwrap_err(), CKR_DEVICE_ERROR);
    }
}
