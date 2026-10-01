//! Descriptors of the C structures that carry mechanism parameters, and the
//! four walks over them:
//!
//! - [`capture`] (client): read the caller's structure into a [`Node`] tree
//! - [`materialize`] (daemon): rebuild an equivalent structure in the
//!   daemon's own memory from a tree, sized and bounded by the descriptor
//! - [`extract`] (daemon): after the call, read back the members the module
//!   filled in
//! - [`apply`] (client): write those into the caller's structure
//!
//! A descriptor lists a structure's members in order; a member says how it
//! sits in memory (offset, kind) and which way it flows: `req` is the set of
//! phases in which the value goes to the module, `resp` whether the module's
//! value comes back. Offsets come from `offset_of!` on the bindgen types, so
//! a member that doesn't exist doesn't compile. Nothing a peer sends is ever
//! used as a pointer: pointers in rebuilt structures point into the arena.

use crate::arena::Arena;
use crate::attrs;
use crate::mech;
use core::mem::size_of;
use p11_types::*;
use p11_wire::Node;

/// The mechanism parameter itself (`C_EncryptInit`, `C_DeriveKey`, ...).
pub const MECH: u8 = 1;
/// A parameter of an `C_EncryptMessage*` call.
pub const ENC: u8 = 2;
/// A parameter of a `C_DecryptMessage*` call.
pub const DEC: u8 = 4;
pub const MSG: u8 = ENC | DEC;
pub const ALL: u8 = MECH | ENC | DEC;

/// Most memory one buffer member may hold.
pub const MAX_BUF: u64 = 1 << 20;
/// Most elements in an array member.
pub const MAX_ELEMS: u64 = 256;
/// Longest string member.
pub const MAX_CSTR: usize = 4096;
/// Deepest nesting of structures and nested mechanisms.
pub const MAX_NEST: usize = 5;

/// Where a buffer member gets its length from.
#[derive(Debug, Clone, Copy)]
pub enum Len {
    /// The member with this index in the same descriptor: a `CK_ULONG`, or
    /// the `CK_ULONG` a pointer member refers to.
    Field(u8),
    /// The same, in the enclosing structure.
    Parent(u8),
    Fixed(u32),
}

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Ulong,
    /// A `CK_ULONG` that holds an object handle; the daemon translates it.
    Handle,
    Bool,
    Byte,
    /// A pointer to `len` bytes (`bits`: the length member counts bits).
    Bytes {
        len: Len,
        bits: bool,
        max: u32,
    },
    /// A byte array inside the structure.
    Inline(u32),
    /// A pointer to one `CK_ULONG`.
    UlongPtr,
    /// A pointer to one object handle the module produces.
    HandlePtr,
    /// A pointer to a structure.
    Struct(&'static Desc),
    /// A structure by value.
    Embedded(&'static Desc),
    /// A pointer to an array of structures whose count is member `count`.
    Array {
        desc: &'static Desc,
        count: u8,
    },
    /// A pointer to an attribute template whose count is member `count`.
    Attrs {
        count: u8,
    },
    /// A NUL-terminated string.
    CStr,
    /// A pointer to another `CK_MECHANISM`.
    MechPtr,
    /// A `CK_MECHANISM` by value.
    Mech,
    /// A pointer to an array of object handles the module writes. The room the caller gives is in the
    /// `CK_ULONG` that member `count` points to, which comes back holding the number written.
    HandleArray {
        count: u8,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub off: usize,
    pub kind: Kind,
    /// Phases in which the value goes to the module.
    pub req: u8,
    /// The module's value comes back to the caller.
    pub resp: bool,
}

#[derive(Debug)]
pub struct Desc {
    pub name: &'static str,
    pub size: usize,
    /// Phases in which this structure may be used.
    pub phases: u8,
    pub fields: &'static [Field],
}

/// How a flat (pointer-free) parameter's length is checked.
#[derive(Debug, Clone, Copy)]
pub enum Flat {
    Exact(usize),
    Either(usize, usize),
    /// Any length up to this.
    Any(usize),
}

impl Flat {
    /// Zero (no parameter) is always acceptable.
    pub fn ok(&self, len: usize) -> bool {
        len == 0
            || match *self {
                Flat::Exact(n) => len == n,
                Flat::Either(a, b) => len == a || len == b,
                Flat::Any(max) => len <= max,
            }
    }
}

/// How a mechanism's parameter travels.
#[derive(Debug, Clone, Copy)]
pub enum Spec {
    /// The mechanism takes no parameter; whatever the caller passed is ignored.
    NoParam,
    /// Bytes copied as they are (IVs, structures without pointers).
    Flat(Flat),
    /// A `CK_ULONG` that is an object handle.
    FlatHandle,
    /// Bytes without pointers, exactly `len`, holding object handles at these byte offsets.
    FlatHandles { len: usize, offs: &'static [usize] },
    /// `CK_AES_XTS_PARAMS`, or just its 16-byte tweak.
    Xts,
    /// A structure described by a descriptor; the caller may pass none.
    Struct(&'static Desc),
    /// The same, for parameters that are optional by definition.
    OptStruct(&'static Desc),
    /// `CK_PKCS5_PBKD2_PARAMS2` or the older `CK_PKCS5_PBKD2_PARAMS`.
    Pbkd2,
}

// ---- constructors used by the descriptor tables ----

pub const fn ulong(off: usize) -> Field {
    Field { off, kind: Kind::Ulong, req: ALL, resp: false }
}
pub const fn handle(off: usize) -> Field {
    Field { off, kind: Kind::Handle, req: ALL, resp: false }
}
/// An object handle the module produces.
pub const fn handle_out(off: usize) -> Field {
    Field { off, kind: Kind::Handle, req: 0, resp: true }
}
pub const fn boolean(off: usize) -> Field {
    Field { off, kind: Kind::Bool, req: ALL, resp: false }
}
pub const fn byte(off: usize) -> Field {
    Field { off, kind: Kind::Byte, req: ALL, resp: false }
}
/// An input buffer.
pub const fn buf(off: usize, len: Len, req: u8) -> Field {
    Field { off, kind: Kind::Bytes { len, bits: false, max: MAX_BUF as u32 }, req, resp: false }
}
/// An input buffer whose length counts bits.
pub const fn buf_bits(off: usize, len: Len, req: u8) -> Field {
    Field { off, kind: Kind::Bytes { len, bits: true, max: MAX_BUF as u32 }, req, resp: false }
}
/// An input buffer with a shorter limit.
pub const fn buf_max(off: usize, len: Len, max: u32) -> Field {
    Field { off, kind: Kind::Bytes { len, bits: false, max }, req: ALL, resp: false }
}
/// A buffer that goes in and whose contents come back.
pub const fn buf_io(off: usize, len: Len, bits: bool, req: u8) -> Field {
    Field { off, kind: Kind::Bytes { len, bits, max: MAX_BUF as u32 }, req, resp: true }
}
/// A buffer the module fills in.
pub const fn buf_out(off: usize, len: Len, bits: bool) -> Field {
    Field { off, kind: Kind::Bytes { len, bits, max: MAX_BUF as u32 }, req: 0, resp: true }
}
pub const fn inline(off: usize, n: u32) -> Field {
    Field { off, kind: Kind::Inline(n), req: ALL, resp: false }
}
/// A pointer to a `CK_ULONG`: `req` phases send its value, `resp` gets it back.
pub const fn ulong_ptr(off: usize, req: u8, resp: bool) -> Field {
    Field { off, kind: Kind::UlongPtr, req, resp }
}
/// A pointer to an object handle the module produces.
pub const fn handle_ptr(off: usize) -> Field {
    Field { off, kind: Kind::HandlePtr, req: 0, resp: true }
}
pub const fn structure(off: usize, d: &'static Desc) -> Field {
    Field { off, kind: Kind::Struct(d), req: ALL, resp: false }
}
pub const fn embedded(off: usize, d: &'static Desc) -> Field {
    Field { off, kind: Kind::Embedded(d), req: ALL, resp: false }
}
pub const fn array(off: usize, d: &'static Desc, count: u8) -> Field {
    Field { off, kind: Kind::Array { desc: d, count }, req: ALL, resp: false }
}
pub const fn attrs(off: usize, count: u8) -> Field {
    Field { off, kind: Kind::Attrs { count }, req: ALL, resp: false }
}
pub const fn cstr(off: usize) -> Field {
    Field { off, kind: Kind::CStr, req: ALL, resp: false }
}
pub const fn mech_ptr(off: usize) -> Field {
    Field { off, kind: Kind::MechPtr, req: ALL, resp: false }
}

impl Desc {
    /// Whether any member of the structure (or of one it contains) comes back.
    pub fn has_outputs(&self) -> bool {
        self.fields.iter().any(|f| {
            f.resp
                || match f.kind {
                    Kind::Struct(d) | Kind::Embedded(d) | Kind::Array { desc: d, .. } => d.has_outputs(),
                    _ => false,
                }
        })
    }
}

// ---------------------------------------------------------------------
// memory access
// ---------------------------------------------------------------------

const BAD: Rv = CKR_MECHANISM_PARAM_INVALID;

/// The structure a member's length may live in besides its own.
#[derive(Clone, Copy)]
pub(crate) struct Parent<'a> {
    d: &'a Desc,
    base: *const u8,
}

/// Whether `p` is an allocation the daemon made with room for `need` bytes.
/// Without `caps` (the caller's own structure, or one being built) nothing is
/// checked. A module can overwrite the pointer members it is handed; what it
/// left there is followed only if it is still one of ours.
fn own(caps: Option<&Caps>, p: usize, need: usize) -> Result<(), Rv> {
    match caps {
        Some(c) if c.get(&p).is_none_or(|&cap| cap < need) => Err(CKR_DEVICE_ERROR),
        _ => Ok(()),
    }
}

unsafe fn rd_scalar(base: *const u8, f: &Field) -> u64 {
    match f.kind {
        // SAFETY: `off` is inside the structure the caller vouches for.
        Kind::Ulong | Kind::Handle => unsafe { (base.add(f.off) as *const CK_ULONG).read_unaligned() as u64 },
        // SAFETY: as above.
        Kind::Bool | Kind::Byte => unsafe { *base.add(f.off) as u64 },
        _ => 0,
    }
}

unsafe fn rd_ptr(base: *const u8, f: &Field) -> *mut u8 {
    // SAFETY: `off` is inside the structure the caller vouches for.
    unsafe { (base.add(f.off) as *const *mut u8).read_unaligned() }
}

unsafe fn wr_ptr(base: *mut u8, f: &Field, p: *mut u8) {
    // SAFETY: `off` is inside the structure the caller vouches for.
    unsafe { (base.add(f.off) as *mut *mut u8).write_unaligned(p) }
}

/// The value of member `i`: a scalar, or what a `UlongPtr` points to. With
/// `caps` (reading what a module wrote), the pointer must be one of the
/// daemon's own allocations: a module may have repointed it.
unsafe fn scalar_at(d: &Desc, base: *const u8, i: u8, caps: Option<&Caps>) -> Result<u64, Rv> {
    let f = d.fields.get(i as usize).ok_or(BAD)?;
    match f.kind {
        // SAFETY: forwarded.
        Kind::Ulong | Kind::Handle | Kind::Bool | Kind::Byte => Ok(unsafe { rd_scalar(base, f) }),
        Kind::UlongPtr => {
            // SAFETY: forwarded.
            let p = unsafe { rd_ptr(base, f) } as *const CK_ULONG;
            if !p.is_null() {
                own(caps, p as usize, size_of::<CK_ULONG>())?;
            }
            // SAFETY: a non-null pointer member refers to a readable CK_ULONG.
            Ok(if p.is_null() { 0 } else { unsafe { p.read_unaligned() as u64 } })
        }
        _ => Err(BAD),
    }
}

unsafe fn len_of(
    d: &Desc,
    base: *const u8,
    parent: Option<Parent<'_>>,
    f: &Field,
    caps: Option<&Caps>,
) -> Result<usize, Rv> {
    let Kind::Bytes { len, bits, max } = f.kind else { return Err(BAD) };
    // SAFETY: forwarded.
    let mut v = unsafe {
        match len {
            Len::Fixed(n) => n as u64,
            Len::Field(i) => scalar_at(d, base, i, caps)?,
            Len::Parent(i) => {
                let p = parent.ok_or(BAD)?;
                scalar_at(p.d, p.base, i, caps)?
            }
        }
    };
    if bits {
        if v > max as u64 * 8 {
            return Err(BAD);
        }
        v = v.div_ceil(8);
    }
    if v > max as u64 {
        return Err(BAD);
    }
    Ok(v as usize)
}

unsafe fn count_of(d: &Desc, base: *const u8, i: u8, caps: Option<&Caps>) -> Result<usize, Rv> {
    // SAFETY: forwarded.
    let v = unsafe { scalar_at(d, base, i, caps)? };
    if v > MAX_ELEMS {
        return Err(BAD);
    }
    Ok(v as usize)
}

// ---------------------------------------------------------------------
// capture: caller's structure -> tree
// ---------------------------------------------------------------------

/// Read the structure at `base` as a tree.
///
/// # Safety
/// `base` must point to a readable structure laid out as `d` says, whose
/// pointer members are null or point to readable memory of the size their
/// length members give.
pub unsafe fn capture(d: &Desc, base: *const u8, phase: u8) -> Result<Node, Rv> {
    // SAFETY: forwarded.
    unsafe { capture_at(d, base, phase, None, 0) }
}

pub(crate) unsafe fn capture_at(
    d: &Desc,
    base: *const u8,
    phase: u8,
    parent: Option<Parent<'_>>,
    depth: usize,
) -> Result<Node, Rv> {
    if depth >= MAX_NEST {
        return Err(BAD);
    }
    let here = Parent { d, base };
    let mut out = Vec::with_capacity(d.fields.len());
    for f in d.fields {
        let sent = f.req & phase != 0;
        let n = match f.kind {
            Kind::Ulong | Kind::Handle | Kind::Bool | Kind::Byte => {
                if sent {
                    // SAFETY: forwarded.
                    Node::U(unsafe { rd_scalar(base, f) })
                } else {
                    Node::Absent
                }
            }
            Kind::Bytes { .. } => {
                // SAFETY: forwarded.
                let (p, len) = unsafe { (rd_ptr(base, f), len_of(d, base, parent, f, None)?) };
                if p.is_null() {
                    if sent && len != 0 {
                        return Err(BAD);
                    }
                    Node::Absent
                } else if sent {
                    // SAFETY: `len` readable bytes per the contract.
                    Node::B(unsafe { core::slice::from_raw_parts(p, len) }.to_vec())
                } else {
                    Node::U(1)
                }
            }
            Kind::Inline(n) => {
                if sent {
                    // SAFETY: the array is inside the structure.
                    Node::B(unsafe { core::slice::from_raw_parts(base.add(f.off), n as usize) }.to_vec())
                } else {
                    Node::Absent
                }
            }
            Kind::UlongPtr | Kind::HandlePtr => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) } as *const CK_ULONG;
                if p.is_null() {
                    Node::Absent
                } else if sent {
                    // SAFETY: a non-null pointer member refers to a readable CK_ULONG.
                    Node::U(unsafe { p.read_unaligned() } as u64)
                } else {
                    Node::U(0)
                }
            }
            Kind::Struct(sub) => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) };
                if p.is_null() {
                    Node::Absent
                } else {
                    // SAFETY: a non-null pointer member refers to a structure of that kind.
                    unsafe { capture_at(sub, p, phase, Some(here), depth + 1)? }
                }
            }
            // SAFETY: the structure is embedded at `off`.
            Kind::Embedded(sub) => unsafe { capture_at(sub, base.add(f.off), phase, Some(here), depth + 1)? },
            Kind::Array { desc, count } => {
                // SAFETY: forwarded.
                let (p, n) = unsafe { (rd_ptr(base, f), count_of(d, base, count, None)?) };
                if p.is_null() {
                    if n != 0 {
                        return Err(BAD);
                    }
                    Node::Absent
                } else {
                    let mut v = Vec::with_capacity(n);
                    for k in 0..n {
                        // SAFETY: `n` elements of `desc.size` bytes per the contract.
                        v.push(unsafe { capture_at(desc, p.add(k * desc.size), phase, Some(here), depth + 1)? });
                    }
                    Node::L(v)
                }
            }
            Kind::Attrs { count } => {
                // SAFETY: forwarded.
                let (p, n) = unsafe { (rd_ptr(base, f), count_of(d, base, count, None)?) };
                if p.is_null() {
                    if n != 0 {
                        return Err(BAD);
                    }
                    Node::Absent
                } else {
                    // SAFETY: `n` readable attributes per the contract.
                    Node::T(unsafe { attrs::capture_template(p as *const CK_ATTRIBUTE, n as CK_ULONG)? })
                }
            }
            Kind::CStr => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) };
                if p.is_null() {
                    Node::Absent
                } else {
                    let mut v = Vec::new();
                    loop {
                        // SAFETY: reading up to the terminator the contract guarantees.
                        let b = unsafe { *p.add(v.len()) };
                        if b == 0 {
                            break;
                        }
                        v.push(b);
                        if v.len() > MAX_CSTR {
                            return Err(BAD);
                        }
                    }
                    Node::B(v)
                }
            }
            Kind::MechPtr => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) } as *const CK_MECHANISM;
                if p.is_null() {
                    Node::Absent
                } else {
                    // SAFETY: a non-null pointer member refers to a CK_MECHANISM.
                    let m = unsafe { mech::capture_mech_at(p, depth + 1)? };
                    Node::L(vec![Node::U(m.mechanism), m.param.unwrap_or(Node::Absent)])
                }
            }
            Kind::Mech => {
                // SAFETY: the structure holds a CK_MECHANISM at `off`.
                let m = unsafe { mech::capture_mech_at(base.add(f.off) as *const CK_MECHANISM, depth + 1)? };
                Node::L(vec![Node::U(m.mechanism), m.param.unwrap_or(Node::Absent)])
            }
            Kind::HandleArray { .. } => {
                // nothing goes in: only whether the caller gave a buffer
                // SAFETY: forwarded.
                if unsafe { rd_ptr(base, f) }.is_null() {
                    Node::Absent
                } else {
                    Node::U(1)
                }
            }
        };
        out.push(n);
    }
    Ok(Node::L(out))
}

// ---------------------------------------------------------------------
// materialize: tree -> structure in the daemon's memory
// ---------------------------------------------------------------------

/// Capacity of each output buffer given to the module, by address, so that
/// reading results back can't run past what was allocated.
pub(crate) type Caps = std::collections::HashMap<usize, usize>;

/// Build the structure `n` describes at `base` (which must have room for
/// `d.size` zeroed bytes in `arena`).
///
/// # Safety
/// `base` must point to `d.size` writable, zeroed, 8-aligned bytes.
pub(crate) unsafe fn materialize(
    d: &Desc,
    n: &Node,
    phase: u8,
    arena: &mut Arena,
    caps: &mut Caps,
    base: *mut u8,
) -> Result<(), Rv> {
    // SAFETY: forwarded.
    unsafe { materialize_at(d, n, phase, arena, caps, base, None, 0) }
}

#[allow(clippy::too_many_arguments)]
unsafe fn materialize_at(
    d: &Desc,
    n: &Node,
    phase: u8,
    arena: &mut Arena,
    caps: &mut Caps,
    base: *mut u8,
    parent: Option<Parent<'_>>,
    depth: usize,
) -> Result<(), Rv> {
    if depth >= MAX_NEST {
        return Err(BAD);
    }
    let Node::L(items) = n else { return Err(BAD) };
    if items.len() != d.fields.len() {
        return Err(BAD);
    }
    let here = Parent { d, base };

    // 1. scalars and CK_ULONG pointers: lengths come from these
    for (f, it) in d.fields.iter().zip(items) {
        let sent = f.req & phase != 0;
        match f.kind {
            Kind::Ulong | Kind::Handle | Kind::Bool | Kind::Byte => match it {
                Node::U(v) => {
                    // SAFETY: `off` is inside the zeroed structure.
                    unsafe {
                        match f.kind {
                            Kind::Ulong | Kind::Handle => {
                                (base.add(f.off) as *mut CK_ULONG).write_unaligned(*v as CK_ULONG)
                            }
                            Kind::Bool => *base.add(f.off) = (*v != 0) as u8,
                            _ => *base.add(f.off) = u8::try_from(*v).map_err(|_| BAD)?,
                        }
                    }
                }
                Node::Absent if !sent => {}
                _ => return Err(BAD),
            },
            Kind::UlongPtr | Kind::HandlePtr => match it {
                Node::Absent => {}
                Node::U(v) => {
                    let p = arena.alloc(size_of::<CK_ULONG>())?;
                    caps.insert(p as usize, size_of::<CK_ULONG>());
                    // SAFETY: fresh allocation of a CK_ULONG.
                    unsafe {
                        (p as *mut CK_ULONG).write_unaligned(if sent { *v as CK_ULONG } else { 0 });
                        wr_ptr(base, f, p);
                    }
                }
                _ => return Err(BAD),
            },
            _ => {}
        }
    }

    // 2. everything else, in order
    for (f, it) in d.fields.iter().zip(items) {
        let sent = f.req & phase != 0;
        match f.kind {
            Kind::Ulong | Kind::Handle | Kind::Bool | Kind::Byte | Kind::UlongPtr | Kind::HandlePtr => {}
            Kind::Bytes { .. } => {
                // SAFETY: lengths were set in step 1.
                let len = unsafe { len_of(d, base, parent, f, None)? };
                match it {
                    Node::Absent => {
                        if sent && len != 0 {
                            return Err(BAD);
                        }
                    }
                    Node::B(b) => {
                        if !sent || b.len() != len {
                            return Err(BAD);
                        }
                        if len > 0 {
                            let p = arena.copy(b)?;
                            caps.insert(p as usize, len);
                            // SAFETY: pointer member inside the structure.
                            unsafe { wr_ptr(base, f, p) };
                        }
                    }
                    Node::U(1) if !sent => {
                        let p = arena.alloc(len)?;
                        caps.insert(p as usize, len);
                        // SAFETY: as above.
                        unsafe { wr_ptr(base, f, p) };
                    }
                    _ => return Err(BAD),
                }
            }
            Kind::Inline(len) => match it {
                Node::B(b) if sent && b.len() == len as usize => {
                    // SAFETY: the array is inside the structure.
                    unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), base.add(f.off), b.len()) };
                }
                Node::Absent if !sent => {}
                _ => return Err(BAD),
            },
            Kind::Struct(sub) => match it {
                Node::Absent => {}
                Node::L(_) => {
                    let p = arena.alloc(sub.size)?;
                    caps.insert(p as usize, sub.size);
                    // SAFETY: fresh zeroed allocation of `sub.size` bytes.
                    unsafe {
                        materialize_at(sub, it, phase, arena, caps, p, Some(here), depth + 1)?;
                        wr_ptr(base, f, p);
                    }
                }
                _ => return Err(BAD),
            },
            // SAFETY: embedded inside the zeroed structure.
            Kind::Embedded(sub) => unsafe {
                materialize_at(sub, it, phase, arena, caps, base.add(f.off), Some(here), depth + 1)?
            },
            Kind::Array { desc, count } => {
                // SAFETY: counts were set in step 1.
                let cnt = unsafe { count_of(d, base, count, None)? };
                match it {
                    Node::Absent if cnt == 0 => {}
                    Node::L(v) if v.len() == cnt => {
                        let bytes = cnt.checked_mul(desc.size).ok_or(BAD)?;
                        let p = arena.alloc(bytes)?;
                        caps.insert(p as usize, bytes);
                        for (k, e) in v.iter().enumerate() {
                            // SAFETY: element k of the fresh array.
                            unsafe {
                                materialize_at(
                                    desc,
                                    e,
                                    phase,
                                    arena,
                                    caps,
                                    p.add(k * desc.size),
                                    Some(here),
                                    depth + 1,
                                )?
                            };
                        }
                        // SAFETY: pointer member inside the structure.
                        unsafe { wr_ptr(base, f, p) };
                    }
                    _ => return Err(BAD),
                }
            }
            Kind::Attrs { count } => {
                // SAFETY: counts were set in step 1.
                let cnt = unsafe { count_of(d, base, count, None)? };
                match it {
                    Node::Absent if cnt == 0 => {}
                    Node::T(t) if t.len() == cnt => {
                        let p = attrs::build_template(arena, t, 0)?;
                        // SAFETY: pointer member inside the structure.
                        unsafe { wr_ptr(base, f, p.cast()) };
                    }
                    _ => return Err(BAD),
                }
            }
            Kind::CStr => match it {
                Node::Absent => {}
                Node::B(b) if b.len() <= MAX_CSTR && !b.contains(&0) => {
                    let mut v = b.clone();
                    v.push(0);
                    let p = arena.copy(&v)?;
                    // SAFETY: pointer member inside the structure.
                    unsafe { wr_ptr(base, f, p) };
                }
                _ => return Err(BAD),
            },
            Kind::MechPtr => match it {
                Node::Absent => {}
                Node::L(v) if v.len() == 2 => {
                    let Node::U(t) = v[0] else { return Err(BAD) };
                    let param = if v[1].is_absent() { None } else { Some(v[1].clone()) };
                    let m = arena.alloc(size_of::<CK_MECHANISM>())? as *mut CK_MECHANISM;
                    // SAFETY: fresh zeroed CK_MECHANISM.
                    unsafe {
                        mech::fill_mech(t, &param, arena, caps, &mut *m, depth + 1)?;
                        wr_ptr(base, f, m.cast());
                    }
                }
                _ => return Err(BAD),
            },
            Kind::Mech => match it {
                Node::Absent => {}
                Node::L(v) if v.len() == 2 => {
                    let Node::U(t) = v[0] else { return Err(BAD) };
                    let param = if v[1].is_absent() { None } else { Some(v[1].clone()) };
                    // SAFETY: the zeroed structure holds room for a CK_MECHANISM at `off`.
                    unsafe {
                        mech::fill_mech(
                            t,
                            &param,
                            arena,
                            caps,
                            &mut *(base.add(f.off) as *mut CK_MECHANISM),
                            depth + 1,
                        )?
                    };
                }
                _ => return Err(BAD),
            },
            Kind::HandleArray { count } => match it {
                Node::Absent => {}
                Node::U(1) => {
                    // SAFETY: counts were set in step 1.
                    let cnt = unsafe { count_of(d, base, count, None)? };
                    let bytes = cnt.checked_mul(size_of::<CK_ULONG>()).ok_or(BAD)?;
                    let p = arena.alloc(bytes)?;
                    caps.insert(p as usize, bytes);
                    // SAFETY: pointer member inside the structure.
                    unsafe { wr_ptr(base, f, p) };
                }
                _ => return Err(BAD),
            },
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// extract: module's results -> tree
// ---------------------------------------------------------------------

/// Read back the members the module filled in. The tree has the shape of
/// the structure, with `Absent` where nothing comes back. The bool says
/// whether anything did.
///
/// # Safety
/// `base` must be a structure built by [`materialize`] with the same
/// `caps`.
pub(crate) unsafe fn extract(d: &Desc, base: *const u8, caps: &Caps) -> Result<Option<Node>, Rv> {
    // SAFETY: forwarded.
    let (n, any) = unsafe { extract_at(d, base, caps, None, 0)? };
    Ok(any.then_some(n))
}

unsafe fn extract_at(
    d: &Desc,
    base: *const u8,
    caps: &Caps,
    parent: Option<Parent<'_>>,
    depth: usize,
) -> Result<(Node, bool), Rv> {
    if depth >= MAX_NEST {
        return Err(CKR_DEVICE_ERROR);
    }
    let here = Parent { d, base };
    let mut any = false;
    let mut out = Vec::with_capacity(d.fields.len());
    for f in d.fields {
        let n = match f.kind {
            Kind::Ulong | Kind::Handle | Kind::Bool | Kind::Byte if f.resp => {
                any = true;
                // SAFETY: forwarded.
                Node::U(unsafe { rd_scalar(base, f) })
            }
            Kind::UlongPtr | Kind::HandlePtr if f.resp => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) } as *const CK_ULONG;
                if p.is_null() {
                    Node::Absent
                } else {
                    own(Some(caps), p as usize, size_of::<CK_ULONG>())?;
                    any = true;
                    // SAFETY: allocated by materialize (checked just above: the module may have repointed it).
                    Node::U(unsafe { p.read_unaligned() } as u64)
                }
            }
            Kind::Bytes { .. } if f.resp => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) };
                if p.is_null() {
                    Node::Absent
                } else {
                    // SAFETY: forwarded.
                    let len = unsafe { len_of(d, base, parent, f, Some(caps)) }.map_err(|_| CKR_DEVICE_ERROR)?;
                    let cap = caps.get(&(p as usize)).copied().ok_or(CKR_DEVICE_ERROR)?;
                    if len > cap {
                        return Err(CKR_DEVICE_ERROR);
                    }
                    any = true;
                    // SAFETY: `len <= cap` bytes were allocated.
                    Node::B(unsafe { core::slice::from_raw_parts(p, len) }.to_vec())
                }
            }
            Kind::Inline(n) if f.resp => {
                any = true;
                // SAFETY: the array is inside the structure.
                Node::B(unsafe { core::slice::from_raw_parts(base.add(f.off), n as usize) }.to_vec())
            }
            Kind::HandleArray { count } if f.resp => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) };
                if p.is_null() {
                    Node::Absent
                } else {
                    // SAFETY: forwarded; the count pointer is checked to be ours.
                    let n = unsafe { count_of(d, base, count, Some(caps)) }.map_err(|_| CKR_DEVICE_ERROR)?;
                    let bytes = n.checked_mul(size_of::<CK_ULONG>()).ok_or(CKR_DEVICE_ERROR)?;
                    own(Some(caps), p as usize, bytes)?;
                    any = true;
                    // SAFETY: `n` handles fit the allocation made by materialize (checked just above).
                    let hs = unsafe { core::slice::from_raw_parts(p as *const u8, bytes) };
                    Node::L(
                        hs.chunks_exact(size_of::<CK_ULONG>())
                            .map(|c| Node::U(CK_ULONG::from_ne_bytes(c.try_into().unwrap()) as u64))
                            .collect(),
                    )
                }
            }
            Kind::Struct(sub) => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) };
                if p.is_null() || !sub.has_outputs() {
                    Node::Absent
                } else {
                    own(Some(caps), p as usize, sub.size)?;
                    // SAFETY: allocated by materialize, and still ours (checked just above).
                    let (n, a) = unsafe { extract_at(sub, p, caps, Some(here), depth + 1)? };
                    any |= a;
                    n
                }
            }
            Kind::Embedded(sub) if sub.has_outputs() => {
                // SAFETY: embedded in the structure.
                let (n, a) = unsafe { extract_at(sub, base.add(f.off), caps, Some(here), depth + 1)? };
                any |= a;
                n
            }
            Kind::Array { desc, count } if desc.has_outputs() => {
                // SAFETY: forwarded.
                let (p, cnt) =
                    unsafe { (rd_ptr(base, f), count_of(d, base, count, Some(caps)).map_err(|_| CKR_DEVICE_ERROR)?) };
                if p.is_null() {
                    Node::Absent
                } else {
                    own(Some(caps), p as usize, cnt.checked_mul(desc.size).ok_or(CKR_DEVICE_ERROR)?)?;
                    let mut v = Vec::with_capacity(cnt);
                    for k in 0..cnt {
                        // SAFETY: elements allocated by materialize, the array checked to be ours and to hold `cnt`.
                        let (n, a) = unsafe { extract_at(desc, p.add(k * desc.size), caps, Some(here), depth + 1)? };
                        any |= a;
                        v.push(n);
                    }
                    Node::L(v)
                }
            }
            _ => Node::Absent,
        };
        out.push(n);
    }
    Ok((Node::L(out), any))
}

// ---------------------------------------------------------------------
// apply: results -> caller's structure
// ---------------------------------------------------------------------

/// Write a result tree into the caller's structure. The tree is untrusted:
/// shapes, lengths and counts are checked against the caller's own
/// structure, and with `dry` set nothing is written (so a bad reply can be
/// found before the caller's memory is touched).
///
/// # Safety
/// `base` must be a writable structure laid out as `d` says.
pub unsafe fn apply(d: &Desc, out: &Node, base: *mut u8, dry: bool) -> Result<(), Rv> {
    // SAFETY: forwarded.
    unsafe { apply_at(d, out, base, None, dry, 0) }
}

unsafe fn apply_at(
    d: &Desc,
    out: &Node,
    base: *mut u8,
    parent: Option<Parent<'_>>,
    dry: bool,
    depth: usize,
) -> Result<(), Rv> {
    if depth >= MAX_NEST {
        return Err(CKR_DEVICE_ERROR);
    }
    let Node::L(items) = out else { return Err(CKR_DEVICE_ERROR) };
    if items.len() != d.fields.len() {
        return Err(CKR_DEVICE_ERROR);
    }
    let here = Parent { d, base };

    // The room the caller gave each buffer, before any length is overwritten.
    let mut room = vec![0usize; d.fields.len()];
    for (i, f) in d.fields.iter().enumerate() {
        if f.resp && matches!(f.kind, Kind::Bytes { .. }) {
            // SAFETY: forwarded.
            room[i] = unsafe { len_of(d, base, parent, f, None) }.map_err(|_| CKR_DEVICE_ERROR)?;
        }
        if let Kind::HandleArray { count } = f.kind {
            // SAFETY: forwarded.
            room[i] = unsafe { count_of(d, base, count, None) }.map_err(|_| CKR_DEVICE_ERROR)?;
        }
    }

    // scalars first: buffer lengths may be among them
    for (f, it) in d.fields.iter().zip(items) {
        if !f.resp {
            continue;
        }
        match f.kind {
            Kind::Ulong | Kind::Handle | Kind::Bool | Kind::Byte => {
                let Node::U(v) = it else { return Err(CKR_DEVICE_ERROR) };
                if !dry {
                    // SAFETY: `off` is inside the caller's structure.
                    unsafe {
                        match f.kind {
                            Kind::Ulong | Kind::Handle => {
                                (base.add(f.off) as *mut CK_ULONG).write_unaligned(*v as CK_ULONG)
                            }
                            Kind::Bool => *base.add(f.off) = (*v != 0) as u8,
                            _ => *base.add(f.off) = *v as u8,
                        }
                    }
                }
            }
            Kind::UlongPtr | Kind::HandlePtr => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) } as *mut CK_ULONG;
                match it {
                    Node::Absent if p.is_null() => {}
                    Node::U(v) if !p.is_null() => {
                        if !dry {
                            // SAFETY: the caller's pointer member refers to a CK_ULONG.
                            unsafe { p.write_unaligned(*v as CK_ULONG) };
                        }
                    }
                    _ => return Err(CKR_DEVICE_ERROR),
                }
            }
            _ => {}
        }
    }

    // then buffers and nested structures
    for (i, (f, it)) in d.fields.iter().zip(items).enumerate() {
        match f.kind {
            Kind::Bytes { .. } if f.resp => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) };
                match it {
                    Node::Absent if p.is_null() => {}
                    Node::B(b) if !p.is_null() && b.len() <= room[i] => {
                        if !dry && !b.is_empty() {
                            // SAFETY: the caller's buffer holds `room[i] >= b.len()` bytes.
                            unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), p, b.len()) };
                        }
                    }
                    _ => return Err(CKR_DEVICE_ERROR),
                }
            }
            Kind::Inline(n) if f.resp => match it {
                Node::B(b) if b.len() == n as usize => {
                    if !dry {
                        // SAFETY: the array is inside the caller's structure.
                        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), base.add(f.off), b.len()) };
                    }
                }
                _ => return Err(CKR_DEVICE_ERROR),
            },
            Kind::HandleArray { .. } => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) };
                match it {
                    Node::Absent if p.is_null() => {}
                    Node::L(v) if !p.is_null() && v.len() <= room[i] => {
                        if !dry {
                            for (k, h) in v.iter().enumerate() {
                                let Node::U(h) = h else { return Err(CKR_DEVICE_ERROR) };
                                // SAFETY: the caller's array holds `room[i] >= v.len()` handles.
                                unsafe { (p as *mut CK_ULONG).add(k).write_unaligned(*h as CK_ULONG) };
                            }
                        }
                    }
                    _ => return Err(CKR_DEVICE_ERROR),
                }
            }
            Kind::Struct(sub) if sub.has_outputs() => {
                // SAFETY: forwarded.
                let p = unsafe { rd_ptr(base, f) };
                match it {
                    Node::Absent if p.is_null() => {}
                    // SAFETY: the caller's pointer member refers to such a structure.
                    Node::L(_) if !p.is_null() => unsafe { apply_at(sub, it, p, Some(here), dry, depth + 1)? },
                    _ => return Err(CKR_DEVICE_ERROR),
                }
            }
            // SAFETY: embedded in the caller's structure.
            Kind::Embedded(sub) if sub.has_outputs() => unsafe {
                apply_at(sub, it, base.add(f.off), Some(here), dry, depth + 1)?
            },
            Kind::Array { desc, count } if desc.has_outputs() => {
                // SAFETY: forwarded.
                let (p, cnt) =
                    unsafe { (rd_ptr(base, f), count_of(d, base, count, None).map_err(|_| CKR_DEVICE_ERROR)?) };
                match it {
                    Node::Absent if p.is_null() => {}
                    Node::L(v) if !p.is_null() && v.len() == cnt => {
                        for (k, e) in v.iter().enumerate() {
                            // SAFETY: `cnt` elements in the caller's array.
                            unsafe { apply_at(desc, e, p.add(k * desc.size), Some(here), dry, depth + 1)? };
                        }
                    }
                    _ => return Err(CKR_DEVICE_ERROR),
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// handles inside trees
// ---------------------------------------------------------------------

/// Visit every object handle in a tree shaped by `d`.
pub fn walk_handles(d: &Desc, n: &mut Node, f: &mut dyn FnMut(&mut u64), depth: usize) {
    if depth >= MAX_NEST {
        return;
    }
    let Node::L(items) = n else { return };
    for (fd, it) in d.fields.iter().zip(items.iter_mut()) {
        match fd.kind {
            Kind::Handle | Kind::HandlePtr => {
                if let Node::U(v) = it {
                    f(v);
                }
            }
            Kind::Struct(sub) | Kind::Embedded(sub) => walk_handles(sub, it, f, depth + 1),
            Kind::Array { desc, .. } => {
                if let Node::L(v) = it {
                    for e in v {
                        walk_handles(desc, e, f, depth + 1);
                    }
                }
            }
            Kind::MechPtr | Kind::Mech => {
                if let Node::L(v) = it {
                    if v.len() == 2 {
                        if let Node::U(t) = v[0] {
                            let (a, b) = v.split_at_mut(1);
                            let _ = a;
                            mech::walk_param(t, &mut b[0], f, depth + 1);
                        }
                    }
                }
            }
            Kind::HandleArray { .. } => {
                // the handles the module wrote; what goes in is only a marker
                if let Node::L(v) = it {
                    for h in v.iter_mut() {
                        if let Node::U(h) = h {
                            f(h);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
