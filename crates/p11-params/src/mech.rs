//! Mechanisms and their parameters.
//!
//! The daemon is the trust boundary, so it never hands the module a
//! parameter that arrived as memory: pointer-free parameters are copied to
//! private memory after their length is checked, and structures with
//! pointers are rebuilt member by member from a tree ([`crate::desc`]).

use crate::arena::Arena;
use crate::desc::{self, Caps, Desc, Flat, Spec};
use crate::descs;
use crate::mechtab;
use core::mem::size_of;
use p11_types::*;
use p11_wire::structs::{Mech, MsgParam, MSG_ENCRYPT};
use p11_wire::Node;

const BAD: Rv = CKR_MECHANISM_PARAM_INVALID;

/// Whether the proxy can carry this mechanism: it knows the layout, or (with the `vendor`
/// feature) the configuration declares it.
pub fn is_supported(mechanism: u64) -> bool {
    lookup(mechanism).is_some()
}

/// Whether the mechanism is one the proxy carries by itself, whatever is declared.
#[cfg(feature = "vendor")]
pub(crate) fn is_builtin(mechanism: u64) -> bool {
    builtin_spec(mechanism).is_some()
}

/// How a mechanism the proxy carries by itself has its parameter carried.
#[cfg(feature = "vendor")]
pub(crate) fn builtin_spec(mechanism: u64) -> Option<Spec> {
    mechtab::spec(mechanism as CK_ULONG)
}

#[cfg(feature = "vendor")]
fn lookup(m: u64) -> Option<Spec> {
    mechtab::spec(m as CK_ULONG).or_else(|| crate::vendor::lookup(m))
}

#[cfg(not(feature = "vendor"))]
fn lookup(m: u64) -> Option<Spec> {
    mechtab::spec(m as CK_ULONG)
}

fn spec_of(m: u64) -> Result<Spec, Rv> {
    lookup(m).ok_or(CKR_MECHANISM_INVALID)
}

/// The older PBKD2 structure has a pointer to the password length where the
/// newer has the length; both are the same size. No password is anywhere
/// near 4 KiB and no pointer is anywhere near that low.
unsafe fn pbkd2_variant(p: *const u8) -> u64 {
    // SAFETY: `p` points to a structure of either kind, which are the same size.
    let last = unsafe {
        (p.add(core::mem::offset_of!(CK_PKCS5_PBKD2_PARAMS2, ulPasswordLen)) as *const CK_ULONG).read_unaligned()
    };
    if last > 4096 {
        1
    } else {
        0
    }
}

fn pbkd2_desc(variant: u64) -> Result<&'static Desc, Rv> {
    match variant {
        0 => Ok(&descs::PBKD2_2),
        1 => Ok(&descs::PBKD2),
        _ => Err(BAD),
    }
}

/// Read the caller's `CK_MECHANISM`.
///
/// # Safety
/// `m` must point to a readable `CK_MECHANISM` whose parameter is what the
/// mechanism type says it is.
pub unsafe fn capture_mech(m: *const CK_MECHANISM) -> Result<Mech, Rv> {
    if m.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: forwarded.
    unsafe { capture_mech_at(m, 0) }
}

pub(crate) unsafe fn capture_mech_at(m: *const CK_MECHANISM, depth: usize) -> Result<Mech, Rv> {
    if depth >= desc::MAX_NEST {
        return Err(BAD);
    }
    // SAFETY: readable per the contract.
    let m = unsafe { &*m };
    let spec = spec_of(m.mechanism as u64)?;
    let p = m.pParameter as *const u8;
    let len = m.ulParameterLen as usize;
    let none = p.is_null() && len == 0;
    if p.is_null() && len != 0 {
        return Err(BAD);
    }
    let param = match spec {
        Spec::NoParam => None,
        _ if none => None,
        Spec::Flat(fl) => {
            if !fl.ok(len) {
                return Err(BAD);
            }
            // SAFETY: `len` readable bytes per the contract.
            Some(Node::B(unsafe { core::slice::from_raw_parts(p, len) }.to_vec()))
        }
        Spec::FlatHandle => {
            if len != size_of::<CK_ULONG>() {
                return Err(BAD);
            }
            // SAFETY: eight readable bytes.
            Some(Node::U(unsafe { (p as *const CK_ULONG).read_unaligned() } as u64))
        }
        Spec::FlatHandles { len: want, .. } => {
            if len != want {
                return Err(BAD);
            }
            // SAFETY: `len` readable bytes per the contract.
            Some(Node::B(unsafe { core::slice::from_raw_parts(p, len) }.to_vec()))
        }
        Spec::Xts => {
            if len == 16 {
                // SAFETY: 16 readable bytes.
                Some(Node::B(unsafe { core::slice::from_raw_parts(p, 16) }.to_vec()))
            } else if len == descs::XTS.size {
                // SAFETY: the structure the length says it is.
                Some(unsafe { desc::capture_at(&descs::XTS, p, desc::MECH, None, depth + 1)? })
            } else {
                return Err(BAD);
            }
        }
        Spec::Struct(d) | Spec::OptStruct(d) => {
            if len != d.size {
                return Err(BAD);
            }
            // SAFETY: the structure the length says it is.
            Some(unsafe { desc::capture_at(d, p, desc::MECH, None, depth + 1)? })
        }
        Spec::Pbkd2 => {
            if len != size_of::<CK_PKCS5_PBKD2_PARAMS2>() {
                return Err(BAD);
            }
            // SAFETY: as above.
            let v = unsafe { pbkd2_variant(p) };
            let d = pbkd2_desc(v)?;
            // SAFETY: as above.
            let body = unsafe { desc::capture_at(d, p, desc::MECH, None, depth + 1)? };
            Some(Node::L(vec![Node::U(v), body]))
        }
    };
    Ok(Mech { mechanism: m.mechanism as u64, param })
}

/// Copy members the module filled in back into the caller's parameter (only
/// when the call succeeded, `rv == CKR_OK`).
///
/// # Safety
/// As for [`capture_mech`], and the parameter must be writable.
pub unsafe fn apply_mech_out(out: &Option<Node>, m: *mut CK_MECHANISM, rv: u64) -> Result<(), Rv> {
    let Some(node) = out else { return Ok(()) };
    if rv != CKR_OK as u64 {
        return Ok(());
    }
    // SAFETY: valid per the contract (the stub checked non-null when it captured it).
    let m = unsafe { &*m };
    let p = m.pParameter as *mut u8;
    if p.is_null() {
        return Err(CKR_DEVICE_ERROR);
    }
    let (d, body) = match spec_of(m.mechanism as u64).map_err(|_| CKR_DEVICE_ERROR)? {
        Spec::Struct(d) | Spec::OptStruct(d) => (d, node),
        Spec::Pbkd2 => {
            // SAFETY: the caller's structure, of either kind.
            let v = unsafe { pbkd2_variant(p) };
            (pbkd2_desc(v).map_err(|_| CKR_DEVICE_ERROR)?, node)
        }
        _ => return Err(CKR_DEVICE_ERROR),
    };
    if m.ulParameterLen as usize != d.size {
        return Err(CKR_DEVICE_ERROR);
    }
    // check the whole reply first, so a bad one leaves the caller's structure alone
    // SAFETY: the caller's structure, laid out as `d`.
    unsafe {
        desc::apply(d, body, p, true)?;
        desc::apply(d, body, p, false)
    }
}

/// The parameter structure of a message-based call for this mechanism.
fn msg_desc(mechanism: u64) -> Option<&'static Desc> {
    match mechanism as CK_ULONG {
        CKM_AES_GCM => Some(&descs::GCM_MSG),
        CKM_AES_CCM => Some(&descs::CCM_MSG),
        CKM_CHACHA20_POLY1305 | CKM_SALSA20_POLY1305 => Some(&descs::CHACHA_MSG),
        _ => None,
    }
}

/// The three message structures differ in size, which identifies them.
fn msg_desc_by_size(len: usize) -> Option<&'static Desc> {
    [&descs::GCM_MSG, &descs::CCM_MSG, &descs::CHACHA_MSG].into_iter().find(|d| d.size == len)
}

/// Read the parameter of a message-based call. `mechanism` is the one the
/// session's `C_Message*Init` selected.
///
/// # Safety
/// `p` must point to `len` readable bytes holding the structure that
/// `mechanism` defines, or be null with `len == 0`.
pub unsafe fn capture_msg_param(
    mechanism: u64,
    phase: u8,
    p: *const core::ffi::c_void,
    len: CK_ULONG,
) -> Result<MsgParam, Rv> {
    if p.is_null() && len == 0 {
        return Ok(MsgParam { mechanism, phase, param: None });
    }
    let d = msg_desc(mechanism).ok_or(BAD)?;
    if p.is_null() || len as usize != d.size {
        return Err(BAD);
    }
    // SAFETY: the structure the length says it is.
    let node = unsafe { desc::capture(d, p as *const u8, phase)? };
    Ok(MsgParam { mechanism, phase, param: Some(node) })
}

/// # Safety
/// As for [`capture_msg_param`], and the parameter must be writable.
pub unsafe fn apply_msg_out(out: &Option<Node>, p: *mut core::ffi::c_void, len: CK_ULONG, rv: u64) -> Result<(), Rv> {
    let Some(node) = out else { return Ok(()) };
    if rv != CKR_OK as u64 {
        return Ok(());
    }
    let d = msg_desc_by_size(len as usize).ok_or(CKR_DEVICE_ERROR)?;
    if p.is_null() {
        return Err(CKR_DEVICE_ERROR);
    }
    // SAFETY: the caller's structure, laid out as `d`.
    unsafe {
        desc::apply(d, node, p as *mut u8, true)?;
        desc::apply(d, node, p as *mut u8, false)
    }
}

/// Where the module's results are read back from.
type Root = (&'static Desc, *mut u8);

/// Fill `out` from the wire form of a mechanism. Nested mechanisms (KIP,
/// CMS) come through here too, with `depth` counting.
pub(crate) fn fill_mech(
    mechanism: u64,
    param: &Option<Node>,
    arena: &mut Arena,
    caps: &mut Caps,
    out: &mut CK_MECHANISM,
    depth: usize,
) -> Result<Option<Root>, Rv> {
    if depth >= desc::MAX_NEST {
        return Err(BAD);
    }
    out.mechanism = mechanism as CK_MECHANISM_TYPE;
    out.pParameter = core::ptr::null_mut();
    out.ulParameterLen = 0;
    let spec = spec_of(mechanism)?;
    let Some(node) = param else { return Ok(None) };
    let mut set = |arena: &mut Arena, bytes: &[u8]| -> Result<(), Rv> {
        out.pParameter = arena.copy(bytes)?.cast();
        out.ulParameterLen = bytes.len() as CK_ULONG;
        Ok(())
    };
    match (spec, node) {
        (Spec::NoParam, _) => Ok(None),
        (Spec::Flat(fl), Node::B(b)) => {
            if !fl.ok(b.len()) {
                return Err(BAD);
            }
            set(arena, b)?;
            Ok(None)
        }
        (Spec::FlatHandle, Node::U(h)) => {
            set(arena, &(*h as CK_ULONG).to_ne_bytes())?;
            Ok(None)
        }
        (Spec::FlatHandles { len, .. }, Node::B(b)) if b.len() == len => {
            set(arena, b)?;
            Ok(None)
        }
        (Spec::Xts, Node::B(b)) if b.len() == 16 => {
            set(arena, b)?;
            Ok(None)
        }
        (Spec::Xts, n @ Node::L(_)) => build_struct(&descs::XTS, n, arena, caps, out).map(|_| None),
        (Spec::Struct(d) | Spec::OptStruct(d), n @ Node::L(_)) => build_struct(d, n, arena, caps, out).map(Some),
        (Spec::Pbkd2, Node::L(v)) if v.len() == 2 => {
            let Node::U(var) = v[0] else { return Err(BAD) };
            build_struct(pbkd2_desc(var)?, &v[1], arena, caps, out).map(Some)
        }
        _ => Err(BAD),
    }
}

fn build_struct(
    d: &'static Desc,
    n: &Node,
    arena: &mut Arena,
    caps: &mut Caps,
    out: &mut CK_MECHANISM,
) -> Result<Root, Rv> {
    let p = arena.alloc(d.size)?;
    // SAFETY: fresh zeroed allocation of `d.size` bytes.
    unsafe { desc::materialize(d, n, desc::MECH, arena, caps, p)? };
    out.pParameter = p.cast();
    out.ulParameterLen = d.size as CK_ULONG;
    Ok((d, p))
}

/// A `CK_MECHANISM` rebuilt in the daemon's memory.
#[derive(Debug)]
pub struct MechBuf {
    _arena: Arena,
    caps: Caps,
    m: CK_MECHANISM,
    root: Option<Root>,
}

impl MechBuf {
    pub fn build(m: &Mech) -> Result<MechBuf, Rv> {
        let mut arena = Arena::new();
        let mut caps = Caps::new();
        let mut out = CK_MECHANISM { mechanism: 0, pParameter: core::ptr::null_mut(), ulParameterLen: 0 };
        let root = fill_mech(m.mechanism, &m.param, &mut arena, &mut caps, &mut out, 0)?;
        Ok(MechBuf { _arena: arena, caps, m: out, root })
    }
    pub fn as_mut_ptr(&mut self) -> CK_MECHANISM_PTR {
        &mut self.m
    }
    /// Members the module filled in, to send back to the caller.
    pub fn extract_out(&self) -> Option<Node> {
        let (d, p) = self.root?;
        // SAFETY: `p` is the structure `fill_mech` built for `d`, with these `caps`.
        unsafe { desc::extract(d, p, &self.caps) }.ok().flatten()
    }
}

/// A message-based call's parameter rebuilt in the daemon's memory.
#[derive(Debug)]
pub struct MsgBuf {
    _arena: Arena,
    caps: Caps,
    root: Option<Root>,
    phase: u8,
}

impl MsgBuf {
    pub fn build(p: &MsgParam) -> Result<MsgBuf, Rv> {
        let mut arena = Arena::new();
        let mut caps = Caps::new();
        let mut root = None;
        if let Some(n) = &p.param {
            let d = msg_desc(p.mechanism).ok_or(BAD)?;
            if d.phases & p.phase == 0 {
                return Err(BAD);
            }
            let mem = arena.alloc(d.size)?;
            // SAFETY: fresh zeroed allocation of `d.size` bytes.
            unsafe { desc::materialize(d, n, p.phase, &mut arena, &mut caps, mem)? };
            root = Some((d, mem));
        }
        Ok(MsgBuf { _arena: arena, caps, root, phase: p.phase })
    }
    pub fn as_mut_ptr(&mut self) -> CK_VOID_PTR {
        self.root.map_or(core::ptr::null_mut(), |(_, p)| p.cast())
    }
    #[doc(hidden)]
    pub fn root_ptr(&self) -> *const u8 {
        self.root.map_or(core::ptr::null(), |(_, p)| p)
    }
    pub fn len(&self) -> CK_ULONG {
        self.root.map_or(0, |(d, _)| d.size as CK_ULONG)
    }
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }
    /// The module's results (after an encrypt call only: on decrypt the
    /// parameter is all input).
    pub fn extract_out(&self) -> Option<Node> {
        if self.phase != MSG_ENCRYPT {
            return None;
        }
        let (d, p) = self.root?;
        // SAFETY: built by `build` for `d` with these `caps`.
        unsafe { desc::extract(d, p, &self.caps) }.ok().flatten()
    }
}

/// Visit every object handle inside a mechanism parameter tree, so the
/// daemon can translate it: applied to request trees (client handle to
/// module handle) and to response trees (module handle to client handle).
pub fn walk_handles(mechanism: u64, node: &mut Node, f: &mut dyn FnMut(&mut u64)) {
    walk_param(mechanism, node, f, 0)
}

pub(crate) fn walk_param(mechanism: u64, node: &mut Node, f: &mut dyn FnMut(&mut u64), depth: usize) {
    match lookup(mechanism) {
        Some(Spec::FlatHandle) => {
            if let Node::U(v) = node {
                f(v);
            }
        }
        Some(Spec::FlatHandles { offs, .. }) => {
            if let Node::B(b) = node {
                for &o in offs {
                    let Some(w) = b.get_mut(o..o + size_of::<CK_ULONG>()) else { continue };
                    let mut h = CK_ULONG::from_ne_bytes((&*w).try_into().unwrap()) as u64;
                    f(&mut h);
                    w.copy_from_slice(&(h as CK_ULONG).to_ne_bytes());
                }
            }
        }
        Some(Spec::Xts) => desc::walk_handles(&descs::XTS, node, f, depth),
        Some(Spec::Struct(d) | Spec::OptStruct(d)) => desc::walk_handles(d, node, f, depth),
        Some(Spec::Pbkd2) | Some(Spec::Flat(Flat::Exact(_))) | Some(Spec::Flat(_)) | Some(Spec::NoParam) | None => {}
    }
}
