//! Vendor-defined functions: the registry of what is declared, and the pointer work of carrying a
//! call. The client turns the caller's C arguments into wire values and writes the results back into
//! the caller's memory; the daemon builds buffers of its own for the module and reads the results out
//! of them. Nothing a peer sent is ever used as a pointer, and what a module leaves in a buffer is
//! read only from the daemon's own allocation.

use crate::arena::Arena;
use crate::attrs::{capture_template, AttrBuf};
use p11_types::*;
use p11_wire::limits::MAX_BYTES;
use p11_wire::structs::OutBytes;
use p11_wire::vendorfn::*;
use serde::Deserialize;
use std::sync::RwLock;

/// The C arguments of a call as the machine passes them: each an integer or a pointer.
pub type CArgs = [usize; MAX_C_ARGS];

// ---- what is declared ----

/// One `[[vendor_function]]` entry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VendorFunction {
    /// The module's exported symbol.
    pub name: String,
    /// One kind per argument, in C order; a kind may stand for several C parameters.
    pub args: Vec<String>,
    /// The function changes the token: refused for a read-only client.
    #[serde(default)]
    pub rw: bool,
}

impl VendorFunction {
    pub fn desc(&self) -> Result<FnDesc, String> {
        let mut args = Vec::with_capacity(self.args.len());
        for a in &self.args {
            args.push(ArgKind::parse(a).ok_or_else(|| {
                format!(
                    "vendor_function {}: unknown argument kind {a:?} (one of {})",
                    self.name,
                    ArgKind::ALL.map(|k| k.name()).join(", ")
                )
            })?);
        }
        let d = FnDesc { name: self.name.clone(), rw: self.rw, args };
        d.validate()?;
        Ok(d)
    }
}

static DECLARED: RwLock<Vec<FnDesc>> = RwLock::new(Vec::new());

/// Replace the declared vendor functions. Nothing changes if any is invalid.
pub fn set(list: &[FnDesc]) -> Result<(), String> {
    for (i, d) in list.iter().enumerate() {
        d.validate()?;
        if list[..i].iter().any(|e| e.name == d.name) {
            return Err(format!("vendor_function {} is declared twice", d.name));
        }
    }
    *DECLARED.write().unwrap_or_else(|e| e.into_inner()) = list.to_vec();
    Ok(())
}

/// Declare the functions of a configuration.
pub fn set_from_config(list: &[VendorFunction]) -> Result<(), String> {
    let descs = list.iter().map(VendorFunction::desc).collect::<Result<Vec<_>, _>>()?;
    set(&descs)
}

pub fn get(name: &str) -> Option<FnDesc> {
    DECLARED.read().unwrap_or_else(|e| e.into_inner()).iter().find(|d| d.name == name).cloned()
}

pub fn declared() -> Vec<FnDesc> {
    DECLARED.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// What the daemon announces to a client.
pub fn to_wire(list: &[FnDesc]) -> VendorFns {
    VendorFns(list.to_vec())
}

/// Install what a daemon announced; nothing changes if any entry is invalid.
pub fn set_from_wire(f: &VendorFns) -> Result<(), String> {
    set(&f.0)
}

// ---- the client: C arguments to values, results back into the caller's memory ----

unsafe fn slice<'a>(p: usize, n: usize) -> Result<&'a [u8], Rv> {
    if n > MAX_BYTES {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if n == 0 {
        return Ok(&[]);
    }
    if p == 0 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: the caller promised `n` readable bytes at `p`, as the function's contract requires.
    Ok(unsafe { core::slice::from_raw_parts(p as *const u8, n) })
}

fn need(p: usize) -> Result<usize, Rv> {
    if p == 0 {
        Err(CKR_ARGUMENTS_BAD)
    } else {
        Ok(p)
    }
}

/// The room a caller gave an output buffer.
fn room(cap: usize) -> Option<u64> {
    Some(cap.min(MAX_BYTES) as u64)
}

/// The caller's arguments as values.
///
/// # Safety
/// Each pointer among `c` must be null or valid as the function's contract says for its kind.
pub unsafe fn capture(desc: &FnDesc, c: &CArgs) -> Result<Vec<InVal>, Rv> {
    let mut out = Vec::with_capacity(desc.args.len());
    let mut i = 0;
    for k in &desc.args {
        out.push(match k {
            ArgKind::U8 => InVal::Int(c[i] as u64 & 0xff),
            ArgKind::U16 => InVal::Int(c[i] as u64 & 0xffff),
            ArgKind::U32 => InVal::Int(c[i] as u64 & 0xffff_ffff),
            ArgKind::U64 | ArgKind::Slot | ArgKind::Session | ArgKind::Object => InVal::Int(c[i] as u64),
            // SAFETY: forwarded contract.
            ArgKind::Bytes | ArgKind::Secret => InVal::Bytes(unsafe { slice(c[i], c[i + 1])? }.to_vec()),
            ArgKind::CStr => {
                let p = need(c[i])? as *const u8;
                let mut v = Vec::new();
                loop {
                    // SAFETY: a NUL-terminated string is readable up to its NUL.
                    let b = unsafe { p.add(v.len()).read() };
                    if b == 0 {
                        break;
                    }
                    v.push(b);
                    if v.len() > MAX_CSTR {
                        return Err(CKR_ARGUMENTS_BAD);
                    }
                }
                InVal::Bytes(v)
            }
            // SAFETY: forwarded contract.
            ArgKind::Label => InVal::Bytes(unsafe { slice(need(c[i])?, LABEL_LEN)? }.to_vec()),
            ArgKind::Attrs => {
                // SAFETY: forwarded contract.
                InVal::Attrs(unsafe { capture_template(c[i] as *const CK_ATTRIBUTE, c[i + 1] as CK_ULONG)? })
            }
            ArgKind::OU32 | ArgKind::OU64 | ArgKind::OObject => {
                need(c[i])?;
                InVal::Nothing
            }
            ArgKind::OBytes => {
                let lenp = need(c[i + 1])? as *const u64;
                // SAFETY: a non-null length pointer refers to a readable length.
                let cap = unsafe { lenp.read_unaligned() } as usize;
                InVal::Cap(if c[i] == 0 { None } else { room(cap) })
            }
            ArgKind::OBuf => InVal::Cap(if c[i] == 0 { None } else { room(c[i + 1]) }),
        });
        i += k.c_args();
    }
    Ok(out)
}

/// Write a reply into the caller's memory. The reply is untrusted: shapes are checked against the
/// description and no value may exceed the room the caller gave, and nothing is written unless
/// everything checks out.
///
/// # Safety
/// As for [`capture`], and the output pointers must be writable.
pub unsafe fn apply(desc: &FnDesc, c: &CArgs, ins: &[InVal], reply: &VendorReply) -> Result<(), Rv> {
    let plan = |write: bool| -> Result<(), Rv> {
        let mut i = 0;
        let mut o = reply.0.iter();
        for (k, inv) in desc.args.iter().zip(ins) {
            if k.is_output() {
                let v = o.next().ok_or(CKR_DEVICE_ERROR)?;
                match (k, v) {
                    (ArgKind::OU32, OutVal::Int(x)) if write => {
                        // SAFETY: a writable 32-bit integer, per the contract.
                        unsafe { (c[i] as *mut u32).write_unaligned(*x as u32) }
                    }
                    (ArgKind::OU64 | ArgKind::OObject, OutVal::Int(x)) if write => {
                        // SAFETY: a writable CK_ULONG, per the contract.
                        unsafe { (c[i] as *mut u64).write_unaligned(*x) }
                    }
                    (ArgKind::OU32 | ArgKind::OU64 | ArgKind::OObject, OutVal::Int(_)) => {}
                    (ArgKind::OBytes | ArgKind::OBuf, OutVal::Bytes(b)) => {
                        let cap = match inv {
                            InVal::Cap(Some(n)) => Some(*n),
                            _ => None,
                        };
                        if let Some(d) = &b.data {
                            // the bytes come only when the caller gave a buffer, and fit it
                            if cap.is_none_or(|n| d.len() as u64 > n || d.len() as u64 != b.len) {
                                return Err(CKR_DEVICE_ERROR);
                            }
                        }
                        if write {
                            let (buf, lenp) = if *k == ArgKind::OBytes { (c[i], c[i + 1]) } else { (c[i], c[i + 2]) };
                            if let Some(d) = &b.data {
                                // SAFETY: the caller's buffer holds the room it declared; `d` fits it.
                                unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), buf as *mut u8, d.len()) };
                            }
                            if lenp != 0 {
                                // SAFETY: a writable length, per the contract.
                                unsafe { (lenp as *mut u64).write_unaligned(b.len) };
                            }
                        }
                    }
                    _ => return Err(CKR_DEVICE_ERROR),
                }
            }
            i += k.c_args();
        }
        Ok(())
    };
    plan(false)?;
    plan(true)
}

// ---- the daemon: values to buffers for the module, and the call ----

#[derive(Debug)]
enum Slot {
    U32(*mut u8),
    U64(*mut u8),
    Bytes { buf: *mut u8, cap: usize, len: *mut u8, supplied: bool },
}

/// A call rebuilt in the daemon's memory.
#[derive(Debug)]
pub struct VendorCall {
    _arena: Arena,
    _attrs: Vec<AttrBuf>,
    cargs: Vec<usize>,
    slots: Vec<Slot>,
    secrets: Vec<(*mut u8, usize)>,
}

impl VendorCall {
    /// Build the C arguments for `desc` from `ins`. Handles must already be the module's.
    pub fn build(desc: &FnDesc, ins: &[InVal]) -> Result<VendorCall, Rv> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if desc.c_arg_count() > 8 {
            // the platform packs stack arguments by size; this call would need them by slot
            return Err(CKR_FUNCTION_NOT_SUPPORTED);
        }
        if ins.len() != desc.args.len() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let mut arena = Arena::new();
        let mut attrs = Vec::new();
        let (mut cargs, mut slots, mut secrets) = (Vec::new(), Vec::new(), Vec::new());
        for (k, v) in desc.args.iter().zip(ins) {
            match (k, v) {
                (
                    ArgKind::U8
                    | ArgKind::U16
                    | ArgKind::U32
                    | ArgKind::U64
                    | ArgKind::Slot
                    | ArgKind::Session
                    | ArgKind::Object,
                    InVal::Int(x),
                ) => cargs.push(*x as usize),
                (ArgKind::Bytes | ArgKind::Secret, InVal::Bytes(b)) => {
                    let p = arena.copy(b)?;
                    if *k == ArgKind::Secret {
                        secrets.push((p, b.len()));
                    }
                    cargs.extend([p as usize, b.len()]);
                }
                (ArgKind::CStr, InVal::Bytes(b)) => {
                    let mut z = b.clone();
                    z.push(0);
                    cargs.push(arena.copy(&z)? as usize);
                }
                (ArgKind::Label, InVal::Bytes(b)) => cargs.push(arena.copy(b)? as usize),
                (ArgKind::Attrs, InVal::Attrs(a)) => {
                    let mut buf = AttrBuf::build(a)?;
                    cargs.extend([buf.as_mut_ptr() as usize, buf.len() as usize]);
                    attrs.push(buf);
                }
                (ArgKind::OU32, InVal::Nothing) => {
                    let p = arena.alloc(8)?;
                    slots.push(Slot::U32(p));
                    cargs.push(p as usize);
                }
                (ArgKind::OU64 | ArgKind::OObject, InVal::Nothing) => {
                    let p = arena.alloc(8)?;
                    slots.push(Slot::U64(p));
                    cargs.push(p as usize);
                }
                (ArgKind::OBytes | ArgKind::OBuf, InVal::Cap(cap)) => {
                    let n = cap.unwrap_or(0) as usize;
                    let supplied = cap.is_some();
                    let buf = arena.alloc(n)?;
                    let len = arena.alloc(8)?;
                    if *k == ArgKind::OBytes {
                        // SAFETY: eight writable bytes just allocated.
                        unsafe { (len as *mut u64).write(n as u64) };
                        cargs.extend([if supplied { buf as usize } else { 0 }, len as usize]);
                    } else {
                        cargs.extend([if supplied { buf as usize } else { 0 }, n, len as usize]);
                    }
                    slots.push(Slot::Bytes { buf, cap: n, len, supplied });
                }
                _ => return Err(CKR_ARGUMENTS_BAD),
            }
        }
        Ok(VendorCall { _arena: arena, _attrs: attrs, cargs, slots, secrets })
    }

    /// Call the function at address `f` with the arguments built.
    ///
    /// # Safety
    /// `f` must be a function whose C parameters are the ones the description declares.
    pub unsafe fn invoke(&self, f: usize) -> u64 {
        let a = &self.cargs[..];
        // SAFETY: `f` is such a function; every argument is an integer or a pointer to memory owned by `self`.
        let rv = unsafe {
            match a.len() {
                0 => core::mem::transmute::<usize, unsafe extern "C" fn() -> usize>(f)(),
                1 => core::mem::transmute::<usize, unsafe extern "C" fn(usize) -> usize>(f)(a[0]),
                2 => core::mem::transmute::<usize, unsafe extern "C" fn(usize, usize) -> usize>(f)(a[0], a[1]),
                3 => core::mem::transmute::<usize, unsafe extern "C" fn(usize, usize, usize) -> usize>(f)(
                    a[0], a[1], a[2],
                ),
                4 => core::mem::transmute::<usize, unsafe extern "C" fn(usize, usize, usize, usize) -> usize>(f)(
                    a[0], a[1], a[2], a[3],
                ),
                5 => {
                    core::mem::transmute::<usize, unsafe extern "C" fn(usize, usize, usize, usize, usize) -> usize>(f)(
                        a[0], a[1], a[2], a[3], a[4],
                    )
                }
                6 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(usize, usize, usize, usize, usize, usize) -> usize,
                >(f)(a[0], a[1], a[2], a[3], a[4], a[5]),
                7 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(usize, usize, usize, usize, usize, usize, usize) -> usize,
                >(f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]),
                8 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(usize, usize, usize, usize, usize, usize, usize, usize) -> usize,
                >(f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]),
                9 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(usize, usize, usize, usize, usize, usize, usize, usize, usize) -> usize,
                >(f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]),
                10 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(usize, usize, usize, usize, usize, usize, usize, usize, usize, usize) -> usize,
                >(f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]),
                11 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10]),
                12 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11]),
                13 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12]
                ),
                14 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13]
                ),
                15 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14]
                ),
                16 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14],
                    a[15],
                ),
                17 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14],
                    a[15], a[16],
                ),
                18 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14],
                    a[15], a[16], a[17],
                ),
                19 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14],
                    a[15], a[16], a[17], a[18],
                ),
                20 => core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                        usize,
                    ) -> usize,
                >(f)(
                    a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14],
                    a[15], a[16], a[17], a[18], a[19],
                ),
                _ => return CKR_FUNCTION_NOT_SUPPORTED as u64,
            }
        };
        rv as u64
    }

    /// What the module wrote, read from the daemon's own buffers, and the secrets wiped.
    pub fn finish(&mut self, rv: u64) -> VendorReply {
        let ok = rv == CKR_OK as u64;
        let mut out = Vec::with_capacity(self.slots.len());
        for s in &self.slots {
            out.push(match s {
                // SAFETY: eight bytes allocated by `build`, still ours.
                Slot::U32(p) => OutVal::Int(unsafe { (*p as *const u64).read() } & 0xffff_ffff),
                // SAFETY: as above.
                Slot::U64(p) => OutVal::Int(unsafe { (*p as *const u64).read() }),
                Slot::Bytes { buf, cap, len, supplied } => {
                    // SAFETY: as above.
                    let l = unsafe { (*len as *const u64).read() };
                    let data = (*supplied && ok && l as usize <= *cap).then(|| {
                        // SAFETY: `cap >= l` bytes were allocated by `build`.
                        unsafe { core::slice::from_raw_parts(*buf as *const u8, l as usize) }.to_vec()
                    });
                    OutVal::Bytes(OutBytes { len: l, data })
                }
            });
        }
        self.wipe();
        VendorReply(out)
    }

    fn wipe(&mut self) {
        for (p, n) in self.secrets.drain(..) {
            for i in 0..n {
                // SAFETY: `n` bytes copied by `build`, still ours.
                unsafe { p.add(i).write_volatile(0) };
            }
        }
    }
}

impl Drop for VendorCall {
    fn drop(&mut self) {
        self.wipe();
    }
}
