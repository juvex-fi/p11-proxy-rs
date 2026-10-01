//! Runtime support for the generated C entry points: argument capture
//! (caller memory to wire values), result application (wire values to caller
//! memory), the global connection, and panic containment.

use crate::state;
use p11_params::{attrs, conv};
use p11_types::*;
use p11_wire::attr::Reply;
use p11_wire::calls::{Request, Response, CALL_WAIT_FOR_SLOT_EVENT};
use p11_wire::limits::{MAX_ARRAY, MAX_BYTES};
use p11_wire::structs::*;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

/// Run an entry point body: panics become `CKR_GENERAL_ERROR` instead of
/// unwinding into the application, errors become their `CK_RV`.
pub fn guard(f: impl FnOnce() -> Result<CK_RV, CK_RV>) -> CK_RV {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(rv)) | Ok(Err(rv)) => rv,
        Err(_) => CKR_GENERAL_ERROR,
    }
}

/// Send a request over the process's connection.
pub fn call(req: Request, call_id: u16) -> Result<(u64, Option<Response>), CK_RV> {
    let core = state::current()?;
    core.call(&req, call_id == CALL_WAIT_FOR_SLOT_EVENT)
}

// ---- mechanisms chosen by message-based sessions ----

static MSG_MECH: Mutex<Option<HashMap<u64, u64>>> = Mutex::new(None);

pub fn record_msg_mech(session: u64, mech: u64) {
    MSG_MECH.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).insert(session, mech);
}

pub fn forget_session(session: u64) {
    if let Some(m) = MSG_MECH.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        m.remove(&session);
    }
}

pub fn forget_all_sessions() {
    *MSG_MECH.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn msg_mech(session: u64) -> Option<u64> {
    MSG_MECH.lock().unwrap_or_else(|e| e.into_inner()).as_ref()?.get(&session).copied()
}

// ---- capture ----

/// # Safety
/// `p` must be null or point to `len` readable bytes.
pub unsafe fn bytes(p: *const u8, len: CK_ULONG) -> Result<Vec<u8>, CK_RV> {
    if len as usize > MAX_BYTES {
        return Err(CKR_DATA_LEN_RANGE);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: `len` readable bytes per the contract.
    Ok(unsafe { core::slice::from_raw_parts(p, len as usize) }.to_vec())
}

/// # Safety
/// As for [`bytes`].
pub unsafe fn opt_bytes(p: *const u8, len: CK_ULONG) -> Result<Option<Vec<u8>>, CK_RV> {
    if p.is_null() {
        return if len == 0 { Ok(None) } else { Err(CKR_ARGUMENTS_BAD) };
    }
    // SAFETY: forwarded.
    unsafe { bytes(p, len) }.map(Some)
}

/// # Safety
/// As for [`bytes`]; the bytes are a PIN or user name.
pub unsafe fn opt_secret(p: *const u8, len: CK_ULONG) -> Result<Option<p11_wire::Secret>, CK_RV> {
    // SAFETY: forwarded.
    let v = unsafe { opt_bytes(p, len) }?;
    Ok(v.map(p11_wire::Secret::from))
}

/// # Safety
/// `p` must point to 32 readable bytes.
pub unsafe fn label(p: *const u8) -> Result<[u8; 32], CK_RV> {
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let mut a = [0u8; 32];
    // SAFETY: 32 readable bytes per the contract.
    unsafe { core::ptr::copy_nonoverlapping(p, a.as_mut_ptr(), 32) };
    Ok(a)
}

/// # Safety
/// `p` must point to a NUL-terminated string.
pub unsafe fn cstr(p: *const u8) -> Result<Vec<u8>, CK_RV> {
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let mut v = Vec::new();
    loop {
        // SAFETY: reading up to the terminator, which the contract guarantees exists.
        let b = unsafe { *p.add(v.len()) };
        if b == 0 {
            return Ok(v);
        }
        v.push(b);
        if v.len() > p11_wire::limits::MAX_TEXT {
            return Err(CKR_ARGUMENTS_BAD);
        }
    }
}

/// # Safety
/// `len` is null or points to a valid `CK_ULONG`.
pub unsafe fn out_spec(p: *mut u8, len: *mut CK_ULONG) -> Result<OutSpec, CK_RV> {
    if len.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if p.is_null() {
        return Ok(OutSpec::Length);
    }
    // SAFETY: `len` is a valid CK_ULONG pointer per the contract (checked non-null).
    let n = unsafe { *len } as u64;
    Ok(OutSpec::Capacity(n.min(MAX_BYTES as u64)))
}

pub fn fixed_len(p: *mut u8, len: CK_ULONG) -> Result<u64, CK_RV> {
    if len as usize > MAX_BYTES {
        return Err(CKR_DATA_LEN_RANGE);
    }
    if p.is_null() && len > 0 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok(len as u64)
}

pub fn handles_max(p: *mut CK_ULONG, max: CK_ULONG, count: *mut CK_ULONG) -> Result<u64, CK_RV> {
    if count.is_null() || (p.is_null() && max > 0) {
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok((max as u64).min(MAX_ARRAY as u64))
}

/// # Safety
/// `p` must be null or point to `len` readable bytes holding the structure
/// the session's message mechanism defines.
pub unsafe fn msg_param(session: u64, phase: u8, p: *mut core::ffi::c_void, len: CK_ULONG) -> Result<MsgParam, CK_RV> {
    let mech = msg_mech(session).ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
    // SAFETY: forwarded.
    unsafe { p11_params::mech::capture_msg_param(mech, phase, p, len) }
}

/// # Safety
/// `p` must point to a readable `CK_ASYNC_DATA`.
pub unsafe fn async_in(p: *const CK_ASYNC_DATA) -> AsyncIn {
    // SAFETY: non-null and readable per the caller (checked by the generated stub).
    let d = unsafe { &*p };
    AsyncIn {
        version: d.ulVersion as u64,
        value: if d.pValue.is_null() {
            OutSpec::Length
        } else {
            OutSpec::Capacity((d.ulValue as u64).min(MAX_BYTES as u64))
        },
    }
}

// ---- apply ----

/// Whether a response's outputs are to be applied: they are when the call
/// succeeded, or reports sizes.
fn sizes_only(rv: u64) -> bool {
    rv == CKR_BUFFER_TOO_SMALL as u64
}

/// # Safety
/// `p` writable for `*len` bytes, `len` a valid pointer.
pub unsafe fn apply_out_bytes(o: &OutBytes, p: *mut u8, len: *mut CK_ULONG, rv: u64) -> Result<(), CK_RV> {
    if rv != CKR_OK as u64 && !sizes_only(rv) {
        return Ok(());
    }
    // SAFETY: `len` is non-null (checked when the request was built) and valid.
    let cap = unsafe { *len };
    if rv == CKR_OK as u64 && !p.is_null() {
        let Some(d) = o.data.as_ref() else { return Err(CKR_DEVICE_ERROR) };
        if d.len() as u64 != o.len || d.len() as CK_ULONG > cap {
            return Err(CKR_DEVICE_ERROR);
        }
        // SAFETY: the caller's buffer holds `cap >= d.len()` bytes.
        unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), p, d.len()) };
    }
    // SAFETY: as above.
    unsafe { *len = o.len as CK_ULONG };
    Ok(())
}

/// # Safety
/// `p` writable for `len` bytes.
pub unsafe fn apply_fixed(d: &[u8], p: *mut u8, len: CK_ULONG, rv: u64) -> Result<(), CK_RV> {
    if rv != CKR_OK as u64 {
        return Ok(());
    }
    if d.len() as u64 != len as u64 {
        return Err(CKR_DEVICE_ERROR);
    }
    if len > 0 {
        // SAFETY: `len` writable bytes per the contract.
        unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), p, d.len()) };
    }
    Ok(())
}

/// # Safety
/// `p` writable for `*len` elements.
pub unsafe fn apply_out_u64s(o: &OutU64s, p: *mut CK_ULONG, len: *mut CK_ULONG, rv: u64) -> Result<(), CK_RV> {
    if rv != CKR_OK as u64 && !sizes_only(rv) {
        return Ok(());
    }
    // SAFETY: `len` valid and non-null.
    let cap = unsafe { *len };
    if rv == CKR_OK as u64 && !p.is_null() {
        let Some(d) = o.data.as_ref() else { return Err(CKR_DEVICE_ERROR) };
        if d.0.len() as u64 != o.len || d.0.len() as CK_ULONG > cap {
            return Err(CKR_DEVICE_ERROR);
        }
        for (i, v) in d.0.iter().enumerate() {
            // SAFETY: within the caller's `cap` elements.
            unsafe { p.add(i).write(*v as CK_ULONG) };
        }
    }
    // SAFETY: as above.
    unsafe { *len = o.len as CK_ULONG };
    Ok(())
}

/// # Safety
/// `p` writable for `max` elements, `count` valid.
pub unsafe fn apply_handles(
    h: &p11_wire::U64s,
    p: *mut CK_ULONG,
    max: CK_ULONG,
    count: *mut CK_ULONG,
    rv: u64,
) -> Result<(), CK_RV> {
    if rv != CKR_OK as u64 {
        return Ok(());
    }
    if h.0.len() as CK_ULONG > max {
        return Err(CKR_DEVICE_ERROR);
    }
    for (i, v) in h.0.iter().enumerate() {
        // SAFETY: within the caller's `max` elements.
        unsafe { p.add(i).write(*v as CK_ULONG) };
    }
    // SAFETY: `count` valid.
    unsafe { *count = h.0.len() as CK_ULONG };
    Ok(())
}

/// # Safety
/// `p` a valid pointer.
pub unsafe fn apply_u64(v: u64, p: *mut CK_ULONG, rv: u64) {
    if rv == CKR_OK as u64 {
        // SAFETY: valid per the contract.
        unsafe { *p = v as CK_ULONG };
    }
}

macro_rules! apply_info {
    ($name:ident, $wire:ty, $c:ty, $conv:ident) => {
        /// # Safety
        /// `p` a valid pointer.
        pub unsafe fn $name(v: &$wire, p: *mut $c, rv: u64) {
            if rv == CKR_OK as u64 {
                // SAFETY: valid per the contract.
                unsafe { *p = conv::$conv(v) };
            }
        }
    };
}
apply_info!(apply_info, Info, CK_INFO, info_from_wire);
apply_info!(apply_slot_info, SlotInfo, CK_SLOT_INFO, slot_info_from_wire);
apply_info!(apply_token_info, TokenInfo, CK_TOKEN_INFO, token_info_from_wire);
apply_info!(apply_session_info, SessionInfo, CK_SESSION_INFO, session_info_from_wire);
apply_info!(apply_mech_info, MechanismInfo, CK_MECHANISM_INFO, mech_info_from_wire);

/// # Safety
/// `p` points to the caller's `n` attributes.
pub unsafe fn apply_query(r: &p11_wire::Seq<Reply>, p: *mut CK_ATTRIBUTE, n: CK_ULONG, rv: u64) -> Result<(), CK_RV> {
    // The module reports per-attribute results for these as well as for success.
    if !matches!(rv as CK_ULONG, CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID | CKR_BUFFER_TOO_SMALL) {
        return Ok(());
    }
    // SAFETY: forwarded.
    unsafe { attrs::apply_replies(&r.0, p, n) }
}

/// # Safety
/// `p` points to the caller's `CK_ASYNC_DATA`.
pub unsafe fn apply_async(o: &AsyncOut, p: *mut CK_ASYNC_DATA, rv: u64) -> Result<(), CK_RV> {
    if rv != CKR_OK as u64 && !sizes_only(rv) {
        return Ok(());
    }
    // SAFETY: valid and writable per the contract.
    let d = unsafe { &mut *p };
    if sizes_only(rv) {
        // the buffer was too small: report the size it needs
        d.ulValue = o.value.len as CK_ULONG;
        return Ok(());
    }
    if !d.pValue.is_null() {
        let Some(data) = o.value.data.as_ref() else { return Err(CKR_DEVICE_ERROR) };
        if data.len() as CK_ULONG > d.ulValue {
            return Err(CKR_DEVICE_ERROR);
        }
        // SAFETY: the caller's buffer holds `ulValue >= data.len()` bytes.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), d.pValue, data.len()) };
    }
    d.ulValue = o.value.len as CK_ULONG;
    d.ulVersion = o.version as CK_ULONG;
    d.hObject = o.object as CK_OBJECT_HANDLE;
    d.hAdditionalObject = o.additional_object as CK_OBJECT_HANDLE;
    Ok(())
}
