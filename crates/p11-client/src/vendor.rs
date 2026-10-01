//! Vendor-defined functions, from the application's side.
//!
//! The daemon announces the functions it carries in the handshake (see `docs/PROTOCOL.md`). An
//! application reaches one two ways: by the exported name of a function the SDK of a known vendor
//! defines (the names are in the list below), or by asking [`P11P_GetVendorFunction`] for a callable pointer to any
//! function the daemon declared. Both take the caller's C arguments as they are passed, which for these
//! functions are integers and pointers, and both go through [`invoke`].
//!
//! A function with fewer than 20 parameters is called through an entry point that declares 20: the
//! ones the caller did not pass are read and ignored (the ABIs of the platforms supported pass integer
//! and pointer arguments in registers and eight-byte stack slots, so the extra reads are harmless).

use crate::rt::guard;
use crate::state;
use p11_params::vendorfn::{self, CArgs};
use p11_types::*;
use p11_wire::vendorfn::{InVal, VendorReply, VendorRequest, MAX_C_ARGS};
use std::ffi::{c_char, c_void, CStr};
use std::sync::Mutex;

/// Call the declared function `name` with the caller's C arguments.
pub fn invoke(name: &str, c: &CArgs) -> CK_RV {
    guard(|| {
        let desc = vendorfn::get(name).ok_or(CKR_FUNCTION_NOT_SUPPORTED)?;
        let core = state::current()?;
        // SAFETY: the caller's pointers are as the function's contract says for the declared kinds.
        let mut ins = unsafe { vendorfn::capture(&desc, c) }?;
        let body = VendorRequest { name: desc.name.clone(), args: ins.clone() }.encode();
        let sent = core.call_vendor(body, desc.has_secret());
        let result = (|| {
            let (rv, reply) = sent?;
            if let Some(b) = reply {
                let reply = VendorReply::decode(&b, &desc).map_err(|_| CKR_DEVICE_ERROR)?;
                // SAFETY: as above, and the output pointers are writable.
                unsafe { vendorfn::apply(&desc, c, &ins, &reply) }?;
            }
            Ok(rv as CK_RV)
        })();
        // a PIN among the arguments does not outlive the call
        for v in ins.iter_mut() {
            if let InVal::Bytes(b) = v {
                p11_wire::wipe_vec(b);
            }
        }
        result
    })
}

macro_rules! vendor_export {
    ($($name:ident),* $(,)?) => {$(
        /// A vendor-defined function of a known SDK, carried to the daemon when it declares it and
        /// answered with `CKR_FUNCTION_NOT_SUPPORTED` when it does not.
        ///
        /// # Safety
        /// The arguments are those of the vendor's C function of this name.
        #[no_mangle]
        #[allow(non_snake_case, clippy::too_many_arguments)]
        pub unsafe extern "C" fn $name(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize, a8: usize, a9: usize, a10: usize, a11: usize, a12: usize, a13: usize, a14: usize, a15: usize, a16: usize, a17: usize, a18: usize, a19: usize) -> CK_RV {
            invoke(stringify!($name), &[a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19])
        }
    )*};
}

// The extension functions of one vendor's SDK whose arguments the proxy can carry. A function of that
// SDK that returns a session handle of the module's own is left out on purpose.
vendor_export!(
    CT_InitToken,
    CT_InitPIN,
    CT_ResetToken,
    CT_CopyObject,
    CT_HsmIdFromSlotId,
    CT_SetHsmDead,
    CT_GetHSMId,
    FMSC_SendReceive,
    CT_InitOtpSeed,
    CT_DelOtpSeed,
    CT_GetSMC,
    CT_FetchCertificate,
);

// ---- any declared function, by name ----

type Thunk = unsafe extern "C" fn(
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
) -> CK_RV;

/// Names handed out by [`P11P_GetVendorFunction`]; the index is the entry point's.
static POOL: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn pool_thunk<const I: usize>(
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    a8: usize,
    a9: usize,
    a10: usize,
    a11: usize,
    a12: usize,
    a13: usize,
    a14: usize,
    a15: usize,
    a16: usize,
    a17: usize,
    a18: usize,
    a19: usize,
) -> CK_RV {
    let name = POOL.lock().unwrap_or_else(|e| e.into_inner()).get(I).cloned();
    match name {
        Some(n) => {
            invoke(&n, &[a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19])
        }
        None => CKR_FUNCTION_NOT_SUPPORTED,
    }
}

static THUNKS: [Thunk; 32] = [
    pool_thunk::<0>,
    pool_thunk::<1>,
    pool_thunk::<2>,
    pool_thunk::<3>,
    pool_thunk::<4>,
    pool_thunk::<5>,
    pool_thunk::<6>,
    pool_thunk::<7>,
    pool_thunk::<8>,
    pool_thunk::<9>,
    pool_thunk::<10>,
    pool_thunk::<11>,
    pool_thunk::<12>,
    pool_thunk::<13>,
    pool_thunk::<14>,
    pool_thunk::<15>,
    pool_thunk::<16>,
    pool_thunk::<17>,
    pool_thunk::<18>,
    pool_thunk::<19>,
    pool_thunk::<20>,
    pool_thunk::<21>,
    pool_thunk::<22>,
    pool_thunk::<23>,
    pool_thunk::<24>,
    pool_thunk::<25>,
    pool_thunk::<26>,
    pool_thunk::<27>,
    pool_thunk::<28>,
    pool_thunk::<29>,
    pool_thunk::<30>,
    pool_thunk::<31>,
];

/// A callable pointer to the vendor function `name` the daemon declared, or NULL if it declared none of
/// that name (or 32 names have been asked for already). Call it with the C arguments of the function.
///
/// # Safety
/// `name` must be a NUL-terminated string.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn P11P_GetVendorFunction(name: *const c_char) -> *const c_void {
    if name.is_null() {
        return core::ptr::null();
    }
    // SAFETY: a NUL-terminated string, per the contract.
    let Ok(name) = unsafe { CStr::from_ptr(name) }.to_str() else { return core::ptr::null() };
    if vendorfn::get(name).is_none() {
        return core::ptr::null();
    }
    let mut pool = POOL.lock().unwrap_or_else(|e| e.into_inner());
    let i = match pool.iter().position(|n| n == name) {
        Some(i) => i,
        None if pool.len() < THUNKS.len() => {
            pool.push(name.to_string());
            pool.len() - 1
        }
        None => return core::ptr::null(),
    };
    THUNKS[i] as *const c_void
}

const _: () = assert!(MAX_C_ARGS == 20, "the entry points above declare MAX_C_ARGS parameters");
