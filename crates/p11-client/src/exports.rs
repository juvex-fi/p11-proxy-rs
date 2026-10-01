//! Entry points that aren't a plain "send the arguments" call: they manage
//! the connection, or are answered locally.

use crate::core::{dlog, Core};
use crate::{config, rt, state};
use p11_types::*;
use p11_wire::calls::*;

/// # Safety
/// `init_args` is null or points to a `CK_C_INITIALIZE_ARGS`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_Initialize(init_args: CK_VOID_PTR) -> CK_RV {
    rt::guard(|| {
        if !init_args.is_null() {
            // SAFETY: the application passes a CK_C_INITIALIZE_ARGS.
            let a = unsafe { &*(init_args as *const CK_C_INITIALIZE_ARGS) };
            let callbacks =
                [a.CreateMutex.is_some(), a.DestroyMutex.is_some(), a.LockMutex.is_some(), a.UnlockMutex.is_some()];
            if !a.pReserved.is_null() || (callbacks.iter().any(|&x| x) && !callbacks.iter().all(|&x| x)) {
                return Err(CKR_ARGUMENTS_BAD);
            }
            // Threads are ours to create; user-supplied mutexes are not needed:
            // the library protects its own state.
        }
        if state::current().is_ok() {
            return Err(CKR_CRYPTOKI_ALREADY_INITIALIZED);
        }
        let (connector, cfg) = config::from_env().map_err(|e| {
            dlog!("{e}");
            CKR_GENERAL_ERROR
        })?;
        initialize_with(Core::open(connector, cfg)?)?;
        Ok(CKR_OK)
    })
}

/// Install a connection and tell the daemon to initialise the client context.
#[doc(hidden)]
pub fn initialize_with(core: Core) -> Result<(), CK_RV> {
    let (rv, _) = core.call(&Request::Initialize(InitializeReq {}), false)?;
    if rv != CKR_OK as u64 {
        core.shutdown();
        return Err(rv as CK_RV);
    }
    match state::install(core) {
        Ok(()) => Ok(()),
        Err(e) => Err(e),
    }
}

/// # Safety
/// `reserved` must be null.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_Finalize(reserved: CK_VOID_PTR) -> CK_RV {
    rt::guard(|| {
        if !reserved.is_null() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let core = state::take()?;
        // Tell the daemon (best effort) so it closes our sessions now; either
        // way the connections go away and it cleans up.
        let _ = core.call(&Request::Finalize(FinalizeReq {}), false);
        core.shutdown();
        rt::forget_all_sessions();
        Ok(CKR_OK)
    })
}

/// # Safety
/// `slot` points to a `CK_SLOT_ID`; `reserved` must be null.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_WaitForSlotEvent(flags: CK_FLAGS, slot: CK_SLOT_ID_PTR, reserved: CK_VOID_PTR) -> CK_RV {
    rt::guard(|| {
        if slot.is_null() || !reserved.is_null() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let (rv, resp) =
            rt::call(Request::WaitForSlotEvent(WaitForSlotEventReq { flags: flags as u64 }), CALL_WAIT_FOR_SLOT_EVENT)?;
        if rv == CKR_OK as u64 {
            let Some(Response::WaitForSlotEvent(r)) = resp else { return Err(CKR_DEVICE_ERROR) };
            // SAFETY: `slot` is a valid pointer (checked non-null).
            unsafe { *slot = r.slot as CK_SLOT_ID };
        }
        Ok(rv as CK_RV)
    })
}

/// Notification callbacks are not supported: sessions never call `notify`.
///
/// # Safety
/// `session` points to a `CK_SESSION_HANDLE`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_OpenSession(
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    rt::guard(|| {
        if session.is_null() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let (rv, resp) = rt::call(
            Request::OpenSession(OpenSessionReq { slot: slot as u64, flags: flags as u64 }),
            CALL_OPEN_SESSION,
        )?;
        if rv == CKR_OK as u64 {
            let Some(Response::OpenSession(r)) = resp else { return Err(CKR_DEVICE_ERROR) };
            // SAFETY: valid pointer (checked non-null).
            unsafe { *session = r.session as CK_SESSION_HANDLE };
        }
        Ok(rv as CK_RV)
    })
}

/// # Safety
/// `list` points to a `CK_FUNCTION_LIST_PTR`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_GetFunctionList(list: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    if list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // SAFETY: valid pointer (checked non-null).
    unsafe { *list = &crate::tables::LIST_2_40 as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST };
    CKR_OK
}

const NAME: &[u8] = b"PKCS 11\0";

fn interfaces() -> [CK_INTERFACE; 4] {
    let mk = |l: *const CK_FUNCTION_LIST_3_2| CK_INTERFACE {
        pInterfaceName: NAME.as_ptr() as *mut u8,
        pFunctionList: l as *mut _,
        flags: 0,
    };
    [
        mk(&crate::tables::LIST_3_2),
        mk(&crate::tables::LIST_3_1),
        mk(&crate::tables::LIST_3_0),
        CK_INTERFACE {
            pInterfaceName: NAME.as_ptr() as *mut u8,
            pFunctionList: &crate::tables::LIST_2_40 as *const CK_FUNCTION_LIST as *mut _,
            flags: 0,
        },
    ]
}

/// # Safety
/// `list` is null or points to `*count` interfaces; `count` is valid.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_GetInterfaceList(list: CK_INTERFACE_PTR, count: CK_ULONG_PTR) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let all = interfaces();
    // SAFETY: valid pointer (checked non-null).
    let cap = unsafe { *count };
    // SAFETY: as above.
    unsafe { *count = all.len() as CK_ULONG };
    if list.is_null() {
        return CKR_OK;
    }
    if cap < all.len() as CK_ULONG {
        return CKR_BUFFER_TOO_SMALL;
    }
    for (i, x) in all.iter().enumerate() {
        // SAFETY: the caller's array holds `cap >= 4` interfaces.
        unsafe { list.add(i).write(*x) };
    }
    CKR_OK
}

/// No name or version asks for the newest interface. Otherwise the match must
/// be exact; none of the interfaces has flags, so a request that requires one
/// can't be satisfied.
///
/// # Safety
/// `name` is null or a NUL-terminated string, `version` null or valid,
/// `out` valid.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_GetInterface(
    name: CK_UTF8CHAR_PTR,
    version: CK_VERSION_PTR,
    out: *mut *mut CK_INTERFACE,
    flags: CK_FLAGS,
) -> CK_RV {
    if out.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // SAFETY: valid pointer (checked non-null).
    unsafe { *out = core::ptr::null_mut() };
    static TABLE: std::sync::OnceLock<Vec<usize>> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        // leak the interface array once: applications keep the pointer
        let b: &'static mut [CK_INTERFACE; 4] = Box::leak(Box::new(interfaces()));
        (0..4).map(|i| &mut b[i] as *mut CK_INTERFACE as usize).collect()
    });
    for &p in table {
        let iface = p as *mut CK_INTERFACE;
        // SAFETY: entries are the leaked, never freed array.
        let (n, l, f) = unsafe { ((*iface).pInterfaceName, (*iface).pFunctionList, (*iface).flags) };
        if !name.is_null() {
            // SAFETY: the caller passes a NUL-terminated string.
            let want = unsafe { std::ffi::CStr::from_ptr(name as *const _) };
            // SAFETY: our own static, NUL-terminated.
            let have = unsafe { std::ffi::CStr::from_ptr(n as *const _) };
            if want != have {
                continue;
            }
        }
        // every function list starts with its version
        // SAFETY: each list begins with a CK_VERSION.
        let v = unsafe { *(l as *const CK_VERSION) };
        if !version.is_null() {
            // SAFETY: valid pointer (checked non-null).
            let w = unsafe { *version };
            if w.major != v.major || w.minor != v.minor {
                continue;
            }
        }
        if f & flags != flags {
            continue;
        }
        // SAFETY: `out` is valid.
        unsafe { *out = iface };
        return CKR_OK;
    }
    CKR_ARGUMENTS_BAD
}
