//! Loading a PKCS#11 module.

use crate::dl_impl::Fns;
use crate::Reply;
use p11_types::*;
use p11_wire::calls::{FinalizeReq, FinalizeResp, InitializeReq, InitializeResp};
use std::ffi::c_void;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

#[derive(Debug)]
pub enum LoadError {
    Open(String),
    NoEntryPoint,
    Initialize(u64),
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LoadError::Open(e) => write!(f, "cannot load the module: {e}"),
            LoadError::NoEntryPoint => f.write_str("the module exports neither C_GetInterface nor C_GetFunctionList"),
            LoadError::Initialize(rv) => write!(f, "C_Initialize failed with 0x{rv:x}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// A loaded, initialised PKCS#11 module.
pub struct DlBackend {
    pub(crate) fns: Fns,
    pub(crate) lock: Option<Mutex<()>>,
    version: CK_VERSION,
    // kept last so the code stays mapped as long as the function pointers exist
    _lib: libloading::Library,
    finalize: CK_C_Finalize,
    finalized: std::sync::atomic::AtomicBool,
}

impl core::fmt::Debug for DlBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DlBackend").field("interface", &(self.version.major, self.version.minor)).finish()
    }
}

const INTERFACE_NAME: &[u8] = b"PKCS 11\0";

impl DlBackend {
    /// Load `path`, pick the newest interface it offers, and call `C_Initialize`
    /// with OS locking allowed. `serialize` puts one lock around every call for
    /// modules that are not thread safe.
    pub fn open(path: &Path, serialize: bool) -> Result<DlBackend, LoadError> {
        // SAFETY: loading a shared object runs its initialisers; that is what the operator asked for.
        let lib = unsafe { libloading::Library::new(path) }.map_err(|e| LoadError::Open(e.to_string()))?;
        let (fns, version) = Self::find_interface(&lib)?;
        let init = fns.C_Initialize.ok_or(LoadError::NoEntryPoint)?;
        let mut args = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: core::ptr::null_mut(),
        };
        // SAFETY: `args` outlives the call; the module was loaded above.
        let rv = unsafe { init(&mut args as *mut _ as *mut c_void) };
        if rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED {
            return Err(LoadError::Initialize(rv as u64));
        }
        Ok(DlBackend {
            finalize: fns.C_Finalize,
            finalized: std::sync::atomic::AtomicBool::new(false),
            fns,
            lock: serialize.then(|| Mutex::new(())),
            version,
            _lib: lib,
        })
    }

    fn find_interface(lib: &libloading::Library) -> Result<(Fns, CK_VERSION), LoadError> {
        // SAFETY: symbols are looked up by their PKCS#11 names and have the header's signatures.
        unsafe {
            if let Ok(get) = lib.get::<unsafe extern "C" fn(
                CK_UTF8CHAR_PTR,
                CK_VERSION_PTR,
                *mut *mut CK_INTERFACE,
                CK_FLAGS,
            ) -> CK_RV>(b"C_GetInterface\0")
            {
                for (major, minor) in [(3u8, 2u8), (3, 0)] {
                    let mut want = CK_VERSION { major, minor };
                    let mut iface: *mut CK_INTERFACE = core::ptr::null_mut();
                    let rv = get(INTERFACE_NAME.as_ptr() as CK_UTF8CHAR_PTR, &mut want, &mut iface, 0);
                    if rv == CKR_OK && !iface.is_null() && !(*iface).pFunctionList.is_null() {
                        let l = (*iface).pFunctionList;
                        let fns = if minor == 2 {
                            Fns::from_v3_2(&*(l as *const CK_FUNCTION_LIST_3_2))
                        } else {
                            Fns::from_v3_0(&*(l as *const CK_FUNCTION_LIST_3_0))
                        };
                        return Ok((fns, want));
                    }
                }
            }
            let get = lib
                .get::<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV>(b"C_GetFunctionList\0")
                .map_err(|_| LoadError::NoEntryPoint)?;
            let mut list: *mut CK_FUNCTION_LIST = core::ptr::null_mut();
            if get(&mut list) != CKR_OK || list.is_null() {
                return Err(LoadError::NoEntryPoint);
            }
            let v = (*list).version;
            Ok((Fns::from_v2_40(&*list), v))
        }
    }

    /// The interface version in use (2.40, 3.0 or 3.2).
    pub fn interface_version(&self) -> (u8, u8) {
        (self.version.major, self.version.minor)
    }

    /// Find the module's exported function `name` and run `call` on its address, under the
    /// serialising lock if there is one. `CKR_FUNCTION_NOT_SUPPORTED` if the module has no such symbol.
    #[cfg(feature = "vendor")]
    pub(crate) fn vendor_symbol(&self, name: &str, call: &mut dyn FnMut(usize) -> u64) -> Result<u64, u64> {
        let cname = std::ffi::CString::new(name).map_err(|_| CKR_ARGUMENTS_BAD as u64)?;
        // SAFETY: only the symbol's address is taken here; whoever calls it knows its signature.
        let addr = unsafe { self._lib.get::<unsafe extern "C" fn()>(cname.as_bytes_with_nul()) }
            .map(|s| *s as usize)
            .map_err(|_| CKR_FUNCTION_NOT_SUPPORTED as u64)?;
        let _g = self.guard();
        Ok(call(addr))
    }

    pub(crate) fn guard(&self) -> Option<MutexGuard<'_, ()>> {
        self.lock.as_ref().map(|m| m.lock().unwrap_or_else(|e| e.into_inner()))
    }

    // The module is initialised once, by `open`, and shared by every client;
    // a client's own Initialize/Finalize only affect its connection state in
    // the daemon.
    pub(crate) fn initialize(&self, _r: &InitializeReq) -> Reply<InitializeResp> {
        Reply::done()
    }
    pub(crate) fn finalize(&self, _r: &FinalizeReq) -> Reply<FinalizeResp> {
        Reply::done()
    }
}

impl DlBackend {
    /// Call `C_Finalize` on the module (once). The daemon calls this on
    /// shutdown, when threads may still hold the backend; after it, calls
    /// fail in whatever way the module fails.
    pub fn finalize_module(&self) {
        if self.finalized.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        if let Some(f) = self.finalize {
            // SAFETY: the module is still loaded (`_lib` drops after this).
            unsafe { f(core::ptr::null_mut()) };
        }
    }
}

impl Drop for DlBackend {
    fn drop(&mut self) {
        self.finalize_module();
    }
}
