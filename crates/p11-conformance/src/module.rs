use libloading::Library;
use p11_types::*;
use std::path::Path;

/// A loaded PKCS#11 module (the real one, or a proxy).
#[allow(missing_debug_implementations)]
pub struct Module {
    _lib: Library,
    pub f: CK_FUNCTION_LIST,
    /// The 3.x entry points, if the module offers a 3.2 interface.
    pub f32: Option<CK_FUNCTION_LIST_3_2>,
}

impl Module {
    pub fn load(path: &Path) -> Result<Module, String> {
        // SAFETY: loading the module the caller names.
        let lib = unsafe { Library::new(path) }.map_err(|e| format!("{}: {e}", path.display()))?;
        // SAFETY: symbol names and signatures are PKCS#11's.
        unsafe {
            let get: libloading::Symbol<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV> =
                lib.get(b"C_GetFunctionList\0").map_err(|e| e.to_string())?;
            let mut l: *mut CK_FUNCTION_LIST = core::ptr::null_mut();
            let rv = get(&mut l);
            if rv != CKR_OK || l.is_null() {
                return Err(format!("C_GetFunctionList: 0x{rv:x}"));
            }
            let f = *l;
            let mut f32 = None;
            if let Ok(gi) = lib
                .get::<unsafe extern "C" fn(*mut u8, *mut CK_VERSION, *mut *mut CK_INTERFACE, CK_FLAGS) -> CK_RV>(
                    b"C_GetInterface\0",
                )
            {
                let mut v = CK_VERSION { major: 3, minor: 2 };
                let mut i: *mut CK_INTERFACE = core::ptr::null_mut();
                if gi(b"PKCS 11\0".as_ptr() as *mut u8, &mut v, &mut i, 0) == CKR_OK && !i.is_null() {
                    f32 = Some(*((*i).pFunctionList as *const CK_FUNCTION_LIST_3_2));
                }
            }
            Ok(Module { _lib: lib, f, f32 })
        }
    }
}
