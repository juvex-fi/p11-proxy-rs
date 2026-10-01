//! What a module offers against what the proxy carries.
//!
//! The daemon leaves out of `C_GetMechanismList` every mechanism whose
//! parameter it cannot carry, so an application never sees a mechanism the
//! proxy would fail on, and nothing says that it was left out. This lists the
//! module's own answer and sorts each mechanism into one of four classes, so a
//! gap shows up when a module is first tried rather than in production.

use crate::Module;
use core::ptr::null_mut;
use p11_types::*;

/// Families the proxy refuses on purpose (see `docs/MIGRATION.md`).
const REFUSED: [&str; 6] =
    ["CKM_SKIPJACK_", "CKM_BATON_", "CKM_JUNIPER_", "CKM_GOST28147", "CKM_X3DH_", "CKM_X2RATCHET_"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The proxy carries it, parameter and all.
    Carried,
    /// In the PKCS#11 header and refused on purpose.
    Refused,
    /// In the vendor range (`CKM_VENDOR_DEFINED` and up): the proxy has no idea what its parameter is.
    Vendor,
    /// Neither: a value outside the header the proxy was built from, or one
    /// the header names that is neither carried nor a documented refusal.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub mechanism: CK_MECHANISM_TYPE,
    pub name: Option<&'static str>,
    pub class: Class,
}

pub fn classify(m: CK_MECHANISM_TYPE) -> Entry {
    let name = mechanism_name(m);
    let class = if p11_params::mech::is_supported(m as u64) {
        Class::Carried
    } else if m >= CKM_VENDOR_DEFINED {
        Class::Vendor
    } else if name.is_some_and(|n| REFUSED.iter().any(|p| n.starts_with(p))) {
        Class::Refused
    } else {
        Class::Unknown
    };
    Entry { mechanism: m, name, class }
}

/// The mechanisms of the token in the `index`th slot with a token, straight from the module.
pub fn list(module: &Module, index: usize) -> Result<Vec<Entry>, String> {
    let f = &module.f;
    let bad = |what: &str, rv: CK_RV| format!("{what}: 0x{rv:x}");
    // SAFETY: valid buffers to the module throughout; the module is finalised before returning.
    unsafe {
        let init = f.C_Initialize.ok_or("no C_Initialize")?;
        let rv = init(null_mut());
        if rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED {
            return Err(bad("C_Initialize", rv));
        }
        let out = (|| {
            let slots = f.C_GetSlotList.ok_or("no C_GetSlotList")?;
            let mut n: CK_ULONG = 0;
            let rv = slots(1, null_mut(), &mut n);
            if rv != CKR_OK {
                return Err(bad("C_GetSlotList", rv));
            }
            let mut ids = vec![0 as CK_SLOT_ID; n as usize];
            let rv = slots(1, ids.as_mut_ptr(), &mut n);
            if rv != CKR_OK {
                return Err(bad("C_GetSlotList", rv));
            }
            let slot = *ids.get(index).ok_or_else(|| format!("slot index {index} of {n}"))?;
            let list = f.C_GetMechanismList.ok_or("no C_GetMechanismList")?;
            let mut cnt: CK_ULONG = 0;
            let rv = list(slot, null_mut(), &mut cnt);
            if rv != CKR_OK {
                return Err(bad("C_GetMechanismList", rv));
            }
            let mut ms = vec![0 as CK_MECHANISM_TYPE; cnt as usize];
            let rv = list(slot, ms.as_mut_ptr(), &mut cnt);
            if rv != CKR_OK {
                return Err(bad("C_GetMechanismList", rv));
            }
            ms.truncate(cnt as usize);
            ms.sort_unstable();
            Ok(ms.into_iter().map(classify).collect())
        })();
        if let Some(fin) = f.C_Finalize {
            fin(null_mut());
        }
        out
    }
}

/// The class counts, for a summary line.
pub fn counts(entries: &[Entry]) -> [usize; 4] {
    let mut c = [0; 4];
    for e in entries {
        c[e.class as usize] += 1;
    }
    c
}
