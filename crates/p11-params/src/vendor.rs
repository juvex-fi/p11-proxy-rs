//! Vendor-defined mechanisms, declared in the configuration.
//!
//! The proxy carries a mechanism's parameter by knowing its layout, and it cannot know the layout of a
//! mechanism a vendor made up. An administrator who does can declare it here, in one of the forms that
//! can be carried without describing a structure:
//!
//! * no parameter, or bytes without pointers of an exact or a maximum length (`length`, `max_length`);
//! * one object handle (`handle = true`);
//! * bytes without pointers holding object handles at known offsets (`length` and `handles`), which the
//!   daemon translates as it does the handles of every other call;
//! * the parameter of a mechanism the proxy already carries (`same_as`).
//!
//! A parameter that holds pointers cannot be declared this way: the module would be handed pointers into
//! the client's memory. Nothing comes back from such a call except the call's own results; a parameter the
//! module fills in is not returned.
//!
//! The daemon announces the declarations to the client library in the handshake, and both ends check them
//! the same way: the client to accept the mechanism and capture its parameter, the daemon to list it and
//! rebuild the parameter.

use crate::desc::{Flat, Spec};
use p11_types::*;
use p11_wire::handshake::{Dir, FieldKind, VendorEntry, VendorField, VendorLayout, VendorMechs, VendorParam};
use p11_wire::limits::MAX_HANDLE_OFFSETS;
use serde::Deserialize;
use std::sync::{Mutex, RwLock};

/// The longest parameter that can be declared.
pub const MAX_LENGTH: usize = 4096;

/// A mechanism given by name (`CKM_AES_GCM`) or number.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum NameOrNum {
    Name(String),
    Num(u64),
}

/// One member of a `[[vendor_struct]]`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VendorStructField {
    /// A name other members can refer to.
    pub name: Option<String>,
    /// Where the member is, in bytes from the start of the structure.
    pub offset: u32,
    /// `ulong`, `handle`, `bool`, `byte`, `bytes`, `inline`, `ulong_ptr`, `handle_ptr`, `struct`,
    /// `embedded`, `array`, `attrs`, `cstr`, `mech_ptr`, `mech` or `handle_array`.
    pub kind: String,
    /// `in` (default), `out` or `inout`.
    pub dir: Option<String>,
    /// The structure a `struct`, `embedded` or `array` refers to.
    pub of: Option<String>,
    /// The member holding the length or count of a `bytes`, `array` or `attrs`.
    pub by: Option<String>,
    /// The size of an `inline`, or the most a `bytes` may hold.
    pub n: Option<u32>,
}

/// One `[[vendor_struct]]` entry: a structure a vendor mechanism's parameter is made of.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VendorStruct {
    pub name: String,
    /// Its size in bytes.
    pub size: u32,
    pub fields: Vec<VendorStructField>,
}

impl VendorStruct {
    pub fn layout(&self) -> Result<VendorLayout, String> {
        let mut fields = Vec::with_capacity(self.fields.len());
        for (i, f) in self.fields.iter().enumerate() {
            let at = |m: String| format!("vendor_struct {}: field {i}: {m}", self.name);
            fields.push(VendorField {
                name: f.name.clone().unwrap_or_default(),
                off: f.offset,
                kind: FieldKind::parse(&f.kind).ok_or_else(|| {
                    at(format!("unknown kind {:?} (one of {})", f.kind, FieldKind::ALL.map(|k| k.name()).join(", ")))
                })?,
                dir: match &f.dir {
                    None => Dir::In,
                    Some(d) => Dir::parse(d).ok_or_else(|| at(format!("dir is in, out or inout, not {d:?}")))?,
                },
                of: f.of.clone().unwrap_or_default(),
                by: f.by.clone().unwrap_or_default(),
                n: f.n.unwrap_or(0),
            });
        }
        Ok(VendorLayout { name: self.name.clone(), size: self.size, fields })
    }
}

/// One `[[vendor_mechanism]]` entry.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VendorMech {
    /// The mechanism's number: `CKM_VENDOR_DEFINED` (`0x80000000`) or above.
    pub id: u64,
    /// The parameter is exactly this many bytes (0: the mechanism takes none).
    pub length: Option<usize>,
    /// The parameter is at most this many bytes.
    pub max_length: Option<usize>,
    /// The parameter is one object handle.
    #[serde(default)]
    pub handle: bool,
    /// Byte offsets of object handles inside a parameter of `length` bytes.
    #[serde(default)]
    pub handles: Vec<usize>,
    /// The parameter is that of this mechanism, which the proxy already carries.
    pub same_as: Option<NameOrNum>,
    /// The parameter is this `[[vendor_struct]]`.
    #[serde(rename = "struct")]
    pub layout: Option<String>,
}

impl VendorMech {
    /// What the parameter is, if the entry gives exactly one form of it.
    pub fn param(&self) -> Result<VendorParam, String> {
        let id = self.id;
        let one = |what: &str| format!("vendor_mechanism 0x{id:x}: {what}");
        let others = self.length.is_some()
            || self.max_length.is_some()
            || self.handle
            || !self.handles.is_empty()
            || self.layout.is_some();
        if let Some(m) = &self.same_as {
            if others {
                return Err(one("same_as stands alone"));
            }
            let m = match m {
                NameOrNum::Num(n) => *n,
                NameOrNum::Name(n) => {
                    mechanism_by_name(n).ok_or_else(|| one(&format!("same_as: unknown mechanism {n}")))? as u64
                }
            };
            return Ok(VendorParam::SameAs(m));
        }
        if let Some(n) = &self.layout {
            if self.length.is_some() || self.max_length.is_some() || self.handle || !self.handles.is_empty() {
                return Err(one("struct stands alone"));
            }
            return Ok(VendorParam::Struct(n.clone()));
        }
        if self.handle {
            if self.length.is_some() || self.max_length.is_some() || !self.handles.is_empty() {
                return Err(one("handle stands alone"));
            }
            return Ok(VendorParam::Handle);
        }
        let fits = |n: usize| -> Result<u32, String> {
            if n > MAX_LENGTH {
                Err(one(&format!("a parameter is at most {MAX_LENGTH} bytes")))
            } else {
                Ok(n as u32)
            }
        };
        match (self.length, self.max_length) {
            (Some(n), None) if self.handles.is_empty() => Ok(VendorParam::Exact(fits(n)?)),
            (Some(n), None) => {
                let offs = self.handles.iter().map(|o| fits(*o)).collect::<Result<Vec<_>, _>>()?;
                Ok(VendorParam::Handles { len: fits(n)?, offs })
            }
            (None, Some(n)) if self.handles.is_empty() => Ok(VendorParam::Max(fits(n)?)),
            (None, Some(_)) => Err(one("handles need a length, not a max_length")),
            (Some(_), Some(_)) | (None, None) => Err(one(
                "give exactly one of length, max_length, handle, same_as and struct (handles goes with length)",
            )),
        }
    }
}

/// The parameter forms as machine specs, with the offsets of a `Handles` kept for good (one copy of each
/// distinct list, however often a client is told it).
fn intern(offs: &[usize]) -> &'static [usize] {
    static SEEN: Mutex<Vec<&'static [usize]>> = Mutex::new(Vec::new());
    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = seen.iter().find(|s| **s == offs) {
        return s;
    }
    let s: &'static [usize] = Box::leak(offs.to_vec().into_boxed_slice());
    seen.push(s);
    s
}

fn spec(id: u64, p: &VendorParam, layouts: &[(String, &'static crate::desc::Desc)]) -> Result<Spec, String> {
    let one = |what: &str| format!("vendor_mechanism 0x{id:x}: {what}");
    if id < CKM_VENDOR_DEFINED as u64 || id > u32::MAX as u64 {
        return Err(one("not in the vendor range (0x80000000 to 0xffffffff)"));
    }
    if crate::mech::is_builtin(id) {
        return Err(one("the proxy already carries it"));
    }
    let check = |n: u32| -> Result<usize, String> {
        if n as usize > MAX_LENGTH {
            Err(one(&format!("a parameter is at most {MAX_LENGTH} bytes")))
        } else {
            Ok(n as usize)
        }
    };
    Ok(match p {
        VendorParam::Exact(n) => Spec::Flat(Flat::Exact(check(*n)?)),
        VendorParam::Max(n) => Spec::Flat(Flat::Any(check(*n)?)),
        VendorParam::Handle => Spec::FlatHandle,
        VendorParam::Handles { len, offs } => {
            let len = check(*len)?;
            if offs.is_empty() || offs.len() > MAX_HANDLE_OFFSETS {
                return Err(one(&format!("handles: between 1 and {MAX_HANDLE_OFFSETS} offsets")));
            }
            let mut v = Vec::with_capacity(offs.len());
            for (i, o) in offs.iter().enumerate() {
                let o = *o as usize;
                // inside the parameter, and clear of the handle before it
                if o + size_of::<CK_ULONG>() > len || (i > 0 && o < v[i - 1] + size_of::<CK_ULONG>()) {
                    return Err(one(
                        "handles: offsets must be increasing, 8 bytes apart at least, and inside the parameter",
                    ));
                }
                v.push(o);
            }
            Spec::FlatHandles { len, offs: intern(&v) }
        }
        VendorParam::Struct(n) => Spec::Struct(
            layouts
                .iter()
                .find(|(l, _)| l == n)
                .map(|(_, d)| *d)
                .ok_or_else(|| one(&format!("struct: no vendor_struct {n:?}")))?,
        ),
        VendorParam::SameAs(m) => crate::mech::builtin_spec(*m)
            .ok_or_else(|| one(&format!("same_as: the proxy does not carry mechanism 0x{m:x}")))?,
    })
}

/// What the daemon announces to a client, from its declarations.
pub fn to_wire(list: &[VendorMech], structs: &[VendorStruct]) -> Result<VendorMechs, String> {
    let entries =
        list.iter().map(|v| Ok(VendorEntry { id: v.id, param: v.param()? })).collect::<Result<Vec<_>, String>>()?;
    let layouts = structs.iter().map(VendorStruct::layout).collect::<Result<Vec<_>, String>>()?;
    Ok(VendorMechs(entries, layouts))
}

static DECLARED: RwLock<Vec<(u64, Spec)>> = RwLock::new(Vec::new());

fn install(list: &[(u64, VendorParam)], layouts: &[VendorLayout]) -> Result<(), String> {
    let built = crate::layout::build(layouts)?;
    let mut out: Vec<(u64, Spec)> = Vec::with_capacity(list.len());
    for (id, p) in list {
        if out.iter().any(|(i, _)| i == id) {
            return Err(format!("vendor_mechanism 0x{id:x} is declared twice"));
        }
        out.push((*id, spec(*id, p, &built)?));
    }
    *DECLARED.write().unwrap_or_else(|e| e.into_inner()) = out;
    Ok(())
}

/// Replace the declared vendor mechanisms and the structures their parameters are made of. Nothing changes
/// if anything is invalid.
pub fn set(list: &[VendorMech], structs: &[VendorStruct]) -> Result<(), String> {
    let params = list.iter().map(|v| Ok((v.id, v.param()?))).collect::<Result<Vec<_>, String>>()?;
    let layouts = structs.iter().map(VendorStruct::layout).collect::<Result<Vec<_>, String>>()?;
    install(&params, &layouts)
}

/// Install what a daemon announced. It is checked like the local configuration would be, and
/// nothing changes if any entry is invalid.
pub fn set_from_wire(m: &VendorMechs) -> Result<(), String> {
    install(&m.0.iter().map(|e| (e.id, e.param.clone())).collect::<Vec<_>>(), &m.1)
}

pub(crate) fn lookup(id: u64) -> Option<Spec> {
    DECLARED.read().unwrap_or_else(|e| e.into_inner()).iter().find(|(i, _)| *i == id).map(|(_, s)| *s)
}
