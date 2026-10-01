//! Structures declared for vendor mechanism parameters, built into descriptors at run time.
//!
//! A vendor mechanism's parameter that holds pointers, nested structures or handles can be described here
//! with the kinds of member the descriptors of the mechanisms the proxy knows are made of, and then the
//! proxy carries it the same way: the client reads the caller's structure by these offsets, the daemon
//! rebuilds it in its own memory, translates the handles, and hands it to the module.
//!
//! A layout that is wrong reads the caller's memory where the structure is not, or gives the module a
//! structure it does not expect, so everything that can be checked is checked before a layout is used:
//! members inside the structure, aligned, not overlapping, every reference to another structure or to a
//! length or count member resolves, and no structure contains itself.

use crate::desc::*;
use core::mem::size_of;
use p11_types::*;
use p11_wire::handshake::{Dir, FieldKind, VendorField, VendorLayout};
use p11_wire::limits::{MAX_LAYOUT_FIELDS, MAX_LAYOUT_NAME, MAX_VENDOR_LAYOUTS};
use std::collections::HashMap;
use std::sync::Mutex;

/// The largest structure that can be declared.
pub const MAX_STRUCT: u32 = 4096;
const WORD: u32 = size_of::<CK_ULONG>() as u32;

/// The size a member takes inside its structure, and what alignment it needs.
fn footprint(f: &VendorField, sizes: &HashMap<&str, u32>) -> Result<(u32, u32), String> {
    Ok(match f.kind {
        FieldKind::Bool | FieldKind::Byte => (1, 1),
        FieldKind::Inline => (f.n, 1),
        FieldKind::Embedded => (*sizes.get(f.of.as_str()).ok_or_else(|| format!("no structure {:?}", f.of))?, WORD),
        FieldKind::Mech => (size_of::<CK_MECHANISM>() as u32, WORD),
        _ => (WORD, WORD),
    })
}

fn ident(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_LAYOUT_NAME
        && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        && !n.as_bytes()[0].is_ascii_digit()
}

/// Check the layouts as a whole. Nothing is built.
pub fn check(layouts: &[VendorLayout]) -> Result<(), String> {
    if layouts.len() > MAX_VENDOR_LAYOUTS {
        return Err(format!("at most {MAX_VENDOR_LAYOUTS} vendor_struct entries"));
    }
    let mut sizes: HashMap<&str, u32> = HashMap::new();
    for l in layouts {
        if !ident(&l.name) {
            return Err(format!("vendor_struct {:?}: not a name of letters, digits and _", l.name));
        }
        if sizes.insert(&l.name, l.size).is_some() {
            return Err(format!("vendor_struct {} is declared twice", l.name));
        }
        if l.size == 0 || l.size > MAX_STRUCT {
            return Err(format!("vendor_struct {}: size is 1 to {MAX_STRUCT} bytes", l.name));
        }
    }
    for l in layouts {
        let bad = |m: String| Err(format!("vendor_struct {}: {m}", l.name));
        if l.fields.is_empty() || l.fields.len() > MAX_LAYOUT_FIELDS {
            return bad(format!("between 1 and {MAX_LAYOUT_FIELDS} fields"));
        }
        let mut spans: Vec<(u32, u32)> = Vec::new();
        for (i, f) in l.fields.iter().enumerate() {
            let what = |m: &str| format!("field {i}: {m}");
            if !f.name.is_empty() {
                if !ident(&f.name) {
                    return bad(what("a name is letters, digits and _"));
                }
                if l.fields[..i].iter().any(|g| g.name == f.name) {
                    return bad(what(&format!("the name {} is used twice", f.name)));
                }
            }
            let (size, align) = match footprint(f, &sizes) {
                Ok(x) => x,
                Err(m) => return bad(what(&m)),
            };
            if f.kind == FieldKind::Inline && (f.n == 0 || f.n > MAX_STRUCT) {
                return bad(what("an inline array is 1 to 4096 bytes"));
            }
            if f.off % align != 0 {
                return bad(what(&format!("offset {} is not aligned to {align}", f.off)));
            }
            if f.off.checked_add(size).is_none_or(|end| end > l.size) {
                return bad(what(&format!(
                    "offset {} and {size} bytes are outside the {} byte structure",
                    f.off, l.size
                )));
            }
            if spans.iter().any(|(o, s)| f.off < o + s && *o < f.off + size) {
                return bad(what("overlaps another field"));
            }
            spans.push((f.off, size));
            // what a kind refers to, and which way it may go
            match f.kind {
                FieldKind::Struct | FieldKind::Embedded | FieldKind::Array => {
                    if !sizes.contains_key(f.of.as_str()) {
                        return bad(what(&format!("no structure {:?}", f.of)));
                    }
                }
                _ if !f.of.is_empty() => return bad(what("`of` is for struct, embedded and array")),
                _ => {}
            }
            match f.kind {
                FieldKind::Bytes | FieldKind::Array | FieldKind::Attrs | FieldKind::HandleArray => {
                    let by = l.fields.iter().position(|g| !f.by.is_empty() && g.name == f.by);
                    let ok = match by.map(|b| (b, l.fields[b].kind, l.fields[b].dir)) {
                        // the room for a handle array is a count the module updates
                        Some((b, FieldKind::UlongPtr, Dir::InOut)) if b != i && f.kind == FieldKind::HandleArray => {
                            true
                        }
                        Some((b, FieldKind::Ulong | FieldKind::Byte | FieldKind::Bool | FieldKind::UlongPtr, _))
                            if b != i && f.kind != FieldKind::HandleArray =>
                        {
                            true
                        }
                        _ => false,
                    };
                    if !ok {
                        let want = if f.kind == FieldKind::HandleArray {
                            "a ulong_ptr field of this structure that goes inout"
                        } else {
                            "a ulong, byte, bool or ulong_ptr field of this structure"
                        };
                        return bad(what(&format!("`by` must name {want}, not {:?}", f.by)));
                    }
                }
                _ if !f.by.is_empty() => return bad(what("`by` is for bytes, array, attrs and handle_array")),
                _ => {}
            }
            let dir_ok = match f.kind {
                FieldKind::HandlePtr | FieldKind::HandleArray => f.dir == Dir::Out,
                FieldKind::Bytes
                | FieldKind::Ulong
                | FieldKind::Handle
                | FieldKind::Bool
                | FieldKind::Byte
                | FieldKind::UlongPtr
                | FieldKind::Inline => true,
                _ => f.dir == Dir::In,
            };
            if !dir_ok {
                return bad(what(&format!("a {} cannot go {:?}", f.kind.name(), f.dir).to_lowercase()));
            }
            if f.n != 0 && !matches!(f.kind, FieldKind::Inline | FieldKind::Bytes) {
                return bad(what("`n` is for inline and bytes"));
            }
        }
    }
    // no structure contains itself, however indirectly
    fn visit<'a>(
        l: &'a VendorLayout,
        all: &'a [VendorLayout],
        stack: &mut Vec<&'a str>,
        done: &mut Vec<&'a str>,
    ) -> Result<(), String> {
        if done.contains(&l.name.as_str()) {
            return Ok(());
        }
        if stack.contains(&l.name.as_str()) {
            return Err(format!("vendor_struct {} contains itself", l.name));
        }
        stack.push(&l.name);
        for f in &l.fields {
            if matches!(f.kind, FieldKind::Struct | FieldKind::Embedded | FieldKind::Array) {
                let next = all.iter().find(|x| x.name == f.of).expect("checked above");
                visit(next, all, stack, done)?;
            }
        }
        stack.pop();
        done.push(&l.name);
        Ok(())
    }
    let (mut stack, mut done) = (Vec::new(), Vec::new());
    for l in layouts {
        visit(l, layouts, &mut stack, &mut done)?;
    }
    Ok(())
}

fn field(f: &VendorField, by_index: Option<u8>, of: Option<&'static Desc>) -> Field {
    let off = f.off as usize;
    let (req, resp) = match f.dir {
        Dir::In => (MECH, false),
        Dir::Out => (0, true),
        Dir::InOut => (MECH, true),
    };
    let len = by_index.map(Len::Field);
    let max = if f.n == 0 { MAX_BUF as u32 } else { f.n };
    let kind = match f.kind {
        FieldKind::Ulong => Kind::Ulong,
        FieldKind::Handle => Kind::Handle,
        FieldKind::Bool => Kind::Bool,
        FieldKind::Byte => Kind::Byte,
        FieldKind::Bytes => Kind::Bytes { len: len.expect("checked"), bits: false, max },
        FieldKind::Inline => Kind::Inline(f.n),
        FieldKind::UlongPtr => Kind::UlongPtr,
        FieldKind::HandlePtr => Kind::HandlePtr,
        FieldKind::Struct => Kind::Struct(of.expect("checked")),
        FieldKind::Embedded => Kind::Embedded(of.expect("checked")),
        FieldKind::Array => Kind::Array { desc: of.expect("checked"), count: by_index.expect("checked") },
        FieldKind::Attrs => Kind::Attrs { count: by_index.expect("checked") },
        FieldKind::CStr => Kind::CStr,
        FieldKind::MechPtr => Kind::MechPtr,
        FieldKind::Mech => Kind::Mech,
        FieldKind::HandleArray => Kind::HandleArray { count: by_index.expect("checked") },
    };
    Field { off, kind, req, resp }
}

type Built = Vec<(String, &'static Desc)>;

/// Descriptors for layouts already built, so a client told the same layouts on every connection keeps one
/// copy of each.
static BUILT: Mutex<Vec<(Vec<u8>, Built)>> = Mutex::new(Vec::new());

fn key(layouts: &[VendorLayout]) -> Vec<u8> {
    use p11_wire::codec::{Encode, Writer};
    let mut w = Writer::new();
    w.count(layouts.len());
    for l in layouts {
        l.encode(&mut w);
    }
    w.into_vec()
}

/// Check the layouts and build a descriptor for each.
pub fn build(layouts: &[VendorLayout]) -> Result<Built, String> {
    let k = key(layouts);
    let mut cache = BUILT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, b)) = cache.iter().find(|(c, _)| *c == k) {
        return Ok(b.clone());
    }
    check(layouts)?;
    let mut done: HashMap<String, &'static Desc> = HashMap::new();
    fn one(name: &str, all: &[VendorLayout], done: &mut HashMap<String, &'static Desc>) -> &'static Desc {
        if let Some(d) = done.get(name) {
            return d;
        }
        let l = all.iter().find(|l| l.name == name).expect("checked");
        let mut fields = Vec::with_capacity(l.fields.len());
        for f in &l.fields {
            let of = matches!(f.kind, FieldKind::Struct | FieldKind::Embedded | FieldKind::Array)
                .then(|| one(&f.of, all, done));
            let by = (!f.by.is_empty()).then(|| l.fields.iter().position(|g| g.name == f.by).expect("checked") as u8);
            fields.push(field(f, by, of));
        }
        let d: &'static Desc = Box::leak(Box::new(Desc {
            name: Box::leak(l.name.clone().into_boxed_str()),
            size: l.size as usize,
            phases: MECH,
            fields: Box::leak(fields.into_boxed_slice()),
        }));
        done.insert(name.to_string(), d);
        d
    }
    let built: Built = layouts.iter().map(|l| (l.name.clone(), one(&l.name, layouts, &mut done))).collect();
    cache.push((k, built.clone()));
    Ok(built)
}
