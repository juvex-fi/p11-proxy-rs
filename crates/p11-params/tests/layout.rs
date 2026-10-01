//! Structures declared for a vendor mechanism's parameter: what is refused, and a nested structure with
//! pointers, handles and outputs carried through the whole path.
#![cfg(feature = "vendor")]
#![allow(clippy::undocumented_unsafe_blocks)]

use core::ffi::c_void;
use p11_params::layout;
use p11_params::mech::*;
use p11_params::vendor::{VendorMech, VendorStruct, VendorStructField};
use p11_types::*;
use p11_wire::handshake::{Dir, FieldKind, VendorField, VendorLayout};
use p11_wire::{from_slice, to_vec, Node};

// ---- the rules ----

fn f(name: &str, off: u32, kind: FieldKind) -> VendorField {
    VendorField { name: name.into(), off, kind, dir: Dir::In, of: String::new(), by: String::new(), n: 0 }
}

fn l(name: &str, size: u32, fields: Vec<VendorField>) -> VendorLayout {
    VendorLayout { name: name.into(), size, fields }
}

fn refused(what: &str, layouts: Vec<VendorLayout>) {
    let e = layout::check(&layouts).expect_err(what);
    eprintln!("{what}: {e}");
}

#[test]
fn a_layout_that_could_misread_memory_is_refused() {
    assert!(layout::check(&[l("ok", 16, vec![f("a", 0, FieldKind::Ulong), f("h", 8, FieldKind::Handle)])]).is_ok());
    refused("no fields", vec![l("s", 8, vec![])]);
    refused("size 0", vec![l("s", 0, vec![f("a", 0, FieldKind::Byte)])]);
    refused("size too big", vec![l("s", 100_000, vec![f("a", 0, FieldKind::Byte)])]);
    refused("a bad name", vec![l("has space", 8, vec![f("a", 0, FieldKind::Ulong)])]);
    refused("twice", vec![l("s", 8, vec![f("a", 0, FieldKind::Ulong)]), l("s", 8, vec![f("a", 0, FieldKind::Ulong)])]);
    refused("a field outside", vec![l("s", 8, vec![f("a", 8, FieldKind::Ulong)])]);
    refused("a field crossing the end", vec![l("s", 12, vec![f("a", 8, FieldKind::Ulong)])]);
    refused("unaligned", vec![l("s", 16, vec![f("a", 4, FieldKind::Ulong)])]);
    refused(
        "overlap",
        vec![l("s", 16, vec![f("a", 0, FieldKind::Ulong), f("b", 4, FieldKind::Byte), f("c", 0, FieldKind::Byte)])],
    );
    refused("the same name twice", vec![l("s", 16, vec![f("a", 0, FieldKind::Ulong), f("a", 8, FieldKind::Ulong)])]);
    refused("an offset that would overflow", vec![l("s", 16, vec![f("a", u32::MAX - 3, FieldKind::Ulong)])]);
    // references
    let mut arr = f("", 0, FieldKind::Array);
    arr.of = "nope".into();
    arr.by = "n".into();
    refused("an unknown structure", vec![l("s", 16, vec![arr.clone(), f("n", 8, FieldKind::Ulong)])]);
    let mut bytes = f("", 0, FieldKind::Bytes);
    refused("bytes with no length member", vec![l("s", 16, vec![bytes.clone(), f("n", 8, FieldKind::Ulong)])]);
    bytes.by = "missing".into();
    refused("bytes with an unknown length member", vec![l("s", 16, vec![bytes.clone(), f("n", 8, FieldKind::Ulong)])]);
    bytes.by = "h".into();
    refused("a length member that is a handle", vec![l("s", 16, vec![bytes.clone(), f("h", 8, FieldKind::Handle)])]);
    let mut me = f("me", 0, FieldKind::Bytes);
    me.by = "me".into();
    refused("a length that is the field itself", vec![l("s", 8, vec![me])]);
    let mut c = f("c", 0, FieldKind::Ulong);
    c.of = "x".into();
    refused("`of` on a ulong", vec![l("s", 8, vec![c])]);
    // directions
    let mut hp = f("p", 0, FieldKind::HandlePtr);
    refused("a handle pointer that goes in", vec![l("s", 8, vec![hp.clone()])]);
    hp.dir = Dir::Out;
    assert!(layout::check(&[l("s", 8, vec![hp])]).is_ok());
    let mut st = f("p", 0, FieldKind::CStr);
    st.dir = Dir::Out;
    refused("a string that goes out", vec![l("s", 8, vec![st])]);
    // no structure contains itself
    let mut e = f("e", 0, FieldKind::Embedded);
    e.of = "s".into();
    refused("a structure inside itself", vec![l("s", 8, vec![e])]);
    let mut pa = f("p", 0, FieldKind::Struct);
    pa.of = "b".into();
    let mut pb = f("p", 0, FieldKind::Struct);
    pb.of = "a".into();
    refused("a cycle", vec![l("a", 8, vec![pa]), l("b", 8, vec![pb])]);
    // an embedded structure takes its own size
    let mut inner_in_outer = f("i", 8, FieldKind::Embedded);
    inner_in_outer.of = "inner".into();
    let inner = l("inner", 16, vec![f("a", 0, FieldKind::Ulong), f("b", 8, FieldKind::Ulong)]);
    refused(
        "an embedded structure that does not fit",
        vec![inner.clone(), l("outer", 16, vec![inner_in_outer.clone()])],
    );
    assert!(layout::check(&[inner, l("outer", 24, vec![inner_in_outer])]).is_ok());
    // an inline array
    let mut il = f("i", 0, FieldKind::Inline);
    refused("an inline array of no size", vec![l("s", 8, vec![il.clone()])]);
    il.n = 9;
    refused("an inline array that does not fit", vec![l("s", 8, vec![il.clone()])]);
    il.n = 8;
    assert!(layout::check(&[l("s", 8, vec![il])]).is_ok());
}

#[test]
fn the_same_layouts_are_built_once() {
    let ls = vec![l("cached", 16, vec![f("a", 0, FieldKind::Ulong), f("h", 8, FieldKind::Handle)])];
    let a = layout::build(&ls).unwrap();
    let b = layout::build(&ls).unwrap();
    assert!(std::ptr::eq(a[0].1, b[0].1), "a client told the same layouts again keeps the descriptor it has");
}

#[test]
fn the_configuration_names_kinds_and_directions() {
    let field = |kind: &str| VendorStructField {
        name: Some("a".into()),
        offset: 0,
        kind: kind.into(),
        dir: None,
        of: None,
        by: None,
        n: None,
    };
    let st = |fields: Vec<VendorStructField>| VendorStruct { name: "s".into(), size: 8, fields };
    let ok = st(vec![field("ulong")]).layout().unwrap();
    assert_eq!((ok.fields[0].kind, ok.fields[0].dir), (FieldKind::Ulong, Dir::In));
    assert!(st(vec![field("nonsense")]).layout().unwrap_err().contains("one of ulong"));
    assert!(st(vec![VendorStructField { dir: Some("sideways".into()), ..field("ulong") }]).layout().is_err());
    assert_eq!(
        st(vec![VendorStructField { dir: Some("out".into()), ..field("handle") }]).layout().unwrap().fields[0].dir,
        Dir::Out
    );
}

// ---- carrying a structure ----

/// The declaration is process-wide: tests that change it take turns.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[repr(C)]
struct Inner {
    a: CK_ULONG,
    h: CK_OBJECT_HANDLE,
}

#[repr(C)]
struct Outer {
    flags: CK_ULONG,
    n: CK_ULONG,
    items: *mut Inner,
    attrs: *mut CK_ATTRIBUTE,
    n_attrs: CK_ULONG,
    label: *const core::ffi::c_char,
    buf: *const u8,
    buf_len: CK_ULONG,
    key: CK_OBJECT_HANDLE,
    made: *mut CK_OBJECT_HANDLE,
    status: CK_ULONG,
}

fn declared() -> (Vec<VendorMech>, Vec<VendorStruct>) {
    let fld = |name: &str, offset: u32, kind: &str| VendorStructField {
        name: Some(name.into()),
        offset,
        kind: kind.into(),
        dir: None,
        of: None,
        by: None,
        n: None,
    };
    let inner =
        VendorStruct { name: "inner".into(), size: 16, fields: vec![fld("a", 0, "ulong"), fld("h", 8, "handle")] };
    let outer = VendorStruct {
        name: "outer".into(),
        size: std::mem::size_of::<Outer>() as u32,
        fields: vec![
            fld("flags", 0, "ulong"),
            fld("n", 8, "ulong"),
            VendorStructField { of: Some("inner".into()), by: Some("n".into()), ..fld("items", 16, "array") },
            VendorStructField { by: Some("n_attrs".into()), ..fld("attrs", 24, "attrs") },
            fld("n_attrs", 32, "ulong"),
            fld("label", 40, "cstr"),
            VendorStructField { by: Some("buf_len".into()), ..fld("buf", 48, "bytes") },
            fld("buf_len", 56, "ulong"),
            fld("key", 64, "handle"),
            VendorStructField { dir: Some("out".into()), ..fld("made", 72, "handle_ptr") },
            VendorStructField { dir: Some("out".into()), ..fld("status", 80, "ulong") },
        ],
    };
    (vec![VendorMech { id: 0x8000_0040, layout: Some("outer".into()), ..Default::default() }], vec![inner, outer])
}

#[test]
fn a_structure_with_pointers_handles_and_outputs_goes_through_and_back() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (mechs, structs) = declared();
    assert_eq!(std::mem::size_of::<Outer>(), 88);
    p11_params::vendor::set(&mechs, &structs).unwrap();
    const M: u64 = 0x8000_0040;
    unsafe {
        // the caller's structure
        let mut items = [Inner { a: 1, h: 10 }, Inner { a: 2, h: 20 }];
        let mut label_attr = *b"lab";
        let mut attrs = [CK_ATTRIBUTE { type_: CKA_LABEL, pValue: label_attr.as_mut_ptr().cast(), ulValueLen: 3 }];
        let label = c"hello";
        let buf = [7u8, 8, 9];
        let mut made: CK_OBJECT_HANDLE = 0;
        let mut p = Outer {
            flags: 5,
            n: 2,
            items: items.as_mut_ptr(),
            attrs: attrs.as_mut_ptr(),
            n_attrs: 1,
            label: label.as_ptr(),
            buf: buf.as_ptr(),
            buf_len: 3,
            key: 30,
            made: &mut made,
            status: 0,
        };
        let m = CK_MECHANISM {
            mechanism: M as CK_MECHANISM_TYPE,
            pParameter: (&mut p as *mut Outer).cast::<c_void>(),
            ulParameterLen: 88,
        };

        // client: capture and send
        let w = from_slice::<p11_wire::structs::Mech>(&to_vec(&capture_mech(&m).unwrap())).unwrap();
        // daemon: the client's handles become the module's
        let mut w = w;
        walk_handles(M, w.param.as_mut().unwrap(), &mut |h| *h += 1000);
        let mut b = MechBuf::build(&w).unwrap();
        let q = &mut *((*b.as_mut_ptr()).pParameter as *mut Outer);
        assert_ne!(q as *mut Outer as usize, &p as *const Outer as usize, "the module gets the daemon's own copy");
        assert_eq!((q.flags, q.n, q.n_attrs, q.buf_len, q.key), (5, 2, 1, 3, 1030));
        let its = std::slice::from_raw_parts(q.items, 2);
        assert_eq!((its[0].a, its[0].h, its[1].a, its[1].h), (1, 1010, 2, 1020));
        assert_eq!(std::slice::from_raw_parts(q.buf, 3), &[7, 8, 9]);
        assert_eq!(std::ffi::CStr::from_ptr(q.label), label);
        assert_eq!((*q.attrs).type_, CKA_LABEL);
        assert_eq!(std::slice::from_raw_parts((*q.attrs).pValue as *const u8, 3), b"lab");
        assert_eq!(*q.made, 0);

        // the module writes its results
        *q.made = 555;
        q.status = 9;
        let mut out = b.extract_out().expect("outputs");
        // the daemon maps the module's handle to the client's, on the way back
        walk_handles(M, &mut out, &mut |h| *h -= 500);
        let out = from_slice::<Node>(&to_vec(&out)).unwrap();
        apply_mech_out(&Some(out), &m as *const _ as *mut _, CKR_OK as u64).unwrap();
        assert_eq!((made, p.status), (55, 9), "the caller's structure has the results");
        assert_eq!((p.flags, p.n, p.key), (5, 2, 30), "and nothing else changed");

        // a parameter of another size is refused
        let short = CK_MECHANISM { ulParameterLen: 80, ..m };
        assert_eq!(capture_mech(&short).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
    }
    p11_params::vendor::set(&[], &[]).unwrap();
}

#[test]
fn a_module_that_repoints_what_it_wrote_is_not_followed() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (mechs, structs) = declared();
    p11_params::vendor::set(&mechs, &structs).unwrap();
    const M: u64 = 0x8000_0040;
    unsafe {
        let mut made: CK_OBJECT_HANDLE = 0;
        let mut p: Outer = std::mem::zeroed();
        p.made = &mut made;
        let m = CK_MECHANISM {
            mechanism: M as CK_MECHANISM_TYPE,
            pParameter: (&mut p as *mut Outer).cast::<c_void>(),
            ulParameterLen: 88,
        };
        let w = capture_mech(&m).unwrap();
        let mut b = MechBuf::build(&w).unwrap();
        let q = &mut *((*b.as_mut_ptr()).pParameter as *mut Outer);
        let mut elsewhere: CK_OBJECT_HANDLE = 0xdead;
        q.made = &mut elsewhere;
        assert!(b.extract_out().is_none(), "the pointer to the handle moved");
    }
    p11_params::vendor::set(&[], &[]).unwrap();
}

// ---- an embedded mechanism, a handle array the module fills, and inline output ----

#[test]
fn the_rules_for_the_three_newer_kinds() {
    let mut mech = f("m", 0, FieldKind::Mech);
    assert!(layout::check(&[l("s", 24, vec![mech.clone()])]).is_ok());
    refused("a mechanism that does not fit", vec![l("s", 16, vec![mech.clone()])]);
    mech.dir = Dir::Out;
    refused("a mechanism that goes out", vec![l("s", 24, vec![mech])]);

    let cap = |dir| VendorField { dir, ..f("cap", 0, FieldKind::UlongPtr) };
    let arr = |dir, by: &str| VendorField { dir, by: by.into(), ..f("hs", 8, FieldKind::HandleArray) };
    assert!(layout::check(&[l("s", 16, vec![cap(Dir::InOut), arr(Dir::Out, "cap")])]).is_ok());
    refused("a handle array that goes in", vec![l("s", 16, vec![cap(Dir::InOut), arr(Dir::In, "cap")])]);
    refused("room the module does not update", vec![l("s", 16, vec![cap(Dir::In), arr(Dir::Out, "cap")])]);
    refused("room that is a plain ulong", vec![l("s", 16, vec![f("cap", 0, FieldKind::Ulong), arr(Dir::Out, "cap")])]);
    refused("no room named", vec![l("s", 16, vec![cap(Dir::InOut), arr(Dir::Out, "")])]);

    let mut tag = f("tag", 0, FieldKind::Inline);
    tag.n = 16;
    tag.dir = Dir::Out;
    assert!(layout::check(&[l("s", 16, vec![tag])]).is_ok(), "an inline array can be written by the module");
}

fn fld(name: &str, offset: u32, kind: &str) -> VendorStructField {
    VendorStructField { name: Some(name.into()), offset, kind: kind.into(), dir: None, of: None, by: None, n: None }
}

#[repr(C)]
struct MechAndObject {
    mechanism: CK_MECHANISM,
    obj: CK_OBJECT_HANDLE,
}

#[repr(C)]
struct Signed {
    flags: CK_ULONG,
    n: CK_ULONG,
    items: *mut MechAndObject,
}

#[test]
fn an_array_of_structures_each_with_a_mechanism_and_a_handle() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    const M: u64 = 0x8000_0041;
    let structs = vec![
        VendorStruct { name: "mo".into(), size: 32, fields: vec![fld("mech", 0, "mech"), fld("obj", 24, "handle")] },
        VendorStruct {
            name: "signed".into(),
            size: 24,
            fields: vec![
                fld("flags", 0, "ulong"),
                fld("n", 8, "ulong"),
                VendorStructField { of: Some("mo".into()), by: Some("n".into()), ..fld("items", 16, "array") },
            ],
        },
    ];
    p11_params::vendor::set(&[VendorMech { id: M, layout: Some("signed".into()), ..Default::default() }], &structs)
        .unwrap();
    unsafe {
        let mut iv = [3u8; 16];
        let mut items = [
            MechAndObject {
                mechanism: CK_MECHANISM {
                    mechanism: CKM_AES_CBC,
                    pParameter: iv.as_mut_ptr().cast(),
                    ulParameterLen: 16,
                },
                obj: 11,
            },
            MechAndObject {
                mechanism: CK_MECHANISM { mechanism: CKM_SHA256, pParameter: core::ptr::null_mut(), ulParameterLen: 0 },
                obj: 12,
            },
        ];
        let mut p = Signed { flags: 1, n: 2, items: items.as_mut_ptr() };
        let m = CK_MECHANISM {
            mechanism: M as CK_MECHANISM_TYPE,
            pParameter: (&mut p as *mut Signed).cast::<c_void>(),
            ulParameterLen: 24,
        };
        let mut w = from_slice::<p11_wire::structs::Mech>(&to_vec(&capture_mech(&m).unwrap())).unwrap();
        walk_handles(M, w.param.as_mut().unwrap(), &mut |h| *h += 1000);
        let mut b = MechBuf::build(&w).unwrap();
        let q = &*((*b.as_mut_ptr()).pParameter as *const Signed);
        let its = std::slice::from_raw_parts(q.items, 2);
        // each nested mechanism is its own, with its own parameter, rebuilt in the daemon's memory
        assert_eq!((its[0].mechanism.mechanism, its[0].mechanism.ulParameterLen, its[0].obj), (CKM_AES_CBC, 16, 1011));
        assert_ne!(its[0].mechanism.pParameter as usize, iv.as_ptr() as usize);
        assert_eq!(std::slice::from_raw_parts(its[0].mechanism.pParameter as *const u8, 16), &[3u8; 16]);
        assert_eq!(
            (its[1].mechanism.mechanism, its[1].mechanism.pParameter.is_null(), its[1].obj),
            (CKM_SHA256, true, 1012)
        );
        // a nested mechanism the proxy cannot carry is refused, not passed on
        (*p.items.add(1)).mechanism.mechanism = 0x7777_0001;
        assert_eq!(capture_mech(&m).unwrap_err(), CKR_MECHANISM_INVALID);
    }
    p11_params::vendor::set(&[], &[]).unwrap();
}

#[repr(C)]
struct Import {
    cap: *mut CK_ULONG,
    handles: *mut CK_OBJECT_HANDLE,
    tag: [u8; 16],
}

#[test]
fn a_handle_array_the_module_fills_and_an_inline_result() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    const M: u64 = 0x8000_0042;
    let structs = vec![VendorStruct {
        name: "imp".into(),
        size: 32,
        fields: vec![
            VendorStructField { dir: Some("inout".into()), ..fld("cap", 0, "ulong_ptr") },
            VendorStructField { dir: Some("out".into()), by: Some("cap".into()), ..fld("handles", 8, "handle_array") },
            VendorStructField { dir: Some("out".into()), n: Some(16), ..fld("tag", 16, "inline") },
        ],
    }];
    p11_params::vendor::set(&[VendorMech { id: M, layout: Some("imp".into()), ..Default::default() }], &structs)
        .unwrap();
    unsafe {
        let mut cap: CK_ULONG = 4;
        let mut room = [0 as CK_OBJECT_HANDLE; 4];
        let mut p = Import { cap: &mut cap, handles: room.as_mut_ptr(), tag: [0; 16] };
        let m = CK_MECHANISM {
            mechanism: M as CK_MECHANISM_TYPE,
            pParameter: (&mut p as *mut Import).cast::<c_void>(),
            ulParameterLen: 32,
        };
        let w = capture_mech(&m).unwrap();
        let mut b = MechBuf::build(&w).unwrap();
        let q = &mut *((*b.as_mut_ptr()).pParameter as *mut Import);
        assert_eq!(*q.cap, 4, "the module is told how much room there is");
        // the module writes three handles, the count and the tag
        for (i, h) in [511, 512, 513].into_iter().enumerate() {
            *q.handles.add(i) = h;
        }
        *q.cap = 3;
        q.tag = [0xAA; 16];
        let mut out = b.extract_out().expect("outputs");
        walk_handles(M, &mut out, &mut |h| *h -= 500); // the module's handles become the client's
        let out = from_slice::<Node>(&to_vec(&out)).unwrap();
        apply_mech_out(&Some(out.clone()), &m as *const _ as *mut _, CKR_OK as u64).unwrap();
        assert_eq!((cap, &room[..4], p.tag), (3, &[11, 12, 13, 0][..], [0xAA; 16]));

        // more handles than room, or a count that promises more than was allocated: refused whole
        cap = 2;
        room = [0; 4];
        assert!(apply_mech_out(&Some(out), &m as *const _ as *mut _, CKR_OK as u64).is_err());
        assert_eq!((cap, room), (2, [0; 4]), "and nothing is written");
        *p.cap = 4;
        let mut b2 = MechBuf::build(&w).unwrap();
        let q2 = &mut *((*b2.as_mut_ptr()).pParameter as *mut Import);
        *q2.cap = 5;
        assert!(b2.extract_out().is_none(), "a count beyond the room it was given");
        // the module points the array somewhere else
        let mut b3 = MechBuf::build(&w).unwrap();
        let q3 = &mut *((*b3.as_mut_ptr()).pParameter as *mut Import);
        let mut elsewhere = [9 as CK_OBJECT_HANDLE; 4];
        *q3.cap = 1;
        q3.handles = elsewhere.as_mut_ptr();
        assert!(b3.extract_out().is_none(), "the array moved");
        // the count pointer moved
        let mut b4 = MechBuf::build(&w).unwrap();
        let q4 = &mut *((*b4.as_mut_ptr()).pParameter as *mut Import);
        let mut other: CK_ULONG = 1;
        q4.cap = &mut other;
        assert!(b4.extract_out().is_none(), "the count pointer moved");
    }
    p11_params::vendor::set(&[], &[]).unwrap();
}
