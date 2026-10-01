//! A vendor function through the whole path, both ends in one process: the caller's C arguments,
//! the wire, the daemon's rebuilt buffers, a real C function, the reply and the caller's memory.
#![cfg(feature = "vendor")]
#![allow(clippy::undocumented_unsafe_blocks)]

use p11_params::vendorfn::*;
use p11_types::*;
use p11_wire::structs::OutBytes;
use p11_wire::vendorfn::*;
use std::sync::Mutex;

static SEEN: Mutex<Vec<(u64, Vec<u8>)>> = Mutex::new(Vec::new());

/// `CK_RV f(session, pin, pin_len, out, out_len*, object*, count32*)`
extern "C" fn t_a(
    session: u64,
    pin: *const u8,
    pin_len: u64,
    out: *mut u8,
    outlen: *mut u64,
    obj: *mut u64,
    n: *mut u32,
) -> u64 {
    unsafe {
        SEEN.lock().unwrap().push((session, std::slice::from_raw_parts(pin, pin_len as usize).to_vec()));
        *obj = 77;
        *n = 9;
        if out.is_null() {
            *outlen = 5;
            return CKR_OK as u64;
        }
        if *outlen < 5 {
            *outlen = 5;
            return CKR_BUFFER_TOO_SMALL as u64;
        }
        std::ptr::copy_nonoverlapping(b"hello".as_ptr(), out, 5);
        *outlen = 5;
    }
    CKR_OK as u64
}

/// Claims to have written more than it was given room for.
extern "C" fn t_liar(out: *mut u8, outlen: *mut u64) -> u64 {
    unsafe {
        if !out.is_null() {
            *out = 1;
        }
        *outlen = 500;
    }
    CKR_OK as u64
}

extern "C" fn t_sum20(
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
) -> usize {
    a0 + 2 * a1
        + 3 * a2
        + 4 * a3
        + 5 * a4
        + 6 * a5
        + 7 * a6
        + 8 * a7
        + 9 * a8
        + 10 * a9
        + 11 * a10
        + 12 * a11
        + 13 * a12
        + 14 * a13
        + 15 * a14
        + 16 * a15
        + 17 * a16
        + 18 * a17
        + 19 * a18
        + 20 * a19
}

fn desc_a() -> FnDesc {
    FnDesc {
        name: "t_a".into(),
        rw: false,
        args: vec![ArgKind::Session, ArgKind::Secret, ArgKind::OBytes, ArgKind::OObject, ArgKind::OU32],
    }
}

/// The daemon's half: decode, build, call, finish, encode.
fn daemon(desc: &FnDesc, wire: &[u8], f: usize) -> (u64, Vec<u8>) {
    let ins = decode_request(wire, desc).unwrap();
    let mut call = VendorCall::build(desc, &ins).unwrap();
    let rv = unsafe { call.invoke(f) };
    (rv, call.finish(rv).encode())
}

/// The client's half around a daemon: capture, send, apply.
fn roundtrip(desc: &FnDesc, c: &CArgs, f: usize) -> Result<u64, u64> {
    let ins = unsafe { capture(desc, c)? };
    let wire = VendorRequest { name: desc.name.clone(), args: ins.clone() }.encode();
    let (rv, reply) = daemon(desc, &wire, f);
    let reply = VendorReply::decode(&reply, desc).unwrap();
    unsafe { apply(desc, c, &ins, &reply)? };
    Ok(rv)
}

#[test]
fn the_two_call_convention_secrets_handles_and_small_integers() {
    let d = desc_a();
    let mut pin = *b"1234";
    let (mut out, mut len, mut obj, mut n) = ([0u8; 16], 0u64, 0u64, 0u32);
    // addresses, so the checks below can read the variables while the module writes through them
    let (pin_p, out_p) = (pin.as_mut_ptr() as usize, out.as_mut_ptr() as usize);
    let (len_p, obj_p, n_p) =
        (&mut len as *mut u64 as usize, &mut obj as *mut u64 as usize, &mut n as *mut u32 as usize);
    let set = |buf: usize, cap: u64| -> CArgs {
        unsafe { *(len_p as *mut u64) = cap };
        let mut c: CArgs = [0; MAX_C_ARGS];
        c[..7].copy_from_slice(&[5, pin_p, 4, buf, len_p, obj_p, n_p]);
        c
    };

    // no buffer: just the length
    let c1 = set(0, 0);
    assert_eq!(roundtrip(&d, &c1, t_a as *const () as usize), Ok(CKR_OK as u64));
    assert_eq!((len, obj, n), (5, 77, 9));
    // (another test calls the same function, so the entry is looked for, not assumed to be the last)
    assert!(SEEN.lock().unwrap().contains(&(5, b"1234".to_vec())), "the module got the session and the PIN");

    // a buffer that is too small: the length it needs, nothing written
    let c2 = set(out_p, 3);
    assert_eq!(roundtrip(&d, &c2, t_a as *const () as usize), Ok(CKR_BUFFER_TOO_SMALL as u64));
    assert_eq!((len, out[0]), (5, 0));

    // room enough
    let c3 = set(out_p, 16);
    assert_eq!(roundtrip(&d, &c3, t_a as *const () as usize), Ok(CKR_OK as u64));
    assert_eq!((len, &out[..5]), (5, &b"hello"[..]));
}

#[test]
fn a_secret_is_wiped_after_the_call() {
    let d = desc_a();
    let ins =
        vec![InVal::Int(1), InVal::Bytes(b"topsecret".to_vec()), InVal::Cap(None), InVal::Nothing, InVal::Nothing];
    let mut call = VendorCall::build(&d, &ins).unwrap();
    // the copy the module sees is the second and third C arguments
    let (p, n) = call_args(&call);
    assert_eq!(unsafe { std::slice::from_raw_parts(p as *const u8, n) }, b"topsecret");
    let rv = unsafe { call.invoke(t_a as *const () as usize) };
    let _ = call.finish(rv);
    assert_eq!(unsafe { std::slice::from_raw_parts(p as *const u8, n) }, &[0u8; 9], "wiped");
}

fn call_args(c: &VendorCall) -> (usize, usize) {
    let a = format!("{c:?}");
    // cargs: [session, ptr, len, ...]
    let cargs = a.split("cargs: [").nth(1).unwrap().split(']').next().unwrap();
    let v: Vec<usize> = cargs.split(", ").map(|x| x.trim().parse().unwrap()).collect();
    (v[1], v[2])
}

#[test]
fn a_module_that_overstates_a_length_gets_no_data_through() {
    let d = FnDesc { name: "t_liar".into(), rw: false, args: vec![ArgKind::OBytes] };
    let mut buf = [0u8; 8];
    let mut len = 8u64;
    let mut c: CArgs = [0; MAX_C_ARGS];
    c[0] = buf.as_mut_ptr() as usize;
    c[1] = &mut len as *mut u64 as usize;
    // rv OK with 500 > 8: the length is reported and no bytes are copied to the caller
    assert_eq!(roundtrip(&d, &c, t_liar as *const () as usize), Ok(CKR_OK as u64));
    assert_eq!(len, 500);
    assert_eq!(buf, [0u8; 8]);
}

#[test]
fn a_hostile_reply_writes_nothing_into_the_callers_memory() {
    let d = FnDesc { name: "f".into(), rw: false, args: vec![ArgKind::OU64, ArgKind::OBytes] };
    let mut v = 0u64;
    let mut buf = [0xAAu8; 4];
    let mut len = 4u64;
    let mut c: CArgs = [0; MAX_C_ARGS];
    c[0] = &mut v as *mut u64 as usize;
    c[1] = buf.as_mut_ptr() as usize;
    c[2] = &mut len as *mut u64 as usize;
    let ins = unsafe { capture(&d, &c) }.unwrap();
    let hostile =
        |data: Option<Vec<u8>>, l: u64| VendorReply(vec![OutVal::Int(9), OutVal::Bytes(OutBytes { len: l, data })]);
    // more bytes than the caller's buffer
    assert_eq!(unsafe { apply(&d, &c, &ins, &hostile(Some(vec![1; 9]), 9)) }, Err(CKR_DEVICE_ERROR));
    // bytes whose count is not the length said
    assert_eq!(unsafe { apply(&d, &c, &ins, &hostile(Some(vec![1; 2]), 3)) }, Err(CKR_DEVICE_ERROR));
    // the wrong shape
    assert_eq!(unsafe { apply(&d, &c, &ins, &VendorReply(vec![OutVal::Int(1)])) }, Err(CKR_DEVICE_ERROR));
    assert_eq!((v, buf, len), (0, [0xAA; 4], 4), "nothing was written, not even the first output");
    // and a good one is applied
    assert_eq!(unsafe { apply(&d, &c, &ins, &hostile(Some(vec![1, 2]), 2)) }, Ok(()));
    assert_eq!((v, &buf[..2], len), (9, &[1u8, 2][..], 2));
}

#[test]
fn bad_arguments_are_refused_before_anything_is_sent() {
    let d = FnDesc { name: "f".into(), rw: false, args: vec![ArgKind::Bytes, ArgKind::OU64, ArgKind::CStr] };
    let mut c: CArgs = [0; MAX_C_ARGS];
    // a length with no pointer
    c[1] = 4;
    assert_eq!(unsafe { capture(&d, &c) }.unwrap_err(), CKR_ARGUMENTS_BAD);
    // an output with no pointer
    c[1] = 0;
    assert_eq!(unsafe { capture(&d, &c) }.unwrap_err(), CKR_ARGUMENTS_BAD);
    // a string without its NUL within the limit
    let mut o = 0u64;
    let long = vec![b'a'; MAX_CSTR + 2];
    c[2] = &mut o as *mut u64 as usize;
    c[3] = long.as_ptr() as usize;
    assert_eq!(unsafe { capture(&d, &c) }.unwrap_err(), CKR_ARGUMENTS_BAD);
    // narrow integers are cut to their width whatever the upper register bits hold
    let n = FnDesc { name: "n".into(), rw: false, args: vec![ArgKind::U8, ArgKind::U16, ArgKind::U32] };
    let mut c: CArgs = [0; MAX_C_ARGS];
    c[..3].copy_from_slice(&[0xdead_beef_0000_00ab, 0xffff_ffff_ffff_1234, 0x1_0000_0056]);
    assert_eq!(unsafe { capture(&n, &c) }.unwrap(), vec![InVal::Int(0xab), InVal::Int(0x1234), InVal::Int(0x56)]);
}

extern "C" fn t_sum8(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize, a7: usize) -> usize {
    a0 + 2 * a1 + 3 * a2 + 4 * a3 + 5 * a4 + 6 * a5 + 7 * a6 + 8 * a7
}

#[test]
fn eight_parameters_reach_the_function_everywhere() {
    let d = FnDesc { name: "t_sum8".into(), rw: false, args: vec![ArgKind::U64; 8] };
    let ins: Vec<InVal> = (1..=8).map(InVal::Int).collect();
    let call = VendorCall::build(&d, &ins).unwrap();
    let expect: usize = (1..=8usize).map(|i| i * i).sum();
    assert_eq!(unsafe { call.invoke(t_sum8 as *const () as usize) } as usize, expect);
}

#[test]
fn twenty_parameters_reach_the_function_where_the_abi_passes_the_stack_by_slot() {
    let d = FnDesc { name: "t_sum20".into(), rw: false, args: vec![ArgKind::U64; 20] };
    let ins: Vec<InVal> = (1..=20).map(InVal::Int).collect();
    let call = VendorCall::build(&d, &ins);
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        // stack arguments there are packed by their size, so a call this wide is refused
        assert_eq!(call.unwrap_err(), CKR_FUNCTION_NOT_SUPPORTED);
    } else {
        let expect: usize = (1..=20usize).map(|i| i * i).sum();
        assert_eq!(unsafe { call.unwrap().invoke(t_sum20 as *const () as usize) } as usize, expect);
    }
}

#[test]
fn registry_and_configuration() {
    let cfg = |name: &str, args: &[&str]| VendorFunction {
        name: name.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        rw: false,
    };
    assert!(cfg("F", &["session", "secret", "o_bytes"]).desc().is_ok());
    assert!(cfg("F", &["nonsense"]).desc().unwrap_err().contains("one of u8"));
    assert!(cfg("C_Login", &[]).desc().is_err());
    assert!(set_from_config(&[cfg("A", &["u64"]), cfg("A", &["u64"])]).is_err(), "twice");
    set_from_config(&[cfg("A", &["u64"]), cfg("B", &["o_u64"])]).unwrap();
    assert!(get("A").is_some() && get("nope").is_none());
    assert!(set_from_config(&[cfg("Bad Name", &[])]).is_err());
    assert!(get("A").is_some(), "a bad list changes nothing");
    set(&[]).unwrap();
    assert!(get("A").is_none());
}
