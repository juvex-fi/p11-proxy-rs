//! Vendor-defined functions through the client's exported entry points, the daemon and the mock token:
//! handles translated both ways, the two-call convention, a PIN, the read-only rule, and what happens to a
//! function nobody declared. The declarations are process-wide, so this is its own test binary.
#![cfg(feature = "vendor")]
#![allow(clippy::undocumented_unsafe_blocks, clippy::too_many_arguments, unsafe_op_in_unsafe_fn)]

use p11_daemon::{Limits, Policy, Rules, Server};
use p11_params::vendorfn::VendorFunction;
use p11_proxy::core::CoreConfig;
use p11_proxy::testing;
use p11_proxy::*;
use p11_testkit::mock::Mock;
use p11_testkit::raw::Loopback;
use p11_types::*;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};

const SLOT: CK_SLOT_ID = 7;
static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn note(s: String) {
    SEEN.lock().unwrap().push(s);
}

fn last() -> String {
    SEEN.lock().unwrap().last().cloned().unwrap_or_default()
}

// the "module's" functions, with the C signatures of the functions they stand for

extern "C" fn t_get_hsm_id(session: u64, out: *mut u64) -> u64 {
    note(format!("hsm {session:#x}"));
    unsafe { *out = 4242 };
    CKR_OK as u64
}

extern "C" fn t_fetch(hsm: u64, ty: u64, out: *mut u8, outlen: *mut u64) -> u64 {
    note(format!("fetch {hsm} {ty}"));
    unsafe {
        if out.is_null() {
            *outlen = 5;
            return CKR_OK as u64;
        }
        if *outlen < 5 {
            *outlen = 5;
            return CKR_BUFFER_TOO_SMALL as u64;
        }
        std::ptr::copy_nonoverlapping(b"CERT!".as_ptr(), out, 5);
        *outlen = 5;
    }
    CKR_OK as u64
}

extern "C" fn t_copy(dest: u64, src: u64, obj: u64, tpl: *const CK_ATTRIBUTE, count: u64, new: *mut u64) -> u64 {
    let first = if count > 0 { unsafe { (*tpl).type_ } } else { 0 };
    note(format!("copy {dest:#x} {src:#x} {obj:#x} n={count} first={first:#x}"));
    unsafe { *new = obj.wrapping_add(1000) };
    CKR_OK as u64
}

extern "C" fn t_init_pin(session: u64, user_type: u64, pin: *const u8, len: u64) -> u64 {
    let pin = unsafe { std::slice::from_raw_parts(pin, len as usize) };
    note(format!("pin {session:#x} {user_type} {}", String::from_utf8_lossy(pin)));
    CKR_OK as u64
}

extern "C" fn t_add(a: u64, b: u64, out: *mut u64) -> u64 {
    unsafe { *out = a + b };
    CKR_OK as u64
}

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

/// Call a vendor entry point the way an application does, with only the arguments its C function has.
unsafe fn call(f: Thunk, a: &[usize]) -> CK_RV {
    let mut p = [0usize; 20];
    p[..a.len()].copy_from_slice(a);
    f(
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15], p[16],
        p[17], p[18], p[19],
    )
}

fn declared(cfg: &[(&str, &[&str], bool)]) -> Vec<p11_wire::vendorfn::FnDesc> {
    cfg.iter()
        .map(|(n, a, rw)| {
            VendorFunction { name: n.to_string(), args: a.iter().map(|s| s.to_string()).collect(), rw: *rw }
                .desc()
                .unwrap()
        })
        .collect()
}

fn connect(mock: &Arc<Mock>, rules: Rules, fns: &[p11_wire::vendorfn::FnDesc]) -> testing::Session {
    let server = Server::new(mock.clone(), Policy::allow_all(rules), Limits::default()).with_vendor_functions(fns);
    let lb = Loopback { server: Arc::new(server), identity: "test".into() };
    testing::install(Box::new(lb), CoreConfig::default()).expect("initialize")
}

unsafe fn open() -> CK_SESSION_HANDLE {
    let mut s = 0;
    assert_eq!(C_OpenSession(SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, null_mut(), None, &mut s), CKR_OK);
    s
}

unsafe fn data_object(s: CK_SESSION_HANDLE) -> CK_OBJECT_HANDLE {
    let mut class = CKO_DATA;
    let mut t = [CK_ATTRIBUTE { type_: CKA_CLASS, pValue: (&mut class as *mut CK_ULONG).cast(), ulValueLen: 8 }];
    let mut o = 0;
    assert_eq!(C_CreateObject(s, t.as_mut_ptr(), 1, &mut o), CKR_OK);
    o
}

fn everything() -> Vec<p11_wire::vendorfn::FnDesc> {
    declared(&[
        ("CT_GetHSMId", &["session", "o_u64"], false),
        ("CT_FetchCertificate", &["u64", "u64", "o_bytes"], false),
        ("CT_CopyObject", &["session", "session", "object", "attrs", "o_object"], true),
        ("CT_InitPIN", &["session", "u64", "secret"], true),
        ("CT_SetHsmDead", &["u64", "u8"], true), // declared, but the module has no such function
        ("MOCK_Add", &["u64", "u64", "o_u64"], false),
    ])
}

#[test]
fn vendor_functions_through_the_client_the_daemon_and_the_module() {
    let mock = Arc::new(Mock::new());
    for (n, f) in [
        ("CT_GetHSMId", t_get_hsm_id as *const () as usize),
        ("CT_FetchCertificate", t_fetch as *const () as usize),
        ("CT_CopyObject", t_copy as *const () as usize),
        ("CT_InitPIN", t_init_pin as *const () as usize),
        ("MOCK_Add", t_add as *const () as usize),
    ] {
        mock.register_vendor(n, f);
    }

    // before a daemon says so, nothing is declared
    assert_eq!(unsafe { call(CT_GetHSMId, &[1, 0]) }, CKR_FUNCTION_NOT_SUPPORTED);
    assert!(unsafe { P11P_GetVendorFunction(c"MOCK_Add".as_ptr()) }.is_null());

    let session = connect(&mock, Rules::default(), &everything());
    // the handshake installed what the daemon declared
    let names: Vec<String> = p11_params::vendorfn::declared().into_iter().map(|d| d.name).collect();
    assert_eq!(names.len(), 6);
    assert!(names.iter().any(|n| n == "CT_CopyObject"));
    unsafe {
        let s = open();
        let obj = data_object(s);

        // an integer out, and the session handle the module sees is its own, not the client's
        let mut hsm = 0u64;
        assert_eq!(call(CT_GetHSMId, &[s as usize, &mut hsm as *mut u64 as usize]), CKR_OK);
        assert_eq!(hsm, 4242);
        assert!(last().starts_with("hsm 0x5"), "the module got its own session handle: {}", last());
        assert_ne!(s, 0x5000);

        // the two-call convention: the length, too small a buffer, then the data
        let mut len = 0u64;
        assert_eq!(call(CT_FetchCertificate, &[3, 9, 0, &mut len as *mut u64 as usize]), CKR_OK);
        assert_eq!(len, 5);
        let mut buf = [0u8; 16];
        len = 3;
        assert_eq!(
            call(CT_FetchCertificate, &[3, 9, buf.as_mut_ptr() as usize, &mut len as *mut u64 as usize]),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!((len, buf[0]), (5, 0));
        len = 16;
        assert_eq!(
            call(CT_FetchCertificate, &[3, 9, buf.as_mut_ptr() as usize, &mut len as *mut u64 as usize]),
            CKR_OK
        );
        assert_eq!((len, &buf[..5]), (5, &b"CERT!"[..]));
        assert_eq!(last(), "fetch 3 9");

        // two sessions, an object and a template in; an object out, under a handle of the client's own
        let s2 = open();
        let mut label = *b"x";
        let mut t = [CK_ATTRIBUTE { type_: CKA_LABEL, pValue: label.as_mut_ptr().cast(), ulValueLen: 1 }];
        let mut new = 0u64;
        assert_eq!(
            call(
                CT_CopyObject,
                &[s2 as usize, s as usize, obj as usize, t.as_mut_ptr() as usize, 1, &mut new as *mut u64 as usize]
            ),
            CKR_OK
        );
        let seen = last();
        assert!(
            seen.starts_with("copy 0x5") && seen.contains("n=1") && seen.contains(&format!("first={:#x}", CKA_LABEL)),
            "{seen}"
        );
        // the module's new object (its object + 1000) is not what the client got back
        let module_obj =
            u64::from_str_radix(seen.split_whitespace().nth(3).unwrap().trim_start_matches("0x"), 16).unwrap();
        assert!(new != 0 && new != module_obj + 1000, "translated: {new:#x} vs {:#x}", module_obj + 1000);
        // a handle the client never had goes to the module as one no object has, and is answered
        // by the module (here it just accepts it): the function still ran
        assert_eq!(
            call(
                CT_CopyObject,
                &[s2 as usize, s as usize, 0xdead, null_mut::<u8>() as usize, 0, &mut new as *mut u64 as usize]
            ),
            CKR_OK
        );
        // a session handle the client never had is refused before the module is called
        let before = SEEN.lock().unwrap().len();
        assert_eq!(call(CT_GetHSMId, &[0xdead, &mut hsm as *mut u64 as usize]), CKR_SESSION_HANDLE_INVALID);
        assert_eq!(SEEN.lock().unwrap().len(), before);

        // a PIN reaches the module as it is
        let mut pin = *b"9999";
        assert_eq!(call(CT_InitPIN, &[s as usize, 1, pin.as_mut_ptr() as usize, 4]), CKR_OK);
        assert!(last().ends_with(" 1 9999"), "{}", last());

        // a function the daemon declared and the module lacks
        assert_eq!(call(CT_SetHsmDead, &[0, 1]), CKR_FUNCTION_NOT_SUPPORTED);
        // one nobody declared is refused by the client
        assert_eq!(call(CT_ResetToken, &[s as usize, 0, 0, 0]), CKR_FUNCTION_NOT_SUPPORTED);

        // any declared function by name
        let add = P11P_GetVendorFunction(c"MOCK_Add".as_ptr());
        assert!(!add.is_null());
        assert_eq!(add, P11P_GetVendorFunction(c"MOCK_Add".as_ptr()), "the same entry point for the same name");
        let mut sum = 0u64;
        let add: Thunk = std::mem::transmute(add);
        assert_eq!(call(add, &[2, 3, &mut sum as *mut u64 as usize]), CKR_OK);
        assert_eq!(sum, 5);
        assert!(P11P_GetVendorFunction(c"Nobody".as_ptr()).is_null());
        assert!(P11P_GetVendorFunction(std::ptr::null()).is_null());

        // bad arguments are refused before anything is sent
        assert_eq!(call(CT_GetHSMId, &[s as usize, 0]), CKR_ARGUMENTS_BAD);
        assert_eq!(call(CT_InitPIN, &[s as usize, 1, 0, 4]), CKR_ARGUMENTS_BAD);
    }
    drop(session);

    // a read-only client may call what does not change the token, and not what does
    let ro = Rules { read_only: true, ..Rules::default() };
    let session = connect(&mock, ro, &everything());
    unsafe {
        let mut s = 0;
        assert_eq!(C_OpenSession(SLOT, CKF_SERIAL_SESSION, null_mut(), None, &mut s), CKR_OK);
        let mut hsm = 0u64;
        assert_eq!(call(CT_GetHSMId, &[s as usize, &mut hsm as *mut u64 as usize]), CKR_OK);
        let mut pin = *b"9999";
        assert_eq!(call(CT_InitPIN, &[s as usize, 1, pin.as_mut_ptr() as usize, 4]), CKR_ACTION_PROHIBITED);
    }
    drop(session);

    // a daemon that declares none takes them all away
    let session = connect(&mock, Rules::default(), &[]);
    unsafe {
        let s = open();
        let mut hsm = 0u64;
        assert_eq!(call(CT_GetHSMId, &[s as usize, &mut hsm as *mut u64 as usize]), CKR_FUNCTION_NOT_SUPPORTED);
    }
    drop(session);
}
