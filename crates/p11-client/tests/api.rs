// The tests below drive the C entry points directly; each block calls them with valid,
// live buffers as the PKCS#11 contract requires.
#![allow(clippy::undocumented_unsafe_blocks)]

//! The C entry points, called as Rust functions, against a daemon serving the
//! mock token over an in-process connection.

use p11_daemon::{Limits, Policy, Rules, Server};
use p11_proxy::core::CoreConfig;
use p11_proxy::testing;
use p11_proxy::*;
use p11_testkit::mock::{Mock, USER_PIN};
use p11_testkit::raw::Loopback;
use p11_types::*;
use std::ptr::{null, null_mut};
use std::sync::Arc;

struct Env {
    _s: testing::Session,
    mock: Arc<Mock>,
    server: Arc<Server>,
}

fn env_with(rules: Rules) -> Env {
    let mock = Arc::new(Mock::new());
    let server = Arc::new(Server::new(mock.clone(), Policy::allow_all(rules), Limits::default()));
    let lb = Loopback { server: server.clone(), identity: "test".into() };
    let s = testing::install(Box::new(lb), CoreConfig::default()).expect("initialize");
    Env { _s: s, mock, server }
}

fn env() -> Env {
    env_with(Rules::default())
}

const SLOT: CK_SLOT_ID = 7;

unsafe fn open_rw() -> CK_SESSION_HANDLE {
    let mut s = 0;
    // SAFETY: valid out pointer.
    assert_eq!(unsafe { C_OpenSession(SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, null_mut(), None, &mut s) }, CKR_OK);
    s
}

unsafe fn login(s: CK_SESSION_HANDLE) {
    let mut pin = USER_PIN.to_vec();
    // SAFETY: pin buffer is valid for its length.
    assert_eq!(unsafe { C_Login(s, CKU_USER, pin.as_mut_ptr(), pin.len() as CK_ULONG) }, CKR_OK);
}

#[test]
fn info_slots_and_the_two_call_convention() {
    let _e = env();
    unsafe {
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(C_GetInfo(&mut info), CKR_OK);
        assert_eq!(info.cryptokiVersion.major, 3);
        assert_eq!(&info.libraryDescription[..10], b"Mock token");

        // length first, then the data
        let mut n = 0;
        assert_eq!(C_GetSlotList(0, null_mut(), &mut n), CKR_OK);
        assert_eq!(n, 2);
        let mut slots = [0 as CK_SLOT_ID; 1];
        let mut cap = 1;
        assert_eq!(C_GetSlotList(0, slots.as_mut_ptr(), &mut cap), CKR_BUFFER_TOO_SMALL);
        assert_eq!(cap, 2);
        let mut slots = [0 as CK_SLOT_ID; 4];
        let mut cap = 4;
        assert_eq!(C_GetSlotList(0, slots.as_mut_ptr(), &mut cap), CKR_OK);
        assert_eq!((cap, &slots[..2]), (2, &[7, 8][..]));

        assert_eq!(C_GetSlotList(0, null_mut(), null_mut()), CKR_ARGUMENTS_BAD);

        let mut ti: CK_TOKEN_INFO = std::mem::zeroed();
        assert_eq!(C_GetTokenInfo(SLOT, &mut ti), CKR_OK);
        assert_eq!(&ti.label[..10], b"mock token");
        assert_eq!(C_GetTokenInfo(99, &mut ti), CKR_SLOT_ID_INVALID);
        assert_eq!(C_GetTokenInfo(SLOT, null_mut()), CKR_ARGUMENTS_BAD);
    }
}

#[test]
fn sessions_objects_and_attributes() {
    let e = env();
    unsafe {
        let s = open_rw();
        login(s);
        let mut label = *b"my label";
        let mut class = CKO_DATA;
        let mut tpl = [
            CK_ATTRIBUTE { type_: CKA_CLASS, pValue: &mut class as *mut _ as *mut _, ulValueLen: 8 },
            CK_ATTRIBUTE { type_: CKA_LABEL, pValue: label.as_mut_ptr().cast(), ulValueLen: label.len() as CK_ULONG },
        ];
        let mut obj = 0;
        assert_eq!(C_CreateObject(s, tpl.as_mut_ptr(), 2, &mut obj), CKR_OK);
        assert_ne!(obj, 0);
        assert_eq!(e.mock.object_count(), 1);

        // find it by label
        assert_eq!(C_FindObjectsInit(s, tpl.as_mut_ptr().add(1), 1), CKR_OK);
        let mut found = [0 as CK_OBJECT_HANDLE; 4];
        let mut nfound = 0;
        assert_eq!(C_FindObjects(s, found.as_mut_ptr(), 4, &mut nfound), CKR_OK);
        assert_eq!((nfound, found[0]), (1, obj));
        assert_eq!(C_FindObjectsFinal(s), CKR_OK);

        // read attributes: length query, exact buffer, and a missing attribute
        let mut q = [
            CK_ATTRIBUTE { type_: CKA_LABEL, pValue: null_mut(), ulValueLen: 0 },
            CK_ATTRIBUTE { type_: CKA_CLASS, pValue: null_mut(), ulValueLen: 0 },
        ];
        assert_eq!(C_GetAttributeValue(s, obj, q.as_mut_ptr(), 2), CKR_OK);
        assert_eq!((q[0].ulValueLen, q[1].ulValueLen), (8, 8));
        let mut lab = [0u8; 8];
        let mut cls: CK_ULONG = 99;
        let mut q = [
            CK_ATTRIBUTE { type_: CKA_LABEL, pValue: lab.as_mut_ptr().cast(), ulValueLen: 8 },
            CK_ATTRIBUTE { type_: CKA_CLASS, pValue: &mut cls as *mut _ as *mut _, ulValueLen: 8 },
        ];
        assert_eq!(C_GetAttributeValue(s, obj, q.as_mut_ptr(), 2), CKR_OK);
        assert_eq!(&lab, b"my label");
        assert_eq!(cls, CKO_DATA);
        let mut q = [CK_ATTRIBUTE { type_: CKA_MODULUS, pValue: null_mut(), ulValueLen: 0 }];
        assert_eq!(C_GetAttributeValue(s, obj, q.as_mut_ptr(), 1), CKR_ATTRIBUTE_TYPE_INVALID);
        assert_eq!(q[0].ulValueLen, CK_UNAVAILABLE_INFORMATION);

        assert_eq!(C_DestroyObject(s, obj), CKR_OK);
        assert_eq!(C_DestroyObject(s, obj), CKR_OBJECT_HANDLE_INVALID);
        assert_eq!(C_CloseSession(s), CKR_OK);
        assert_eq!(C_CloseSession(s), CKR_SESSION_HANDLE_INVALID);
    }
}

#[test]
fn encrypt_decrypt_and_random() {
    let _e = env();
    unsafe {
        let s = open_rw();
        login(s);
        let mut mech = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: null_mut(), ulParameterLen: 0 };
        let mut len: CK_ULONG = 32;
        let mut t = [CK_ATTRIBUTE { type_: CKA_VALUE_LEN, pValue: &mut len as *mut _ as *mut _, ulValueLen: 8 }];
        let mut key = 0;
        assert_eq!(C_GenerateKey(s, &mut mech, t.as_mut_ptr(), 1, &mut key), CKR_OK);

        let mut ecb = CK_MECHANISM { mechanism: CKM_AES_ECB, pParameter: null_mut(), ulParameterLen: 0 };
        assert_eq!(C_EncryptInit(s, &mut ecb, key), CKR_OK);
        let mut data = *b"hello world";
        let mut n: CK_ULONG = 0;
        assert_eq!(C_Encrypt(s, data.as_mut_ptr(), 11, null_mut(), &mut n), CKR_OK);
        assert_eq!(n, 11);
        let mut ct = [0u8; 11];
        assert_eq!(C_Encrypt(s, data.as_mut_ptr(), 11, ct.as_mut_ptr(), &mut n), CKR_OK);
        assert_ne!(&ct, b"hello world");

        assert_eq!(C_DecryptInit(s, &mut ecb, key), CKR_OK);
        let mut pt = [0u8; 11];
        let mut n: CK_ULONG = 11;
        assert_eq!(C_Decrypt(s, ct.as_mut_ptr(), 11, pt.as_mut_ptr(), &mut n), CKR_OK);
        assert_eq!(&pt, b"hello world");

        // too small a buffer reports the size and leaves the operation active
        assert_eq!(C_EncryptInit(s, &mut ecb, key), CKR_OK);
        let mut small = [0u8; 3];
        let mut n: CK_ULONG = 3;
        assert_eq!(C_Encrypt(s, data.as_mut_ptr(), 11, small.as_mut_ptr(), &mut n), CKR_BUFFER_TOO_SMALL);
        assert_eq!(n, 11);

        let mut rnd = [0u8; 16];
        assert_eq!(C_GenerateRandom(s, rnd.as_mut_ptr(), 16), CKR_OK);
        assert!(rnd.iter().any(|&b| b != 0));
        assert_eq!(C_GenerateRandom(s, null_mut(), 16), CKR_ARGUMENTS_BAD);
    }
}

#[test]
fn sign_and_verify() {
    let _e = env();
    unsafe {
        let s = open_rw();
        login(s);
        let mut mech = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: null_mut(), ulParameterLen: 0 };
        let mut key = 0;
        assert_eq!(C_GenerateKey(s, &mut mech, null_mut(), 0, &mut key), CKR_OK);
        let mut hm = CK_MECHANISM { mechanism: CKM_SHA256_HMAC, pParameter: null_mut(), ulParameterLen: 0 };
        let mut msg = *b"message";
        assert_eq!(C_SignInit(s, &mut hm, key), CKR_OK);
        let mut sig = [0u8; 16];
        let mut n: CK_ULONG = 16;
        assert_eq!(C_Sign(s, msg.as_mut_ptr(), 7, sig.as_mut_ptr(), &mut n), CKR_OK);
        assert_eq!(n, 8);
        assert_eq!(C_VerifyInit(s, &mut hm, key), CKR_OK);
        assert_eq!(C_Verify(s, msg.as_mut_ptr(), 7, sig.as_mut_ptr(), 8), CKR_OK);
        assert_eq!(C_VerifyInit(s, &mut hm, key), CKR_OK);
        sig[0] ^= 1;
        assert_eq!(C_Verify(s, msg.as_mut_ptr(), 7, sig.as_mut_ptr(), 8), CKR_SIGNATURE_INVALID);
    }
}

#[test]
fn errors_and_argument_checks() {
    let _e = env();
    unsafe {
        assert_eq!(C_Login(0xdead, CKU_USER, null_mut(), 0), CKR_SESSION_HANDLE_INVALID);
        // a session that never existed for this client
        let mut n = 0;
        assert_eq!(C_FindObjects(1, null_mut(), 0, &mut n), CKR_SESSION_HANDLE_INVALID);
        // NULL where the contract forbids it
        assert_eq!(C_OpenSession(SLOT, CKF_SERIAL_SESSION, null_mut(), None, null_mut()), CKR_ARGUMENTS_BAD);
        assert_eq!(C_EncryptInit(1, null_mut(), 1), CKR_ARGUMENTS_BAD);
        // data pointers with lengths but no memory
        let s = open_rw();
        assert_eq!(C_DigestUpdate(s, null_mut(), 5), CKR_ARGUMENTS_BAD);
        // parameters the library can't carry are refused before they leave
        let mut junk = [0u8; 4];
        let mut m = CK_MECHANISM { mechanism: CKM_AES_CBC, pParameter: junk.as_mut_ptr().cast(), ulParameterLen: 4 };
        assert_eq!(C_DigestInit(s, &mut m,), CKR_MECHANISM_PARAM_INVALID);
    }
}

#[test]
fn pin_may_be_null_for_protected_paths() {
    let _e = env();
    unsafe {
        let s = open_rw();
        // NULL pin with zero length is passed on as "no pin"; the mock refuses it
        assert_eq!(C_Login(s, CKU_USER, null_mut(), 0), CKR_PIN_INCORRECT);
        assert_eq!(C_Login(s, CKU_USER, null_mut(), 4), CKR_ARGUMENTS_BAD);
    }
}

#[test]
fn slot_events_block_without_stopping_other_threads() {
    let e = env();
    unsafe {
        let mock = e.mock.clone();
        let t = std::thread::spawn(|| {
            let mut slot = 0;
            let rv = C_WaitForSlotEvent(0, &mut slot, null_mut());
            (rv, slot)
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(C_GetInfo(&mut info), CKR_OK, "other calls proceed while one waits");
        mock.slot_event(8);
        assert_eq!(t.join().unwrap(), (CKR_OK, 8));
        let mut slot = 0;
        assert_eq!(C_WaitForSlotEvent(CKF_DONT_BLOCK, &mut slot, null_mut()), CKR_NO_EVENT);
    }
}

#[test]
fn many_threads_share_the_library() {
    let e = env();
    unsafe {
        let s = open_rw();
        login(s);
    }
    let mut ts = Vec::new();
    for i in 0..8u8 {
        ts.push(std::thread::spawn(move || unsafe {
            let mut s = 0;
            assert_eq!(C_OpenSession(SLOT, CKF_SERIAL_SESSION, null_mut(), None, &mut s), CKR_OK);
            for _ in 0..50 {
                let mut rnd = [0u8; 8];
                assert_eq!(C_GenerateRandom(s, rnd.as_mut_ptr(), 8), CKR_OK);
            }
            assert_eq!(C_CloseSession(s), CKR_OK);
            i
        }));
    }
    for t in ts {
        t.join().unwrap();
    }
    assert_eq!(e.mock.open_sessions(), 1);
    assert!(e.server.context_count() == 1);
}

#[test]
fn initialize_and_finalize_semantics() {
    let e = env();
    unsafe {
        // already initialised by the fixture
        assert_eq!(C_Initialize(null_mut()), CKR_CRYPTOKI_ALREADY_INITIALIZED);
        assert_eq!(C_Finalize(std::ptr::dangling_mut()), CKR_ARGUMENTS_BAD);
        let s = open_rw();
        assert_eq!(C_Finalize(null_mut()), CKR_OK);
        assert_eq!(e.mock.open_sessions(), 0, "finalize closes the sessions");
        assert_eq!(C_Finalize(null_mut()), CKR_CRYPTOKI_NOT_INITIALIZED);
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(C_GetInfo(&mut info), CKR_CRYPTOKI_NOT_INITIALIZED);
        let _ = s;
        // reinitialise through the fixture path for the drop of the session guard
        let lb = Loopback { server: e.server.clone(), identity: "test".into() };
        let core = p11_proxy::core::Core::open(Box::new(lb), CoreConfig::default()).unwrap();
        p11_proxy::exports::initialize_with(core).unwrap();
        assert_eq!(C_GetInfo(&mut info), CKR_OK);
    }
}

#[test]
fn function_lists_and_interfaces() {
    unsafe {
        let mut l: *mut CK_FUNCTION_LIST = null_mut();
        assert_eq!(C_GetFunctionList(&mut l), CKR_OK);
        assert_eq!((*l).version.major, 2);
        assert!((*l).C_Encrypt.is_some());
        assert_eq!(C_GetFunctionList(null_mut()), CKR_ARGUMENTS_BAD);

        let mut n = 0;
        assert_eq!(C_GetInterfaceList(null_mut(), &mut n), CKR_OK);
        assert_eq!(n, 4);
        let mut list: [CK_INTERFACE; 4] = std::mem::zeroed();
        let mut cap = 3;
        assert_eq!(C_GetInterfaceList(list.as_mut_ptr(), &mut cap), CKR_BUFFER_TOO_SMALL);
        let mut cap = 4;
        assert_eq!(C_GetInterfaceList(list.as_mut_ptr(), &mut cap), CKR_OK);
        let versions: Vec<(u8, u8)> = list
            .iter()
            .map(|i| {
                let v = *(i.pFunctionList as *const CK_VERSION);
                (v.major, v.minor)
            })
            .collect();
        assert_eq!(versions, [(3, 2), (3, 1), (3, 0), (2, 40)]);

        // default: the newest
        let mut iface: *mut CK_INTERFACE = null_mut();
        assert_eq!(C_GetInterface(null_mut(), null_mut(), &mut iface, 0), CKR_OK);
        assert_eq!((*((*iface).pFunctionList as *const CK_VERSION)).minor, 2);
        // exact version by name
        let mut v = CK_VERSION { major: 3, minor: 0 };
        let mut name = *b"PKCS 11\0";
        assert_eq!(C_GetInterface(name.as_mut_ptr(), &mut v, &mut iface, 0), CKR_OK);
        assert_eq!((*((*iface).pFunctionList as *const CK_VERSION)).minor, 0);
        // 3.0 lists carry the 3.x functions
        let l30 = (*iface).pFunctionList as *const CK_FUNCTION_LIST_3_0;
        assert!((*l30).C_LoginUser.is_some() && (*l30).C_MessageEncryptInit.is_some());
        // unknown name, version or required flags
        let mut bad = *b"nope\0";
        assert_eq!(C_GetInterface(bad.as_mut_ptr(), null_mut(), &mut iface, 0), CKR_ARGUMENTS_BAD);
        assert!(iface.is_null());
        let mut v = CK_VERSION { major: 9, minor: 9 };
        assert_eq!(C_GetInterface(null_mut(), &mut v, &mut iface, 0), CKR_ARGUMENTS_BAD);
        assert_eq!(C_GetInterface(null_mut(), null_mut(), &mut iface, CKF_INTERFACE_FORK_SAFE), CKR_ARGUMENTS_BAD);
        let _ = null::<u8>();
    }
}
