//! DlBackend against a real module. Skipped unless a SoftHSM is available
//! (see p11_testkit::softhsm).

use p11_module::Backend;
use p11_testkit::softhsm::{SoftHsm, USER_PIN};
use p11_types::*;
use p11_wire::calls::*;
use p11_wire::structs::*;

macro_rules! hsm {
    () => {
        match SoftHsm::global() {
            Some(h) => h,
            None => {
                eprintln!("SKIP: no SoftHSM (set P11_SOFTHSM_MODULE and P11_SOFTHSM_UTIL)");
                return;
            }
        }
    };
}

fn ok<T>(r: p11_module::Reply<T>) -> T {
    assert_eq!(r.rv, CKR_OK as u64, "rv 0x{:x}", r.rv);
    r.resp.expect("body")
}

fn done<T>(r: p11_module::Reply<T>) {
    assert_eq!(r.rv, CKR_OK as u64, "rv 0x{:x}", r.rv);
}

fn session(h: &SoftHsm, rw: bool) -> u64 {
    let flags = CKF_SERIAL_SESSION | if rw { CKF_RW_SESSION } else { 0 };
    ok(h.backend.c_open_session(&OpenSessionReq { slot: h.slot, flags: flags as u64 })).session
}

#[test]
fn info_and_token() {
    let h = hsm!();
    let info = ok(h.backend.c_get_info(&GetInfoReq {})).info;
    assert!(info.cryptoki_version.major >= 2);
    let t = ok(h.backend.c_get_token_info(&GetTokenInfoReq { slot: h.slot })).info;
    let label = p11_testkit::softhsm::token_label();
    assert_eq!(&t.label[..label.len()], label.as_bytes());
    assert!(t.flags & CKF_TOKEN_INITIALIZED as u64 != 0);
}

#[test]
fn two_call_convention() {
    let h = hsm!();
    // length only
    let r = ok(h.backend.c_get_mechanism_list(&GetMechanismListReq { slot: h.slot, mechanisms: OutSpec::Length }));
    assert!(r.mechanisms.len > 10);
    assert!(r.mechanisms.data.is_none());
    // buffer too small still reports the size
    let r = h.backend.c_get_mechanism_list(&GetMechanismListReq { slot: h.slot, mechanisms: OutSpec::Capacity(2) });
    assert_eq!(r.rv, CKR_BUFFER_TOO_SMALL as u64);
    assert!(r.resp.unwrap().mechanisms.len > 10);
}

#[test]
fn login_random_digest() {
    let h = hsm!();
    let s = session(h, true);
    let r = h.backend.c_login(&LoginReq {
        session: s,
        user_type: CKU_USER as u64,
        pin: Some(p11_wire::Secret::from(USER_PIN.as_bytes().to_vec())),
    });
    assert!(r.rv == CKR_OK as u64 || r.rv == CKR_USER_ALREADY_LOGGED_IN as u64);
    let rnd = ok(h.backend.c_generate_random(&GenerateRandomReq { session: s, random: 32 })).random;
    assert_eq!(rnd.len(), 32);
    assert!(rnd.iter().any(|&b| b != 0));

    done(
        h.backend.c_digest_init(&DigestInitReq {
            session: s,
            mechanism: Mech { mechanism: CKM_SHA256 as u64, param: None },
        }),
    );
    let d =
        ok(h.backend.c_digest(&DigestReq { session: s, data: b"abc".to_vec(), digest: OutSpec::Capacity(64) })).digest;
    assert_eq!(d.len, 32);
    assert_eq!(
        d.data.unwrap(),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03,
            0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        ]
    );
    done(h.backend.c_close_session(&CloseSessionReq { session: s }));
}

#[test]
fn objects_and_attributes() {
    use p11_wire::attr::*;
    let h = hsm!();
    let s = session(h, true);
    let _ = h.backend.c_login(&LoginReq {
        session: s,
        user_type: CKU_USER as u64,
        pin: Some(p11_wire::Secret::from(USER_PIN.as_bytes().to_vec())),
    });
    let tpl = |label: &[u8]| {
        p11_wire::Seq(vec![
            Attr { ty: CKA_CLASS as u64, val: AttrVal::Ulong(CKO_DATA as u64) },
            Attr { ty: CKA_TOKEN as u64, val: AttrVal::Bytes(vec![0]) },
            Attr { ty: CKA_LABEL as u64, val: AttrVal::Bytes(label.to_vec()) },
            Attr { ty: CKA_VALUE as u64, val: AttrVal::Bytes(b"hello".to_vec()) },
        ])
    };
    let obj = ok(h.backend.c_create_object(&CreateObjectReq { session: s, template: tpl(b"obj-1") })).object;
    done(h.backend.c_find_objects_init(&FindObjectsInitReq {
        session: s,
        template: p11_wire::Seq(vec![Attr { ty: CKA_LABEL as u64, val: AttrVal::Bytes(b"obj-1".to_vec()) }]),
    }));
    let found = ok(h.backend.c_find_objects(&FindObjectsReq { session: s, objects: 10 })).objects;
    done(h.backend.c_find_objects_final(&FindObjectsFinalReq { session: s }));
    assert_eq!(found.0, vec![obj]);

    let q = p11_wire::Seq(vec![
        Query { ty: CKA_CLASS as u64, slot: Slot::Capacity(8) },
        Query { ty: CKA_VALUE as u64, slot: Slot::Length },
        Query { ty: CKA_LABEL as u64, slot: Slot::Capacity(2) },
        Query { ty: CKA_MODULUS as u64, slot: Slot::Capacity(8) },
    ]);
    let r = h.backend.c_get_attribute_value(&GetAttributeValueReq { session: s, object: obj, template: q });
    // The label buffer is too small and a data object has no modulus: PKCS#11 marks both
    // unavailable and reports the failure as the call's result, the type error being the last.
    assert_eq!(r.rv, CKR_ATTRIBUTE_TYPE_INVALID as u64);
    let a = r.resp.unwrap().template.0;
    assert_eq!(a[0].answer, Answer::Ulong(CKO_DATA as u64));
    assert_eq!(a[1].answer, Answer::Length(5));
    if p11_testkit::softhsm::external() {
        // some modules report the length a too small buffer needs instead of -1, and an empty
        // value for an attribute the object does not have
        assert!(matches!(a[2].answer, Answer::Unavailable | Answer::Length(5)), "{:?}", a[2].answer);
        assert!(
            matches!(&a[3].answer, Answer::Unavailable) || a[3].answer == Answer::Bytes(vec![]),
            "{:?}",
            a[3].answer
        );
    } else {
        assert_eq!(a[2].answer, Answer::Unavailable);
        assert_eq!(a[3].answer, Answer::Unavailable);
    }

    done(h.backend.c_destroy_object(&DestroyObjectReq { session: s, object: obj }));
    done(h.backend.c_close_session(&CloseSessionReq { session: s }));
}

#[test]
fn errors_pass_through() {
    let h = hsm!();
    let r = h.backend.c_digest(&DigestReq { session: 0xdead_beef, data: vec![], digest: OutSpec::Length });
    assert_eq!(r.rv, CKR_SESSION_HANDLE_INVALID as u64);
    assert!(r.resp.is_none());
}
