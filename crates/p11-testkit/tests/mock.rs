use p11_module::Backend;
use p11_testkit::mock::*;
use p11_types::*;
use p11_wire::attr::*;
use p11_wire::calls::*;
use p11_wire::structs::*;
use p11_wire::Seq;

fn open(m: &Mock) -> u64 {
    m.c_open_session(&OpenSessionReq { slot: SLOT, flags: (CKF_SERIAL_SESSION | CKF_RW_SESSION) as u64 })
        .resp
        .unwrap()
        .session
}

fn login(m: &Mock, s: u64) {
    assert_eq!(
        m.c_login(&LoginReq {
            session: s,
            user_type: CKU_USER as u64,
            pin: Some(p11_wire::Secret::from(USER_PIN.to_vec()))
        })
        .rv,
        0
    );
}

#[test]
fn sessions_login_and_state() {
    let m = Mock::new();
    let s = open(&m);
    assert_eq!(s, FIRST_SESSION);
    let info = m.c_get_session_info(&GetSessionInfoReq { session: s }).resp.unwrap().info;
    assert_eq!(info.state, CKS_RW_PUBLIC_SESSION as u64);
    assert_eq!(
        m.c_login(&LoginReq { session: s, user_type: 1, pin: Some(p11_wire::Secret::from(b"bad".to_vec())) }).rv,
        CKR_PIN_INCORRECT as u64
    );
    login(&m, s);
    assert_eq!(
        m.c_login(&LoginReq { session: s, user_type: 1, pin: Some(p11_wire::Secret::from(USER_PIN.to_vec())) }).rv,
        CKR_USER_ALREADY_LOGGED_IN as u64
    );
    assert_eq!(m.c_close_session(&CloseSessionReq { session: s }).rv, 0);
    assert_eq!(m.c_close_session(&CloseSessionReq { session: s }).rv, CKR_SESSION_HANDLE_INVALID as u64);
}

#[test]
fn key_cipher_roundtrip() {
    let m = Mock::new();
    let s = open(&m);
    let key = m
        .c_generate_key(&GenerateKeyReq {
            session: s,
            mechanism: Mech { mechanism: CKM_AES_KEY_GEN as u64, param: None },
            template: Seq(vec![Attr { ty: CKA_VALUE_LEN as u64, val: AttrVal::Ulong(32) }]),
        })
        .resp
        .unwrap()
        .key;
    let mech = || Mech { mechanism: CKM_AES_ECB as u64, param: None };
    assert_eq!(m.c_encrypt_init(&EncryptInitReq { session: s, mechanism: mech(), key }).rv, 0);
    let ct = m
        .c_encrypt(&EncryptReq { session: s, data: b"secret".to_vec(), encrypted: OutSpec::Capacity(64) })
        .resp
        .unwrap()
        .encrypted;
    assert_ne!(ct.data.as_deref(), Some(&b"secret"[..]));
    assert_eq!(m.c_decrypt_init(&DecryptInitReq { session: s, mechanism: mech(), key }).rv, 0);
    let pt = m
        .c_decrypt(&DecryptReq { session: s, encrypted: ct.data.unwrap(), data: OutSpec::Capacity(64) })
        .resp
        .unwrap()
        .data;
    assert_eq!(pt.data.unwrap(), b"secret");
}

#[test]
fn two_call_convention_and_failure_injection() {
    let m = Mock::new();
    let r = m.c_get_slot_list(&GetSlotListReq { token_present: false, slots: OutSpec::Capacity(1) });
    assert_eq!(r.rv, CKR_BUFFER_TOO_SMALL as u64);
    assert_eq!(r.resp.unwrap().slots.len, 2);
    m.fail_next(CALL_GET_INFO, CKR_DEVICE_REMOVED);
    assert_eq!(m.c_get_info(&GetInfoReq {}).rv, CKR_DEVICE_REMOVED as u64);
    assert_eq!(m.c_get_info(&GetInfoReq {}).rv, 0);
    assert_eq!(m.calls(), vec![CALL_GET_SLOT_LIST, CALL_GET_INFO, CALL_GET_INFO]);
}

#[test]
fn slot_event_wakes_waiter() {
    let m = std::sync::Arc::new(Mock::new());
    let m2 = m.clone();
    let t = std::thread::spawn(move || m2.c_wait_for_slot_event(&WaitForSlotEventReq { flags: 0 }));
    std::thread::sleep(std::time::Duration::from_millis(50));
    m.slot_event(SLOT + 1);
    assert_eq!(t.join().unwrap().resp.unwrap().slot, SLOT + 1);
    assert_eq!(m.c_wait_for_slot_event(&WaitForSlotEventReq { flags: CKF_DONT_BLOCK as u64 }).rv, CKR_NO_EVENT as u64);
}
