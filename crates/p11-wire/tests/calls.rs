use p11_wire::attr::*;
use p11_wire::calls::*;
use p11_wire::structs::*;
use p11_wire::Seq;
use proptest::prelude::*;

#[test]
fn call_table_is_consistent() {
    for (i, c) in CALLS.iter().enumerate() {
        assert_eq!(c.id as usize, i + 1);
        assert_eq!(call_info(c.id), Some(c));
    }
    assert_eq!(call_info(0), None);
    assert_eq!(call_info(CALLS.len() as u16 + 1), None);
    assert_eq!(CALL_ENCRYPT, 33);
    assert_eq!(CALLS[32].name, "C_Encrypt");
    assert!(CALLS[22].rw && !CALLS[32].rw);
}

#[test]
fn golden_encrypt_request() {
    let r = Request::Encrypt(EncryptReq { session: 0x0102, data: vec![0xaa, 0xbb], encrypted: OutSpec::Capacity(16) });
    assert_eq!(r.call_id(), 33);
    assert_eq!(
        r.encode_body(),
        [
            0, 0, 0, 0, 0, 0, 1, 2, // session
            0, 0, 0, 2, 0xaa, 0xbb, // data
            1, 0, 0, 0, 0, 0, 0, 0, 16, // OutSpec::Capacity(16)
        ]
    );
    assert_eq!(Request::decode(33, &r.encode_body()).unwrap(), r);
}

#[test]
fn golden_get_slot_list_response() {
    let r =
        Response::GetSlotList(GetSlotListResp { slots: OutU64s { len: 2, data: Some(p11_wire::U64s(vec![1, 5])) } });
    let b = r.encode_body();
    assert_eq!(b, [0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5]);
    assert_eq!(Response::decode(4, &b).unwrap(), r);
}

#[test]
fn template_and_query_roundtrip() {
    let r = Request::CreateObject(CreateObjectReq {
        session: 1,
        template: Seq(vec![Attr { ty: 0, val: AttrVal::Ulong(4) }, Attr { ty: 0x103, val: AttrVal::Bytes(vec![1]) }]),
    });
    assert_eq!(Request::decode(23, &r.encode_body()).unwrap(), r);
    let q = Request::GetAttributeValue(GetAttributeValueReq {
        session: 1,
        object: 2,
        template: Seq(vec![Query { ty: 0x11, slot: Slot::Length }]),
    });
    assert_eq!(Request::decode(27, &q.encode_body()).unwrap(), q);
}

#[test]
fn unknown_and_malformed() {
    assert_eq!(Request::decode(0, &[]).unwrap_err(), RequestError::Unknown);
    assert_eq!(Request::decode(60000, &[]).unwrap_err(), RequestError::Unknown);
    assert!(matches!(Request::decode(33, &[1, 2, 3]).unwrap_err(), RequestError::Malformed(_)));
    // trailing bytes are malformed
    let mut b = Request::Logout(LogoutReq { session: 1 }).encode_body();
    b.push(0);
    assert!(matches!(Request::decode(22, &b).unwrap_err(), RequestError::Malformed(_)));
}

proptest! {
    #[test]
    fn every_call_survives_garbage(call in 0u16..120, body in proptest::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(r) = Request::decode(call, &body) {
            // whatever decodes must re-encode to the same bytes
            prop_assert_eq!(r.encode_body(), body.clone());
        }
        if let Ok(r) = Response::decode(call, &body) {
            prop_assert_eq!(r.encode_body(), body);
        }
    }
}

#[test]
fn pins_are_not_printed_and_calls_know_they_carry_them() {
    use p11_wire::Secret;
    let r = Request::Login(LoginReq { session: 1, user_type: 1, pin: Some(Secret::from(&b"hunter2"[..])) });
    let shown = format!("{r:?}");
    assert!(!shown.contains("hunter2") && shown.contains("Secret(<7 bytes>)"), "{shown}");
    let secret_calls: Vec<&str> = CALLS.iter().filter(|c| c.secret).map(|c| c.name).collect();
    assert_eq!(secret_calls, ["C_InitToken", "C_InitPIN", "C_SetPIN", "C_Login", "C_LoginUser"]);
    // and they go over the wire exactly as before
    assert_eq!(Request::decode(21, &r.encode_body()).unwrap(), r);
}
