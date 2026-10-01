use p11_daemon::*;
use p11_module::Backend;
use p11_testkit::mock::*;
use p11_testkit::raw::*;
use p11_types::*;
use p11_wire::attr::*;
use p11_wire::calls::*;
use p11_wire::frame::*;
use p11_wire::structs::*;
use p11_wire::Seq;
use std::sync::Arc;

fn server_with(policy: Policy) -> (Arc<Server>, Arc<Mock>) {
    let mock = Arc::new(Mock::new());
    (Arc::new(Server::new(mock.clone(), policy, Limits::default())), mock)
}

fn server() -> (Arc<Server>, Arc<Mock>) {
    server_with(Policy::allow_all(Rules::default()))
}

fn ok(rv: u64) {
    assert_eq!(rv, 0, "rv 0x{rv:x}");
}

fn init(c: &mut RawClient) {
    ok(c.call(&Request::Initialize(InitializeReq {})).0);
}

fn open(c: &mut RawClient) -> u64 {
    let (rv, r) = c.call(&Request::OpenSession(OpenSessionReq {
        slot: SLOT,
        flags: (CKF_SERIAL_SESSION | CKF_RW_SESSION) as u64,
    }));
    ok(rv);
    let Some(Response::OpenSession(r)) = r else { panic!() };
    r.session
}

fn login(c: &mut RawClient, s: u64) {
    ok(c.call(&Request::Login(LoginReq {
        session: s,
        user_type: CKU_USER as u64,
        pin: Some(p11_wire::Secret::from(USER_PIN.to_vec())),
    }))
    .0);
}

fn data_object(c: &mut RawClient, s: u64, label: &[u8]) -> u64 {
    let (rv, r) = c.call(&Request::CreateObject(CreateObjectReq {
        session: s,
        template: Seq(vec![
            Attr { ty: CKA_CLASS as u64, val: AttrVal::Ulong(CKO_DATA as u64) },
            Attr { ty: CKA_LABEL as u64, val: AttrVal::Bytes(label.to_vec()) },
        ]),
    }));
    ok(rv);
    let Some(Response::CreateObject(r)) = r else { panic!() };
    r.object
}

#[cfg(feature = "vendor")]
fn hello_asking_for_vendor_mechanisms() -> p11_wire::handshake::Hello {
    let mut h = hello(None);
    h.features = p11_wire::handshake::features::VENDOR_MECHANISMS;
    h
}

#[cfg(feature = "vendor")]
fn stream_client(srv: &Arc<Server>) -> RawClient {
    let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
    let s = srv.clone();
    std::thread::spawn(move || {
        let _ = s.serve(b, &Identity::anonymous());
    });
    RawClient::from_stream(a)
}

#[test]
#[cfg(feature = "vendor")]
fn vendor_mechanisms_are_announced_only_to_a_client_that_asks() {
    use p11_wire::codec::from_slice;
    use p11_wire::handshake::{features, VendorEntry, VendorMechs};
    let list = [
        p11_params::vendor::VendorMech { id: 0x8000_0123, length: Some(16), ..Default::default() },
        p11_params::vendor::VendorMech { id: 0x8000_0124, max_length: Some(64), ..Default::default() },
    ];
    let mock = Arc::new(Mock::new());
    let with = Arc::new(
        Server::new(mock.clone(), Policy::allow_all(Rules::default()), Limits::default())
            .with_vendor_mechanisms(&list, &[])
            .unwrap(),
    );

    // asked for, and there are some: the bit in the ack, and the list right after it
    let mut c = stream_client(&with);
    let Hi::Ack(ack) = c.exchange_hello(&hello_asking_for_vendor_mechanisms()) else { panic!("refused") };
    assert_eq!(ack.features, features::VENDOR_MECHANISMS);
    let f = read_frame(&mut c.stream).unwrap();
    assert_eq!(f.kind, Kind::VendorMechanisms);
    assert_eq!(
        from_slice::<VendorMechs>(&f.payload).unwrap(),
        VendorMechs(
            vec![
                VendorEntry { id: 0x8000_0123, param: p11_wire::handshake::VendorParam::Exact(16) },
                VendorEntry { id: 0x8000_0124, param: p11_wire::handshake::VendorParam::Max(64) },
            ],
            vec![]
        )
    );
    // and the connection then works as any other
    init(&mut c);

    // not asked for: nothing extra, the first frame after the ack is a response
    let mut c = stream_client(&with);
    let Hi::Ack(ack) = c.exchange_hello(&hello(None)) else { panic!("refused") };
    assert_eq!(ack.features, features::NONE);
    init(&mut c);

    // asked for, but there are none: no bit, no frame
    let (without, _m) = server();
    let mut c = stream_client(&without);
    let Hi::Ack(ack) = c.exchange_hello(&hello_asking_for_vendor_mechanisms()) else { panic!("refused") };
    assert_eq!(ack.features, features::NONE);
    init(&mut c);
}

#[test]
#[cfg(feature = "vendor")]
fn vendor_functions_are_announced_only_to_a_client_that_asks() {
    use p11_wire::codec::from_slice;
    use p11_wire::handshake::features;
    use p11_wire::vendorfn::{ArgKind, FnDesc, VendorFns};
    let list = vec![
        FnDesc { name: "Vnd_GetId".into(), rw: false, args: vec![ArgKind::Session, ArgKind::OU64] },
        FnDesc { name: "Vnd_SetPin".into(), rw: true, args: vec![ArgKind::Session, ArgKind::U64, ArgKind::Secret] },
    ];
    let mock = Arc::new(Mock::new());
    let with = Arc::new(
        Server::new(mock.clone(), Policy::allow_all(Rules::default()), Limits::default()).with_vendor_functions(&list),
    );
    let asking = |bits: u64| {
        let mut h = hello(None);
        h.features = bits;
        h
    };

    // asked for: the bit in the ack, the frame right after, then requests as usual
    let mut c = stream_client(&with);
    let Hi::Ack(ack) = c.exchange_hello(&asking(features::VENDOR_FUNCTIONS)) else { panic!("refused") };
    assert_eq!(ack.features, features::VENDOR_FUNCTIONS);
    let f = read_frame(&mut c.stream).unwrap();
    assert_eq!(f.kind, Kind::VendorFunctions);
    assert_eq!(from_slice::<VendorFns>(&f.payload).unwrap(), VendorFns(list.clone()));
    init(&mut c);

    // both kinds asked for and only functions declared: the ack says so and only that frame follows
    let mut c = stream_client(&with);
    let Hi::Ack(ack) = c.exchange_hello(&asking(features::VENDOR_FUNCTIONS | features::VENDOR_MECHANISMS)) else {
        panic!("refused")
    };
    assert_eq!(ack.features, features::VENDOR_FUNCTIONS);
    assert_eq!(read_frame(&mut c.stream).unwrap().kind, Kind::VendorFunctions);
    init(&mut c);

    // not asked for: nothing extra
    let mut c = stream_client(&with);
    let Hi::Ack(ack) = c.exchange_hello(&asking(0)) else { panic!("refused") };
    assert_eq!(ack.features, features::NONE);
    init(&mut c);

    // a vendor call before the daemon has anything declared is not supported
    let (without, _m) = server();
    let mut c = stream_client(&without);
    let Hi::Ack(_) = c.exchange_hello(&asking(features::VENDOR_FUNCTIONS)) else { panic!("refused") };
    init(&mut c);
    let body = p11_wire::vendorfn::VendorRequest { name: "Vnd_GetId".into(), args: vec![] }.encode();
    write_frame(&mut c.stream, Kind::Request, &build_request(9, p11_wire::vendorfn::CALL_VENDOR, &body)).unwrap();
    let f = read_frame(&mut c.stream).unwrap();
    let (h, _) = parse_response(&f.payload).unwrap();
    assert_eq!((h.id, h.rv), (9, CKR_FUNCTION_NOT_SUPPORTED as u64));
    // and a malformed body for a function that is declared drops the connection
    p11_params::vendorfn::set(&list).unwrap();
    write_frame(&mut c.stream, Kind::Request, &build_request(10, p11_wire::vendorfn::CALL_VENDOR, &body)).unwrap();
    let f = read_frame(&mut c.stream).unwrap();
    assert_eq!(f.kind, Kind::Abort);
    p11_params::vendorfn::set(&[]).unwrap();
}

#[test]
fn handshake_versions_and_policy() {
    let (srv, _m) = server();
    // a client that only speaks a newer protocol is refused
    let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
    let s = srv.clone();
    let t = std::thread::spawn(move || s.serve(b, &Identity::anonymous()));
    let mut c = RawClient::from_stream(a);
    let mut h = hello(None);
    h.min_version = 2;
    h.max_version = 3;
    assert!(matches!(c.exchange_hello(&h), Hi::Abort(AbortReason::Version)));
    assert!(t.join().unwrap().is_err());

    // an identity the policy doesn't know is refused
    let strict = Policy::default().with_identity("alice", Rules::default());
    let (srv, _m) = server_with(strict);
    assert!(RawClient::connect(&srv, "mallory", None).is_err());
    let c = RawClient::connect(&srv, "alice", None).unwrap();
    c.close().unwrap();
}

#[test]
fn initialize_is_required_and_per_context() {
    let (srv, m) = server();
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    let (rv, _) = c.call(&Request::GetInfo(GetInfoReq {}));
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as u64);
    assert_eq!(c.call(&Request::Finalize(FinalizeReq {})).0, CKR_CRYPTOKI_NOT_INITIALIZED as u64);
    init(&mut c);
    assert_eq!(c.call(&Request::Initialize(InitializeReq {})).0, CKR_CRYPTOKI_ALREADY_INITIALIZED as u64);
    let (rv, r) = c.call(&Request::GetInfo(GetInfoReq {}));
    ok(rv);
    assert!(matches!(r, Some(Response::GetInfo(_))));
    // nothing reached the module for the calls that were refused
    assert_eq!(m.calls(), vec![CALL_GET_INFO]);
    c.close().unwrap();
}

#[test]
fn handles_are_virtual_and_private_to_the_client() {
    let (srv, m) = server();
    let mut a = RawClient::connect(&srv, "a", None).unwrap();
    let mut b = RawClient::connect(&srv, "b", None).unwrap();
    init(&mut a);
    init(&mut b);
    let sa = open(&mut a);
    let sb = open(&mut b);
    // the client's handles are small counters, not the module's
    assert_eq!(sa, 1);
    assert_eq!(sb, 1);
    login(&mut a, sa);
    let oa = data_object(&mut a, sa, b"mine");
    assert_eq!(oa, 1);
    assert!(m.object_count() == 1);

    // b can't use a's session or object handles: its own table has no such entries
    let (rv, _) = b.call(&Request::GetObjectSize(GetObjectSizeReq { session: sb, object: oa }));
    assert_eq!(rv, CKR_OBJECT_HANDLE_INVALID as u64);
    let (rv, _) = b.call(&Request::GetObjectSize(GetObjectSizeReq { session: 0x5000, object: 1 }));
    assert_eq!(rv, CKR_SESSION_HANDLE_INVALID as u64);
    let (rv, _) = a.call(&Request::GetObjectSize(GetObjectSizeReq { session: sa, object: 0x1000 }));
    assert_eq!(rv, CKR_OBJECT_HANDLE_INVALID as u64, "the module's own handle is not a valid client handle");

    // a can use its own
    let (rv, r) = a.call(&Request::GetObjectSize(GetObjectSizeReq { session: sa, object: oa }));
    ok(rv);
    assert!(matches!(r, Some(Response::GetObjectSize(_))));
    a.close().unwrap();
    b.close().unwrap();
}

#[test]
fn find_objects_returns_client_handles() {
    let (srv, _m) = server();
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut c);
    let s = open(&mut c);
    login(&mut c, s);
    let o1 = data_object(&mut c, s, b"x");
    let o2 = data_object(&mut c, s, b"y");
    ok(c.call(&Request::FindObjectsInit(FindObjectsInitReq { session: s, template: Seq(vec![]) })).0);
    let (rv, r) = c.call(&Request::FindObjects(FindObjectsReq { session: s, objects: 10 }));
    ok(rv);
    let Some(Response::FindObjects(r)) = r else { panic!() };
    assert_eq!(r.objects.0, vec![o1, o2], "the same module object keeps the same client handle");
    ok(c.call(&Request::FindObjectsFinal(FindObjectsFinalReq { session: s })).0);

    // destroying forgets the mapping
    ok(c.call(&Request::DestroyObject(DestroyObjectReq { session: s, object: o1 })).0);
    let (rv, _) = c.call(&Request::GetObjectSize(GetObjectSizeReq { session: s, object: o1 }));
    assert_eq!(rv, CKR_OBJECT_HANDLE_INVALID as u64);
    c.close().unwrap();
}

#[test]
fn sessions_are_closed_when_the_client_goes_away() {
    let (srv, m) = server();
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut c);
    open(&mut c);
    open(&mut c);
    assert_eq!(m.open_sessions(), 2);
    c.close().unwrap();
    assert_eq!(m.open_sessions(), 0);
    assert_eq!(srv.context_count(), 0);
}

#[test]
fn close_all_sessions_only_closes_the_callers() {
    let (srv, m) = server();
    let mut a = RawClient::connect(&srv, "a", None).unwrap();
    let mut b = RawClient::connect(&srv, "b", None).unwrap();
    init(&mut a);
    init(&mut b);
    open(&mut a);
    open(&mut a);
    let sb = open(&mut b);
    ok(a.call(&Request::CloseAllSessions(CloseAllSessionsReq { slot: SLOT })).0);
    assert_eq!(m.open_sessions(), 1, "b's session survives a's CloseAllSessions");
    let (rv, _) = b.call(&Request::GetSessionInfo(GetSessionInfoReq { session: sb }));
    ok(rv);
    a.close().unwrap();
    b.close().unwrap();
}

#[test]
fn finalize_releases_sessions_and_allows_initialize_again() {
    let (srv, m) = server();
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut c);
    let s = open(&mut c);
    ok(c.call(&Request::Finalize(FinalizeReq {})).0);
    assert_eq!(m.open_sessions(), 0);
    let (rv, _) = c.call(&Request::GetSessionInfo(GetSessionInfoReq { session: s }));
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as u64);
    init(&mut c);
    c.close().unwrap();
}

#[test]
fn pooled_connections_share_one_context() {
    let (srv, m) = server();
    let mut a = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut a);
    let s = open(&mut a);
    let mut a2 = RawClient::connect(&srv, "a", Some(a.token)).unwrap();
    assert_eq!(a2.token, a.token);
    // the second connection sees the first one's session and initialised state
    let (rv, _) = a2.call(&Request::GetSessionInfo(GetSessionInfoReq { session: s }));
    ok(rv);

    // another identity can't join with a stolen token
    assert!(matches!(RawClient::connect(&srv, "mallory", Some(a.token)), Err(AbortReason::Unauthorized)));
    // and an unknown token is a protocol error
    assert!(matches!(RawClient::connect(&srv, "a", Some([9; 16])), Err(AbortReason::Protocol)));

    // the context lives until the last connection closes
    a.close().unwrap();
    assert_eq!(srv.context_count(), 1);
    assert_eq!(m.open_sessions(), 1);
    a2.close().unwrap();
    assert_eq!(srv.context_count(), 0);
    assert_eq!(m.open_sessions(), 0);
}

#[test]
fn a_blocked_call_does_not_block_other_connections() {
    let (srv, m) = server();
    let mut a = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut a);
    let mut waiter = RawClient::connect(&srv, "a", Some(a.token)).unwrap();
    let t = std::thread::spawn(move || {
        let r = waiter.call(&Request::WaitForSlotEvent(WaitForSlotEventReq { flags: 0 }));
        (r, waiter)
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    // while one connection waits, the other keeps working
    let (rv, _) = a.call(&Request::GetInfo(GetInfoReq {}));
    ok(rv);
    m.slot_event(SLOT);
    let ((rv, r), waiter) = t.join().unwrap();
    ok(rv);
    let Some(Response::WaitForSlotEvent(r)) = r else { panic!() };
    assert_eq!(r.slot, SLOT);
    waiter.close().unwrap();
    a.close().unwrap();
}

#[test]
fn policy_read_only_slots_mechanisms_attributes() {
    let rules = Rules {
        read_only: true,
        slots: Some([SLOT].into()),
        mechanisms: Some([CKM_SHA256 as u64].into()),
        deny_attrs: [CKA_EXTRACTABLE as u64].into(),
        ..Rules::default()
    };
    let (srv, _m) = server_with(Policy::allow_all(rules));
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut c);

    // read-write sessions and calls that change the token are refused
    let (rv, _) = c.call(&Request::OpenSession(OpenSessionReq {
        slot: SLOT,
        flags: (CKF_SERIAL_SESSION | CKF_RW_SESSION) as u64,
    }));
    assert_eq!(rv, CKR_TOKEN_WRITE_PROTECTED as u64);
    let (rv, r) = c.call(&Request::OpenSession(OpenSessionReq { slot: SLOT, flags: CKF_SERIAL_SESSION as u64 }));
    ok(rv);
    let Some(Response::OpenSession(r)) = r else { panic!() };
    let s = r.session;
    let (rv, _) = c.call(&Request::CreateObject(CreateObjectReq { session: s, template: Seq(vec![]) }));
    assert_eq!(rv, CKR_ACTION_PROHIBITED as u64);

    // slots the identity may not see are hidden
    let (rv, r) = c.call(&Request::GetSlotList(GetSlotListReq { token_present: false, slots: OutSpec::Capacity(10) }));
    ok(rv);
    let Some(Response::GetSlotList(r)) = r else { panic!() };
    assert_eq!(r.slots.data.unwrap().0, vec![SLOT], "the mock has two slots; only one is allowed");
    let (rv, r) = c.call(&Request::GetSlotList(GetSlotListReq { token_present: false, slots: OutSpec::Length }));
    ok(rv);
    let Some(Response::GetSlotList(r)) = r else { panic!() };
    assert_eq!((r.slots.len, r.slots.data.is_none()), (1, true));
    let (rv, _) = c.call(&Request::GetSlotInfo(GetSlotInfoReq { slot: SLOT + 1 }));
    assert_eq!(rv, CKR_SLOT_ID_INVALID as u64);

    // mechanism allow-list applies to lists and to use
    let (rv, r) =
        c.call(&Request::GetMechanismList(GetMechanismListReq { slot: SLOT, mechanisms: OutSpec::Capacity(50) }));
    ok(rv);
    let Some(Response::GetMechanismList(r)) = r else { panic!() };
    assert_eq!(r.mechanisms.data.unwrap().0, vec![CKM_SHA256 as u64]);
    let (rv, _) = c.call(&Request::DigestInit(DigestInitReq {
        session: s,
        mechanism: Mech { mechanism: CKM_SHA224 as u64, param: None },
    }));
    assert_eq!(rv, CKR_MECHANISM_INVALID as u64);
    let (rv, _) = c.call(&Request::DigestInit(DigestInitReq {
        session: s,
        mechanism: Mech { mechanism: CKM_SHA256 as u64, param: None },
    }));
    ok(rv);
    c.close().unwrap();

    // denied attribute types
    let rules = Rules { deny_attrs: [CKA_EXTRACTABLE as u64].into(), ..Rules::default() };
    let (srv, _m) = server_with(Policy::allow_all(rules));
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut c);
    let s = open(&mut c);
    login(&mut c, s);
    let (rv, _) = c.call(&Request::CreateObject(CreateObjectReq {
        session: s,
        template: Seq(vec![Attr { ty: CKA_EXTRACTABLE as u64, val: AttrVal::Bytes(vec![1]) }]),
    }));
    assert_eq!(rv, CKR_ATTRIBUTE_TYPE_INVALID as u64);
    c.close().unwrap();
}

#[test]
fn unknown_calls_and_malformed_bodies() {
    let (srv, m) = server();
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut c);
    // an id from a newer protocol: answered, connection stays up
    write_frame(&mut c.stream, Kind::Request, &build_request(50, 999, &[])).unwrap();
    let f = read_frame(&mut c.stream).unwrap();
    let (h, _) = parse_response(&f.payload).unwrap();
    assert_eq!((h.id, h.rv), (50, CKR_FUNCTION_NOT_SUPPORTED as u64));
    ok(c.call(&Request::GetInfo(GetInfoReq {})).0);

    // a body that doesn't decode is a protocol violation: the daemon hangs up
    write_frame(&mut c.stream, Kind::Request, &build_request(51, CALL_ENCRYPT, &[1, 2, 3])).unwrap();
    let f = read_frame(&mut c.stream).unwrap();
    assert_eq!(f.kind, Kind::Abort);
    assert!(c.close().is_err());
    // nothing reached the module for the bad call
    assert!(!m.calls().contains(&CALL_ENCRYPT));
}

#[test]
fn backend_panics_become_general_errors() {
    struct Boom;
    impl Backend for Boom {
        fn c_get_info(&self, _r: &GetInfoReq) -> p11_module::Reply<GetInfoResp> {
            panic!("module bug")
        }
    }
    let srv = Arc::new(Server::new(Arc::new(Boom), Policy::allow_all(Rules::default()), Limits::default()));
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut c);
    let (rv, _) = c.call(&Request::GetInfo(GetInfoReq {}));
    assert_eq!(rv, CKR_GENERAL_ERROR as u64);
    // the connection survives
    let (rv, _) = c.call(&Request::GetSlotList(GetSlotListReq { token_present: true, slots: OutSpec::Length }));
    assert_eq!(rv, CKR_FUNCTION_NOT_SUPPORTED as u64);
    c.close().unwrap();
}

#[test]
fn message_parameters_must_match_the_selected_mechanism() {
    let (srv, _m) = server();
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut c);
    let s = open(&mut c);
    login(&mut c, s);
    let (rv, r) = c.call(&Request::GenerateKey(GenerateKeyReq {
        session: s,
        mechanism: Mech { mechanism: CKM_AES_KEY_GEN as u64, param: None },
        template: Seq(vec![]),
    }));
    ok(rv);
    let Some(Response::GenerateKey(k)) = r else { panic!() };
    let param = |m: u64| MsgParam { mechanism: m, phase: MSG_ENCRYPT, param: None };
    let msg = |p: MsgParam| {
        Request::EncryptMessage(EncryptMessageReq {
            session: s,
            parameter: p,
            associated_data: vec![],
            plaintext: b"abc".to_vec(),
            ciphertext: OutSpec::Capacity(16),
        })
    };
    // before MessageEncryptInit
    assert_eq!(c.call(&msg(param(CKM_AES_GCM as u64))).0, CKR_OPERATION_NOT_INITIALIZED as u64);
    ok(c.call(&Request::MessageEncryptInit(MessageEncryptInitReq {
        session: s,
        mechanism: Mech { mechanism: CKM_AES_GCM as u64, param: None },
        key: k.key,
    }))
    .0);
    assert_eq!(c.call(&msg(param(CKM_AES_ECB as u64))).0, CKR_MECHANISM_PARAM_INVALID as u64);
    let (rv, r) = c.call(&msg(param(CKM_AES_GCM as u64)));
    ok(rv);
    let Some(Response::EncryptMessage(r)) = r else { panic!() };
    assert_eq!(r.ciphertext.data.unwrap(), b"cba");
    c.close().unwrap();
}

fn send_wait(c: &mut RawClient, flags: u64) {
    let req = Request::WaitForSlotEvent(WaitForSlotEventReq { flags });
    write_frame(&mut c.stream, Kind::Request, &build_request(900, req.call_id(), &req.encode_body())).unwrap();
}

fn eventually(what: &str, f: impl Fn() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !f() {
        assert!(std::time::Instant::now() < end, "timed out waiting for: {what}");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn a_client_that_leaves_while_waiting_for_an_event_is_cleaned_up() {
    let (srv, m) = server();
    let mut a = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut a);
    open(&mut a);
    let mut waiter = RawClient::connect(&srv, "a", Some(a.token)).unwrap();
    send_wait(&mut waiter, 0);
    // the daemon is polling the module on the waiter's behalf; nobody is stuck inside it
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(m.open_sessions(), 1);
    drop(a.stream);
    drop(waiter.stream);
    eventually("the context to be released", || srv.context_count() == 0);
    eventually("the sessions to be closed", || m.open_sessions() == 0);
}

#[test]
fn finalize_wakes_a_waiting_call() {
    let (srv, _m) = server();
    let mut a = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut a);
    let mut waiter = RawClient::connect(&srv, "a", Some(a.token)).unwrap();
    let t = std::thread::spawn(move || waiter.call(&Request::WaitForSlotEvent(WaitForSlotEventReq { flags: 0 })));
    std::thread::sleep(std::time::Duration::from_millis(100));
    ok(a.call(&Request::Finalize(FinalizeReq {})).0);
    let (rv, _) = t.join().unwrap();
    assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED as u64);
}

#[test]
fn events_for_slots_a_client_may_not_see_are_skipped() {
    let rules = Rules { slots: Some([SLOT].into()), ..Rules::default() };
    let (srv, m) = server_with(Policy::allow_all(rules));
    let mut c = RawClient::connect(&srv, "a", None).unwrap();
    init(&mut c);
    let mut waiter = RawClient::connect(&srv, "a", Some(c.token)).unwrap();
    let t = std::thread::spawn(move || waiter.call(&Request::WaitForSlotEvent(WaitForSlotEventReq { flags: 0 })));
    std::thread::sleep(std::time::Duration::from_millis(50));
    m.slot_event(SLOT + 1); // hidden: the waiter keeps waiting
    std::thread::sleep(std::time::Duration::from_millis(100));
    m.slot_event(SLOT);
    let (rv, r) = t.join().unwrap();
    ok(rv);
    let Some(Response::WaitForSlotEvent(r)) = r else { panic!() };
    assert_eq!(r.slot, SLOT);
}

#[test]
#[cfg(not(feature = "vendor"))]
fn a_daemon_built_without_vendor_support_announces_nothing_and_answers_no_vendor_call() {
    use p11_wire::codec::to_vec;
    use p11_wire::handshake::features;
    let (srv, _m) = server();
    let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
    let s = srv.clone();
    std::thread::spawn(move || {
        let _ = s.serve(b, &Identity::anonymous());
    });
    let mut c = RawClient::from_stream(a);
    let mut h = hello(None);
    h.features = features::VENDOR_MECHANISMS | features::VENDOR_FUNCTIONS;
    let Hi::Ack(ack) = c.exchange_hello(&h) else { panic!("refused") };
    assert_eq!(ack.features, features::NONE, "asked for, and not offered");
    init(&mut c);
    // call 1000 is one this build does not know
    let body = to_vec(&0u32);
    write_frame(&mut c.stream, Kind::Request, &build_request(5, 1000, &body)).unwrap();
    let f = read_frame(&mut c.stream).unwrap();
    let (head, _) = parse_response(&f.payload).unwrap();
    assert_eq!((head.id, head.rv), (5, CKR_FUNCTION_NOT_SUPPORTED as u64));
}
