//! An in-memory PKCS#11 provider for tests that must not depend on a real
//! module. It behaves like a small token: one slot, sessions, login, data and
//! secret-key objects with attributes, a toy cipher (XOR with the key), a toy
//! MAC and digest, deterministic randomness, and a slot-event queue. It is
//! not cryptography; it exists to make every layer above it observable.

use p11_module::{Backend, Reply};
use p11_types::*;
use p11_wire::attr::*;
use p11_wire::calls::*;
use p11_wire::structs::*;
use p11_wire::{Node, Seq, U64s};
use std::collections::HashMap;
use std::sync::{Condvar, Mutex};

pub const SLOT: u64 = 7;
pub const USER_PIN: &[u8] = b"1234";
/// Object handles the mock hands out start here, so they never look like the
/// small virtual handles the daemon gives clients.
pub const FIRST_OBJECT: u64 = 0x1000;
pub const FIRST_SESSION: u64 = 0x5000;

#[derive(Debug, Clone)]
enum Op {
    None,
    Digest(Vec<u8>),
    Cipher { key: Vec<u8>, decrypt: bool },
    Mac { key: Vec<u8>, data: Vec<u8>, verify: bool },
    SigVerify { key: Vec<u8>, data: Vec<u8>, sig: Vec<u8> },
    MsgKey(Vec<u8>),
}

#[derive(Debug)]
struct Sess {
    flags: u64,
    find: Option<Vec<u64>>,
    op: Op,
    msg_mech: Option<u64>,
}

#[derive(Debug, Clone)]
struct Obj {
    attrs: Vec<(u64, AttrVal)>,
    /// session object: dies with its session
    owner: Option<u64>,
}

#[derive(Debug, Default)]
struct State {
    sessions: HashMap<u64, Sess>,
    objects: HashMap<u64, Obj>,
    next_session: u64,
    next_object: u64,
    logged_in: bool,
    events: Vec<u64>,
    log: Vec<u16>,
    fail: HashMap<u16, u64>,
    rnd: u64,
    vendor_param: Option<Vec<u8>>,
    vendor_node: Option<Node>,
    vendor_syms: HashMap<String, usize>,
}

/// A vendor-defined mechanism the mock digests with, to test declared vendor mechanisms.
pub const VENDOR_DIGEST: u64 = 0x8000_0100;

#[derive(Debug)]
pub struct Mock {
    st: Mutex<State>,
    cv: Condvar,
}

impl Default for Mock {
    fn default() -> Self {
        Self::new()
    }
}

fn fnv(data: &[u8], seed: u64) -> u64 {
    let mut h = 0xcbf29ce484222325u64 ^ seed;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn xor(key: &[u8], data: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len().max(1)]).collect()
}

fn pad<const N: usize>(s: &str) -> [u8; N] {
    let mut a = [b' '; N];
    a[..s.len().min(N)].copy_from_slice(&s.as_bytes()[..s.len().min(N)]);
    a
}

fn size_of_val(v: &AttrVal) -> u64 {
    match v {
        AttrVal::Unavailable => 0,
        AttrVal::Bytes(b) => b.len() as u64,
        AttrVal::Ulong(_) => 8,
        AttrVal::UlongArray(a) => a.len() as u64 * 8,
        AttrVal::Nested(n) => n.len() as u64 * 24,
    }
}

/// Two-call convention helper: `(rv, output)` for data offered against `spec`.
pub fn out_bytes(spec: OutSpec, data: &[u8]) -> (u64, OutBytes) {
    match spec {
        OutSpec::Length => (CKR_OK as u64, OutBytes { len: data.len() as u64, data: None }),
        OutSpec::Capacity(n) if (data.len() as u64) <= n => {
            (CKR_OK as u64, OutBytes { len: data.len() as u64, data: Some(data.to_vec()) })
        }
        OutSpec::Capacity(_) => (CKR_BUFFER_TOO_SMALL as u64, OutBytes { len: data.len() as u64, data: None }),
    }
}

fn bytes_reply<T>(spec: OutSpec, data: &[u8], make: impl FnOnce(OutBytes) -> T) -> Reply<T> {
    let (rv, o) = out_bytes(spec, data);
    Reply { rv, resp: Some(make(o)) }
}

impl Mock {
    /// The key of the message operation on `session`, or the error to return.
    fn msg_key(&self, call: u16, session: u64) -> Result<Vec<u8>, u64> {
        let mut s = self.enter(call)?;
        match get(&mut s, session) {
            Ok(Sess { op: Op::MsgKey(k), .. }) => Ok(k.clone()),
            Ok(Sess { msg_mech: Some(_), .. }) => Ok(vec![0x55]),
            Ok(_) => Err(CKR_OPERATION_NOT_INITIALIZED as u64),
            Err(e) => Err(e as u64),
        }
    }

    fn msg_end(&self, call: u16, session: u64) -> Result<(), u64> {
        let mut s = self.enter(call)?;
        match get(&mut s, session) {
            Ok(ss) if matches!(ss.op, Op::MsgKey(_)) || ss.msg_mech.is_some() => {
                ss.op = Op::None;
                ss.msg_mech = None;
                Ok(())
            }
            Ok(_) => Err(CKR_OPERATION_NOT_INITIALIZED as u64),
            Err(e) => Err(e as u64),
        }
    }

    pub fn new() -> Mock {
        Mock {
            st: Mutex::new(State {
                next_session: FIRST_SESSION,
                next_object: FIRST_OBJECT,
                rnd: 1,
                ..Default::default()
            }),
            cv: Condvar::new(),
        }
    }

    /// Make the next call with this id fail with `rv` (once).
    pub fn fail_next(&self, call: u16, rv: CK_RV) {
        self.st.lock().unwrap().fail.insert(call, rv as u64);
    }

    /// Make `addr`, the address of an `extern "C"` function, the module's exported function `name`, for
    /// tests of vendor-defined functions.
    pub fn register_vendor(&self, name: &str, addr: usize) {
        self.st.lock().unwrap().vendor_syms.insert(name.to_string(), addr);
    }

    /// The parameter tree the last [`VENDOR_DIGEST`] call carried, as the daemon handed it to the module.
    pub fn vendor_node(&self) -> Option<Node> {
        self.st.lock().unwrap().vendor_node.clone()
    }

    /// The parameter the last [`VENDOR_DIGEST`] call carried (`Some(vec![])`: none).
    pub fn vendor_param(&self) -> Option<Vec<u8>> {
        self.st.lock().unwrap().vendor_param.clone()
    }

    /// The ids of the calls made so far, in order.
    pub fn calls(&self) -> Vec<u16> {
        self.st.lock().unwrap().log.clone()
    }

    pub fn open_sessions(&self) -> usize {
        self.st.lock().unwrap().sessions.len()
    }

    pub fn object_count(&self) -> usize {
        self.st.lock().unwrap().objects.len()
    }

    /// Wake a blocked `C_WaitForSlotEvent` with this slot id.
    pub fn slot_event(&self, slot: u64) {
        self.st.lock().unwrap().events.push(slot);
        self.cv.notify_all();
    }

    fn enter(&self, call: u16) -> Result<std::sync::MutexGuard<'_, State>, u64> {
        let mut s = self.st.lock().unwrap();
        s.log.push(call);
        if let Some(rv) = s.fail.remove(&call) {
            return Err(rv);
        }
        Ok(s)
    }
}

macro_rules! enter {
    ($self:ident, $call:expr) => {
        match $self.enter($call) {
            Ok(s) => s,
            Err(rv) => return Reply { rv, resp: None },
        }
    };
}

fn err<T>(rv: CK_RV) -> Reply<T> {
    Reply::err(rv)
}

fn get(s: &mut State, h: u64) -> Result<&mut Sess, CK_RV> {
    s.sessions.get_mut(&h).ok_or(CKR_SESSION_HANDLE_INVALID)
}

fn attr(o: &Obj, ty: CK_ULONG) -> Option<&AttrVal> {
    o.attrs.iter().find(|(t, _)| *t == ty as u64).map(|(_, v)| v)
}

fn key_bytes(s: &State, h: u64) -> Result<Vec<u8>, CK_RV> {
    let o = s.objects.get(&h).ok_or(CKR_KEY_HANDLE_INVALID)?;
    match attr(o, CKA_VALUE) {
        Some(AttrVal::Bytes(b)) if !b.is_empty() => Ok(b.clone()),
        _ => Err(CKR_KEY_HANDLE_INVALID),
    }
}

fn store(s: &mut State, attrs: &Template, owner: Option<u64>) -> Result<u64, CK_RV> {
    let is_token = attrs.0.iter().any(|a| a.ty == CKA_TOKEN as u64 && matches!(&a.val, AttrVal::Bytes(b) if b == &[1]));
    let h = s.next_object;
    s.next_object += 1;
    s.objects.insert(
        h,
        Obj {
            attrs: attrs.0.iter().map(|a| (a.ty, a.val.clone())).collect(),
            owner: if is_token { None } else { owner },
        },
    );
    Ok(h)
}

fn matches_template(o: &Obj, t: &[Attr]) -> bool {
    t.iter().all(|a| o.attrs.iter().any(|(ty, v)| *ty == a.ty && *v == a.val))
}

impl Backend for Mock {
    fn with_vendor_symbol(&self, name: &str, call: &mut dyn FnMut(usize) -> u64) -> Result<u64, u64> {
        let addr = self.st.lock().unwrap().vendor_syms.get(name).copied();
        // the lock is not held while the function runs
        addr.map(call).ok_or(CKR_FUNCTION_NOT_SUPPORTED as u64)
    }

    fn c_get_info(&self, _r: &GetInfoReq) -> Reply<GetInfoResp> {
        let _s = enter!(self, CALL_GET_INFO);
        Reply::ok(GetInfoResp {
            info: Info {
                cryptoki_version: Version { major: 3, minor: 2 },
                manufacturer_id: pad("p11-testkit mock"),
                flags: 0,
                library_description: pad("Mock token"),
                library_version: Version { major: 1, minor: 0 },
            },
        })
    }

    fn c_get_slot_list(&self, r: &GetSlotListReq) -> Reply<GetSlotListResp> {
        let _s = enter!(self, CALL_GET_SLOT_LIST);
        let all = [SLOT, SLOT + 1];
        let list: Vec<u64> = if r.token_present { vec![SLOT] } else { all.to_vec() };
        let raw = list.iter().flat_map(|x| x.to_be_bytes()).collect::<Vec<_>>();
        let cap = match r.slots {
            OutSpec::Length => None,
            OutSpec::Capacity(n) => Some(n),
        };
        match cap {
            None => Reply::ok(GetSlotListResp { slots: OutU64s { len: list.len() as u64, data: None } }),
            Some(n) if n as usize >= list.len() => {
                let _ = raw;
                Reply::ok(GetSlotListResp { slots: OutU64s { len: list.len() as u64, data: Some(U64s(list)) } })
            }
            Some(_) => Reply {
                rv: CKR_BUFFER_TOO_SMALL as u64,
                resp: Some(GetSlotListResp { slots: OutU64s { len: list.len() as u64, data: None } }),
            },
        }
    }

    fn c_get_slot_info(&self, r: &GetSlotInfoReq) -> Reply<GetSlotInfoResp> {
        let _s = enter!(self, CALL_GET_SLOT_INFO);
        if r.slot != SLOT && r.slot != SLOT + 1 {
            return err(CKR_SLOT_ID_INVALID);
        }
        Reply::ok(GetSlotInfoResp {
            info: SlotInfo {
                slot_description: pad("Mock slot"),
                manufacturer_id: pad("p11-testkit"),
                flags: if r.slot == SLOT { CKF_TOKEN_PRESENT as u64 } else { 0 },
                hardware_version: Version { major: 1, minor: 0 },
                firmware_version: Version { major: 1, minor: 0 },
            },
        })
    }

    fn c_get_token_info(&self, r: &GetTokenInfoReq) -> Reply<GetTokenInfoResp> {
        let s = enter!(self, CALL_GET_TOKEN_INFO);
        if r.slot != SLOT {
            return err(if r.slot == SLOT + 1 { CKR_TOKEN_NOT_PRESENT } else { CKR_SLOT_ID_INVALID });
        }
        Reply::ok(GetTokenInfoResp {
            info: TokenInfo {
                label: pad("mock token"),
                manufacturer_id: pad("p11-testkit"),
                model: pad("mock"),
                serial_number: pad("0001"),
                flags: (CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED) as u64,
                max_session_count: u64::MAX,
                session_count: s.sessions.len() as u64,
                max_rw_session_count: u64::MAX,
                rw_session_count: 0,
                max_pin_len: 32,
                min_pin_len: 4,
                total_public_memory: u64::MAX,
                free_public_memory: u64::MAX,
                total_private_memory: u64::MAX,
                free_private_memory: u64::MAX,
                hardware_version: Version { major: 1, minor: 0 },
                firmware_version: Version { major: 1, minor: 0 },
                utc_time: [b'0'; 16],
            },
        })
    }

    fn c_get_mechanism_list(&self, r: &GetMechanismListReq) -> Reply<GetMechanismListResp> {
        let _s = enter!(self, CALL_GET_MECHANISM_LIST);
        if r.slot != SLOT {
            return err(CKR_SLOT_ID_INVALID);
        }
        let list = [CKM_AES_ECB, CKM_AES_KEY_GEN, CKM_SHA256, CKM_SHA256_HMAC, CKM_AES_GCM, CKM_ML_DSA];
        let all: Vec<u64> = list.iter().map(|&m| m as u64).collect();
        match r.mechanisms {
            OutSpec::Length => {
                Reply::ok(GetMechanismListResp { mechanisms: OutU64s { len: all.len() as u64, data: None } })
            }
            OutSpec::Capacity(n) if n as usize >= all.len() => {
                Reply::ok(GetMechanismListResp { mechanisms: OutU64s { len: all.len() as u64, data: Some(U64s(all)) } })
            }
            OutSpec::Capacity(_) => Reply {
                rv: CKR_BUFFER_TOO_SMALL as u64,
                resp: Some(GetMechanismListResp { mechanisms: OutU64s { len: all.len() as u64, data: None } }),
            },
        }
    }

    fn c_get_mechanism_info(&self, r: &GetMechanismInfoReq) -> Reply<GetMechanismInfoResp> {
        let _s = enter!(self, CALL_GET_MECHANISM_INFO);
        match r.mechanism as CK_ULONG {
            CKM_AES_ECB | CKM_AES_KEY_GEN | CKM_AES_GCM => Reply::ok(GetMechanismInfoResp {
                info: MechanismInfo { min_key_size: 16, max_key_size: 32, flags: (CKF_ENCRYPT | CKF_DECRYPT) as u64 },
            }),
            CKM_SHA256 => Reply::ok(GetMechanismInfoResp {
                info: MechanismInfo { min_key_size: 0, max_key_size: 0, flags: CKF_DIGEST as u64 },
            }),
            _ => err(CKR_MECHANISM_INVALID),
        }
    }

    fn c_open_session(&self, r: &OpenSessionReq) -> Reply<OpenSessionResp> {
        let mut s = enter!(self, CALL_OPEN_SESSION);
        if r.slot != SLOT {
            return err(CKR_SLOT_ID_INVALID);
        }
        if r.flags & CKF_SERIAL_SESSION as u64 == 0 {
            return err(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        }
        let h = s.next_session;
        s.next_session += 1;
        s.sessions.insert(h, Sess { flags: r.flags, find: None, op: Op::None, msg_mech: None });
        Reply::ok(OpenSessionResp { session: h })
    }

    fn c_close_session(&self, r: &CloseSessionReq) -> Reply<CloseSessionResp> {
        let mut s = enter!(self, CALL_CLOSE_SESSION);
        if s.sessions.remove(&r.session).is_none() {
            return err(CKR_SESSION_HANDLE_INVALID);
        }
        let h = r.session;
        s.objects.retain(|_, o| o.owner != Some(h));
        if s.sessions.is_empty() {
            s.logged_in = false;
        }
        Reply::done()
    }

    fn c_close_all_sessions(&self, r: &CloseAllSessionsReq) -> Reply<CloseAllSessionsResp> {
        let mut s = enter!(self, CALL_CLOSE_ALL_SESSIONS);
        if r.slot != SLOT {
            return err(CKR_SLOT_ID_INVALID);
        }
        s.sessions.clear();
        s.objects.retain(|_, o| o.owner.is_none());
        s.logged_in = false;
        Reply::done()
    }

    fn c_get_session_info(&self, r: &GetSessionInfoReq) -> Reply<GetSessionInfoResp> {
        let mut s = enter!(self, CALL_GET_SESSION_INFO);
        let logged = s.logged_in;
        let ss = match get(&mut s, r.session) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        let rw = ss.flags & CKF_RW_SESSION as u64 != 0;
        let state = match (logged, rw) {
            (false, false) => CKS_RO_PUBLIC_SESSION,
            (false, true) => CKS_RW_PUBLIC_SESSION,
            (true, false) => CKS_RO_USER_FUNCTIONS,
            (true, true) => CKS_RW_USER_FUNCTIONS,
        };
        Reply::ok(GetSessionInfoResp {
            info: SessionInfo { slot_id: SLOT, state: state as u64, flags: ss.flags, device_error: 0 },
        })
    }

    fn c_login(&self, r: &LoginReq) -> Reply<LoginResp> {
        let mut s = enter!(self, CALL_LOGIN);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        if s.logged_in {
            return err(CKR_USER_ALREADY_LOGGED_IN);
        }
        if r.pin.as_ref().map(|p| p.expose()) != Some(USER_PIN) {
            return err(CKR_PIN_INCORRECT);
        }
        s.logged_in = true;
        Reply::done()
    }

    fn c_logout(&self, r: &LogoutReq) -> Reply<LogoutResp> {
        let mut s = enter!(self, CALL_LOGOUT);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        if !s.logged_in {
            return err(CKR_USER_NOT_LOGGED_IN);
        }
        s.logged_in = false;
        Reply::done()
    }

    fn c_create_object(&self, r: &CreateObjectReq) -> Reply<CreateObjectResp> {
        let mut s = enter!(self, CALL_CREATE_OBJECT);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        match store(&mut s, &r.template, Some(r.session)) {
            Ok(h) => Reply::ok(CreateObjectResp { object: h }),
            Err(e) => err(e),
        }
    }

    fn c_destroy_object(&self, r: &DestroyObjectReq) -> Reply<DestroyObjectResp> {
        let mut s = enter!(self, CALL_DESTROY_OBJECT);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        if s.objects.remove(&r.object).is_none() {
            return err(CKR_OBJECT_HANDLE_INVALID);
        }
        Reply::done()
    }

    fn c_get_object_size(&self, r: &GetObjectSizeReq) -> Reply<GetObjectSizeResp> {
        let mut s = enter!(self, CALL_GET_OBJECT_SIZE);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        match s.objects.get(&r.object) {
            Some(o) => Reply::ok(GetObjectSizeResp { size: o.attrs.iter().map(|(_, v)| size_of_val(v)).sum() }),
            None => err(CKR_OBJECT_HANDLE_INVALID),
        }
    }

    fn c_get_attribute_value(&self, r: &GetAttributeValueReq) -> Reply<GetAttributeValueResp> {
        let mut s = enter!(self, CALL_GET_ATTRIBUTE_VALUE);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        let Some(o) = s.objects.get(&r.object) else { return err(CKR_OBJECT_HANDLE_INVALID) };
        let sensitive = matches!(attr(o, CKA_SENSITIVE), Some(AttrVal::Bytes(b)) if b == &[1]);
        let mut rv = CKR_OK;
        let mut out = Vec::new();
        for q in &r.template.0 {
            let v = o.attrs.iter().find(|(t, _)| *t == q.ty).map(|(_, v)| v);
            let answer = match v {
                None => {
                    rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    Answer::Unavailable
                }
                Some(_) if sensitive && q.ty == CKA_VALUE as u64 => {
                    if rv == CKR_OK {
                        rv = CKR_ATTRIBUTE_SENSITIVE;
                    }
                    Answer::Unavailable
                }
                Some(v) => match &q.slot {
                    Slot::Length => Answer::Length(size_of_val(v)),
                    Slot::Capacity(n) if size_of_val(v) > *n => {
                        if rv == CKR_OK {
                            rv = CKR_BUFFER_TOO_SMALL;
                        }
                        Answer::Unavailable
                    }
                    Slot::Capacity(_) => match v {
                        AttrVal::Bytes(b) => Answer::Bytes(b.clone()),
                        AttrVal::Ulong(u) => Answer::Ulong(*u),
                        AttrVal::UlongArray(a) => Answer::UlongArray(a.clone()),
                        AttrVal::Nested(n) => Answer::Nested(
                            n.iter()
                                .map(|a| Reply_ {
                                    ty: a.ty,
                                    answer: match &a.val {
                                        AttrVal::Bytes(b) => Answer::Bytes(b.clone()),
                                        AttrVal::Ulong(u) => Answer::Ulong(*u),
                                        _ => Answer::Unavailable,
                                    },
                                })
                                .collect(),
                        ),
                        AttrVal::Unavailable => Answer::Unavailable,
                    },
                    Slot::Nested(_) => match v {
                        AttrVal::Nested(n) => Answer::Nested(
                            n.iter()
                                .map(|a| Reply_ {
                                    ty: a.ty,
                                    answer: match &a.val {
                                        AttrVal::Bytes(b) => Answer::Bytes(b.clone()),
                                        AttrVal::Ulong(u) => Answer::Ulong(*u),
                                        _ => Answer::Unavailable,
                                    },
                                })
                                .collect(),
                        ),
                        _ => Answer::Unavailable,
                    },
                },
            };
            out.push(Reply_ { ty: q.ty, answer });
        }
        Reply { rv: rv as u64, resp: Some(GetAttributeValueResp { template: Seq(out) }) }
    }

    fn c_set_attribute_value(&self, r: &SetAttributeValueReq) -> Reply<SetAttributeValueResp> {
        let mut s = enter!(self, CALL_SET_ATTRIBUTE_VALUE);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        let Some(o) = s.objects.get_mut(&r.object) else { return err(CKR_OBJECT_HANDLE_INVALID) };
        for a in &r.template.0 {
            match o.attrs.iter_mut().find(|(t, _)| *t == a.ty) {
                Some((_, v)) => *v = a.val.clone(),
                None => o.attrs.push((a.ty, a.val.clone())),
            }
        }
        Reply::done()
    }

    fn c_find_objects_init(&self, r: &FindObjectsInitReq) -> Reply<FindObjectsInitResp> {
        let mut s = enter!(self, CALL_FIND_OBJECTS_INIT);
        let mut found: Vec<u64> =
            s.objects.iter().filter(|(_, o)| matches_template(o, &r.template.0)).map(|(h, _)| *h).collect();
        found.sort_unstable();
        match get(&mut s, r.session) {
            Ok(ss) => {
                if ss.find.is_some() {
                    return err(CKR_OPERATION_ACTIVE);
                }
                ss.find = Some(found);
                Reply::done()
            }
            Err(e) => err(e),
        }
    }

    fn c_find_objects(&self, r: &FindObjectsReq) -> Reply<FindObjectsResp> {
        let mut s = enter!(self, CALL_FIND_OBJECTS);
        let ss = match get(&mut s, r.session) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        let Some(f) = ss.find.as_mut() else { return err(CKR_OPERATION_NOT_INITIALIZED) };
        let n = (r.objects as usize).min(f.len());
        let out: Vec<u64> = f.drain(..n).collect();
        Reply::ok(FindObjectsResp { objects: U64s(out) })
    }

    fn c_find_objects_final(&self, r: &FindObjectsFinalReq) -> Reply<FindObjectsFinalResp> {
        let mut s = enter!(self, CALL_FIND_OBJECTS_FINAL);
        match get(&mut s, r.session) {
            Ok(ss) => {
                if ss.find.take().is_none() {
                    return err(CKR_OPERATION_NOT_INITIALIZED);
                }
                Reply::done()
            }
            Err(e) => err(e),
        }
    }

    fn c_generate_key(&self, r: &GenerateKeyReq) -> Reply<GenerateKeyResp> {
        let mut s = enter!(self, CALL_GENERATE_KEY);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        if r.mechanism.mechanism != CKM_AES_KEY_GEN as u64 {
            return err(CKR_MECHANISM_INVALID);
        }
        let len = r
            .template
            .0
            .iter()
            .find_map(|a| match (&a.val, a.ty) {
                (AttrVal::Ulong(n), t) if t == CKA_VALUE_LEN as u64 => Some(*n as usize),
                _ => None,
            })
            .unwrap_or(16);
        if !matches!(len, 16 | 24 | 32) {
            return err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
        let mut v = Vec::new();
        for _ in 0..len {
            s.rnd = s.rnd.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.push((s.rnd >> 33) as u8);
        }
        let mut t = r.template.clone();
        t.0.retain(|a| a.ty != CKA_VALUE as u64);
        t.0.push(Attr { ty: CKA_VALUE as u64, val: AttrVal::Bytes(v) });
        t.0.push(Attr { ty: CKA_CLASS as u64, val: AttrVal::Ulong(CKO_SECRET_KEY as u64) });
        let owner = Some(r.session);
        match store(&mut s, &t, owner) {
            Ok(h) => Reply::ok(GenerateKeyResp { key: h, mechanism_out: None }),
            Err(e) => err(e),
        }
    }

    fn c_encrypt_init(&self, r: &EncryptInitReq) -> Reply<EncryptInitResp> {
        cipher_init(self, CALL_ENCRYPT_INIT, r.session, r.key, false)
    }
    fn c_decrypt_init(&self, r: &DecryptInitReq) -> Reply<DecryptInitResp> {
        cipher_init(self, CALL_DECRYPT_INIT, r.session, r.key, true)
    }

    fn c_encrypt(&self, r: &EncryptReq) -> Reply<EncryptResp> {
        cipher_one(self, CALL_ENCRYPT, r.session, &r.data, r.encrypted, false, |o| EncryptResp { encrypted: o })
    }
    fn c_decrypt(&self, r: &DecryptReq) -> Reply<DecryptResp> {
        cipher_one(self, CALL_DECRYPT, r.session, &r.encrypted, r.data, true, |o| DecryptResp { data: o })
    }
    fn c_encrypt_update(&self, r: &EncryptUpdateReq) -> Reply<EncryptUpdateResp> {
        cipher_part(self, CALL_ENCRYPT_UPDATE, r.session, &r.part, r.encrypted, false, |o| EncryptUpdateResp {
            encrypted: o,
        })
    }
    fn c_decrypt_update(&self, r: &DecryptUpdateReq) -> Reply<DecryptUpdateResp> {
        cipher_part(self, CALL_DECRYPT_UPDATE, r.session, &r.encrypted, r.part, true, |o| DecryptUpdateResp { part: o })
    }
    fn c_encrypt_final(&self, r: &EncryptFinalReq) -> Reply<EncryptFinalResp> {
        cipher_final(self, CALL_ENCRYPT_FINAL, r.session, r.last, |o| EncryptFinalResp { last: o })
    }
    fn c_decrypt_final(&self, r: &DecryptFinalReq) -> Reply<DecryptFinalResp> {
        cipher_final(self, CALL_DECRYPT_FINAL, r.session, r.last, |o| DecryptFinalResp { last: o })
    }

    fn c_digest_init(&self, r: &DigestInitReq) -> Reply<DigestInitResp> {
        let mut s = enter!(self, CALL_DIGEST_INIT);
        if r.mechanism.mechanism == VENDOR_DIGEST {
            s.vendor_node = r.mechanism.param.clone();
            s.vendor_param = Some(match &r.mechanism.param {
                Some(Node::B(b)) => b.clone(),
                Some(Node::U(h)) => h.to_ne_bytes().to_vec(),
                _ => Vec::new(),
            });
        } else if r.mechanism.mechanism != CKM_SHA256 as u64 {
            return err(CKR_MECHANISM_INVALID);
        }
        match get(&mut s, r.session) {
            Ok(ss) => {
                ss.op = Op::Digest(Vec::new());
                Reply::done()
            }
            Err(e) => err(e),
        }
    }
    fn c_digest_update(&self, r: &DigestUpdateReq) -> Reply<DigestUpdateResp> {
        let mut s = enter!(self, CALL_DIGEST_UPDATE);
        match get(&mut s, r.session) {
            Ok(Sess { op: Op::Digest(d), .. }) => {
                d.extend_from_slice(&r.part);
                Reply::done()
            }
            Ok(_) => err(CKR_OPERATION_NOT_INITIALIZED),
            Err(e) => err(e),
        }
    }
    fn c_digest_final(&self, r: &DigestFinalReq) -> Reply<DigestFinalResp> {
        let mut s = enter!(self, CALL_DIGEST_FINAL);
        let ss = match get(&mut s, r.session) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        let Op::Digest(d) = ss.op.clone() else { return err(CKR_OPERATION_NOT_INITIALIZED) };
        let out = toy_digest(&d);
        let (rv, o) = out_bytes(r.digest, &out);
        if rv == CKR_OK as u64 && !matches!(r.digest, OutSpec::Length) {
            ss.op = Op::None;
        }
        Reply { rv, resp: Some(DigestFinalResp { digest: o }) }
    }
    fn c_digest(&self, r: &DigestReq) -> Reply<DigestResp> {
        let mut s = enter!(self, CALL_DIGEST);
        let ss = match get(&mut s, r.session) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        let Op::Digest(_) = ss.op else { return err(CKR_OPERATION_NOT_INITIALIZED) };
        let out = toy_digest(&r.data);
        let (rv, o) = out_bytes(r.digest, &out);
        if rv == CKR_OK as u64 && !matches!(r.digest, OutSpec::Length) {
            ss.op = Op::None;
        }
        Reply { rv, resp: Some(DigestResp { digest: o }) }
    }

    fn c_sign_init(&self, r: &SignInitReq) -> Reply<SignInitResp> {
        mac_init(self, CALL_SIGN_INIT, r.session, r.key, false)
    }
    fn c_verify_init(&self, r: &VerifyInitReq) -> Reply<VerifyInitResp> {
        mac_init(self, CALL_VERIFY_INIT, r.session, r.key, true)
    }
    fn c_sign_update(&self, r: &SignUpdateReq) -> Reply<SignUpdateResp> {
        mac_update(self, CALL_SIGN_UPDATE, r.session, &r.part)
    }
    fn c_verify_update(&self, r: &VerifyUpdateReq) -> Reply<VerifyUpdateResp> {
        mac_update(self, CALL_VERIFY_UPDATE, r.session, &r.part)
    }
    fn c_sign(&self, r: &SignReq) -> Reply<SignResp> {
        let mut s = enter!(self, CALL_SIGN);
        let ss = match get(&mut s, r.session) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        let Op::Mac { key, verify: false, .. } = ss.op.clone() else { return err(CKR_OPERATION_NOT_INITIALIZED) };
        let sig = toy_mac(&key, &r.data);
        let (rv, o) = out_bytes(r.signature, &sig);
        if rv == CKR_OK as u64 && !matches!(r.signature, OutSpec::Length) {
            ss.op = Op::None;
        }
        Reply { rv, resp: Some(SignResp { signature: o }) }
    }
    fn c_sign_final(&self, r: &SignFinalReq) -> Reply<SignFinalResp> {
        let mut s = enter!(self, CALL_SIGN_FINAL);
        let ss = match get(&mut s, r.session) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        let Op::Mac { key, data, verify: false, .. } = ss.op.clone() else { return err(CKR_OPERATION_NOT_INITIALIZED) };
        let (rv, o) = out_bytes(r.signature, &toy_mac(&key, &data));
        if rv == CKR_OK as u64 && !matches!(r.signature, OutSpec::Length) {
            ss.op = Op::None;
        }
        Reply { rv, resp: Some(SignFinalResp { signature: o }) }
    }
    fn c_verify(&self, r: &VerifyReq) -> Reply<VerifyResp> {
        let mut s = enter!(self, CALL_VERIFY);
        let ss = match get(&mut s, r.session) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        let Op::Mac { key, verify: true, .. } = ss.op.clone() else { return err(CKR_OPERATION_NOT_INITIALIZED) };
        ss.op = Op::None;
        if toy_mac(&key, &r.data) == r.signature {
            Reply::done()
        } else {
            err(CKR_SIGNATURE_INVALID)
        }
    }
    fn c_verify_final(&self, r: &VerifyFinalReq) -> Reply<VerifyFinalResp> {
        let mut s = enter!(self, CALL_VERIFY_FINAL);
        let ss = match get(&mut s, r.session) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        let Op::Mac { key, data, verify: true, .. } = ss.op.clone() else { return err(CKR_OPERATION_NOT_INITIALIZED) };
        ss.op = Op::None;
        if toy_mac(&key, &data) == r.signature {
            Reply::done()
        } else {
            err(CKR_SIGNATURE_INVALID)
        }
    }

    fn c_generate_random(&self, r: &GenerateRandomReq) -> Reply<GenerateRandomResp> {
        let mut s = enter!(self, CALL_GENERATE_RANDOM);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        let mut v = Vec::with_capacity(r.random as usize);
        for _ in 0..r.random {
            s.rnd = s.rnd.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.push((s.rnd >> 33) as u8);
        }
        Reply::ok(GenerateRandomResp { random: v })
    }

    fn c_wait_for_slot_event(&self, r: &WaitForSlotEventReq) -> Reply<WaitForSlotEventResp> {
        let mut s = match self.enter(CALL_WAIT_FOR_SLOT_EVENT) {
            Ok(s) => s,
            Err(rv) => return Reply { rv, resp: None },
        };
        loop {
            if let Some(slot) = s.events.pop() {
                return Reply::ok(WaitForSlotEventResp { slot });
            }
            if r.flags & CKF_DONT_BLOCK as u64 != 0 {
                return err(CKR_NO_EVENT);
            }
            s = self.cv.wait(s).unwrap();
        }
    }

    fn c_login_user(&self, r: &LoginUserReq) -> Reply<LoginUserResp> {
        let mut s = enter!(self, CALL_LOGIN_USER);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        if s.logged_in {
            return err(CKR_USER_ALREADY_LOGGED_IN);
        }
        if r.pin.as_ref().map(|p| p.expose()) != Some(USER_PIN)
            || r.username.as_ref().map(|p| p.expose()) != Some(b"alice")
        {
            return err(CKR_PIN_INCORRECT);
        }
        s.logged_in = true;
        Reply::done()
    }

    fn c_session_cancel(&self, r: &SessionCancelReq) -> Reply<SessionCancelResp> {
        let mut s = enter!(self, CALL_SESSION_CANCEL);
        match get(&mut s, r.session) {
            Ok(ss) => {
                ss.op = Op::None;
                ss.find = None;
                Reply::done()
            }
            Err(e) => err(e),
        }
    }

    fn c_get_session_validation_flags(&self, r: &GetSessionValidationFlagsReq) -> Reply<GetSessionValidationFlagsResp> {
        let mut s = enter!(self, CALL_GET_SESSION_VALIDATION_FLAGS);
        match get(&mut s, r.session) {
            Ok(_) => Reply::ok(GetSessionValidationFlagsResp { flags: 0x50 + r.kind }),
            Err(e) => err(e),
        }
    }

    // ---- asynchronous calls: a table of canned answers ----

    fn c_async_get_id(&self, r: &AsyncGetIDReq) -> Reply<AsyncGetIDResp> {
        let mut s = enter!(self, CALL_ASYNC_GET_ID);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        match r.function_name.as_slice() {
            b"C_SignInit" => Reply::ok(AsyncGetIDResp { id: 7 }),
            _ => err(CKR_FUNCTION_NOT_SUPPORTED),
        }
    }

    fn c_async_join(&self, r: &AsyncJoinReq) -> Reply<AsyncJoinResp> {
        let mut s = enter!(self, CALL_ASYNC_JOIN);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        if r.id != 7 {
            return err(CKR_ARGUMENTS_BAD);
        }
        Reply::ok(AsyncJoinResp { data: (0..r.data).map(|i| (i as u8) ^ 0x5a).collect() })
    }

    fn c_async_complete(&self, r: &AsyncCompleteReq) -> Reply<AsyncCompleteResp> {
        let mut s = enter!(self, CALL_ASYNC_COMPLETE);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        let first = s.objects.keys().min().copied().unwrap_or(0);
        let value = b"async-result";
        let (rv, v) = out_bytes(r.result.value, value);
        Reply {
            rv,
            resp: Some(AsyncCompleteResp {
                result: AsyncOut { version: r.result.version, value: v, object: first, additional_object: 0 },
            }),
        }
    }

    // ---- key encapsulation and authenticated wrapping ----

    fn c_encapsulate_key(&self, r: &EncapsulateKeyReq) -> Reply<EncapsulateKeyResp> {
        let mut s = enter!(self, CALL_ENCAPSULATE_KEY);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        if !s.objects.contains_key(&r.public_key) {
            return err(CKR_KEY_HANDLE_INVALID);
        }
        let ct = b"KEM-ciphertext-0123456789".to_vec();
        let mut t = r.template.clone();
        t.0.retain(|a| a.ty != CKA_VALUE as u64);
        t.0.push(Attr { ty: CKA_VALUE as u64, val: AttrVal::Bytes(toy_digest(&ct)) });
        let (rv, o) = out_bytes(r.ciphertext, &ct);
        if rv != CKR_OK as u64 {
            return Reply { rv, resp: Some(EncapsulateKeyResp { mechanism_out: None, ciphertext: o, key: 0 }) };
        }
        if matches!(r.ciphertext, OutSpec::Length) {
            return Reply { rv, resp: Some(EncapsulateKeyResp { mechanism_out: None, ciphertext: o, key: 0 }) };
        }
        match store(&mut s, &t, Some(r.session)) {
            Ok(h) => Reply::ok(EncapsulateKeyResp { mechanism_out: None, ciphertext: o, key: h }),
            Err(e) => err(e),
        }
    }

    fn c_decapsulate_key(&self, r: &DecapsulateKeyReq) -> Reply<DecapsulateKeyResp> {
        let mut s = enter!(self, CALL_DECAPSULATE_KEY);
        if let Err(e) = get(&mut s, r.session) {
            return err(e);
        }
        if !s.objects.contains_key(&r.private_key) {
            return err(CKR_KEY_HANDLE_INVALID);
        }
        let mut t = r.template.clone();
        t.0.retain(|a| a.ty != CKA_VALUE as u64);
        t.0.push(Attr { ty: CKA_VALUE as u64, val: AttrVal::Bytes(toy_digest(&r.ciphertext)) });
        match store(&mut s, &t, Some(r.session)) {
            Ok(h) => Reply::ok(DecapsulateKeyResp { mechanism_out: None, key: h }),
            Err(e) => err(e),
        }
    }

    fn c_wrap_key_authenticated(&self, r: &WrapKeyAuthenticatedReq) -> Reply<WrapKeyAuthenticatedResp> {
        let s = enter!(self, CALL_WRAP_KEY_AUTHENTICATED);
        let (Ok(wk), Ok(k)) = (key_bytes(&s, r.wrapping_key), key_bytes(&s, r.key)) else {
            return err(CKR_KEY_HANDLE_INVALID);
        };
        let mut w = xor(&wk, &k);
        w.extend_from_slice(&toy_mac(&wk, &r.associated_data)[..4]);
        bytes_reply(r.wrapped, &w, |o| WrapKeyAuthenticatedResp { mechanism_out: None, wrapped: o })
    }

    fn c_unwrap_key_authenticated(&self, r: &UnwrapKeyAuthenticatedReq) -> Reply<UnwrapKeyAuthenticatedResp> {
        let mut s = enter!(self, CALL_UNWRAP_KEY_AUTHENTICATED);
        let Ok(wk) = key_bytes(&s, r.unwrapping_key) else { return err(CKR_KEY_HANDLE_INVALID) };
        if r.wrapped.len() < 4 {
            return err(CKR_WRAPPED_KEY_LEN_RANGE);
        }
        let (body, tag) = r.wrapped.split_at(r.wrapped.len() - 4);
        if tag != &toy_mac(&wk, &r.associated_data)[..4] {
            return err(CKR_WRAPPED_KEY_INVALID);
        }
        let mut t = r.template.clone();
        t.0.retain(|a| a.ty != CKA_VALUE as u64);
        t.0.push(Attr { ty: CKA_VALUE as u64, val: AttrVal::Bytes(xor(&wk, body)) });
        match store(&mut s, &t, Some(r.session)) {
            Ok(h) => Reply::ok(UnwrapKeyAuthenticatedResp { mechanism_out: None, key: h }),
            Err(e) => err(e),
        }
    }

    // ---- verification with the signature given up front ----

    fn c_verify_signature_init(&self, r: &VerifySignatureInitReq) -> Reply<VerifySignatureInitResp> {
        let mut s = enter!(self, CALL_VERIFY_SIGNATURE_INIT);
        let k = match key_bytes(&s, r.key) {
            Ok(k) => k,
            Err(e) => return err(e),
        };
        match get(&mut s, r.session) {
            Ok(ss) => {
                ss.op = Op::SigVerify { key: k, data: Vec::new(), sig: r.signature.clone() };
                Reply::done()
            }
            Err(e) => err(e),
        }
    }

    fn c_verify_signature_update(&self, r: &VerifySignatureUpdateReq) -> Reply<VerifySignatureUpdateResp> {
        let mut s = enter!(self, CALL_VERIFY_SIGNATURE_UPDATE);
        match get(&mut s, r.session) {
            Ok(Sess { op: Op::SigVerify { data, .. }, .. }) => {
                data.extend_from_slice(&r.part);
                Reply::done()
            }
            Ok(_) => err(CKR_OPERATION_NOT_INITIALIZED),
            Err(e) => err(e),
        }
    }

    fn c_verify_signature(&self, r: &VerifySignatureReq) -> Reply<VerifySignatureResp> {
        let mut s = enter!(self, CALL_VERIFY_SIGNATURE);
        match get(&mut s, r.session) {
            Ok(ss) => {
                let Op::SigVerify { key, data, sig } = std::mem::replace(&mut ss.op, Op::None) else {
                    return err(CKR_OPERATION_NOT_INITIALIZED);
                };
                let mut all = data;
                all.extend_from_slice(&r.data);
                if toy_mac(&key, &all) == sig {
                    Reply::done()
                } else {
                    err(CKR_SIGNATURE_INVALID)
                }
            }
            Err(e) => err(e),
        }
    }

    fn c_verify_signature_final(&self, r: &VerifySignatureFinalReq) -> Reply<VerifySignatureFinalResp> {
        let mut s = enter!(self, CALL_VERIFY_SIGNATURE_FINAL);
        match get(&mut s, r.session) {
            Ok(ss) => {
                let Op::SigVerify { key, data, sig } = std::mem::replace(&mut ss.op, Op::None) else {
                    return err(CKR_OPERATION_NOT_INITIALIZED);
                };
                if toy_mac(&key, &data) == sig {
                    Reply::done()
                } else {
                    err(CKR_SIGNATURE_INVALID)
                }
            }
            Err(e) => err(e),
        }
    }

    // ---- message-based sign, verify, encrypt and decrypt ----

    fn c_message_sign_init(&self, r: &MessageSignInitReq) -> Reply<MessageSignInitResp> {
        message_key_init(self, CALL_MESSAGE_SIGN_INIT, r.session, r.key, r.mechanism.mechanism, false)
    }
    fn c_message_verify_init(&self, r: &MessageVerifyInitReq) -> Reply<MessageVerifyInitResp> {
        message_key_init(self, CALL_MESSAGE_VERIFY_INIT, r.session, r.key, r.mechanism.mechanism, true)
    }
    fn c_sign_message(&self, r: &SignMessageReq) -> Reply<SignMessageResp> {
        let s = self.msg_key(CALL_SIGN_MESSAGE, r.session);
        match s {
            Ok(key) => bytes_reply(r.signature, &toy_mac(&key, &r.data), |o| SignMessageResp {
                parameter_out: None,
                signature: o,
            }),
            Err(rv) => Reply { rv, resp: None },
        }
    }
    fn c_sign_message_begin(&self, r: &SignMessageBeginReq) -> Reply<SignMessageBeginResp> {
        self.msg_key(CALL_SIGN_MESSAGE_BEGIN, r.session).map_or_else(|rv| Reply { rv, resp: None }, |_| Reply::done())
    }
    fn c_sign_message_next(&self, r: &SignMessageNextReq) -> Reply<SignMessageNextResp> {
        match self.msg_key(CALL_SIGN_MESSAGE_NEXT, r.session) {
            Ok(key) => bytes_reply(r.signature, &toy_mac(&key, &r.data), |o| SignMessageNextResp {
                parameter_out: None,
                signature: o,
            }),
            Err(rv) => Reply { rv, resp: None },
        }
    }
    fn c_message_sign_final(&self, r: &MessageSignFinalReq) -> Reply<MessageSignFinalResp> {
        self.msg_end(CALL_MESSAGE_SIGN_FINAL, r.session).map_or_else(|rv| Reply { rv, resp: None }, |_| Reply::done())
    }
    fn c_verify_message(&self, r: &VerifyMessageReq) -> Reply<VerifyMessageResp> {
        match self.msg_key(CALL_VERIFY_MESSAGE, r.session) {
            Ok(key) => {
                if toy_mac(&key, &r.data) == r.signature {
                    Reply::done()
                } else {
                    err(CKR_SIGNATURE_INVALID)
                }
            }
            Err(rv) => Reply { rv, resp: None },
        }
    }
    fn c_verify_message_begin(&self, r: &VerifyMessageBeginReq) -> Reply<VerifyMessageBeginResp> {
        self.msg_key(CALL_VERIFY_MESSAGE_BEGIN, r.session).map_or_else(|rv| Reply { rv, resp: None }, |_| Reply::done())
    }
    fn c_verify_message_next(&self, r: &VerifyMessageNextReq) -> Reply<VerifyMessageNextResp> {
        match self.msg_key(CALL_VERIFY_MESSAGE_NEXT, r.session) {
            Ok(key) => {
                if toy_mac(&key, &r.data) == r.signature {
                    Reply::done()
                } else {
                    err(CKR_SIGNATURE_INVALID)
                }
            }
            Err(rv) => Reply { rv, resp: None },
        }
    }
    fn c_message_verify_final(&self, r: &MessageVerifyFinalReq) -> Reply<MessageVerifyFinalResp> {
        self.msg_end(CALL_MESSAGE_VERIFY_FINAL, r.session).map_or_else(|rv| Reply { rv, resp: None }, |_| Reply::done())
    }
    fn c_encrypt_message_begin(&self, r: &EncryptMessageBeginReq) -> Reply<EncryptMessageBeginResp> {
        let out = r.parameter.param.as_ref().map(|_| gcm_out(0x22));
        match self.msg_key(CALL_ENCRYPT_MESSAGE_BEGIN, r.session) {
            Ok(_) => Reply::ok(EncryptMessageBeginResp { parameter_out: out }),
            Err(rv) => Reply { rv, resp: None },
        }
    }
    fn c_encrypt_message_next(&self, r: &EncryptMessageNextReq) -> Reply<EncryptMessageNextResp> {
        if self.msg_key(CALL_ENCRYPT_MESSAGE_NEXT, r.session).is_err() {
            return err(CKR_OPERATION_NOT_INITIALIZED);
        }
        let ct: Vec<u8> = r.plaintext.iter().rev().copied().collect();
        let (rv, o) = out_bytes(r.ciphertext, &ct);
        let out = r.parameter.param.as_ref().map(|_| gcm_out(0x33));
        Reply { rv, resp: Some(EncryptMessageNextResp { parameter_out: out, ciphertext: o }) }
    }
    fn c_message_encrypt_final(&self, r: &MessageEncryptFinalReq) -> Reply<MessageEncryptFinalResp> {
        self.msg_end(CALL_MESSAGE_ENCRYPT_FINAL, r.session)
            .map_or_else(|rv| Reply { rv, resp: None }, |_| Reply::done())
    }
    fn c_message_decrypt_init(&self, r: &MessageDecryptInitReq) -> Reply<MessageDecryptInitResp> {
        message_init(self, CALL_MESSAGE_DECRYPT_INIT, r.session, r.mechanism.mechanism)
    }
    fn c_decrypt_message(&self, r: &DecryptMessageReq) -> Reply<DecryptMessageResp> {
        if self.msg_key(CALL_DECRYPT_MESSAGE, r.session).is_err() {
            return err(CKR_OPERATION_NOT_INITIALIZED);
        }
        let pt: Vec<u8> = r.ciphertext.iter().rev().copied().collect();
        bytes_reply(r.plaintext, &pt, |o| DecryptMessageResp { parameter_out: None, plaintext: o })
    }
    fn c_decrypt_message_begin(&self, r: &DecryptMessageBeginReq) -> Reply<DecryptMessageBeginResp> {
        self.msg_key(CALL_DECRYPT_MESSAGE_BEGIN, r.session)
            .map_or_else(|rv| Reply { rv, resp: None }, |_| Reply::done())
    }
    fn c_decrypt_message_next(&self, r: &DecryptMessageNextReq) -> Reply<DecryptMessageNextResp> {
        if self.msg_key(CALL_DECRYPT_MESSAGE_NEXT, r.session).is_err() {
            return err(CKR_OPERATION_NOT_INITIALIZED);
        }
        let pt: Vec<u8> = r.ciphertext.iter().rev().copied().collect();
        bytes_reply(r.plaintext, &pt, |o| DecryptMessageNextResp { parameter_out: None, plaintext: o })
    }
    fn c_message_decrypt_final(&self, r: &MessageDecryptFinalReq) -> Reply<MessageDecryptFinalResp> {
        self.msg_end(CALL_MESSAGE_DECRYPT_FINAL, r.session)
            .map_or_else(|rv| Reply { rv, resp: None }, |_| Reply::done())
    }

    fn c_message_encrypt_init(&self, r: &MessageEncryptInitReq) -> Reply<MessageEncryptInitResp> {
        message_init(self, CALL_MESSAGE_ENCRYPT_INIT, r.session, r.mechanism.mechanism)
    }
    fn c_encrypt_message(&self, r: &EncryptMessageReq) -> Reply<EncryptMessageResp> {
        let mut s = enter!(self, CALL_ENCRYPT_MESSAGE);
        let ss = match get(&mut s, r.session) {
            Ok(x) => x,
            Err(e) => return err(e),
        };
        if ss.msg_mech != Some(r.parameter.mechanism) {
            return err(CKR_OPERATION_NOT_INITIALIZED);
        }
        // "encrypt": reverse the bytes; the mock fills a fixed IV into the parameter
        let ct: Vec<u8> = r.plaintext.iter().rev().copied().collect();
        let (rv, o) = out_bytes(r.ciphertext, &ct);
        let out = r.parameter.param.as_ref().map(|_| gcm_out(0x11));
        Reply { rv, resp: Some(EncryptMessageResp { parameter_out: out, ciphertext: o }) }
    }
}

// `Reply` from p11_wire::attr collides with p11_module::Reply.
use p11_wire::attr::Reply as Reply_;

fn toy_digest(d: &[u8]) -> Vec<u8> {
    (0..4u64).flat_map(|i| fnv(d, i).to_be_bytes()).collect()
}
fn toy_mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut v = key.to_vec();
    v.extend_from_slice(data);
    fnv(&v, 99).to_be_bytes().to_vec()
}

fn message_init<T>(m: &Mock, call: u16, session: u64, mech: u64) -> Reply<T> {
    let mut s = enter!(m, call);
    match get(&mut s, session) {
        Ok(ss) => {
            ss.msg_mech = Some(mech);
            Reply::done()
        }
        Err(e) => err(e),
    }
}

fn cipher_init<T>(m: &Mock, call: u16, session: u64, key: u64, decrypt: bool) -> Reply<T> {
    let mut s = enter!(m, call);
    let k = match key_bytes(&s, key) {
        Ok(k) => k,
        Err(e) => return err(e),
    };
    match get(&mut s, session) {
        Ok(ss) => {
            if !matches!(ss.op, Op::None) {
                return err(CKR_OPERATION_ACTIVE);
            }
            ss.op = Op::Cipher { key: k, decrypt };
            Reply::done()
        }
        Err(e) => err(e),
    }
}

fn cipher_one<T>(
    m: &Mock,
    call: u16,
    session: u64,
    data: &[u8],
    out: OutSpec,
    decrypt: bool,
    make: impl FnOnce(OutBytes) -> T,
) -> Reply<T> {
    let mut s = enter!(m, call);
    let ss = match get(&mut s, session) {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    let Op::Cipher { key, decrypt: d } = ss.op.clone() else { return err(CKR_OPERATION_NOT_INITIALIZED) };
    if d != decrypt {
        return err(CKR_OPERATION_NOT_INITIALIZED);
    }
    let res = xor(&key, data);
    let (rv, o) = out_bytes(out, &res);
    if rv == CKR_OK as u64 && !matches!(out, OutSpec::Length) {
        ss.op = Op::None;
    }
    Reply { rv, resp: Some(make(o)) }
}

fn cipher_part<T>(
    m: &Mock,
    call: u16,
    session: u64,
    data: &[u8],
    out: OutSpec,
    decrypt: bool,
    make: impl FnOnce(OutBytes) -> T,
) -> Reply<T> {
    let mut s = enter!(m, call);
    let ss = match get(&mut s, session) {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    let Op::Cipher { key, decrypt: d } = ss.op.clone() else { return err(CKR_OPERATION_NOT_INITIALIZED) };
    if d != decrypt {
        return err(CKR_OPERATION_NOT_INITIALIZED);
    }
    bytes_reply(out, &xor(&key, data), make)
}

fn cipher_final<T>(m: &Mock, call: u16, session: u64, out: OutSpec, make: impl FnOnce(OutBytes) -> T) -> Reply<T> {
    let mut s = enter!(m, call);
    let ss = match get(&mut s, session) {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    if !matches!(ss.op, Op::Cipher { .. }) {
        return err(CKR_OPERATION_NOT_INITIALIZED);
    }
    let r = bytes_reply(out, &[], make);
    if r.rv == CKR_OK as u64 {
        ss.op = Op::None;
    }
    r
}

fn mac_init<T>(m: &Mock, call: u16, session: u64, key: u64, verify: bool) -> Reply<T> {
    let mut s = enter!(m, call);
    let k = match key_bytes(&s, key) {
        Ok(k) => k,
        Err(e) => return err(e),
    };
    match get(&mut s, session) {
        Ok(ss) => {
            ss.op = Op::Mac { key: k, data: Vec::new(), verify };
            Reply::done()
        }
        Err(e) => err(e),
    }
}

fn mac_update<T>(m: &Mock, call: u16, session: u64, part: &[u8]) -> Reply<T> {
    let mut s = enter!(m, call);
    match get(&mut s, session) {
        Ok(Sess { op: Op::Mac { data, .. }, .. }) => {
            data.extend_from_slice(part);
            Reply::done()
        }
        Ok(_) => err(CKR_OPERATION_NOT_INITIALIZED),
        Err(e) => err(e),
    }
}

fn message_key_init<T>(m: &Mock, call: u16, session: u64, key: u64, mech: u64, _verify: bool) -> Reply<T> {
    let mut s = enter!(m, call);
    let k = match key_bytes(&s, key) {
        Ok(k) => k,
        Err(e) => return err(e),
    };
    match get(&mut s, session) {
        Ok(ss) => {
            ss.msg_mech = Some(mech);
            ss.op = Op::MsgKey(k);
            Reply::done()
        }
        Err(e) => err(e),
    }
}

/// What the module returns in a `CK_GCM_MESSAGE_PARAMS`: the generated IV and the tag.
fn gcm_out(fill: u8) -> Node {
    Node::L(vec![
        Node::B(vec![fill; 12]),
        Node::Absent,
        Node::Absent,
        Node::Absent,
        Node::B(vec![fill ^ 0xff; 16]),
        Node::Absent,
    ])
}
