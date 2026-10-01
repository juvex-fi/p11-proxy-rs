//! One call: decode, check policy, translate handles, run it against the
//! backend, translate the answer back, encode.

use crate::ctx::{full_list_spec, ClientCtx};
use crate::xlate::{xlate_request, xlate_response};
use p11_module::{dispatch as backend_dispatch, Backend};
use p11_types::*;
use p11_wire::calls::*;
use p11_wire::structs::OutSpec;
use p11_wire::{U64s, WireError};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// A request the daemon can't make sense of; the connection is dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct Malformed(pub WireError);

/// The daemon's answer: `CK_RV` and the encoded response body, if any.
pub type Answer = (u64, Option<Vec<u8>>);

const NOT_INIT: u64 = CKR_CRYPTOKI_NOT_INITIALIZED as u64;

fn ck(rv: CK_RV) -> u64 {
    rv as u64
}

/// Handle a request body for `call` from a client of `ctx`.
pub fn handle(ctx: &ClientCtx, backend: &dyn Backend, call: u16, body: &[u8]) -> Result<Answer, Malformed> {
    handle_with(ctx, backend, call, body, &|| true)
}

/// [`handle`], told how to find out whether the client is still there (for
/// calls that wait).
pub fn handle_with(
    ctx: &ClientCtx,
    backend: &dyn Backend,
    call: u16,
    body: &[u8],
    peer_alive: &dyn Fn() -> bool,
) -> Result<Answer, Malformed> {
    #[cfg(feature = "vendor")]
    if call == p11_wire::vendorfn::CALL_VENDOR {
        // a vendor-defined function, declared in the configuration; a panic in the module is contained too
        return match catch_unwind(AssertUnwindSafe(|| crate::vendorfn::handle(ctx, backend, body))) {
            Ok(r) => r,
            Err(_) => Ok((ck(CKR_GENERAL_ERROR), None)),
        };
    }
    let Some(info) = call_info(call) else { return Ok((ck(CKR_FUNCTION_NOT_SUPPORTED), None)) };
    let mut req = match Request::decode(call, body) {
        Ok(r) => r,
        Err(RequestError::Unknown) => return Ok((ck(CKR_FUNCTION_NOT_SUPPORTED), None)),
        Err(RequestError::Malformed(e)) => return Err(Malformed(e)),
    };
    if !ctx.rules.call_allowed(info.rw) {
        return Ok((ck(CKR_ACTION_PROHIBITED), None));
    }
    // A panic inside a backend must not take the connection thread, and with
    // it the client's sessions, down silently.
    let run = catch_unwind(AssertUnwindSafe(|| run(ctx, backend, &mut req, peer_alive)));
    Ok(match run {
        Ok((rv, resp)) => (rv, resp.map(|r| r.encode_body())),
        Err(_) => (ck(CKR_GENERAL_ERROR), None),
    })
}

fn run(
    ctx: &ClientCtx,
    backend: &dyn Backend,
    req: &mut Request,
    peer_alive: &dyn Fn() -> bool,
) -> (u64, Option<Response>) {
    // Initialize and Finalize come first: everything else needs an initialised context.
    match req {
        Request::Initialize(_) => {
            let mut st = ctx.lock();
            if st.initialized {
                return (ck(CKR_CRYPTOKI_ALREADY_INITIALIZED), None);
            }
            st.initialized = true;
            return (ck(CKR_OK), None);
        }
        Request::Finalize(_) => {
            if !ctx.is_initialized() {
                return (NOT_INIT, None);
            }
            ctx.close_sessions(backend, None);
            let mut st = ctx.lock();
            st.initialized = false;
            st.objects.clear();
            st.rev_objects.clear();
            return (ck(CKR_OK), None);
        }
        _ => {}
    }
    if !ctx.is_initialized() {
        return (NOT_INIT, None);
    }
    match req {
        Request::GetSlotList(r) => return get_slot_list(ctx, backend, r),
        Request::GetMechanismList(r) => return get_mechanism_list(ctx, backend, r),
        Request::WaitForSlotEvent(r) => return wait_for_slot_event(ctx, backend, r, peer_alive),
        Request::OpenSession(r) => return open_session(ctx, backend, r),
        Request::CloseSession(r) => return close_session(ctx, backend, r),
        Request::CloseAllSessions(r) => {
            if let Err(rv) = crate::xlate::Xlate::slot(ctx, r.slot) {
                return (rv, None);
            }
            ctx.close_sessions(backend, Some(r.slot));
            return (ck(CKR_OK), None);
        }
        _ => {}
    }

    // remember client-side names needed after translation
    let vsession = match &*req {
        Request::MessageEncryptInit(r) => Some((r.session, r.mechanism.mechanism)),
        Request::MessageDecryptInit(r) => Some((r.session, r.mechanism.mechanism)),
        Request::MessageSignInit(r) => Some((r.session, r.mechanism.mechanism)),
        Request::MessageVerifyInit(r) => Some((r.session, r.mechanism.mechanism)),
        _ => None,
    };
    let destroyed = match &*req {
        Request::DestroyObject(r) => Some(r.object),
        _ => None,
    };

    if let Err(rv) = xlate_request(ctx, req) {
        return (rv, None);
    }
    let (rv, mut resp) = backend_dispatch(backend, req);
    if rv == ck(CKR_OK) {
        if let Some(r) = resp.as_mut() {
            xlate_response(ctx, req, r);
        }
        if let Some((vs, mech)) = vsession {
            ctx.set_msg_mech(vs, mech);
        }
        if let Some(o) = destroyed {
            ctx.forget_object(o);
        }
    }
    (rv, resp)
}

fn open_session(ctx: &ClientCtx, backend: &dyn Backend, r: &OpenSessionReq) -> (u64, Option<Response>) {
    if let Err(rv) = crate::xlate::Xlate::slot(ctx, r.slot) {
        return (rv, None);
    }
    if !ctx.rules.session_flags_ok(r.flags) {
        return (ck(CKR_TOKEN_WRITE_PROTECTED), None);
    }
    // PKCS#11 sessions are always serial; the flag is mandatory.
    let q = OpenSessionReq { slot: r.slot, flags: r.flags | CKF_SERIAL_SESSION as u64 };
    let rep = backend.c_open_session(&q);
    if rep.rv != ck(CKR_OK) {
        return (rep.rv, None);
    }
    let Some(real) = rep.resp.map(|x| x.session) else { return (ck(CKR_DEVICE_ERROR), None) };
    match ctx.add_session(real, r.slot) {
        Ok(v) => (ck(CKR_OK), Some(Response::OpenSession(OpenSessionResp { session: v }))),
        Err(rv) => {
            let _ = backend.c_close_session(&CloseSessionReq { session: real });
            (rv, None)
        }
    }
}

fn close_session(ctx: &ClientCtx, backend: &dyn Backend, r: &CloseSessionReq) -> (u64, Option<Response>) {
    let Some(rec) = ctx.remove_session(r.session) else { return (ck(CKR_SESSION_HANDLE_INVALID), None) };
    let rep = backend.c_close_session(&CloseSessionReq { session: rec.real });
    (rep.rv, None)
}

/// Apply the two-call convention to a list the daemon filtered itself.
fn respond_list(spec: OutSpec, list: Vec<u64>) -> (u64, p11_wire::structs::OutU64s) {
    use p11_wire::structs::OutU64s;
    let len = list.len() as u64;
    match spec {
        OutSpec::Length => (ck(CKR_OK), OutU64s { len, data: None }),
        OutSpec::Capacity(n) if len <= n => (ck(CKR_OK), OutU64s { len, data: Some(U64s(list)) }),
        OutSpec::Capacity(_) => (ck(CKR_BUFFER_TOO_SMALL), OutU64s { len, data: None }),
    }
}

fn get_slot_list(ctx: &ClientCtx, backend: &dyn Backend, r: &GetSlotListReq) -> (u64, Option<Response>) {
    if ctx.rules.slots.is_none() {
        let rep = backend.c_get_slot_list(r);
        return (rep.rv, rep.resp.map(Response::GetSlotList));
    }
    let rep = backend.c_get_slot_list(&GetSlotListReq { token_present: r.token_present, slots: full_list_spec() });
    if rep.rv != ck(CKR_OK) {
        return (rep.rv, None);
    }
    let all = rep.resp.and_then(|x| x.slots.data).map(|d| d.0).unwrap_or_default();
    let list: Vec<u64> = all.into_iter().filter(|s| ctx.rules.slot_allowed(*s)).collect();
    let (rv, slots) = respond_list(r.slots, list);
    (rv, Some(Response::GetSlotList(GetSlotListResp { slots })))
}

fn get_mechanism_list(ctx: &ClientCtx, backend: &dyn Backend, r: &GetMechanismListReq) -> (u64, Option<Response>) {
    if let Err(rv) = crate::xlate::Xlate::slot(ctx, r.slot) {
        return (rv, None);
    }
    // Mechanisms whose parameters the proxy can't carry are left out of the
    // list, so applications don't pick one that would fail later.
    let rep = backend.c_get_mechanism_list(&GetMechanismListReq { slot: r.slot, mechanisms: full_list_spec() });
    if rep.rv != ck(CKR_OK) {
        return (rep.rv, None);
    }
    let all = rep.resp.and_then(|x| x.mechanisms.data).map(|d| d.0).unwrap_or_default();
    let list: Vec<u64> = all.into_iter().filter(|m| ctx.rules.mechanism_allowed(*m)).collect();
    let (rv, mechanisms) = respond_list(r.mechanisms, list);
    (rv, Some(Response::GetMechanismList(GetMechanismListResp { mechanisms })))
}

/// `C_WaitForSlotEvent` without parking a thread in the module for good: ask
/// the module without blocking, and between asks check that the client is
/// still there and hasn't finalised. (A module that ignores the flag blocks as
/// it always did; one that refuses it is called the plain way.)
fn wait_for_slot_event(
    ctx: &ClientCtx,
    backend: &dyn Backend,
    r: &WaitForSlotEventReq,
    peer_alive: &dyn Fn() -> bool,
) -> (u64, Option<Response>) {
    let dont_block = CKF_DONT_BLOCK as u64;
    let wrap = |rep: p11_module::Reply<WaitForSlotEventResp>| (rep.rv, rep.resp.map(Response::WaitForSlotEvent));
    if r.flags & dont_block != 0 {
        return wrap(backend.c_wait_for_slot_event(r));
    }
    let mut delay = std::time::Duration::from_millis(2);
    loop {
        let rep = backend.c_wait_for_slot_event(&WaitForSlotEventReq { flags: r.flags | dont_block });
        match rep.rv {
            rv if rv == ck(CKR_OK) => {
                match rep.resp {
                    Some(x) if ctx.rules.slot_allowed(x.slot) => return (rv, Some(Response::WaitForSlotEvent(x))),
                    Some(_) => {} // an event for a slot this client may not see
                    None => return (ck(CKR_DEVICE_ERROR), None),
                }
            }
            rv if rv == ck(CKR_NO_EVENT) => {}
            rv if rv == ck(CKR_FUNCTION_NOT_SUPPORTED) || rv == ck(CKR_ARGUMENTS_BAD) => {
                return wrap(backend.c_wait_for_slot_event(r))
            }
            rv => return (rv, None),
        }
        if !ctx.is_initialized() {
            return (NOT_INIT, None);
        }
        if !peer_alive() {
            return (ck(CKR_DEVICE_REMOVED), None);
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(std::time::Duration::from_millis(50));
    }
}
