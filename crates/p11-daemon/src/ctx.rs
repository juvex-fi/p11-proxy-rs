//! One client's state in the daemon: the sessions it opened and the objects
//! it has seen, under handles the client can't use for anything but this
//! context. Shared by all of the client's pooled connections.

use crate::policy::{Identity, Rules};
use crate::xlate::Xlate;
use p11_module::Backend;
use p11_types::*;
use p11_wire::attr::Attr;
use p11_wire::calls::*;
use p11_wire::handshake::Token;
use p11_wire::structs::OutSpec;
use p11_wire::structs::{Mech, MsgParam};
use p11_wire::Node;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Mutex, MutexGuard};

/// What the module sees for a client handle that isn't one: nothing is ever given this handle.
pub const NO_SUCH_OBJECT: u64 = 0xffff_ffff_ffff_fffe;

/// Most object handles one client context may have registered.
pub const MAX_OBJECTS: usize = 1 << 20;

#[derive(Debug)]
pub(crate) struct SessionRec {
    pub real: u64,
    pub slot: u64,
    /// mechanism selected by the last `C_Message*Init`
    pub msg_mech: Option<u64>,
}

#[derive(Debug, Default)]
pub(crate) struct State {
    pub initialized: bool,
    pub sessions: HashMap<u64, SessionRec>,
    pub next_session: u64,
    pub objects: HashMap<u64, u64>,
    pub rev_objects: HashMap<u64, u64>,
    pub next_object: u64,
}

#[derive(Debug)]
pub struct ClientCtx {
    pub token: Token,
    pub identity: Identity,
    pub rules: Rules,
    pub(crate) conns: AtomicUsize,
    pub(crate) st: Mutex<State>,
}

impl ClientCtx {
    pub fn new(token: Token, identity: Identity, rules: Rules) -> ClientCtx {
        ClientCtx {
            token,
            identity,
            rules,
            conns: AtomicUsize::new(0),
            st: Mutex::new(State { next_session: 1, next_object: 1, ..Default::default() }),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn session_count(&self) -> usize {
        self.lock().sessions.len()
    }

    pub fn is_initialized(&self) -> bool {
        self.lock().initialized
    }

    /// Register a session the module opened; returns the client's handle.
    pub(crate) fn add_session(&self, real: u64, slot: u64) -> Result<u64, u64> {
        let mut st = self.lock();
        if st.sessions.len() >= self.rules.max_sessions {
            return Err(CKR_SESSION_COUNT as u64);
        }
        let v = st.next_session;
        st.next_session += 1;
        st.sessions.insert(v, SessionRec { real, slot, msg_mech: None });
        Ok(v)
    }

    pub(crate) fn remove_session(&self, v: u64) -> Option<SessionRec> {
        self.lock().sessions.remove(&v)
    }

    pub(crate) fn forget_object(&self, v: u64) {
        let mut st = self.lock();
        if let Some(real) = st.objects.remove(&v) {
            st.rev_objects.remove(&real);
        }
    }

    /// Close every session this context still holds open in the module.
    /// Called when the client goes away or calls `C_Finalize`.
    pub fn close_sessions(&self, backend: &dyn Backend, only_slot: Option<u64>) {
        let victims: Vec<(u64, u64)> = {
            let mut st = self.lock();
            let ids: Vec<u64> =
                st.sessions.iter().filter(|(_, s)| only_slot.is_none_or(|sl| s.slot == sl)).map(|(v, _)| *v).collect();
            ids.into_iter().filter_map(|v| st.sessions.remove(&v).map(|s| (v, s.real))).collect()
        };
        for (_, real) in victims {
            let _ = backend.c_close_session(&CloseSessionReq { session: real });
        }
    }

    pub(crate) fn set_msg_mech(&self, vsession: u64, mech: u64) {
        if let Some(s) = self.lock().sessions.get_mut(&vsession) {
            s.msg_mech = Some(mech);
        }
    }

    fn translate_handles(&self, mechanism: u64, node: &mut Node) -> Result<(), u64> {
        let mut bad = false;
        p11_params::mech::walk_handles(mechanism, node, &mut |h| match self.object(*h, true) {
            Ok(r) => *h = r,
            Err(_) => bad = true,
        });
        if bad {
            Err(CKR_KEY_HANDLE_INVALID as u64)
        } else {
            Ok(())
        }
    }
}

fn nested_ok(rules: &Rules, a: &[Attr]) -> bool {
    use p11_wire::attr::AttrVal;
    a.iter().all(|x| {
        rules.attr_allowed(x.ty)
            && match &x.val {
                AttrVal::Nested(n) => nested_ok(rules, n),
                _ => true,
            }
    })
}

impl Xlate for ClientCtx {
    fn session(&self, v: u64) -> Result<u64, u64> {
        self.lock().sessions.get(&v).map(|s| s.real).ok_or(CKR_SESSION_HANDLE_INVALID as u64)
    }

    fn object(&self, v: u64, _key: bool) -> Result<u64, u64> {
        if v == 0 {
            return Ok(0);
        }
        // A handle the client doesn't have is passed on as one no object has,
        // so the module answers with its own error for an invalid handle (which
        // differs between modules and between calls) instead of the daemon guessing.
        Ok(self.lock().objects.get(&v).copied().unwrap_or(NO_SUCH_OBJECT))
    }

    fn new_object(&self, real: u64) -> u64 {
        let mut st = self.lock();
        if let Some(v) = st.rev_objects.get(&real) {
            return *v;
        }
        if st.objects.len() >= MAX_OBJECTS {
            // Stop registering; the client gets a handle it can't use rather than
            // the daemon growing without bound.
            return 0;
        }
        let v = st.next_object;
        st.next_object += 1;
        st.objects.insert(v, real);
        st.rev_objects.insert(real, v);
        v
    }

    fn slot(&self, id: u64) -> Result<(), u64> {
        if self.rules.slot_allowed(id) {
            Ok(())
        } else {
            Err(CKR_SLOT_ID_INVALID as u64)
        }
    }

    fn mech_in(&self, m: &mut Mech) -> Result<(), u64> {
        if !self.rules.mechanism_allowed(m.mechanism) {
            return Err(CKR_MECHANISM_INVALID as u64);
        }
        if let Some(n) = m.param.as_mut() {
            self.translate_handles(m.mechanism, n)?;
        }
        Ok(())
    }

    fn attrs_in(&self, _call: u16, a: &[Attr]) -> Result<(), u64> {
        if nested_ok(&self.rules, a) {
            Ok(())
        } else {
            Err(CKR_ATTRIBUTE_TYPE_INVALID as u64)
        }
    }

    fn msg_in(&self, vsession: u64, phase: u8, p: &mut MsgParam) -> Result<(), u64> {
        p.phase = phase;
        let recorded = self.lock().sessions.get(&vsession).and_then(|s| s.msg_mech);
        match recorded {
            None => return Err(CKR_OPERATION_NOT_INITIALIZED as u64),
            Some(m) if m != p.mechanism => return Err(CKR_MECHANISM_PARAM_INVALID as u64),
            Some(_) => {}
        }
        // message parameters (IVs, nonces, tags) hold no object handles
        Ok(())
    }

    fn params_out(&self, mechanism: u64, out: &mut Option<Node>) {
        if let Some(n) = out.as_mut() {
            p11_params::mech::walk_handles(mechanism, n, &mut |h| {
                if *h != 0 {
                    *h = self.new_object(*h);
                }
            });
        }
    }
}

/// The largest number of handles asked of the module when the daemon has to
/// filter a list itself.
pub(crate) const LIST_CAPACITY: u64 = 65_536;

pub(crate) fn full_list_spec() -> OutSpec {
    OutSpec::Capacity(LIST_CAPACITY)
}
