//! What a client identity may do.

use p11_types::*;
use std::collections::HashSet;

pub use p11_transport::Identity;

/// The permissions of one identity. The default allows everything the
/// proxy can carry.
#[derive(Debug, Clone)]
pub struct Rules {
    /// Slots the client may see and use; `None` allows all.
    pub slots: Option<HashSet<u64>>,
    /// Mechanisms the client may use; `None` allows all supported ones.
    pub mechanisms: Option<HashSet<u64>>,
    /// Refuse every call that changes the token, and read-write sessions.
    pub read_only: bool,
    /// Sessions one client context may hold open.
    pub max_sessions: usize,
    /// Attribute types a template may not contain.
    pub deny_attrs: HashSet<u64>,
}

impl Default for Rules {
    fn default() -> Self {
        Rules { slots: None, mechanisms: None, read_only: false, max_sessions: 1024, deny_attrs: HashSet::new() }
    }
}

impl Rules {
    pub fn slot_allowed(&self, id: u64) -> bool {
        self.slots.as_ref().is_none_or(|s| s.contains(&id))
    }
    pub fn mechanism_allowed(&self, m: u64) -> bool {
        p11_params::mech::is_supported(m) && self.mechanisms.as_ref().is_none_or(|s| s.contains(&m))
    }
    pub fn attr_allowed(&self, ty: u64) -> bool {
        !self.deny_attrs.contains(&ty)
    }
    pub(crate) fn call_allowed(&self, rw: bool) -> bool {
        !(self.read_only && rw)
    }
    pub(crate) fn session_flags_ok(&self, flags: u64) -> bool {
        !(self.read_only && flags & CKF_RW_SESSION as u64 != 0)
    }
}

/// Maps identities to rules. An identity with no matching entry is refused
/// at connection time.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    entries: Vec<(String, Rules)>,
    default: Option<Rules>,
}

impl Policy {
    /// Every authenticated client gets the same rules.
    pub fn allow_all(rules: Rules) -> Policy {
        Policy { entries: Vec::new(), default: Some(rules) }
    }
    /// Rules for exactly this identity.
    pub fn with_identity(mut self, identity: &str, rules: Rules) -> Policy {
        self.entries.push((identity.to_string(), rules));
        self
    }
    /// Rules for identities that match no entry.
    pub fn with_default(mut self, rules: Rules) -> Policy {
        self.default = Some(rules);
        self
    }
    /// The rules for an identity: the first entry that names it (by its name
    /// or any alias), else the default, else none.
    pub fn rules_for(&self, id: &Identity) -> Option<&Rules> {
        self.entries.iter().find(|(label, _)| id.matches(label)).map(|(_, r)| r).or(self.default.as_ref())
    }
}
