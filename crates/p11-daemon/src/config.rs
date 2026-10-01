//! The daemon's configuration: a TOML file, overridden by command-line options.
//!
//! ```toml
//! module = "/usr/lib/softhsm/libsofthsm2.so"
//! listen = ["tcp://0.0.0.0:2345", "unix:///run/pkcs11/daemon.sock"]
//! serialize_module = false      # one call at a time, for modules that are not thread safe
//!
//! [tls]                          # for tcp:// listeners
//! cert = "/etc/pkcs11/server.pem"
//! key = "/etc/pkcs11/server.key"
//! client_ca = "/etc/pkcs11/clients-ca.pem"
//!
//! [psk]                          # for psk:// listeners
//! file = "/etc/pkcs11/psk.keys"  # lines of identity:hex-secret
//!
//! [limits]
//! max_connections = 256
//! max_contexts = 128
//! max_conns_per_context = 32
//! handshake_timeout = 10         # seconds
//! idle_timeout = 0               # seconds a connection may sit silent; 0 = no limit
//!
//! [sandbox]
//! mode = "auto"                  # auto, off, or require
//! write_paths = ["/var/lib/softhsm"]   # macOS: where writing stays allowed
//!
//! [policy]
//! default = "allow"              # what identities without an entry get: "allow" or "deny"
//!
//! [[client]]
//! identity = "cert:cn=alice"     # a name or alias from p11_transport::Identity
//! slots = [0, 1]                 # omitted: all
//! mechanisms = ["CKM_SHA256", "CKM_AES_GCM"]   # names or numbers; omitted: all
//! read_only = true
//! max_sessions = 16
//! deny_attributes = ["CKA_EXTRACTABLE"]
//! ```

use crate::policy::{Policy, Rules};
use crate::server::Limits;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub module: Option<PathBuf>,
    pub listen: Vec<String>,
    pub serialize_module: bool,
    pub tls: Tls,
    pub psk: Psk,
    pub unix: Unix,
    pub limits: LimitsCfg,
    pub policy: PolicyCfg,
    #[serde(rename = "client")]
    pub clients: Vec<ClientCfg>,
    pub sandbox: Sandbox,
    /// Run as this user after opening the module and the listeners.
    pub drop_privileges: Option<String>,
    /// Vendor-defined mechanisms to carry, with what their parameter looks like.
    #[cfg(feature = "vendor")]
    #[serde(rename = "vendor_mechanism")]
    pub vendor_mechanisms: Vec<p11_params::vendor::VendorMech>,
    /// Structures the parameters of vendor-defined mechanisms are made of.
    #[cfg(feature = "vendor")]
    #[serde(rename = "vendor_struct")]
    pub vendor_structs: Vec<p11_params::vendor::VendorStruct>,
    /// Vendor-defined functions of the module to carry, with their signatures.
    #[cfg(feature = "vendor")]
    #[serde(rename = "vendor_function")]
    pub vendor_functions: Vec<p11_params::vendorfn::VendorFunction>,
    /// Without vendor support the entries are read only to be refused (see [`Config::parse`]).
    #[cfg(not(feature = "vendor"))]
    #[serde(rename = "vendor_mechanism")]
    vendor_mechanisms: Vec<toml::Value>,
    #[cfg(not(feature = "vendor"))]
    #[serde(rename = "vendor_struct")]
    vendor_structs: Vec<toml::Value>,
    #[cfg(not(feature = "vendor"))]
    #[serde(rename = "vendor_function")]
    vendor_functions: Vec<toml::Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Tls {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub client_ca: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Psk {
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Unix {
    /// File mode of the socket (octal, e.g. 0o660 written as 432 in TOML, or a string "0660").
    pub mode: Option<ModeVal>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ModeVal {
    Str(String),
    Num(u32),
}

impl ModeVal {
    pub fn get(&self) -> Result<u32, String> {
        match self {
            ModeVal::Num(n) => Ok(*n),
            ModeVal::Str(s) => {
                u32::from_str_radix(s.trim_start_matches("0o"), 8).map_err(|_| format!("bad file mode {s:?}"))
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsCfg {
    pub max_connections: usize,
    pub max_contexts: usize,
    pub max_conns_per_context: usize,
    pub handshake_timeout: u64,
    pub idle_timeout: u64,
}

impl Default for LimitsCfg {
    fn default() -> Self {
        LimitsCfg {
            max_connections: 256,
            max_contexts: 128,
            max_conns_per_context: 32,
            handshake_timeout: 10,
            idle_timeout: 0,
        }
    }
}

impl LimitsCfg {
    pub fn server_limits(&self) -> Limits {
        Limits { max_contexts: self.max_contexts, max_conns_per_context: self.max_conns_per_context }
    }
    pub fn handshake(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout.max(1))
    }
    pub fn idle(&self) -> Option<Duration> {
        (self.idle_timeout > 0).then(|| Duration::from_secs(self.idle_timeout))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyCfg {
    /// `allow` (default when there are no `[[client]]` entries) or `deny`.
    pub default: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum NameOrNum {
    Name(String),
    Num(u64),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCfg {
    pub identity: String,
    pub slots: Option<Vec<u64>>,
    pub mechanisms: Option<Vec<NameOrNum>>,
    #[serde(default)]
    pub read_only: bool,
    pub max_sessions: Option<usize>,
    #[serde(default)]
    pub deny_attributes: Vec<NameOrNum>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Sandbox {
    /// `auto` (default): confine the process where the platform supports it; `off`; `require`: refuse to run unconfined.
    pub mode: Option<String>,
    /// macOS: paths the process may still write to (the token store); none means no restriction.
    pub write_paths: Vec<PathBuf>,
    /// Linux: report forbidden system calls instead of killing the process.
    pub debug: bool,
}

impl ClientCfg {
    fn rules(&self) -> Result<Rules, String> {
        let mut r = Rules::default();
        if let Some(s) = &self.slots {
            r.slots = Some(s.iter().copied().collect::<HashSet<_>>());
        }
        if let Some(m) = &self.mechanisms {
            let mut set = HashSet::new();
            for x in m {
                set.insert(match x {
                    NameOrNum::Num(n) => *n,
                    NameOrNum::Name(n) => {
                        p11_types::mechanism_by_name(n).ok_or_else(|| format!("unknown mechanism {n}"))? as u64
                    }
                });
            }
            r.mechanisms = Some(set);
        }
        r.read_only = self.read_only;
        if let Some(n) = self.max_sessions {
            r.max_sessions = n;
        }
        for a in &self.deny_attributes {
            r.deny_attrs.insert(match a {
                NameOrNum::Num(n) => *n,
                NameOrNum::Name(n) => {
                    p11_types::attribute_by_name(n).ok_or_else(|| format!("unknown attribute {n}"))? as u64
                }
            });
        }
        Ok(r)
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let c: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        #[cfg(not(feature = "vendor"))]
        if !(c.vendor_mechanisms.is_empty() && c.vendor_structs.is_empty() && c.vendor_functions.is_empty()) {
            return Err(
                "vendor_mechanism, vendor_struct and vendor_function need a daemon built with the `vendor` feature"
                    .to_string(),
            );
        }
        Ok(c)
    }

    /// The access policy this configuration describes.
    pub fn policy(&self) -> Result<Policy, String> {
        let default_allow = match self.policy.default.as_deref() {
            Some("allow") => true,
            Some("deny") => false,
            Some(other) => return Err(format!("policy.default must be \"allow\" or \"deny\", not {other:?}")),
            None => self.clients.is_empty(),
        };
        let mut p = Policy::default();
        for c in &self.clients {
            p = p.with_identity(&c.identity, c.rules()?);
        }
        if default_allow {
            p = p.with_default(Rules::default());
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Identity;

    #[test]
    #[cfg(not(feature = "vendor"))]
    fn a_configuration_that_names_vendor_support_is_refused_without_it() {
        for text in [
            "[[vendor_mechanism]]\nid = 0x80000123\nlength = 16\n",
            "[[vendor_struct]]\nname = \"s\"\nsize = 8\nfields = []\n",
            "[[vendor_function]]\nname = \"F\"\nargs = []\n",
        ] {
            let e = Config::parse(text).unwrap_err();
            assert!(e.contains("`vendor` feature"), "{e}");
        }
        assert!(Config::parse("module = \"/lib/x.so\"\n").is_ok());
    }

    #[test]
    #[cfg(feature = "vendor")]
    fn vendor_functions_are_read_and_checked() {
        let c = Config::parse(
            "[[vendor_function]]\nname = \"Vnd_CopyObject\"\nargs = [\"session\", \"session\", \"object\", \"attrs\", \"o_object\"]\nrw = true\n\
             [[vendor_function]]\nname = \"Vnd_GetId\"\nargs = [\"session\", \"o_u64\"]\n",
        )
        .unwrap();
        let d: Vec<_> = c.vendor_functions.iter().map(|f| f.desc().unwrap()).collect();
        assert_eq!((d[0].name.as_str(), d[0].rw, d[0].c_arg_count()), ("Vnd_CopyObject", true, 6));
        assert!(!d[1].rw, "rw defaults to false");
        assert!(
            Config::parse("[[vendor_function]]\nname = \"F\"\nargs = []\nrww = true\n").is_err(),
            "typos are errors"
        );
        assert!(Config::parse("[[vendor_function]]\nargs = []\n").is_err(), "a name is required");
        let bad = |t: &str| Config::parse(t).unwrap().vendor_functions[0].desc().is_err();
        assert!(bad("[[vendor_function]]\nname = \"F\"\nargs = [\"nonsense\"]\n"));
        assert!(bad("[[vendor_function]]\nname = \"C_Login\"\nargs = []\n"));
        assert!(bad("[[vendor_function]]\nname = \"has space\"\nargs = []\n"));
    }

    #[test]
    #[cfg(feature = "vendor")]
    fn vendor_mechanisms_are_read() {
        let c = Config::parse(
            "[[vendor_mechanism]]\nid = 0x80000123\nlength = 16\n[[vendor_mechanism]]\nid = 2147484000\nmax_length = 64\n",
        )
        .unwrap();
        let v = &c.vendor_mechanisms;
        assert_eq!((v[0].id, v[0].length, v[0].max_length), (0x8000_0123, Some(16), None));
        assert_eq!((v[1].id, v[1].length, v[1].max_length), (2147484000, None, Some(64)));
        assert!(Config::parse("[[vendor_mechanism]]\nid = 1\nlenght = 2\n").is_err(), "typos are errors");
        // the forms that carry handles, and one shaped like a built-in mechanism
        let c = Config::parse(
            "[[vendor_mechanism]]\nid = 0x80000030\nhandle = true\n\
             [[vendor_mechanism]]\nid = 0x80000031\nlength = 40\nhandles = [8, 32]\n\
             [[vendor_mechanism]]\nid = 0x80000032\nsame_as = \"CKM_AES_GCM\"\n\
             [[vendor_mechanism]]\nid = 0x80000033\nsame_as = 4224\n",
        )
        .unwrap();
        let p: Vec<_> = c.vendor_mechanisms.iter().map(|m| m.param().unwrap()).collect();
        use p11_wire::handshake::VendorParam::*;
        assert_eq!(p[0], Handle);
        assert_eq!(p[1], Handles { len: 40, offs: vec![8, 32] });
        assert_eq!(p[2], SameAs(p11_types::CKM_AES_GCM as u64));
        assert_eq!(p[3], SameAs(4224));
        // structures for a parameter with pointers
        let c = Config::parse(
            "[[vendor_struct]]\nname = \"item\"\nsize = 16\nfields = [{ name = \"a\", offset = 0, kind = \"ulong\" }, { offset = 8, kind = \"handle\", dir = \"out\" }]\n\
             [[vendor_mechanism]]\nid = 0x80000040\nstruct = \"item\"\n",
        )
        .unwrap();
        let l = c.vendor_structs[0].layout().unwrap();
        assert_eq!(
            (l.name.as_str(), l.size, l.fields.len(), l.fields[1].dir),
            ("item", 16, 2, p11_wire::handshake::Dir::Out)
        );
        assert_eq!(c.vendor_mechanisms[0].param().unwrap(), Struct("item".into()));
        assert!(Config::parse(
            "[[vendor_struct]]\nname = \"s\"\nsize = 8\nfields = [{ offset = 0, kind = \"ulong\", typo = 1 }]\n"
        )
        .is_err());
        assert!(Config::parse("[[vendor_mechanism]]\nlength = 2\n").is_err(), "an id is required");
    }

    #[test]
    fn full_example() {
        let c = Config::parse(
            r#"
module = "/lib/x.so"
listen = ["tcp://0.0.0.0:2345"]
[tls]
cert = "c"
key = "k"
client_ca = "ca"
[limits]
max_connections = 5
idle_timeout = 30
[[client]]
identity = "cert:cn=alice"
slots = [0, 1]
mechanisms = ["CKM_SHA256", 4224]
read_only = true
max_sessions = 3
deny_attributes = ["CKA_EXTRACTABLE"]
"#,
        )
        .unwrap();
        assert_eq!(c.limits.max_connections, 5);
        assert_eq!(c.limits.idle(), Some(Duration::from_secs(30)));
        let p = c.policy().unwrap();
        let alice = p.rules_for(&Identity::new("cert:cn=alice")).unwrap();
        assert!(alice.read_only && alice.max_sessions == 3);
        assert!(alice.slot_allowed(1) && !alice.slot_allowed(2));
        assert!(alice.mechanism_allowed(p11_types::CKM_SHA256 as u64) && alice.mechanism_allowed(4224));
        assert!(!alice.attr_allowed(p11_types::CKA_EXTRACTABLE as u64));
        // with clients listed, strangers are refused by default
        assert!(p.rules_for(&Identity::new("cert:cn=bob")).is_none());
    }

    #[test]
    fn defaults_and_errors() {
        // no clients: everyone authenticated is allowed
        let c = Config::parse("module = \"m\"").unwrap();
        assert!(c.policy().unwrap().rules_for(&Identity::new("anyone")).is_some());
        // explicit deny with no clients
        let c = Config::parse("[policy]\ndefault = \"deny\"").unwrap();
        assert!(c.policy().unwrap().rules_for(&Identity::new("anyone")).is_none());
        assert!(Config::parse("[policy]\ndefault = \"maybe\"").unwrap().policy().is_err());
        // typos are errors, not silently ignored
        assert!(Config::parse("moduel = \"m\"").is_err());
        assert!(Config::parse("[[client]]\nidentity = \"a\"\nslotz = [1]").is_err());
        let c = Config::parse("[[client]]\nidentity = \"a\"\nmechanisms = [\"CKM_NOPE\"]").unwrap();
        assert!(c.policy().is_err());
        assert_eq!(ModeVal::Str("0660".into()).get().unwrap(), 0o660);
    }
}
