//! The parsed API description and what each argument kind means.

use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Since {
    V2_40,
    V3_0,
    V3_2,
}

impl Since {
    pub fn label(self) -> &'static str {
        match self {
            Since::V2_40 => "2.40",
            Since::V3_0 => "3.0",
            Since::V3_2 => "3.2",
        }
    }
}

/// What an argument is. Each kind fixes its C parameters, its wire types in
/// the request and the response, and its handling on both ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    // ---- inputs ----
    /// `CK_SLOT_ID`
    Slot,
    /// `CK_SESSION_HANDLE`; the daemon translates it
    Session,
    /// `CK_OBJECT_HANDLE`; the daemon translates it (0 stays 0)
    Object,
    /// any other `CK_ULONG` (flags, types, ids)
    U64,
    /// `CK_BBOOL`
    Bool,
    /// `pointer, length`
    Bytes,
    /// `pointer, length` where a NULL pointer is meaningful (PINs)
    OptBytes,
    /// The same for a PIN or user name: held in a `Secret`, zeroed on drop, never printed
    Secret,
    /// `CK_UTF8CHAR label[32]`
    Label,
    /// NUL-terminated string
    CStr,
    /// `CK_MECHANISM_PTR`; the response carries the parameter members the module filled in
    Mech,
    /// `CK_ATTRIBUTE_PTR, count` used as a template
    Attrs,
    /// `pParameter, ulParameterLen` of a message-based call
    MsgParam,
    // ---- outputs ----
    /// `buffer, CK_ULONG_PTR length` with the two-call convention
    OBytes,
    /// `buffer, length`: the caller wants exactly this many bytes
    OFixed,
    /// `CK_ULONG_PTR array, CK_ULONG_PTR count` with the two-call convention
    OU64s,
    /// `CK_ULONG_PTR array, CK_ULONG max, CK_ULONG_PTR count` (`C_FindObjects`)
    OHandles,
    /// `CK_ULONG_PTR`
    OU64,
    /// `CK_OBJECT_HANDLE_PTR`; the daemon translates it
    OObject,
    /// `CK_SESSION_HANDLE_PTR`; the daemon registers it
    OSession,
    OInfo,
    OSlotInfo,
    OTokenInfo,
    OSessionInfo,
    OMechInfo,
    // ---- both ----
    /// `CK_ATTRIBUTE_PTR, count` of `C_GetAttributeValue`
    AttrsQuery,
    /// `CK_ASYNC_DATA_PTR`
    AsyncData,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "slot" => Kind::Slot,
            "session" => Kind::Session,
            "object" => Kind::Object,
            "u64" => Kind::U64,
            "bool" => Kind::Bool,
            "bytes" => Kind::Bytes,
            "optbytes" => Kind::OptBytes,
            "secret" => Kind::Secret,
            "label" => Kind::Label,
            "cstr" => Kind::CStr,
            "mech" => Kind::Mech,
            "attrs" => Kind::Attrs,
            "msgparam" => Kind::MsgParam,
            "o_bytes" => Kind::OBytes,
            "o_fixed" => Kind::OFixed,
            "o_u64s" => Kind::OU64s,
            "o_handles" => Kind::OHandles,
            "o_u64" => Kind::OU64,
            "o_object" => Kind::OObject,
            "o_session" => Kind::OSession,
            "o_info" => Kind::OInfo,
            "o_slot_info" => Kind::OSlotInfo,
            "o_token_info" => Kind::OTokenInfo,
            "o_session_info" => Kind::OSessionInfo,
            "o_mech_info" => Kind::OMechInfo,
            "attrs_query" => Kind::AttrsQuery,
            "asyncdata" => Kind::AsyncData,
            _ => return None,
        })
    }

    /// Type of the request field, if the kind sends anything.
    pub fn req_ty(self) -> Option<&'static str> {
        Some(match self {
            Kind::Slot | Kind::Session | Kind::Object | Kind::U64 => "u64",
            Kind::Bool => "bool",
            Kind::Bytes | Kind::CStr => "Vec<u8>",
            Kind::OptBytes => "Option<Vec<u8>>",
            Kind::Secret => "Option<Secret>",
            Kind::Label => "[u8; 32]",
            Kind::Mech => "Mech",
            Kind::Attrs => "Template",
            Kind::MsgParam => "MsgParam",
            Kind::OBytes | Kind::OU64s => "OutSpec",
            Kind::OFixed | Kind::OHandles => "u64",
            Kind::AttrsQuery => "Seq<Query>",
            Kind::AsyncData => "AsyncIn",
            Kind::OU64
            | Kind::OObject
            | Kind::OSession
            | Kind::OInfo
            | Kind::OSlotInfo
            | Kind::OTokenInfo
            | Kind::OSessionInfo
            | Kind::OMechInfo => return None,
        })
    }

    /// Type of the response field, if the kind returns anything.
    pub fn resp_ty(self) -> Option<&'static str> {
        Some(match self {
            Kind::Mech | Kind::MsgParam => "Option<Node>",
            Kind::OBytes => "OutBytes",
            Kind::OFixed => "Vec<u8>",
            Kind::OU64s => "OutU64s",
            Kind::OHandles => "U64s",
            Kind::OU64 | Kind::OObject | Kind::OSession => "u64",
            Kind::OInfo => "Info",
            Kind::OSlotInfo => "SlotInfo",
            Kind::OTokenInfo => "TokenInfo",
            Kind::OSessionInfo => "SessionInfo",
            Kind::OMechInfo => "MechanismInfo",
            Kind::AttrsQuery => "Seq<Reply>",
            Kind::AsyncData => "AsyncOut",
            _ => return None,
        })
    }

    /// Suffix of the response field name (`Mech` and `MsgParam` return the
    /// filled-in members under a different name than the request field).
    pub fn resp_suffix(self) -> &'static str {
        match self {
            Kind::Mech | Kind::MsgParam => "_out",
            _ => "",
        }
    }

    /// The C parameters (name suffix, type from the PKCS#11 header) this kind stands for.
    pub fn c_params(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Kind::Slot => &[("", "CK_SLOT_ID")],
            Kind::Session => &[("", "CK_SESSION_HANDLE")],
            Kind::Object => &[("", "CK_OBJECT_HANDLE")],
            Kind::U64 => &[("", "CK_ULONG")],
            Kind::Bool => &[("", "CK_BBOOL")],
            Kind::Bytes | Kind::OptBytes | Kind::Secret => &[("_ptr", "CK_BYTE_PTR"), ("_len", "CK_ULONG")],
            Kind::Label | Kind::CStr => &[("_ptr", "CK_UTF8CHAR_PTR")],
            Kind::Mech => &[("_ptr", "CK_MECHANISM_PTR")],
            Kind::Attrs | Kind::AttrsQuery => &[("_ptr", "CK_ATTRIBUTE_PTR"), ("_len", "CK_ULONG")],
            Kind::MsgParam => &[("_ptr", "CK_VOID_PTR"), ("_len", "CK_ULONG")],
            Kind::OBytes => &[("_ptr", "CK_BYTE_PTR"), ("_len", "CK_ULONG_PTR")],
            Kind::OFixed => &[("_ptr", "CK_BYTE_PTR"), ("_len", "CK_ULONG")],
            Kind::OU64s => &[("_ptr", "CK_ULONG_PTR"), ("_len", "CK_ULONG_PTR")],
            Kind::OHandles => &[("_ptr", "CK_ULONG_PTR"), ("_max", "CK_ULONG"), ("_count", "CK_ULONG_PTR")],
            Kind::OU64 | Kind::OObject | Kind::OSession => &[("_ptr", "CK_ULONG_PTR")],
            Kind::OInfo => &[("_ptr", "CK_INFO_PTR")],
            Kind::OSlotInfo => &[("_ptr", "CK_SLOT_INFO_PTR")],
            Kind::OTokenInfo => &[("_ptr", "CK_TOKEN_INFO_PTR")],
            Kind::OSessionInfo => &[("_ptr", "CK_SESSION_INFO_PTR")],
            Kind::OMechInfo => &[("_ptr", "CK_MECHANISM_INFO_PTR")],
            Kind::AsyncData => &[("_ptr", "CK_ASYNC_DATA_PTR")],
        }
    }

    pub fn is_scalar_in(self) -> bool {
        matches!(self, Kind::Slot | Kind::Session | Kind::Object | Kind::U64 | Kind::Bool)
    }
}

#[derive(Debug, Clone)]
pub struct Arg {
    pub name: String,
    pub kind: Kind,
}

#[derive(Debug, Clone)]
pub struct Call {
    pub id: u16,
    /// `C_Encrypt`
    pub name: String,
    pub since: Since,
    pub rw: bool,
    pub custom: bool,
    pub special: bool,
    pub args: Vec<Arg>,
}

impl Call {
    /// `Encrypt`
    pub fn short(&self) -> &str {
        &self.name[2..]
    }
    /// Whether the request carries a PIN or user name.
    pub fn has_secret(&self) -> bool {
        self.args.iter().any(|a| a.kind == Kind::Secret)
    }
    /// `c_encrypt`
    pub fn method(&self) -> String {
        snake(&self.name)
    }
    pub fn req_fields(&self) -> impl Iterator<Item = (&Arg, &'static str)> {
        self.args.iter().filter_map(|a| a.kind.req_ty().map(|t| (a, t)))
    }
    /// (field name, type) for each response field.
    pub fn resp_fields(&self) -> Vec<(String, &'static str)> {
        self.args
            .iter()
            .filter_map(|a| a.kind.resp_ty().map(|t| (format!("{}{}", a.name, a.kind.resp_suffix()), t)))
            .collect()
    }
}

pub fn snake(name: &str) -> String {
    let mut out = String::new();
    let cs: Vec<char> = name.chars().collect();
    for (i, &c) in cs.iter().enumerate() {
        if c == '_' {
            out.push('_');
            continue;
        }
        if c.is_ascii_uppercase() {
            let prev_lower = i > 0 && (cs[i - 1].is_ascii_lowercase() || cs[i - 1].is_ascii_digit());
            let next_lower = i + 1 < cs.len() && cs[i + 1].is_ascii_lowercase();
            let prev_upper = i > 0 && cs[i - 1].is_ascii_uppercase();
            if i > 0 && cs[i - 1] != '_' && (prev_lower || (prev_upper && next_lower)) {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct Api {
    pub calls: Vec<Call>,
}

#[derive(Debug)]
pub struct ParseError(pub String);

impl Api {
    pub fn parse(text: &str) -> Result<Api, ParseError> {
        let mut calls: Vec<Call> = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            let err = |m: &str| ParseError(format!("line {}: {m}", n + 1));
            let (head, args) = line.split_once(':').ok_or_else(|| err("missing ':'"))?;
            let mut toks = head.split_whitespace();
            let id: u16 = toks.next().and_then(|t| t.parse().ok()).ok_or_else(|| err("bad id"))?;
            let name = toks.next().ok_or_else(|| err("missing name"))?.to_string();
            if !name.starts_with("C_") {
                return Err(err("call names start with C_"));
            }
            let mut c =
                Call { id, name, since: Since::V2_40, rw: false, custom: false, special: false, args: Vec::new() };
            for f in toks {
                match f {
                    "rw" => c.rw = true,
                    "custom" => c.custom = true,
                    "special" => c.special = true,
                    "since=2.40" => c.since = Since::V2_40,
                    "since=3.0" => c.since = Since::V3_0,
                    "since=3.2" => c.since = Since::V3_2,
                    _ => return Err(err(&format!("unknown flag {f}"))),
                }
            }
            for a in args.split_whitespace() {
                let (an, ak) = a.split_once(':').ok_or_else(|| err("argument needs name:kind"))?;
                let kind = Kind::parse(ak).ok_or_else(|| err(&format!("unknown kind {ak}")))?;
                if c.args.iter().any(|x| x.name == an) {
                    return Err(err(&format!("duplicate argument {an}")));
                }
                c.args.push(Arg { name: an.to_string(), kind });
            }
            if c.id as usize != calls.len() + 1 {
                return Err(err("ids must be consecutive from 1; never renumber, only append"));
            }
            calls.push(c);
        }
        Ok(Api { calls })
    }

    pub fn embedded() -> Api {
        Api::parse(include_str!("api.idl")).expect("api.idl is valid")
    }

    /// Markdown table of the calls for `PROTOCOL.md`.
    pub fn markdown(&self) -> String {
        let mut s = String::new();
        writeln!(s, "| id | call | since | rw | request | response |").unwrap();
        writeln!(s, "|---:|---|---|---|---|---|").unwrap();
        for c in &self.calls {
            let req: Vec<String> = c.req_fields().map(|(a, t)| format!("`{}: {}`", a.name, t)).collect();
            let resp: Vec<String> = c.resp_fields().iter().map(|(n, t)| format!("`{n}: {t}`")).collect();
            writeln!(
                s,
                "| {} | `{}` | {} | {} | {} | {} |",
                c.id,
                c.name,
                c.since.label(),
                if c.rw { "yes" } else { "" },
                req.join(", "),
                resp.join(", ")
            )
            .unwrap();
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_api_parses() {
        let api = Api::embedded();
        assert_eq!(api.calls.len(), 101);
        assert_eq!(api.calls[32].name, "C_Encrypt");
        assert_eq!(api.calls[32].id, 33);
    }

    #[test]
    fn snake_case() {
        assert_eq!(snake("C_Encrypt"), "c_encrypt");
        assert_eq!(snake("C_GetSlotList"), "c_get_slot_list");
        assert_eq!(snake("C_WrapKeyAuthenticated"), "c_wrap_key_authenticated");
        assert_eq!(snake("C_AsyncGetID"), "c_async_get_id");
        assert_eq!(snake("C_GetSessionValidationFlags"), "c_get_session_validation_flags");
    }

    #[test]
    fn parse_errors() {
        assert!(Api::parse("1 C_X : a:nope").is_err());
        assert!(Api::parse("2 C_X :").is_err());
        assert!(Api::parse("1 C_X : a:u64 a:u64").is_err());
        assert!(Api::parse("1 X :").is_err());
    }
}
