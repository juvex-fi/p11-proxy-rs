//! Vendor-defined functions: the functions a daemon carries, announced to a client in the
//! handshake, and the encoding of one call (call id [`CALL_VENDOR`], outside the call table).
//!
//! A function is described by a name and a list of argument *kinds*; each kind stands for one to
//! three C parameters (see [`ArgKind`]). The description is all either side knows about the
//! function: the client turns the caller's C arguments into values, the daemon turns the values into
//! C arguments for the module, and both check the values against the description.

use crate::attr::Attr;
use crate::codec::{Decode, Encode, Reader, Writer};
use crate::error::{Result, WireError};
use crate::limits::{MAX_BYTES, MAX_VENDOR_FNS};
use crate::structs::{OutBytes, OutSpec};
use crate::Seq;

/// The call id of a vendor function call. The call table ends below it.
pub const CALL_VENDOR: u16 = 1000;
/// Most arguments (kinds) of one function.
pub const MAX_FN_ARGS: usize = 32;
/// Most C parameters of one function: the widest call the daemon can make.
pub const MAX_C_ARGS: usize = 20;
/// Longest function name.
pub const MAX_FN_NAME: usize = 128;
/// Longest NUL-terminated string argument, without the NUL.
pub const MAX_CSTR: usize = 4096;
/// A `CK_UTF8CHAR label[32]`.
pub const LABEL_LEN: usize = 32;

/// What an argument is, and so how many C parameters it takes and how it travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ArgKind {
    /// An integer passed by value, of this width in bits (the daemon zero-extends it).
    U8 = 1,
    U16 = 2,
    U32 = 3,
    U64 = 4,
    /// A `CK_SLOT_ID` by value.
    Slot = 5,
    /// A `CK_SESSION_HANDLE` by value; the daemon translates it.
    Session = 6,
    /// A `CK_OBJECT_HANDLE` by value; the daemon translates it.
    Object = 7,
    /// A pointer and a length (two parameters): input bytes.
    Bytes = 8,
    /// The same, for a PIN or a key: wiped after the call, never logged.
    Secret = 9,
    /// A pointer to a NUL-terminated string (one parameter).
    CStr = 10,
    /// A pointer to 32 space-padded characters (one parameter).
    Label = 11,
    /// A `CK_ATTRIBUTE` array and its count (two parameters).
    Attrs = 12,
    /// A pointer to a 32-bit integer the function writes (one parameter).
    OU32 = 13,
    /// A pointer to a `CK_ULONG` the function writes (one parameter).
    OU64 = 14,
    /// A pointer to a `CK_OBJECT_HANDLE` the function writes; the daemon translates it back.
    OObject = 15,
    /// A buffer and a pointer to its length, in and out (two parameters): the two-call convention.
    OBytes = 16,
    /// A buffer, its capacity by value, and a pointer to the length written (three parameters).
    OBuf = 17,
}

impl ArgKind {
    pub const ALL: [ArgKind; 17] = [
        ArgKind::U8,
        ArgKind::U16,
        ArgKind::U32,
        ArgKind::U64,
        ArgKind::Slot,
        ArgKind::Session,
        ArgKind::Object,
        ArgKind::Bytes,
        ArgKind::Secret,
        ArgKind::CStr,
        ArgKind::Label,
        ArgKind::Attrs,
        ArgKind::OU32,
        ArgKind::OU64,
        ArgKind::OObject,
        ArgKind::OBytes,
        ArgKind::OBuf,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ArgKind::U8 => "u8",
            ArgKind::U16 => "u16",
            ArgKind::U32 => "u32",
            ArgKind::U64 => "u64",
            ArgKind::Slot => "slot",
            ArgKind::Session => "session",
            ArgKind::Object => "object",
            ArgKind::Bytes => "bytes",
            ArgKind::Secret => "secret",
            ArgKind::CStr => "cstr",
            ArgKind::Label => "label",
            ArgKind::Attrs => "attrs",
            ArgKind::OU32 => "o_u32",
            ArgKind::OU64 => "o_u64",
            ArgKind::OObject => "o_object",
            ArgKind::OBytes => "o_bytes",
            ArgKind::OBuf => "o_buf",
        }
    }

    pub fn parse(s: &str) -> Option<ArgKind> {
        ArgKind::ALL.into_iter().find(|k| k.name() == s)
    }

    pub fn from_u8(v: u8) -> Option<ArgKind> {
        ArgKind::ALL.into_iter().find(|k| *k as u8 == v)
    }

    /// The C parameters this kind stands for.
    pub fn c_args(self) -> usize {
        match self {
            ArgKind::Bytes | ArgKind::Secret | ArgKind::Attrs | ArgKind::OBytes => 2,
            ArgKind::OBuf => 3,
            _ => 1,
        }
    }

    /// Whether the function writes something the caller gets back.
    pub fn is_output(self) -> bool {
        matches!(self, ArgKind::OU32 | ArgKind::OU64 | ArgKind::OObject | ArgKind::OBytes | ArgKind::OBuf)
    }
}

/// One vendor function: the module's exported symbol and what its parameters are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnDesc {
    pub name: String,
    /// The function changes the token: refused for a read-only client.
    pub rw: bool,
    pub args: Vec<ArgKind>,
}

impl FnDesc {
    /// The C parameters of the function.
    pub fn c_arg_count(&self) -> usize {
        self.args.iter().map(|k| k.c_args()).sum()
    }

    /// Whether any argument is a [`ArgKind::Secret`].
    pub fn has_secret(&self) -> bool {
        self.args.contains(&ArgKind::Secret)
    }

    /// A description both sides accept: a plain C identifier that is not a standard `C_` function,
    /// at most [`MAX_FN_ARGS`] arguments and [`MAX_C_ARGS`] C parameters.
    pub fn validate(&self) -> std::result::Result<(), String> {
        let n = &self.name;
        let ident = !n.is_empty()
            && n.len() <= MAX_FN_NAME
            && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            && !n.as_bytes()[0].is_ascii_digit();
        if !ident {
            return Err(format!("vendor_function {n:?}: not a C identifier of at most {MAX_FN_NAME} characters"));
        }
        if n.starts_with("C_") {
            return Err(format!("vendor_function {n}: names starting C_ are the standard PKCS#11 functions"));
        }
        if self.args.len() > MAX_FN_ARGS || self.c_arg_count() > MAX_C_ARGS {
            return Err(format!("vendor_function {n}: at most {MAX_FN_ARGS} arguments and {MAX_C_ARGS} C parameters"));
        }
        Ok(())
    }
}

/// The payload of a `Kind::VendorFunctions` frame.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VendorFns(pub Vec<FnDesc>);

impl Encode for VendorFns {
    fn encode(&self, w: &mut Writer) {
        w.count(self.0.len());
        for f in &self.0 {
            w.bytes(f.name.as_bytes());
            w.bool(f.rw);
            w.u8(f.args.len() as u8);
            for k in &f.args {
                w.u8(*k as u8);
            }
        }
    }
}

impl Decode for VendorFns {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.count(MAX_VENDOR_FNS, 7)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let name = r.bytes_ref()?;
            if name.len() > MAX_FN_NAME {
                return Err(WireError::TooLarge);
            }
            let name = String::from_utf8(name.to_vec()).map_err(|_| WireError::Invalid)?;
            let rw = r.bool()?;
            let na = r.u8()? as usize;
            if na > MAX_FN_ARGS {
                return Err(WireError::TooLarge);
            }
            let mut args = Vec::with_capacity(na);
            for _ in 0..na {
                args.push(ArgKind::from_u8(r.u8()?).ok_or(WireError::BadTag)?);
            }
            let f = FnDesc { name, rw, args };
            f.validate().map_err(|_| WireError::Invalid)?;
            v.push(f);
        }
        Ok(VendorFns(v))
    }
}

/// What the caller passed for one argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InVal {
    /// An integer, a handle, or a slot.
    Int(u64),
    /// Bytes, a PIN, a string, a label.
    Bytes(Vec<u8>),
    Attrs(Vec<Attr>),
    /// The room the caller gave an output buffer; `None` when it passed no buffer (asking for the length).
    Cap(Option<u64>),
    /// An output that takes nothing in.
    Nothing,
}

const T_NOTHING: u8 = 0;
const T_INT: u8 = 1;
const T_BYTES: u8 = 2;
const T_ATTRS: u8 = 3;
const T_CAP_NONE: u8 = 4;
const T_CAP: u8 = 5;

impl InVal {
    fn encode(&self, w: &mut Writer) {
        match self {
            InVal::Nothing => w.u8(T_NOTHING),
            InVal::Int(v) => {
                w.u8(T_INT);
                w.u64(*v)
            }
            InVal::Bytes(b) => {
                w.u8(T_BYTES);
                w.bytes(b)
            }
            InVal::Attrs(a) => {
                w.u8(T_ATTRS);
                // a template on the wire is a Seq of attributes
                Seq(a.clone()).encode(w)
            }
            InVal::Cap(None) => w.u8(T_CAP_NONE),
            InVal::Cap(Some(n)) => {
                w.u8(T_CAP);
                w.u64(*n)
            }
        }
    }

    /// Decode the value of an argument of this kind, refusing any other shape.
    fn decode(kind: ArgKind, r: &mut Reader<'_>) -> Result<InVal> {
        let tag = r.u8()?;
        Ok(match (kind, tag) {
            (ArgKind::OU32 | ArgKind::OU64 | ArgKind::OObject, T_NOTHING) => InVal::Nothing,
            (
                ArgKind::U8
                | ArgKind::U16
                | ArgKind::U32
                | ArgKind::U64
                | ArgKind::Slot
                | ArgKind::Session
                | ArgKind::Object,
                T_INT,
            ) => {
                let v = r.u64()?;
                let max = match kind {
                    ArgKind::U8 => u8::MAX as u64,
                    ArgKind::U16 => u16::MAX as u64,
                    ArgKind::U32 => u32::MAX as u64,
                    _ => u64::MAX,
                };
                if v > max {
                    return Err(WireError::Invalid);
                }
                InVal::Int(v)
            }
            (ArgKind::Bytes | ArgKind::Secret | ArgKind::CStr | ArgKind::Label, T_BYTES) => {
                let b = r.bytes_ref()?;
                let ok = match kind {
                    ArgKind::CStr => b.len() <= MAX_CSTR && !b.contains(&0),
                    ArgKind::Label => b.len() == LABEL_LEN,
                    _ => b.len() <= MAX_BYTES,
                };
                if !ok {
                    return Err(WireError::Invalid);
                }
                InVal::Bytes(b.to_vec())
            }
            (ArgKind::Attrs, T_ATTRS) => InVal::Attrs(Seq::<Attr>::decode(r)?.0),
            (ArgKind::OBytes | ArgKind::OBuf, T_CAP_NONE) => InVal::Cap(None),
            (ArgKind::OBytes | ArgKind::OBuf, T_CAP) => {
                let n = r.u64()?;
                if n > MAX_BYTES as u64 {
                    return Err(WireError::TooLarge);
                }
                InVal::Cap(Some(n))
            }
            _ => return Err(WireError::BadTag),
        })
    }
}

/// A call to a vendor function: its name and one value per argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorRequest {
    pub name: String,
    pub args: Vec<InVal>,
}

impl VendorRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.name.as_bytes());
        w.u8(self.args.len() as u8);
        for a in &self.args {
            a.encode(&mut w);
        }
        w.into_vec()
    }
}

/// The function a request names, before the arguments are looked at.
pub fn request_name(body: &[u8]) -> Result<String> {
    let mut r = Reader::new(body);
    let n = r.bytes_ref()?;
    if n.len() > MAX_FN_NAME {
        return Err(WireError::TooLarge);
    }
    String::from_utf8(n.to_vec()).map_err(|_| WireError::Invalid)
}

/// The arguments of a request for `desc`, checked against it.
pub fn decode_request(body: &[u8], desc: &FnDesc) -> Result<Vec<InVal>> {
    let mut r = Reader::new(body);
    if r.bytes_ref()? != desc.name.as_bytes() {
        return Err(WireError::Invalid);
    }
    if r.u8()? as usize != desc.args.len() {
        return Err(WireError::Invalid);
    }
    let mut v = Vec::with_capacity(desc.args.len());
    for k in &desc.args {
        v.push(InVal::decode(*k, &mut r)?);
    }
    r.finish()?;
    Ok(v)
}

/// What the function gave back for one output argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutVal {
    /// The integer or handle written through an `o_u32`, `o_u64` or `o_object`.
    Int(u64),
    /// The length and, if the caller gave a buffer and the call succeeded, the bytes.
    Bytes(OutBytes),
}

/// The values of the output arguments, in argument order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VendorReply(pub Vec<OutVal>);

impl VendorReply {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.0.len() as u8);
        for o in &self.0 {
            match o {
                OutVal::Int(v) => {
                    w.u8(T_INT);
                    w.u64(*v)
                }
                OutVal::Bytes(b) => {
                    w.u8(T_BYTES);
                    b.encode(&mut w)
                }
            }
        }
        w.into_vec()
    }

    /// Decode the reply of a call of `desc`, checked against it.
    pub fn decode(body: &[u8], desc: &FnDesc) -> Result<VendorReply> {
        let mut r = Reader::new(body);
        let outs: Vec<ArgKind> = desc.args.iter().copied().filter(|k| k.is_output()).collect();
        if r.u8()? as usize != outs.len() {
            return Err(WireError::Invalid);
        }
        let mut v = Vec::with_capacity(outs.len());
        for k in outs {
            v.push(match (k, r.u8()?) {
                (ArgKind::OU32, T_INT) => {
                    let x = r.u64()?;
                    if x > u32::MAX as u64 {
                        return Err(WireError::Invalid);
                    }
                    OutVal::Int(x)
                }
                (ArgKind::OU64 | ArgKind::OObject, T_INT) => OutVal::Int(r.u64()?),
                (ArgKind::OBytes | ArgKind::OBuf, T_BYTES) => OutVal::Bytes(OutBytes::decode(&mut r)?),
                _ => return Err(WireError::BadTag),
            });
        }
        r.finish()?;
        Ok(VendorReply(v))
    }
}

/// The room an output buffer argument asks for, as the wire's `OutSpec`.
pub fn cap_spec(v: &InVal) -> Option<OutSpec> {
    match v {
        InVal::Cap(None) => Some(OutSpec::Length),
        InVal::Cap(Some(n)) => Some(OutSpec::Capacity(*n)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_slice, to_vec};

    fn copy_object() -> FnDesc {
        FnDesc {
            name: "Vnd_CopyObject".into(),
            rw: true,
            args: vec![ArgKind::Session, ArgKind::Session, ArgKind::Object, ArgKind::Attrs, ArgKind::OObject],
        }
    }

    #[test]
    fn kinds_parse_and_count_their_parameters() {
        for k in ArgKind::ALL {
            assert_eq!(ArgKind::parse(k.name()), Some(k));
            assert_eq!(ArgKind::from_u8(k as u8), Some(k));
        }
        assert_eq!(ArgKind::parse("nonsense"), None);
        assert_eq!(copy_object().c_arg_count(), 6);
        assert_eq!(ArgKind::OBuf.c_args(), 3);
    }

    #[test]
    fn descriptions_are_validated() {
        assert!(copy_object().validate().is_ok());
        let bad = |name: &str, args: Vec<ArgKind>| FnDesc { name: name.into(), rw: false, args }.validate().is_err();
        assert!(bad("", vec![]));
        assert!(bad("1abc", vec![]));
        assert!(bad("has space", vec![]));
        assert!(bad("C_Initialize", vec![]));
        assert!(bad(&"x".repeat(MAX_FN_NAME + 1), vec![]));
        assert!(bad("f", vec![ArgKind::OBuf; 7])); // 21 C parameters
        assert!(!bad("f", vec![ArgKind::OBuf; 6]));
        assert!(bad("f", vec![ArgKind::U8; MAX_FN_ARGS + 1]));
    }

    #[test]
    fn the_announcement_roundtrips_and_is_checked() {
        let v = VendorFns(vec![
            copy_object(),
            FnDesc { name: "Vnd_GetId".into(), rw: false, args: vec![ArgKind::Session, ArgKind::OU64] },
        ]);
        assert_eq!(from_slice::<VendorFns>(&to_vec(&v)).unwrap(), v);
        let mut b = Vec::new();
        b.extend_from_slice(&((MAX_VENDOR_FNS as u32) + 1).to_be_bytes());
        assert_eq!(from_slice::<VendorFns>(&b).unwrap_err(), WireError::TooLarge);
        assert_eq!(from_slice::<VendorFns>(&100u32.to_be_bytes()).unwrap_err(), WireError::Truncated);
        // an unknown kind, and a name that is not an identifier
        let mut bad = to_vec(&v);
        let last = bad.len() - 1;
        bad[last] = 99;
        assert_eq!(from_slice::<VendorFns>(&bad).unwrap_err(), WireError::BadTag);
        let evil = VendorFns(vec![FnDesc { name: "C_Login".into(), rw: false, args: vec![] }]);
        assert_eq!(from_slice::<VendorFns>(&to_vec(&evil)).unwrap_err(), WireError::Invalid);
    }

    #[test]
    fn a_request_is_checked_against_the_description() {
        let d = copy_object();
        let req = VendorRequest {
            name: d.name.clone(),
            args: vec![InVal::Int(2), InVal::Int(3), InVal::Int(9), InVal::Attrs(vec![]), InVal::Nothing],
        };
        let body = req.encode();
        assert_eq!(request_name(&body).unwrap(), "Vnd_CopyObject");
        assert_eq!(decode_request(&body, &d).unwrap(), req.args);
        // another function's description, a wrong argument count, a wrong shape, trailing bytes
        let other = FnDesc { name: "Other".into(), rw: false, args: d.args.clone() };
        assert!(decode_request(&body, &other).is_err());
        let short = FnDesc { args: d.args[..4].to_vec(), ..d.clone() };
        assert!(decode_request(&body, &short).is_err());
        let wrong = VendorRequest {
            args: vec![InVal::Bytes(vec![1]), InVal::Int(3), InVal::Int(9), InVal::Attrs(vec![]), InVal::Nothing],
            ..req.clone()
        };
        assert!(decode_request(&wrong.encode(), &d).is_err());
        let mut long = body.clone();
        long.push(0);
        assert!(decode_request(&long, &d).is_err());
    }

    #[test]
    fn values_must_fit_their_kind() {
        let d = |k| FnDesc { name: "f".into(), rw: false, args: vec![k] };
        let enc = |v: InVal| VendorRequest { name: "f".into(), args: vec![v] }.encode();
        assert!(decode_request(&enc(InVal::Int(255)), &d(ArgKind::U8)).is_ok());
        assert!(decode_request(&enc(InVal::Int(256)), &d(ArgKind::U8)).is_err());
        assert!(decode_request(&enc(InVal::Int(1 << 32)), &d(ArgKind::U32)).is_err());
        assert!(decode_request(&enc(InVal::Bytes(vec![b' '; 32])), &d(ArgKind::Label)).is_ok());
        assert!(decode_request(&enc(InVal::Bytes(vec![b' '; 31])), &d(ArgKind::Label)).is_err());
        assert!(decode_request(&enc(InVal::Bytes(b"a\\0b".to_vec())), &d(ArgKind::CStr)).is_ok());
        assert!(decode_request(&enc(InVal::Bytes(vec![b'a', 0])), &d(ArgKind::CStr)).is_err());
        assert!(decode_request(&enc(InVal::Cap(Some(MAX_BYTES as u64 + 1))), &d(ArgKind::OBytes)).is_err());
        assert_eq!(cap_spec(&InVal::Cap(None)), Some(OutSpec::Length));
    }

    #[test]
    fn a_reply_is_checked_against_the_description() {
        let d = FnDesc {
            name: "f".into(),
            rw: false,
            args: vec![ArgKind::Session, ArgKind::OU32, ArgKind::OBytes, ArgKind::OObject],
        };
        let r = VendorReply(vec![
            OutVal::Int(7),
            OutVal::Bytes(OutBytes { len: 3, data: Some(vec![1, 2, 3]) }),
            OutVal::Int(42),
        ]);
        assert_eq!(VendorReply::decode(&r.encode(), &d).unwrap(), r);
        let big = VendorReply(vec![OutVal::Int(1 << 33), r.0[1].clone(), r.0[2].clone()]);
        assert!(VendorReply::decode(&big.encode(), &d).is_err(), "an o_u32 that does not fit");
        let few = VendorReply(r.0[..2].to_vec());
        assert!(VendorReply::decode(&few.encode(), &d).is_err());
        let swapped = VendorReply(vec![r.0[1].clone(), r.0[0].clone(), r.0[2].clone()]);
        assert!(VendorReply::decode(&swapped.encode(), &d).is_err());
    }
}
