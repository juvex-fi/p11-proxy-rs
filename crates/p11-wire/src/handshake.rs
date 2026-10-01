//! Connection setup. The client sends `Hello`, the daemon answers with
//! `HelloAck` (or an `Abort` frame). A client opens its first connection
//! with `join = false` and receives a context token; every further
//! connection of the same client (the library keeps a small pool so calls can
//! run in parallel and `C_WaitForSlotEvent` doesn't block the rest) presents
//! that token with `join = true` and shares the sessions and handles of the
//! first one. The daemon accepts a join only over a connection that
//! authenticated as the same identity.

use crate::codec::{Decode, Encode, Reader, Writer};
use crate::error::{Result, WireError};
use crate::limits::{
    MAX_HANDLE_OFFSETS, MAX_LAYOUT_FIELDS, MAX_LAYOUT_NAME, MAX_TEXT, MAX_VENDOR_LAYOUTS, MAX_VENDOR_MECHS,
};

pub const MAGIC: [u8; 4] = *b"P11P";
/// Protocol versions this build implements.
pub const VERSION_MIN: u16 = 1;
pub const VERSION_MAX: u16 = 1;

/// Feature bits. Unknown bits are ignored by the receiver.
pub mod features {
    pub const NONE: u64 = 0;
    /// In `Hello`: the client understands the vendor mechanism list. In `HelloAck`: the daemon
    /// has some, and a `Kind::VendorMechanisms` frame follows the `HelloAck`.
    pub const VENDOR_MECHANISMS: u64 = 1;
    /// The same for vendor-defined functions: a `Kind::VendorFunctions` frame follows.
    pub const VENDOR_FUNCTIONS: u64 = 2;
}

pub const TOKEN_LEN: usize = 16;
pub type Token = [u8; TOKEN_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub min_version: u16,
    pub max_version: u16,
    pub features: u64,
    pub join: bool,
    pub token: Token,
    pub client: String,
}

fn put_text(w: &mut Writer, s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(MAX_TEXT);
    w.bytes(&b[..n]);
}

fn get_text(r: &mut Reader<'_>) -> Result<String> {
    let b = r.bytes_ref()?;
    if b.len() > MAX_TEXT {
        return Err(WireError::TooLarge);
    }
    // Text is for logs only; keep it printable ASCII so it can't forge log lines.
    Ok(b.iter().map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '?' }).collect())
}

impl Encode for Hello {
    fn encode(&self, w: &mut Writer) {
        w.raw(&MAGIC);
        w.u16(self.min_version);
        w.u16(self.max_version);
        w.u64(self.features);
        w.bool(self.join);
        w.raw(&self.token);
        put_text(w, &self.client);
    }
}

impl Decode for Hello {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        if r.array::<4>()? != MAGIC {
            return Err(WireError::Invalid);
        }
        let min_version = r.u16()?;
        let max_version = r.u16()?;
        if min_version > max_version {
            return Err(WireError::Invalid);
        }
        Ok(Hello {
            min_version,
            max_version,
            features: r.u64()?,
            join: r.bool()?,
            token: r.array()?,
            client: get_text(r)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    pub version: u16,
    pub features: u64,
    pub token: Token,
    pub server: String,
}

impl Encode for HelloAck {
    fn encode(&self, w: &mut Writer) {
        w.raw(&MAGIC);
        w.u16(self.version);
        w.u64(self.features);
        w.raw(&self.token);
        put_text(w, &self.server);
    }
}

impl Decode for HelloAck {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        if r.array::<4>()? != MAGIC {
            return Err(WireError::Invalid);
        }
        Ok(HelloAck { version: r.u16()?, features: r.u64()?, token: r.array()?, server: get_text(r)? })
    }
}

/// What a vendor-defined mechanism's parameter is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorParam {
    /// Bytes without pointers of exactly this length (0: the mechanism takes none).
    Exact(u32),
    /// Bytes without pointers of at most this length.
    Max(u32),
    /// One `CK_OBJECT_HANDLE`, which the daemon translates.
    Handle,
    /// Bytes without pointers of exactly `len`, holding `CK_OBJECT_HANDLE`s at these byte offsets.
    Handles { len: u32, offs: Vec<u32> },
    /// The parameter of another mechanism the proxy already carries, by number.
    SameAs(u64),
    /// A structure with pointers and handles, laid out as the named [`VendorLayout`] says.
    Struct(String),
}

/// What a member of a vendor-declared structure is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FieldKind {
    /// A `CK_ULONG`.
    Ulong = 1,
    /// A `CK_OBJECT_HANDLE`.
    Handle = 2,
    /// A `CK_BBOOL`.
    Bool = 3,
    /// A `CK_BYTE`.
    Byte = 4,
    /// A pointer to bytes, their length in the member named `by`.
    Bytes = 5,
    /// `n` bytes inside the structure.
    Inline = 6,
    /// A pointer to one `CK_ULONG`.
    UlongPtr = 7,
    /// A pointer to one object handle the module produces.
    HandlePtr = 8,
    /// A pointer to the structure `of`.
    Struct = 9,
    /// The structure `of`, inside this one.
    Embedded = 10,
    /// A pointer to an array of the structure `of`, the count in the member named `by`.
    Array = 11,
    /// A pointer to a template of attributes, the count in the member named `by`.
    Attrs = 12,
    /// A pointer to a NUL-terminated string.
    CStr = 13,
    /// A pointer to a `CK_MECHANISM`.
    MechPtr = 14,
    /// A `CK_MECHANISM` inside the structure.
    Mech = 15,
    /// A pointer to an array of object handles the module writes; the room is the `CK_ULONG` the member
    /// named `by` (a `ulong_ptr`, in and out) points to, which comes back holding the number written.
    HandleArray = 16,
}

impl FieldKind {
    pub const ALL: [FieldKind; 16] = [
        FieldKind::Ulong,
        FieldKind::Handle,
        FieldKind::Bool,
        FieldKind::Byte,
        FieldKind::Bytes,
        FieldKind::Inline,
        FieldKind::UlongPtr,
        FieldKind::HandlePtr,
        FieldKind::Struct,
        FieldKind::Embedded,
        FieldKind::Array,
        FieldKind::Attrs,
        FieldKind::CStr,
        FieldKind::MechPtr,
        FieldKind::Mech,
        FieldKind::HandleArray,
    ];

    pub fn name(self) -> &'static str {
        match self {
            FieldKind::Ulong => "ulong",
            FieldKind::Handle => "handle",
            FieldKind::Bool => "bool",
            FieldKind::Byte => "byte",
            FieldKind::Bytes => "bytes",
            FieldKind::Inline => "inline",
            FieldKind::UlongPtr => "ulong_ptr",
            FieldKind::HandlePtr => "handle_ptr",
            FieldKind::Struct => "struct",
            FieldKind::Embedded => "embedded",
            FieldKind::Array => "array",
            FieldKind::Attrs => "attrs",
            FieldKind::CStr => "cstr",
            FieldKind::MechPtr => "mech_ptr",
            FieldKind::Mech => "mech",
            FieldKind::HandleArray => "handle_array",
        }
    }

    pub fn parse(s: &str) -> Option<FieldKind> {
        FieldKind::ALL.into_iter().find(|k| k.name() == s)
    }

    pub fn from_u8(v: u8) -> Option<FieldKind> {
        FieldKind::ALL.into_iter().find(|k| *k as u8 == v)
    }
}

/// Which way a member's value travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Dir {
    /// The caller's value goes to the module.
    #[default]
    In = 0,
    /// The module writes it and the caller gets it back.
    Out = 1,
    /// Both.
    InOut = 2,
}

impl Dir {
    pub fn parse(s: &str) -> Option<Dir> {
        match s {
            "in" => Some(Dir::In),
            "out" => Some(Dir::Out),
            "inout" => Some(Dir::InOut),
            _ => None,
        }
    }

    pub fn from_u8(v: u8) -> Option<Dir> {
        match v {
            0 => Some(Dir::In),
            1 => Some(Dir::Out),
            2 => Some(Dir::InOut),
            _ => None,
        }
    }
}

/// One member of a [`VendorLayout`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorField {
    /// A name other members can refer to (empty: none).
    pub name: String,
    pub off: u32,
    pub kind: FieldKind,
    pub dir: Dir,
    /// The structure a `Struct`, `Embedded` or `Array` refers to.
    pub of: String,
    /// The member holding the length or count of a `Bytes`, `Array` or `Attrs`.
    pub by: String,
    /// The size of an `Inline`, or the most a `Bytes` may hold (0: the protocol's limit).
    pub n: u32,
}

/// A structure a vendor mechanism's parameter is made of: its size and where its members are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorLayout {
    pub name: String,
    pub size: u32,
    pub fields: Vec<VendorField>,
}

fn put_name(w: &mut Writer, s: &str) {
    w.bytes(s.as_bytes());
}

fn get_name(r: &mut Reader<'_>) -> Result<String> {
    let b = r.bytes_ref()?;
    if b.len() > MAX_LAYOUT_NAME {
        return Err(WireError::TooLarge);
    }
    String::from_utf8(b.to_vec()).map_err(|_| WireError::Invalid)
}

impl Encode for VendorLayout {
    fn encode(&self, w: &mut Writer) {
        put_name(w, &self.name);
        w.u32(self.size);
        w.count(self.fields.len());
        for f in &self.fields {
            put_name(w, &f.name);
            w.u32(f.off);
            w.u8(f.kind as u8);
            w.u8(f.dir as u8);
            put_name(w, &f.of);
            put_name(w, &f.by);
            w.u32(f.n);
        }
    }
}

impl Decode for VendorLayout {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let name = get_name(r)?;
        let size = r.u32()?;
        let n = r.count(MAX_LAYOUT_FIELDS, 18)?;
        let mut fields = Vec::with_capacity(n);
        for _ in 0..n {
            fields.push(VendorField {
                name: get_name(r)?,
                off: r.u32()?,
                kind: FieldKind::from_u8(r.u8()?).ok_or(WireError::BadTag)?,
                dir: Dir::from_u8(r.u8()?).ok_or(WireError::BadTag)?,
                of: get_name(r)?,
                by: get_name(r)?,
                n: r.u32()?,
            });
        }
        Ok(VendorLayout { name, size, fields })
    }
}

/// One vendor-defined mechanism the daemon carries and what its parameter is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorEntry {
    pub id: u64,
    pub param: VendorParam,
}

/// The payload of a `Kind::VendorMechanisms` frame: the mechanisms, then the structures their parameters
/// refer to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VendorMechs(pub Vec<VendorEntry>, pub Vec<VendorLayout>);

const P_EXACT: u8 = 0;
const P_MAX: u8 = 1;
const P_HANDLE: u8 = 2;
const P_HANDLES: u8 = 3;
const P_SAME_AS: u8 = 4;
const P_STRUCT: u8 = 5;

impl Encode for VendorMechs {
    fn encode(&self, w: &mut Writer) {
        w.count(self.0.len());
        for e in &self.0 {
            w.u64(e.id);
            match &e.param {
                VendorParam::Exact(n) => {
                    w.u8(P_EXACT);
                    w.u32(*n)
                }
                VendorParam::Max(n) => {
                    w.u8(P_MAX);
                    w.u32(*n)
                }
                VendorParam::Handle => w.u8(P_HANDLE),
                VendorParam::Handles { len, offs } => {
                    w.u8(P_HANDLES);
                    w.u32(*len);
                    w.count(offs.len());
                    for o in offs {
                        w.u32(*o);
                    }
                }
                VendorParam::SameAs(m) => {
                    w.u8(P_SAME_AS);
                    w.u64(*m)
                }
                VendorParam::Struct(n) => {
                    w.u8(P_STRUCT);
                    put_name(w, n)
                }
            }
        }
        w.count(self.1.len());
        for l in &self.1 {
            l.encode(w);
        }
    }
}

impl Decode for VendorMechs {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.count(MAX_VENDOR_MECHS, 9)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let id = r.u64()?;
            let param = match r.u8()? {
                P_EXACT => VendorParam::Exact(r.u32()?),
                P_MAX => VendorParam::Max(r.u32()?),
                P_HANDLE => VendorParam::Handle,
                P_HANDLES => {
                    let len = r.u32()?;
                    let k = r.count(MAX_HANDLE_OFFSETS, 4)?;
                    let mut offs = Vec::with_capacity(k);
                    for _ in 0..k {
                        offs.push(r.u32()?);
                    }
                    VendorParam::Handles { len, offs }
                }
                P_SAME_AS => VendorParam::SameAs(r.u64()?),
                P_STRUCT => VendorParam::Struct(get_name(r)?),
                _ => return Err(WireError::BadTag),
            };
            v.push(VendorEntry { id, param });
        }
        let nl = r.count(MAX_VENDOR_LAYOUTS, 12)?;
        let mut layouts = Vec::with_capacity(nl);
        for _ in 0..nl {
            layouts.push(VendorLayout::decode(r)?);
        }
        Ok(VendorMechs(v, layouts))
    }
}

/// Pick the version both sides support, or `None`.
pub fn negotiate(peer_min: u16, peer_max: u16) -> Option<u16> {
    let v = peer_max.min(VERSION_MAX);
    (v >= peer_min.max(VERSION_MIN)).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_slice, to_vec};

    #[test]
    fn hello_roundtrip() {
        let h = Hello {
            min_version: 1,
            max_version: 3,
            features: 5,
            join: true,
            token: [9; TOKEN_LEN],
            client: "test client".into(),
        };
        assert_eq!(from_slice::<Hello>(&to_vec(&h)).unwrap(), h);
    }

    #[test]
    fn vendor_mechanisms_roundtrip_and_limits() {
        let v = VendorMechs(
            vec![
                VendorEntry { id: 0x8000_0123, param: VendorParam::Exact(16) },
                VendorEntry { id: 0x8000_0124, param: VendorParam::Max(64) },
                VendorEntry { id: 0x8000_0125, param: VendorParam::Handle },
                VendorEntry { id: 0x8000_0126, param: VendorParam::Handles { len: 40, offs: vec![8, 16] } },
                VendorEntry { id: 0x8000_0127, param: VendorParam::SameAs(0x1087) },
            ],
            vec![],
        );
        assert_eq!(from_slice::<VendorMechs>(&to_vec(&v)).unwrap(), v);
        assert_eq!(from_slice::<VendorMechs>(&to_vec(&VendorMechs::default())).unwrap(), VendorMechs::default());
        // a count beyond the limit is refused before anything is allocated
        let mut b = Vec::new();
        b.extend_from_slice(&((MAX_VENDOR_MECHS as u32) + 1).to_be_bytes());
        assert_eq!(from_slice::<VendorMechs>(&b).unwrap_err(), WireError::TooLarge);
        // a count the rest of the frame cannot hold is truncated, not allocated
        assert_eq!(from_slice::<VendorMechs>(&100u32.to_be_bytes()).unwrap_err(), WireError::Truncated);
        // an unknown parameter form
        let mut bad = to_vec(&v);
        bad[4 + 8] = 9;
        assert_eq!(from_slice::<VendorMechs>(&bad).unwrap_err(), WireError::BadTag);
        // too many handle offsets
        let mut w = Writer::new();
        w.count(1);
        w.u64(0x8000_0001);
        w.u8(3);
        w.u32(1024);
        w.count(MAX_HANDLE_OFFSETS + 1);
        assert_eq!(from_slice::<VendorMechs>(&w.into_vec()).unwrap_err(), WireError::TooLarge);
        // trailing bytes
        let mut long = to_vec(&v);
        long.push(0);
        assert!(from_slice::<VendorMechs>(&long).is_err());
    }

    fn sample_layout() -> VendorLayout {
        VendorLayout {
            name: "outer".into(),
            size: 40,
            fields: vec![
                VendorField {
                    name: "n".into(),
                    off: 0,
                    kind: FieldKind::Ulong,
                    dir: Dir::In,
                    of: String::new(),
                    by: String::new(),
                    n: 0,
                },
                VendorField {
                    name: "items".into(),
                    off: 8,
                    kind: FieldKind::Array,
                    dir: Dir::In,
                    of: "inner".into(),
                    by: "n".into(),
                    n: 0,
                },
                VendorField {
                    name: "made".into(),
                    off: 16,
                    kind: FieldKind::HandlePtr,
                    dir: Dir::Out,
                    of: String::new(),
                    by: String::new(),
                    n: 0,
                },
                VendorField {
                    name: String::new(),
                    off: 24,
                    kind: FieldKind::Inline,
                    dir: Dir::In,
                    of: String::new(),
                    by: String::new(),
                    n: 16,
                },
            ],
        }
    }

    #[test]
    fn layouts_travel_with_the_mechanisms_and_are_bounded() {
        let v = VendorMechs(
            vec![VendorEntry { id: 0x8000_0001, param: VendorParam::Struct("outer".into()) }],
            vec![sample_layout()],
        );
        assert_eq!(from_slice::<VendorMechs>(&to_vec(&v)).unwrap(), v);
        // an unknown kind or direction of a member
        let mut b = to_vec(&v);
        let kind_at = b.windows(5).rposition(|w| w == b"outer").unwrap() + 5 + 4 + 4 + 4 + 1 + 4;
        assert_eq!(b[kind_at], FieldKind::Ulong as u8);
        b[kind_at] = 99;
        assert_eq!(from_slice::<VendorMechs>(&b).unwrap_err(), WireError::BadTag);
        b[kind_at] = FieldKind::Ulong as u8;
        b[kind_at + 1] = 7;
        assert_eq!(from_slice::<VendorMechs>(&b).unwrap_err(), WireError::BadTag);
        // more layouts, more members, or longer names than the limits
        let many = VendorMechs(vec![], vec![sample_layout(); MAX_VENDOR_LAYOUTS + 1]);
        assert_eq!(from_slice::<VendorMechs>(&to_vec(&many)).unwrap_err(), WireError::TooLarge);
        let mut wide = sample_layout();
        wide.fields = vec![wide.fields[0].clone(); MAX_LAYOUT_FIELDS + 1];
        assert_eq!(
            from_slice::<VendorMechs>(&to_vec(&VendorMechs(vec![], vec![wide]))).unwrap_err(),
            WireError::TooLarge
        );
        let mut long = sample_layout();
        long.name = "x".repeat(MAX_LAYOUT_NAME + 1);
        assert_eq!(
            from_slice::<VendorMechs>(&to_vec(&VendorMechs(vec![], vec![long]))).unwrap_err(),
            WireError::TooLarge
        );
    }

    #[test]
    fn hello_rejects_bad_magic_and_range() {
        let mut b = to_vec(&Hello {
            min_version: 1,
            max_version: 1,
            features: 0,
            join: false,
            token: [0; TOKEN_LEN],
            client: String::new(),
        });
        b[0] = b'X';
        assert_eq!(from_slice::<Hello>(&b).unwrap_err(), WireError::Invalid);
        let h =
            Hello { min_version: 3, max_version: 2, features: 0, join: false, token: [0; 16], client: String::new() };
        assert_eq!(from_slice::<Hello>(&to_vec(&h)).unwrap_err(), WireError::Invalid);
    }

    #[test]
    fn text_is_sanitised() {
        let mut w = Writer::new();
        put_text(&mut w, "a\nb\u{1b}[31m");
        let b = w.into_vec();
        assert_eq!(get_text(&mut Reader::new(&b)).unwrap(), "a?b?[31m");
    }

    #[test]
    fn negotiation() {
        assert_eq!(negotiate(1, 1), Some(1));
        assert_eq!(negotiate(1, 9), Some(1));
        assert_eq!(negotiate(2, 9), None);
        assert_eq!(negotiate(0, 0), None);
    }
}
