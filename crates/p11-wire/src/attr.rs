//! Attribute templates and attribute queries.
//!
//! A `CK_ATTRIBUTE` holds a pointer and a length, so it is rebuilt from
//! typed values on the other side. Values that PKCS#11 defines as `CK_ULONG`
//! travel as `u64` (never as native-endian memory); attributes that hold a
//! nested template (wrap/unwrap/derive/encapsulate/decapsulate templates)
//! travel as a nested list.

use crate::codec::{Decode, Encode, MinSize, Reader, Seq, Writer};
use crate::error::{Result, WireError};
use crate::limits::{MAX_ATTRS, MAX_BYTES, MAX_DEPTH};
use p11_types as ck;

/// How the attribute type asks for its value to be represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repr {
    /// Opaque bytes.
    Bytes,
    /// A single `CK_ULONG`.
    Ulong,
    /// An array of `CK_ULONG`.
    UlongArray,
    /// An array of `CK_ATTRIBUTE`.
    Template,
}

/// Classify an attribute type. Unknown and vendor types are opaque bytes.
pub fn repr_of(ty: u64) -> Repr {
    match ty {
        ck::CKA_WRAP_TEMPLATE
        | ck::CKA_UNWRAP_TEMPLATE
        | ck::CKA_DERIVE_TEMPLATE
        | ck::CKA_ENCAPSULATE_TEMPLATE
        | ck::CKA_DECAPSULATE_TEMPLATE => Repr::Template,
        ck::CKA_ALLOWED_MECHANISMS | ck::CKA_HSS_LMS_TYPES | ck::CKA_HSS_LMOTS_TYPES => Repr::UlongArray,
        ck::CKA_CLASS
        | ck::CKA_CERTIFICATE_TYPE
        | ck::CKA_CERTIFICATE_CATEGORY
        | ck::CKA_JAVA_MIDP_SECURITY_DOMAIN
        | ck::CKA_NAME_HASH_ALGORITHM
        | ck::CKA_KEY_TYPE
        | ck::CKA_MODULUS_BITS
        | ck::CKA_PRIME_BITS
        | ck::CKA_SUBPRIME_BITS
        | ck::CKA_VALUE_BITS
        | ck::CKA_VALUE_LEN
        | ck::CKA_KEY_GEN_MECHANISM
        | ck::CKA_AUTH_PIN_FLAGS
        | ck::CKA_OTP_FORMAT
        | ck::CKA_OTP_LENGTH
        | ck::CKA_OTP_TIME_INTERVAL
        | ck::CKA_HW_FEATURE_TYPE
        | ck::CKA_PIXEL_X
        | ck::CKA_PIXEL_Y
        | ck::CKA_RESOLUTION
        | ck::CKA_CHAR_ROWS
        | ck::CKA_CHAR_COLUMNS
        | ck::CKA_BITS_PER_PIXEL
        | ck::CKA_MECHANISM_TYPE
        | ck::CKA_PROFILE_ID
        | ck::CKA_X2RATCHET_BAGSIZE
        | ck::CKA_X2RATCHET_NR
        | ck::CKA_X2RATCHET_NS
        | ck::CKA_X2RATCHET_PNS
        | ck::CKA_HSS_LEVELS
        | ck::CKA_HSS_LMS_TYPE
        | ck::CKA_HSS_LMOTS_TYPE
        | ck::CKA_HSS_KEYS_REMAINING
        | ck::CKA_PARAMETER_SET
        | ck::CKA_OBJECT_VALIDATION_FLAGS
        | ck::CKA_VALIDATION_TYPE
        | ck::CKA_VALIDATION_LEVEL
        | ck::CKA_VALIDATION_FLAG
        | ck::CKA_VALIDATION_AUTHORITY_TYPE
        | ck::CKA_TRUST_SERVER_AUTH
        | ck::CKA_TRUST_CLIENT_AUTH
        | ck::CKA_TRUST_CODE_SIGNING
        | ck::CKA_TRUST_EMAIL_PROTECTION
        | ck::CKA_TRUST_IPSEC_IKE
        | ck::CKA_TRUST_TIME_STAMPING
        | ck::CKA_TRUST_OCSP_SIGNING => Repr::Ulong,
        _ => Repr::Bytes,
    }
}

/// The value of one attribute in a template (a request, or a response that
/// hands back what the module stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrVal {
    /// `ulValueLen == CK_UNAVAILABLE_INFORMATION`.
    Unavailable,
    Bytes(Vec<u8>),
    Ulong(u64),
    UlongArray(Vec<u64>),
    Nested(Vec<Attr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    pub ty: u64,
    pub val: AttrVal,
}

const V_UNAVAILABLE: u8 = 0;
const V_BYTES: u8 = 1;
const V_ULONG: u8 = 2;
const V_ULONG_ARRAY: u8 = 3;
const V_NESTED: u8 = 4;

impl Attr {
    fn encode_into(&self, w: &mut Writer) {
        w.u64(self.ty);
        match &self.val {
            AttrVal::Unavailable => w.u8(V_UNAVAILABLE),
            AttrVal::Bytes(b) => {
                w.u8(V_BYTES);
                w.bytes(b)
            }
            AttrVal::Ulong(v) => {
                w.u8(V_ULONG);
                w.u64(*v)
            }
            AttrVal::UlongArray(a) => {
                w.u8(V_ULONG_ARRAY);
                w.count(a.len());
                for v in a {
                    w.u64(*v);
                }
            }
            AttrVal::Nested(n) => {
                w.u8(V_NESTED);
                w.count(n.len());
                for a in n {
                    a.encode_into(w);
                }
            }
        }
    }

    fn decode_from(r: &mut Reader<'_>, depth: usize, budget: &mut usize) -> Result<Attr> {
        *budget = budget.checked_sub(1).ok_or(WireError::TooLarge)?;
        let ty = r.u64()?;
        let val = match r.u8()? {
            V_UNAVAILABLE => AttrVal::Unavailable,
            V_BYTES => AttrVal::Bytes(r.bytes_ref()?.to_vec()),
            V_ULONG => AttrVal::Ulong(r.u64()?),
            V_ULONG_ARRAY => {
                let n = r.count(MAX_BYTES / 8, 8)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(r.u64()?);
                }
                AttrVal::UlongArray(v)
            }
            V_NESTED => {
                if depth >= MAX_DEPTH {
                    return Err(WireError::TooDeep);
                }
                let n = r.count(MAX_ATTRS, 9)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(Attr::decode_from(r, depth + 1, budget)?);
                }
                AttrVal::Nested(v)
            }
            _ => return Err(WireError::BadTag),
        };
        Ok(Attr { ty, val })
    }
}

impl Encode for Attr {
    fn encode(&self, w: &mut Writer) {
        self.encode_into(w)
    }
}
impl Decode for Attr {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let mut budget = MAX_ATTRS * 4;
        Attr::decode_from(r, 0, &mut budget)
    }
}
impl MinSize for Attr {
    const MIN: usize = 9;
    const MAX: usize = MAX_ATTRS;
}

/// A template: what `CK_ATTRIBUTE_PTR` + count carries in `C_CreateObject`,
/// `C_FindObjectsInit`, `C_GenerateKey`, and so on.
pub type Template = Seq<Attr>;

/// What the caller offers for one attribute of `C_GetAttributeValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// `pValue == NULL`: only the length is wanted.
    Length,
    /// A buffer of this many bytes.
    Capacity(u64),
    /// A buffer that holds a template of this shape (its attributes are
    /// described by the nested slots).
    Nested(Vec<Query>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub ty: u64,
    pub slot: Slot,
}

impl Query {
    fn encode_into(&self, w: &mut Writer) {
        w.u64(self.ty);
        match &self.slot {
            Slot::Length => w.u8(0),
            Slot::Capacity(n) => {
                w.u8(1);
                w.u64(*n)
            }
            Slot::Nested(q) => {
                w.u8(2);
                w.count(q.len());
                for x in q {
                    x.encode_into(w);
                }
            }
        }
    }
    fn decode_from(r: &mut Reader<'_>, depth: usize, budget: &mut usize) -> Result<Query> {
        *budget = budget.checked_sub(1).ok_or(WireError::TooLarge)?;
        let ty = r.u64()?;
        let slot = match r.u8()? {
            0 => Slot::Length,
            1 => {
                let n = r.u64()?;
                if n > MAX_BYTES as u64 {
                    return Err(WireError::TooLarge);
                }
                Slot::Capacity(n)
            }
            2 => {
                if depth >= MAX_DEPTH {
                    return Err(WireError::TooDeep);
                }
                let n = r.count(MAX_ATTRS, 9)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(Query::decode_from(r, depth + 1, budget)?);
                }
                Slot::Nested(v)
            }
            _ => return Err(WireError::BadTag),
        };
        Ok(Query { ty, slot })
    }
}

impl Encode for Query {
    fn encode(&self, w: &mut Writer) {
        self.encode_into(w)
    }
}
impl Decode for Query {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let mut budget = MAX_ATTRS * 4;
        Query::decode_from(r, 0, &mut budget)
    }
}
impl MinSize for Query {
    const MIN: usize = 9;
    const MAX: usize = MAX_ATTRS;
}

/// The module's answer for one queried attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// `CK_UNAVAILABLE_INFORMATION`: sensitive, or not present on the object.
    Unavailable,
    /// The value needs this many bytes (length query, or buffer too small).
    Length(u64),
    Bytes(Vec<u8>),
    Ulong(u64),
    UlongArray(Vec<u64>),
    Nested(Vec<Reply>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub ty: u64,
    pub answer: Answer,
}

impl Reply {
    fn encode_into(&self, w: &mut Writer) {
        w.u64(self.ty);
        match &self.answer {
            Answer::Unavailable => w.u8(0),
            Answer::Length(n) => {
                w.u8(1);
                w.u64(*n)
            }
            Answer::Bytes(b) => {
                w.u8(2);
                w.bytes(b)
            }
            Answer::Ulong(v) => {
                w.u8(3);
                w.u64(*v)
            }
            Answer::UlongArray(a) => {
                w.u8(4);
                w.count(a.len());
                for v in a {
                    w.u64(*v)
                }
            }
            Answer::Nested(n) => {
                w.u8(5);
                w.count(n.len());
                for x in n {
                    x.encode_into(w)
                }
            }
        }
    }
    fn decode_from(r: &mut Reader<'_>, depth: usize, budget: &mut usize) -> Result<Reply> {
        *budget = budget.checked_sub(1).ok_or(WireError::TooLarge)?;
        let ty = r.u64()?;
        let answer = match r.u8()? {
            0 => Answer::Unavailable,
            1 => Answer::Length(r.u64()?),
            2 => Answer::Bytes(r.bytes_ref()?.to_vec()),
            3 => Answer::Ulong(r.u64()?),
            4 => {
                let n = r.count(MAX_BYTES / 8, 8)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(r.u64()?);
                }
                Answer::UlongArray(v)
            }
            5 => {
                if depth >= MAX_DEPTH {
                    return Err(WireError::TooDeep);
                }
                let n = r.count(MAX_ATTRS, 9)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(Reply::decode_from(r, depth + 1, budget)?);
                }
                Answer::Nested(v)
            }
            _ => return Err(WireError::BadTag),
        };
        Ok(Reply { ty, answer })
    }
}

impl Encode for Reply {
    fn encode(&self, w: &mut Writer) {
        self.encode_into(w)
    }
}
impl Decode for Reply {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let mut budget = MAX_ATTRS * 4;
        Reply::decode_from(r, 0, &mut budget)
    }
}
impl MinSize for Reply {
    const MIN: usize = 9;
    const MAX: usize = MAX_ATTRS;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_slice, to_vec};
    use proptest::prelude::*;

    fn arb_attr() -> impl Strategy<Value = Attr> {
        let leaf = (
            any::<u64>(),
            prop_oneof![
                Just(AttrVal::Unavailable),
                proptest::collection::vec(any::<u8>(), 0..8).prop_map(AttrVal::Bytes),
                any::<u64>().prop_map(AttrVal::Ulong),
                proptest::collection::vec(any::<u64>(), 0..4).prop_map(AttrVal::UlongArray),
            ],
        )
            .prop_map(|(ty, val)| Attr { ty, val });
        leaf.prop_recursive(3, 16, 4, |inner| {
            (any::<u64>(), proptest::collection::vec(inner, 0..4))
                .prop_map(|(ty, v)| Attr { ty, val: AttrVal::Nested(v) })
        })
    }

    proptest! {
        #[test]
        fn attr_roundtrip(t in proptest::collection::vec(arb_attr(), 0..5)) {
            let t = Template { 0: t };
            prop_assert_eq!(from_slice::<Template>(&to_vec(&t)).unwrap(), t);
        }
        #[test]
        fn garbage_never_panics(b in proptest::collection::vec(any::<u8>(), 0..200)) {
            let _ = from_slice::<Template>(&b);
            let _ = from_slice::<Seq<Query>>(&b);
            let _ = from_slice::<Seq<Reply>>(&b);
        }
    }

    #[test]
    fn classification() {
        assert_eq!(repr_of(ck::CKA_CLASS), Repr::Ulong);
        assert_eq!(repr_of(ck::CKA_VALUE), Repr::Bytes);
        assert_eq!(repr_of(ck::CKA_WRAP_TEMPLATE), Repr::Template);
        assert_eq!(repr_of(ck::CKA_ALLOWED_MECHANISMS), Repr::UlongArray);
        assert_eq!(repr_of(0x8000_1234), Repr::Bytes);
    }

    #[test]
    fn nesting_is_limited() {
        let mut a = Attr { ty: 1, val: AttrVal::Bytes(vec![]) };
        for _ in 0..=MAX_DEPTH + 1 {
            a = Attr { ty: 1, val: AttrVal::Nested(vec![a]) };
        }
        assert_eq!(from_slice::<Attr>(&to_vec(&a)).unwrap_err(), WireError::TooDeep);
    }
}
