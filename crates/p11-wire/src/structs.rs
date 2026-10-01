//! Fixed structures the module fills in: `CK_INFO`, `CK_SLOT_INFO`,
//! `CK_TOKEN_INFO`, `CK_SESSION_INFO`, `CK_MECHANISM_INFO`. Strings stay the
//! space-padded fixed-size arrays PKCS#11 uses; every number is a `u64`.

use crate::codec::{Decode, Encode, Reader, Writer};
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl Encode for Version {
    fn encode(&self, w: &mut Writer) {
        w.u8(self.major);
        w.u8(self.minor);
    }
}
impl Decode for Version {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Version { major: r.u8()?, minor: r.u8()? })
    }
}

macro_rules! wire_struct {
    ($(#[$m:meta])* $name:ident { $($f:ident : $t:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { $(pub $f: $t),* }
        impl Encode for $name {
            fn encode(&self, w: &mut Writer) { $(self.$f.encode(w);)* }
        }
        impl Decode for $name {
            fn decode(r: &mut Reader<'_>) -> Result<Self> {
                Ok($name { $($f: <$t>::decode(r)?),* })
            }
        }
    };
}

wire_struct!(Info {
    cryptoki_version: Version,
    manufacturer_id: [u8; 32],
    flags: u64,
    library_description: [u8; 32],
    library_version: Version,
});

wire_struct!(SlotInfo {
    slot_description: [u8; 64],
    manufacturer_id: [u8; 32],
    flags: u64,
    hardware_version: Version,
    firmware_version: Version,
});

wire_struct!(TokenInfo {
    label: [u8; 32],
    manufacturer_id: [u8; 32],
    model: [u8; 16],
    serial_number: [u8; 16],
    flags: u64,
    max_session_count: u64,
    session_count: u64,
    max_rw_session_count: u64,
    rw_session_count: u64,
    max_pin_len: u64,
    min_pin_len: u64,
    total_public_memory: u64,
    free_public_memory: u64,
    total_private_memory: u64,
    free_private_memory: u64,
    hardware_version: Version,
    firmware_version: Version,
    utc_time: [u8; 16],
});

wire_struct!(SessionInfo { slot_id: u64, state: u64, flags: u64, device_error: u64 });

wire_struct!(MechanismInfo { min_key_size: u64, max_key_size: u64, flags: u64 });

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_slice, to_vec};

    #[test]
    fn token_info_roundtrip() {
        let t = TokenInfo {
            label: [b'a'; 32],
            manufacturer_id: [b' '; 32],
            model: [b'm'; 16],
            serial_number: [b'1'; 16],
            flags: 0x401,
            max_session_count: u64::MAX,
            session_count: 1,
            max_rw_session_count: 2,
            rw_session_count: 3,
            max_pin_len: 255,
            min_pin_len: 4,
            total_public_memory: 5,
            free_public_memory: 6,
            total_private_memory: 7,
            free_private_memory: 8,
            hardware_version: Version { major: 2, minor: 6 },
            firmware_version: Version { major: 2, minor: 6 },
            utc_time: [b'0'; 16],
        };
        let b = to_vec(&t);
        assert_eq!(b.len(), 32 + 32 + 16 + 16 + 8 * 11 + 4 + 16);
        assert_eq!(from_slice::<TokenInfo>(&b).unwrap(), t);
    }
}

/// A `CK_MECHANISM`: the type and, when the mechanism has one, its parameter
/// as a tree (see [`crate::tree`]). `None` means `pParameter == NULL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mech {
    pub mechanism: u64,
    pub param: Option<crate::tree::Node>,
}

impl Encode for Mech {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.mechanism);
        self.param.encode(w);
    }
}
impl Decode for Mech {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Mech { mechanism: r.u64()?, param: Option::decode(r)? })
    }
}

/// What the caller offers for an output buffer under the PKCS#11 two-call
/// convention: `pBuf == NULL` asks for the length only, otherwise the buffer
/// holds `Capacity` items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutSpec {
    Length,
    Capacity(u64),
}

impl Encode for OutSpec {
    fn encode(&self, w: &mut Writer) {
        match self {
            OutSpec::Length => w.u8(0),
            OutSpec::Capacity(n) => {
                w.u8(1);
                w.u64(*n)
            }
        }
    }
}
impl Decode for OutSpec {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        match r.u8()? {
            0 => Ok(OutSpec::Length),
            1 => {
                let n = r.u64()?;
                if n > crate::limits::MAX_BYTES as u64 {
                    return Err(crate::error::WireError::TooLarge);
                }
                Ok(OutSpec::Capacity(n))
            }
            _ => Err(crate::error::WireError::BadTag),
        }
    }
}

/// The module's output for a byte buffer: the length it reports, and the
/// bytes when a buffer was supplied and the call succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutBytes {
    pub len: u64,
    pub data: Option<Vec<u8>>,
}

impl Encode for OutBytes {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.len);
        self.data.encode(w);
    }
}
impl Decode for OutBytes {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(OutBytes { len: r.u64()?, data: Option::decode(r)? })
    }
}

/// The same for an array of `CK_ULONG`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutU64s {
    pub len: u64,
    pub data: Option<crate::codec::U64s>,
}

impl Encode for OutU64s {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.len);
        self.data.encode(w);
    }
}
impl Decode for OutU64s {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(OutU64s { len: r.u64()?, data: Option::decode(r)? })
    }
}

/// The parameter of a message-based call. The mechanism is the one the
/// session's `C_Message*Init` selected; the daemon checks that it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgParam {
    pub mechanism: u64,
    /// `MSG_ENCRYPT` or `MSG_DECRYPT`: which way the parameter is used. The
    /// daemon sets it from the call and ignores the client's value.
    pub phase: u8,
    pub param: Option<crate::tree::Node>,
}

pub const MSG_ENCRYPT: u8 = 2;
pub const MSG_DECRYPT: u8 = 4;

impl Encode for MsgParam {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.mechanism);
        w.u8(self.phase);
        self.param.encode(w);
    }
}
impl Decode for MsgParam {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let mechanism = r.u64()?;
        let phase = r.u8()?;
        if phase != MSG_ENCRYPT && phase != MSG_DECRYPT {
            return Err(crate::error::WireError::BadTag);
        }
        Ok(MsgParam { mechanism, phase, param: Option::decode(r)? })
    }
}

/// `CK_ASYNC_DATA` as the caller supplies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncIn {
    pub version: u64,
    pub value: OutSpec,
}

impl Encode for AsyncIn {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.version);
        self.value.encode(w);
    }
}
impl Decode for AsyncIn {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(AsyncIn { version: r.u64()?, value: OutSpec::decode(r)? })
    }
}

/// `CK_ASYNC_DATA` as the module fills it in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsyncOut {
    pub version: u64,
    pub value: OutBytes,
    pub object: u64,
    pub additional_object: u64,
}

impl Encode for AsyncOut {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.version);
        self.value.encode(w);
        w.u64(self.object);
        w.u64(self.additional_object);
    }
}
impl Decode for AsyncOut {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(AsyncOut { version: r.u64()?, value: OutBytes::decode(r)?, object: r.u64()?, additional_object: r.u64()? })
    }
}
