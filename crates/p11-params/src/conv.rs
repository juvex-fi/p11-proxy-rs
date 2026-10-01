//! The fixed information structures, C <-> wire.

use p11_types::*;
use p11_wire::structs as w;

fn v(x: CK_VERSION) -> w::Version {
    w::Version { major: x.major, minor: x.minor }
}
fn cv(x: w::Version) -> CK_VERSION {
    CK_VERSION { major: x.major, minor: x.minor }
}

pub fn info_to_wire(i: &CK_INFO) -> w::Info {
    w::Info {
        cryptoki_version: v(i.cryptokiVersion),
        manufacturer_id: i.manufacturerID,
        flags: i.flags as u64,
        library_description: i.libraryDescription,
        library_version: v(i.libraryVersion),
    }
}
pub fn info_from_wire(i: &w::Info) -> CK_INFO {
    CK_INFO {
        cryptokiVersion: cv(i.cryptoki_version),
        manufacturerID: i.manufacturer_id,
        flags: i.flags as CK_FLAGS,
        libraryDescription: i.library_description,
        libraryVersion: cv(i.library_version),
    }
}

pub fn slot_info_to_wire(i: &CK_SLOT_INFO) -> w::SlotInfo {
    w::SlotInfo {
        slot_description: i.slotDescription,
        manufacturer_id: i.manufacturerID,
        flags: i.flags as u64,
        hardware_version: v(i.hardwareVersion),
        firmware_version: v(i.firmwareVersion),
    }
}
pub fn slot_info_from_wire(i: &w::SlotInfo) -> CK_SLOT_INFO {
    CK_SLOT_INFO {
        slotDescription: i.slot_description,
        manufacturerID: i.manufacturer_id,
        flags: i.flags as CK_FLAGS,
        hardwareVersion: cv(i.hardware_version),
        firmwareVersion: cv(i.firmware_version),
    }
}

pub fn token_info_to_wire(i: &CK_TOKEN_INFO) -> w::TokenInfo {
    w::TokenInfo {
        label: i.label,
        manufacturer_id: i.manufacturerID,
        model: i.model,
        serial_number: i.serialNumber,
        flags: i.flags as u64,
        max_session_count: i.ulMaxSessionCount as u64,
        session_count: i.ulSessionCount as u64,
        max_rw_session_count: i.ulMaxRwSessionCount as u64,
        rw_session_count: i.ulRwSessionCount as u64,
        max_pin_len: i.ulMaxPinLen as u64,
        min_pin_len: i.ulMinPinLen as u64,
        total_public_memory: i.ulTotalPublicMemory as u64,
        free_public_memory: i.ulFreePublicMemory as u64,
        total_private_memory: i.ulTotalPrivateMemory as u64,
        free_private_memory: i.ulFreePrivateMemory as u64,
        hardware_version: v(i.hardwareVersion),
        firmware_version: v(i.firmwareVersion),
        utc_time: i.utcTime,
    }
}
pub fn token_info_from_wire(i: &w::TokenInfo) -> CK_TOKEN_INFO {
    CK_TOKEN_INFO {
        label: i.label,
        manufacturerID: i.manufacturer_id,
        model: i.model,
        serialNumber: i.serial_number,
        flags: i.flags as CK_FLAGS,
        ulMaxSessionCount: i.max_session_count as CK_ULONG,
        ulSessionCount: i.session_count as CK_ULONG,
        ulMaxRwSessionCount: i.max_rw_session_count as CK_ULONG,
        ulRwSessionCount: i.rw_session_count as CK_ULONG,
        ulMaxPinLen: i.max_pin_len as CK_ULONG,
        ulMinPinLen: i.min_pin_len as CK_ULONG,
        ulTotalPublicMemory: i.total_public_memory as CK_ULONG,
        ulFreePublicMemory: i.free_public_memory as CK_ULONG,
        ulTotalPrivateMemory: i.total_private_memory as CK_ULONG,
        ulFreePrivateMemory: i.free_private_memory as CK_ULONG,
        hardwareVersion: cv(i.hardware_version),
        firmwareVersion: cv(i.firmware_version),
        utcTime: i.utc_time,
    }
}

pub fn session_info_to_wire(i: &CK_SESSION_INFO) -> w::SessionInfo {
    w::SessionInfo {
        slot_id: i.slotID as u64,
        state: i.state as u64,
        flags: i.flags as u64,
        device_error: i.ulDeviceError as u64,
    }
}
pub fn session_info_from_wire(i: &w::SessionInfo) -> CK_SESSION_INFO {
    CK_SESSION_INFO {
        slotID: i.slot_id as CK_SLOT_ID,
        state: i.state as CK_STATE,
        flags: i.flags as CK_FLAGS,
        ulDeviceError: i.device_error as CK_ULONG,
    }
}

pub fn mech_info_to_wire(i: &CK_MECHANISM_INFO) -> w::MechanismInfo {
    w::MechanismInfo { min_key_size: i.ulMinKeySize as u64, max_key_size: i.ulMaxKeySize as u64, flags: i.flags as u64 }
}
pub fn mech_info_from_wire(i: &w::MechanismInfo) -> CK_MECHANISM_INFO {
    CK_MECHANISM_INFO {
        ulMinKeySize: i.min_key_size as CK_ULONG,
        ulMaxKeySize: i.max_key_size as CK_ULONG,
        flags: i.flags as CK_FLAGS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_info_roundtrip() {
        // SAFETY: CK_TOKEN_INFO is plain data; all-zero is valid.
        let mut t: CK_TOKEN_INFO = unsafe { core::mem::zeroed() };
        t.label = [b'L'; 32];
        t.flags = 0x405;
        t.ulMaxPinLen = 255;
        t.hardwareVersion = CK_VERSION { major: 3, minor: 2 };
        let back = token_info_from_wire(&token_info_to_wire(&t));
        assert_eq!(back.label, t.label);
        assert_eq!(back.flags, t.flags);
        assert_eq!(back.ulMaxPinLen, 255);
        assert_eq!(back.hardwareVersion.minor, 2);
    }
}
