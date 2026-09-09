//! The Tradr base UUID and slot allocation (ADR-0019).

/// The 128-bit base UUID with zeroes in the 16-bit slot position (ADR-0019).
pub const TRADR_BASE_UUID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x6e, 0xed, 0x40, 0xd6, 0x85, 0xd3, 0x37, 0x94, 0xea, 0xa7, 0xb2, 0x1c,
];

/// Derives a 128-bit Tradr UUID from a 16-bit slot in big-endian order (ADR-0019).
pub const fn tradr_uuid(slot: u16) -> [u8; 16] {
    let mut uuid = TRADR_BASE_UUID;
    let bytes = slot.to_be_bytes();
    uuid[2] = bytes[0];
    uuid[3] = bytes[1];
    uuid
}

/// Derives a 128-bit Tradr UUID reversed for BLE AD structures (ADR-0019).
pub const fn tradr_uuid_le(slot: u16) -> [u8; 16] {
    let uuid = tradr_uuid(slot);
    let mut le = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        le[i] = uuid[15 - i];
        i += 1;
    }
    le
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tradr_uuid_for_advertisement_slot_matches_adr_0019() {
        assert_eq!(
            tradr_uuid(0x0001),
            [
                0x00, 0x00, 0x00, 0x01, 0x6e, 0xed, 0x40, 0xd6, 0x85, 0xd3, 0x37, 0x94, 0xea, 0xa7,
                0xb2, 0x1c,
            ]
        );
    }

    #[test]
    fn tradr_uuid_le_for_advertisement_slot_matches_reversed_uuid() {
        assert_eq!(
            tradr_uuid_le(0x0001),
            [
                0x1c, 0xb2, 0xa7, 0xea, 0x94, 0x37, 0xd3, 0x85, 0xd6, 0x40, 0xed, 0x6e, 0x01, 0x00,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn distinct_slot_bytes_preserve_big_endian_byte_order() {
        let uuid = tradr_uuid(0x1234);
        assert_eq!(uuid[2], 0x12);
        assert_eq!(uuid[3], 0x34);
    }

    #[test]
    fn different_slots_differ_only_at_slot_indices() {
        let a = tradr_uuid(0x0002);
        let b = tradr_uuid(0x0003);
        assert_ne!(a[2..4], b[2..4]);
        assert_eq!(&a[..2], &b[..2]);
        assert_eq!(&a[4..], &b[4..]);
    }
}
