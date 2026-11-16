// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{FormatError, MediaKeySlot, QualifiedDevice};

fn slot(grant: Vec<u8>, capability: Vec<u8>) -> MediaKeySlot {
    MediaKeySlot {
        recipient: QualifiedDevice {
            account_anchor: "anchor".into(),
            device_id: "device".into(),
            device_epoch: 2,
        },
        encrypted_key: vec![9; 80],
        format: 1,
        grant_id: grant,
        read_capability: capability,
    }
}

#[test]
fn slot_tags_four_and_five_round_trip_and_unknown_tags_fail() -> Result<(), FormatError> {
    let full = slot(vec![3; 32], b"capability".to_vec());
    let bytes = full.encode()?;
    assert_eq!(MediaKeySlot::decode(&bytes)?, full);
    let legacy = slot(Vec::new(), Vec::new());
    assert_eq!(MediaKeySlot::decode(&legacy.encode()?)?, legacy);
    let mut unknown = bytes.clone();
    unknown.extend_from_slice(&[6 << 3 | 2, 1, 1]);
    assert_eq!(MediaKeySlot::decode(&unknown), Err(FormatError("unknown slot field")));
    assert_eq!(slot(vec![1; 31], b"capability".to_vec()).encode(), Err(FormatError("key slot")));
    assert_eq!(slot(Vec::new(), b"capability".to_vec()).encode(), Err(FormatError("key slot")));
    assert_eq!(slot(vec![3; 32], vec![7; 8193]).encode(), Err(FormatError("key slot")));
    Ok(())
}
