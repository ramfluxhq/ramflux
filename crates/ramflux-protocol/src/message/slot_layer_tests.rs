// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{MediaKeySlot, registry::descriptor, scanner, validation::ScanOutcome};
use prost::Message as _;

#[test]
fn grant_slot_fields_are_layer_four() -> Result<(), Box<dyn std::error::Error>> {
    let slot = MediaKeySlot {
        format: 1,
        grant_id: vec![4; 32],
        read_capability: b"capability".to_vec(),
        ..Default::default()
    };
    let bytes = slot.encode_to_vec();
    let message = descriptor("MediaKeySlot")?;
    assert_eq!(scanner::scan(&message, &bytes, 1, 0)?, ScanOutcome::Unsupported);
    assert_eq!(scanner::scan(&message, &bytes, 3, 0)?, ScanOutcome::Unsupported);
    assert_eq!(scanner::scan(&message, &bytes, 4, 0)?, ScanOutcome::Supported);
    let legacy = MediaKeySlot { format: 1, encrypted_key: vec![1; 16], ..Default::default() };
    assert_eq!(scanner::scan(&message, &legacy.encode_to_vec(), 1, 0)?, ScanOutcome::Supported);
    Ok(())
}
