// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

#[test]
fn replay_guard_is_bounded_per_device_and_globally() -> Result<(), NodeCoreError> {
    let mut guard = NodeReplayGuardState::new();
    for index in 0..MAX_REQUESTS_PER_DEVICE {
        guard.accept_request_key(format!("request-{index}"), "device-a".into(), 100)?;
    }
    assert!(guard.accept_request_key("overflow".into(), "device-a".into(), 100).is_err());
    guard.accept_request_key("independent".into(), "device-b".into(), 100)?;
    for index in guard.len()..MAX_REPLAY_ENTRIES {
        guard.insert_entry(format!("legacy-{index}"), 100);
    }
    assert!(guard.accept_request_key("global-overflow".into(), "device-c".into(), 100).is_err());
    assert_eq!(guard.len(), MAX_REPLAY_ENTRIES);
    assert!(guard.accepted_by_key.contains_key("request-0"));
    Ok(())
}

#[test]
fn replay_guard_prune_is_incremental() {
    let mut guard = NodeReplayGuardState::new();
    for index in 0..1000 {
        guard.insert_entry(format!("expired-{index}"), 99);
        guard.insert_entry(format!("live-{index}"), 100);
    }
    guard.prune(100);
    assert_eq!(guard.len(), 2000 - PRUNE_BATCH);
    assert_eq!(guard.expiry_order.len(), guard.len());
    for _ in 0..16 {
        guard.prune(100);
    }
    assert_eq!(guard.len(), 1000);
    assert!(guard.accepted_by_key.contains_key("live-0"));
}
