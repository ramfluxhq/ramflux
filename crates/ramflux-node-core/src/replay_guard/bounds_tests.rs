// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

#[test]
fn gateway_root_shares_protect_existing_accounts() -> Result<(), NodeCoreError> {
    crate::tests::root_identity_replay::gateway_root_admission_preserves_honest_auth_and_submit_after_saturation()
        .map_err(|error| NodeCoreError::Redb(error.to_string()))
}

#[test]
fn replay_guard_is_bounded_per_device_and_globally() -> Result<(), NodeCoreError> {
    // The inherited acceptance name now exercises a shared account-root quota,
    // including devices under that root and transactional disk admission.
    gateway_root_shares_protect_existing_accounts()
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
