// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;

#[test]
fn gateway_root_shares_protect_existing_accounts() -> Result<(), NodeCoreError> {
    let mut guard = NodeReplayGuardState {
        gateway_limits: GatewayReplayLimits { share: 8, roots: 4 },
        ..NodeReplayGuardState::new()
    };
    guard.accept_gateway_request_key("honest-auth".into(), "honest".into(), 604_800)?;
    for root in 0..3 {
        for device in 0..8 {
            guard.accept_gateway_request_key(
                format!("root-{root}-device-{device}"),
                format!("root-{root}"),
                604_800,
            )?;
        }
        assert!(matches!(
            guard.accept_gateway_request_key(
                format!("root-{root}-new-device"),
                format!("root-{root}"),
                604_800
            ),
            Err(NodeCoreError::GatewayReplayCapacity)
        ));
    }
    assert!(matches!(
        guard.accept_gateway_request_key("new-root".into(), "new-root".into(), 604_800),
        Err(NodeCoreError::GatewayReplayCapacity)
    ));
    guard.accept_gateway_request_key("honest-reauth".into(), "honest".into(), 604_800)?;
    guard.accept_gateway_request_key("honest-submit".into(), "honest".into(), 604_800)?;
    assert!(guard.accepted_by_key.contains_key("honest-auth"));
    assert_eq!(guard.admitted_roots.len(), 4);
    const { assert!(GATEWAY_REPLAY_SHARE >= 20_164) };
    assert_eq!(GATEWAY_REPLAY_CAPACITY, GATEWAY_REPLAY_ROOTS * GATEWAY_REPLAY_SHARE);
    Ok(())
}

#[test]
fn replay_guard_is_bounded_per_device_and_globally() -> Result<(), NodeCoreError> {
    // The inherited acceptance name now exercises a shared account-root quota,
    // including devices under that root and permanently reserved root admissions.
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
