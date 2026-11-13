// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retired wake payloads in the current WAL cannot enter the provider path.
use super::*;
use crate::test_support::notification_authority::NativeScenario;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn raw_pending(store: &NotifyRedbStore) -> usize {
    store.notify_wal_pending_counts(20).iter().map(|shard| shard.counts.raw_wake_count).sum()
}

#[test]
fn legacy_pending_wakes_cannot_bypass_new_provider_policy() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let scenario = NativeScenario::new_with_wal(temp.path())?;
    let (caller, target, mut signed) = scenario.call_wake()?;
    let now = now_unix_seconds();
    signed.body.class = ramflux_protocol::WakeClass::Message;
    signed.body.call_intent_digest = None;
    signed.body.expires_at = now + 600;
    signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::wake_signing_bytes(&signed.body)?,
        &caller.branch,
    );
    let projected = crate::project_wake_v2(&signed, now)?;
    let current =
        scenario.notify.queue_wake_for_async_accept(&target.target, &projected, now, false)?;
    let old = notification_wake("legacy-sentinel-wal", 30);
    scenario.notify.queue_wake_for_async_accept(&target.target, &old, now, false)?;
    let old_raw =
        serde_json::to_vec(&serde_json::json!({"wake": old, "device_delivery_id": target.target}))?;
    let new_raw = serde_json::to_vec(
        &serde_json::json!({"signed_wake": signed, "device_delivery_id": target.target}),
    )?;
    scenario.notify.queue_raw_wakes_for_async_accept_batch(vec![(old_raw, now), (new_raw, now)])?;
    drop(scenario);
    let scenario = NativeScenario::new_with_wal(temp.path())?;
    assert_eq!(raw_pending(&scenario.notify), 2, "current WAL failed to retain both raw fixtures");
    assert_eq!(
        scenario.notify.drop_legacy_pending_wakes()?,
        2,
        "old decoded and raw payloads must close"
    );
    drop(scenario);
    let reopened = NativeScenario::new_with_wal(temp.path())?;
    let state = reopened.notify.load_state()?.ok_or("test: recovered queue missing")?;
    assert!(state.entry("legacy-sentinel-wal").is_none(), "retired wake payload survived reopen");
    let retained = state.entry(&current.queue_id).ok_or("test: current message missing")?;
    assert_eq!(
        retained.expires_at, current.expires_at,
        "cleanup extended the current message deadline"
    );
    assert_eq!(retained.status, NotifyQueueStatus::Pending, "cleanup closed current work");
    assert_eq!(
        raw_pending(&reopened.notify),
        1,
        "cleanup must retain the current signed raw payload"
    );
    assert_eq!(
        state.push_routes(&target.target, now).len(),
        1,
        "cleanup removed the native encrypted route"
    );
    assert!(
        state.provider_credential("apns").is_some(),
        "cleanup removed the independent credential"
    );
    Ok(())
}
