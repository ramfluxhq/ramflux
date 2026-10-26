// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Review r3 regression: a legacy WAL record's deadline is computed once, not per restart.
use super::*;

#[test]
fn legacy_wal_record_deadline_is_not_rebased_by_a_restart() -> Result<(), Box<dyn std::error::Error>>
{
    let path = temp_store_path("r4_legacy_wal")?;
    let wal = path.with_extension("wal");
    let now = i64::try_from(now_unix_seconds())?;
    let mut envelope = envelope("legacy-wal", "legacy-wal-mailbox", DeliveryClass::OpaqueEvent);
    envelope.created_at = now + 10 * 365 * 86_400;
    envelope.ttl = 604_800;
    let entry =
        InboxEntry { inbox_seq: 3, target_delivery_id: "legacy-wal-mailbox".into(), envelope };
    crate::router_wal::write_legacy_router_wal_segment(
        &wal,
        "legacy-wal-key",
        i64::MAX / 2,
        &entry,
    )?;
    let deadline = |store: &RouterRedbStore| -> Result<i64, Box<dyn std::error::Error>> {
        let router = store.load_router()?.ok_or("router")?;
        let restored = router.resume("legacy-wal-mailbox", 0, 10);
        let restored = restored.first().ok_or("legacy entry restored")?;
        Ok(router.target_shard("legacy-wal-mailbox").inbox.retain_until(restored))
    };
    let store = RouterRedbStore::open_with_wal(&path, &wal)?;
    let first = deadline(&store)?;
    drop(store);
    assert!(first <= now + 604_800 + 5, "legacy deadline is bounded by the upgrade: {first}");
    std::thread::sleep(Duration::from_millis(1_100));
    let store = RouterRedbStore::open_with_wal(&path, &wal)?;
    assert_eq!(deadline(&store)?, first, "a restart must not push the deadline out again");
    Ok(())
}
