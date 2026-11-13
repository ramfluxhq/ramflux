// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retired WAL records without a server acceptance time are refused.
use super::*;

#[test]
fn legacy_wal_record_without_acceptance_time_is_refused() -> Result<(), Box<dyn std::error::Error>>
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
    assert!(matches!(
        RouterRedbStore::open_with_wal(&path, &wal),
        Err(NodeCoreError::UnsupportedPersistedFormat("router WAL acceptance time"))
    ));
    Ok(())
}
