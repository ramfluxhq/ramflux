// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retention bookkeeping: server deadlines, incremental expiry, dead letters and batching.
use super::*;

#[test]
fn mailbox_deadline_is_capped_seven_days_after_server_acceptance() {
    let mut inbox = OpaqueDeviceInbox::new();
    let accepted_at = 2_000_000_000;
    let mut future = envelope("future", "target", DeliveryClass::OpaqueEvent);
    future.created_at = accepted_at + 10 * 365 * 86_400;
    future.ttl = 604_800;
    let entry = inbox.append_at(future, accepted_at);
    assert_eq!(inbox.retain_until(&entry), accepted_at + 604_800);
    assert_eq!(inbox.expire(accepted_at + 604_799), 0);
    assert_eq!(inbox.expire(accepted_at + 604_800), 1);
    let mut short = envelope("short", "target", DeliveryClass::OpaqueEvent);
    short.created_at = accepted_at;
    short.ttl = 60;
    let short = inbox.append_at(short, accepted_at);
    assert_eq!(inbox.retain_until(&short), accepted_at + 60);
}

#[test]
fn expiry_visits_due_entries_and_checkpoints_only_touched_mailboxes() {
    let mut inbox = OpaqueDeviceInbox::new();
    for target in ["quiet-a", "quiet-b", "expiring"] {
        let mut message = envelope(&format!("{target}-1"), target, DeliveryClass::OpaqueEvent);
        message.created_at = 1_000;
        message.ttl = if target == "expiring" { 10 } else { 600 };
        inbox.append_at(message, 1_000);
    }
    let _creation = inbox.take_checkpoint_due();
    let removed = inbox.expire_entries(1_010);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].target_delivery_id, "expiring");
    let due = inbox.take_checkpoint_due();
    assert_eq!(due.len(), 1, "untouched mailboxes are not rewritten");
    assert_eq!(due[0].target_delivery_id, "expiring");
    assert_eq!(due[0].settled_inbox_seq, 1);
    assert_eq!(inbox.take_checkpoint_due().len(), 0);
}

#[test]
fn mailbox_reads_hide_expired_entries_without_mutating_the_shard() {
    let mut inbox = OpaqueDeviceInbox::new();
    let mut message = envelope("read", "target", DeliveryClass::OpaqueEvent);
    message.created_at = 1_000;
    message.ttl = 10;
    inbox.append_at(message, 1_000);
    assert_eq!(inbox.pull_live_after("target", 0, 10, 1_010).len(), 0);
    assert_eq!(inbox.pull_after("target", 0, 10).len(), 1, "deletion is left to the sweep");
    assert_eq!(inbox.expire(1_010), 1);
}

#[test]
fn repeated_nacks_dead_letter_without_keeping_ciphertext() -> Result<(), Box<dyn std::error::Error>>
{
    let path = temp_store_path("server_retention_dead_letter")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    store.save_router(&RouterCore::new())?;
    let mut inbox = OpaqueDeviceInbox::new();
    let mut message = envelope("poison", "mailbox", DeliveryClass::OpaqueEvent);
    message.created_at = i64::try_from(now_unix_seconds())?;
    let entry = inbox.append(message);
    store.record_submission_increment("poison-key", i64::MAX / 2, Some(&entry))?;
    let mut cursor = CursorAckState::default();
    for _ in 0..crate::inbox::ROUTER_NACK_RETRY_LIMIT {
        cursor =
            inbox.apply_nack_for_target("mailbox", &nack("poison", NackReason::EpochRollback))?;
        store.record_nack_increment(&cursor)?;
    }
    assert_eq!(cursor.retired_inbox_seqs, vec![entry.inbox_seq]);
    let record = cursor.dead_letters.back().ok_or("dead letter")?;
    assert_eq!(record.reason, crate::DeadLetterReason::Nacked(NackReason::EpochRollback));
    assert_eq!(record.envelope_id, "poison");
    assert_eq!(inbox.pull_after("mailbox", 0, 10).len(), 0);
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let restored = store.load_router()?.ok_or("router")?;
    assert!(restored.resume("mailbox", 0, 10).is_empty(), "dead letters keep no ciphertext row");
    assert_eq!(restored.cursor_state("mailbox").ok_or("cursor")?.dead_letters.len(), 1);
    Ok(())
}

#[test]
fn durable_sweep_removes_only_rows_whose_index_deadline_is_due()
-> Result<(), Box<dyn std::error::Error>> {
    let path = temp_store_path("server_retention_index_sweep")?;
    let store = RouterRedbStore::open_without_wal(&path)?;
    store.save_router(&RouterCore::new())?;
    let now = i64::try_from(now_unix_seconds())?;
    let mut inbox = OpaqueDeviceInbox::new();
    for (id, ttl) in [("soon", 10_u32), ("later", 3_600)] {
        let mut message = envelope(id, id, DeliveryClass::OpaqueEvent);
        message.created_at = now;
        message.ttl = ttl;
        let entry = inbox.append(message);
        store.record_submission_increment(id, now + i64::from(ttl), Some(&entry))?;
    }
    assert_eq!(store.sweep_delivery_retention(now + 11, true)?, 2, "one row and one replay tuple");
    assert_eq!(store.sweep_delivery_retention(now + 11, false)?, 2);
    assert_eq!(store.sweep_delivery_retention(now + 11, false)?, 0, "index entries are consumed");
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let router = store.load_router()?.ok_or("router")?;
    assert_eq!(router.resume("soon", 0, 10).len(), 0);
    assert_eq!(router.resume("later", 0, 10).len(), 1);
    Ok(())
}

#[test]
fn retention_requests_cannot_move_a_node_clock_forward() {
    let request = RetentionGcSweepRequest {
        owner_service: "router".into(),
        sweep_id: "skewed".into(),
        now: u64::MAX,
        dry_run: false,
    };
    assert!(request.effective_now() <= now_unix_seconds());
    let past = RetentionGcSweepRequest { now: 5, ..request };
    assert_eq!(past.effective_now(), 5);
}

#[test]
fn router_wal_keeps_issued_watermarks_after_expiry() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_store_path("server_retention_wal_watermark")?.with_extension("wal");
    let store = RouterWalStore::open(&root)?;
    let mut message = envelope("old", "mailbox", DeliveryClass::OpaqueEvent);
    message.created_at = 1_000;
    message.ttl = 10;
    let entry =
        InboxEntry { inbox_seq: 9, target_delivery_id: "mailbox".into(), envelope: message };
    store.record_submission("old", 1_010, Some(&entry))?;
    assert!(store.prune_expired(i64::try_from(now_unix_seconds())?)? >= 1);
    assert_eq!(store.issued_watermarks().get("mailbox"), Some(&9));
    Ok(())
}

#[test]
fn revocation_sweep_batches_authority_lookups() -> Result<(), Box<dyn std::error::Error>> {
    let batches = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut store = NotifyRedbStore::open_with_route_key(
        temp_store_path("server_retention_revocation_batch")?,
        NodeSecret::ephemeral()?,
    )?;
    let seen = std::sync::Arc::clone(&batches);
    store.set_push_route_batch_authorizer(move |owners| {
        seen.lock().map_err(|_| NodeCoreError::ItestHttp("lock".into()))?.push(owners.len());
        Ok(vec![true; owners.len()])
    });
    let now = now_unix_seconds();
    for index in 0..300 {
        let mut open = gateway_open_frame("phone", "stream");
        open.target_delivery_id = format!("batched-{index:03}");
        let mut route = notify_webpush_route(&open.target_delivery_id, "web");
        route.registered_at = now;
        route.expires_at = now + PUSH_ROUTE_TTL_SECONDS;
        store.register_authenticated_push_route(&gateway_registered_key(&open)?, &route)?;
    }
    batches.lock().map_err(|_| "lock")?.clear();
    store.sweep_push_route_revocations()?;
    assert_eq!(*batches.lock().map_err(|_| "lock")?, vec![256, 44]);
    Ok(())
}
