// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The redb-only leg of P2; WAL/restore identity coverage is added with the WAL association.
#![allow(clippy::expect_used, reason = "storage fixture assertions")]

use super::*;
use crate::{OpaqueDeviceInbox, RouterCore, RouterRedbStore};
use redb::ReadableDatabase;
use std::path::{Path, PathBuf};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn fixture(name: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "inbox-incarnation-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}

fn stored(
    store: &RouterRedbStore,
    target: &str,
) -> std::result::Result<Option<StoredCursor>, NodeCoreError> {
    let txn = store.db.begin_read().map_err(error)?;
    let table = txn.open_table(ROUTER_CURSOR_STATE_TABLE).map_err(error)?;
    table
        .get(target)
        .map_err(error)?
        .map(|row| serde_json::from_slice(row.value()).map_err(error))
        .transpose()
}

fn entry(seq: u64) -> InboxEntry {
    let mut inbox = OpaqueDeviceInbox::new();
    let envelope = ramflux_protocol::Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "incarnation-test".into(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "signature".into(),
        },
        envelope_id: "incarnation-row".into(),
        source_principal_id: "sender".into(),
        source_device_id: "sender-device".into(),
        target_delivery_id: "target".into(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Normal,
        ttl: 3600,
        created_at: i64::try_from(crate::now_unix_seconds()).expect("server time"),
        encrypted_payload: "ciphertext".into(),
        payload_hash: "hash".into(),
    };
    let mut entry = inbox.append(envelope);
    entry.inbox_seq = seq;
    entry
}

fn reopen(path: &Path) -> std::result::Result<RouterRedbStore, NodeCoreError> {
    RouterRedbStore::open_without_wal(path)
}

#[test]
fn inbox_incarnation_lifecycle() -> Result {
    crate::router_wal::identity_tests::lifecycle()?;
    let root = fixture("lifecycle");
    let path = root.join("db");
    let store = reopen(&path)?;
    assert!(stored(&store, "unknown")?.is_none());
    assert!(store.load_delivery_state(0)?.0.cursor_state("unknown").is_none());
    let txn = store.db.begin_write()?;
    let empty = ensure_cursor(&txn, "empty", 0)?;
    txn.commit()?;
    let empty_cursor = stored(&store, "empty")?.expect("empty cursor");
    assert_eq!(empty_cursor.cursor.issued_inbox_seq, 0);
    assert_eq!(empty_cursor.inbox_incarnation_id.as_deref(), Some(empty.as_str()));
    let row = entry(7);
    store.record_submission_increment("row", i64::MAX, Some(&row))?;
    let before = stored(&store, "target")?.expect("row cursor");
    let id = before.inbox_incarnation_id.expect("incarnation");
    validate(&id)?;
    assert_ne!(id, empty);
    assert_eq!(before.cursor.issued_inbox_seq, 7);
    // A rolled-back first row leaves neither a counter nor an incarnation.
    let txn = store.db.begin_write()?;
    ensure_cursor(&txn, "rolled-back", 1)?;
    txn.abort()?;
    assert!(stored(&store, "rolled-back")?.is_none());
    let cursor = CursorAckState {
        target_delivery_id: "target".into(),
        issued_inbox_seq: 7,
        last_acknowledged_inbox_seq: Some(1),
        ..CursorAckState::default()
    };
    store.retain_cursor_checkpoint(&cursor)?;
    store.record_nack_increment(&cursor)?;
    store.record_ack_increment(&cursor, "other-row")?;
    let router = store.load_router()?.expect("router");
    store.save_router(&router)?;
    drop(store);
    let store = reopen(&path)?;
    store.load_router()?;
    assert_eq!(stored(&store, "target")?.expect("cursor").inbox_incarnation_id, Some(id));
    assert_eq!(stored(&store, "empty")?.expect("empty cursor").inbox_incarnation_id, Some(empty));
    assert!(stored(&store, "unknown")?.is_none());
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn pre_s6_store_upgrade() -> Result {
    crate::router_wal::identity_tests::upgrade()?;
    crate::router_wal::identity_tests::empty_head_crash()?;
    let root = fixture("upgrade");
    let path = root.join("db");
    let store = reopen(&path)?;
    let row = entry(50);
    store.record_submission_increment("legacy-row", i64::MAX, Some(&row))?;
    // Remove only the new field: this cursor is serialized with the pre-S6 shape.
    let cursor = CursorAckState {
        target_delivery_id: "target".into(),
        issued_inbox_seq: 70,
        settled_inbox_seq: 30,
        ..CursorAckState::default()
    };
    let txn = store.db.begin_write()?;
    {
        let mut table = txn.open_table(ROUTER_CURSOR_STATE_TABLE)?;
        let bytes = serde_json::to_vec(&cursor)?;
        table.insert("target", bytes.as_slice())?;
    }
    txn.commit()?;
    assert!(stored(&store, "target")?.expect("legacy cursor").inbox_incarnation_id.is_none());
    drop(store);
    let store = reopen(&path)?;
    let router: RouterCore = store.load_router()?.expect("legacy router");
    let before = stored(&store, "target")?.expect("upgraded cursor");
    let id = before.inbox_incarnation_id.expect("persisted E");
    assert_eq!(before.cursor.issued_inbox_seq, 70);
    assert_eq!(before.cursor.settled_inbox_seq, 30);
    assert_eq!(router.snapshot().inbox.pull_after("target", 0, 10), vec![row]);
    drop(store);
    let store = reopen(&path)?;
    store.load_router()?;
    assert_eq!(stored(&store, "target")?.expect("cursor").inbox_incarnation_id, Some(id));
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
