// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The redb-only leg of P2; WAL/restore identity coverage is added with the WAL association.
#![allow(clippy::expect_used, reason = "storage fixture assertions")]

use super::*;
use crate::{OpaqueDeviceInbox, RouterCore, RouterRedbStore};
use redb::ReadableDatabase;
use std::path::{Path, PathBuf};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn fixture(name: &str) -> ramflux_test_support::TestPath {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(format!(
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
    let mut stored = table
        .get(target)
        .map_err(error)?
        .map(|row| serde_json::from_slice::<StoredCursor>(row.value()))
        .transpose()
        .map_err(error)?;
    if let Some(row) = txn.open_table(state::TABLE).map_err(error)?.get(target).map_err(error)? {
        let (id, issued) = state::decode(row.value())?;
        let stored = stored.get_or_insert_with(|| StoredCursor {
            cursor: CursorAckState {
                target_delivery_id: target.into(),
                ..CursorAckState::default()
            },
            inbox_incarnation_id: None,
        });
        stored.inbox_incarnation_id = Some(id);
        stored.cursor.issued_inbox_seq = stored.cursor.issued_inbox_seq.max(issued);
    }
    Ok(stored)
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
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
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
    crate::home_migration_store::drain_then_ack_restart_preserves_incarnation_and_ack()?;
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
    store.record_submission_increment(
        &crate::tests::request_replay_fixture("row"),
        i64::MAX,
        Some(&row),
    )?;
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
    store.bootstrap_router(&router)?;
    drop(store);
    let store = reopen(&path)?;
    store.load_router()?;
    assert_eq!(stored(&store, "target")?.expect("cursor").inbox_incarnation_id, Some(id));
    assert_eq!(stored(&store, "empty")?.expect("empty cursor").inbox_incarnation_id, Some(empty));
    assert!(stored(&store, "unknown")?.is_none());
    drop(store);
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
    store.record_submission_increment(
        &crate::tests::request_replay_fixture("legacy-row"),
        i64::MAX,
        Some(&row),
    )?;
    // Remove only the new field: this cursor is serialized with the pre-S6 shape.
    let cursor = CursorAckState {
        target_delivery_id: "target".into(),
        issued_inbox_seq: 70,
        settled_inbox_seq: 30,
        ..CursorAckState::default()
    };
    let txn = store.db.begin_write()?;
    txn.open_table(state::TABLE)?.remove("target")?;
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
    assert_eq!(
        before.cursor.settled_inbox_seq, 49,
        "finalized sparse recovery stops below live row50"
    );
    assert_eq!(router.snapshot().inbox.pull_after("target", 0, 10), vec![row]);
    drop(store);
    let store = reopen(&path)?;
    store.load_router()?;
    assert_eq!(stored(&store, "target")?.expect("cursor").inbox_incarnation_id, Some(id));
    assert_eq!(stored(&store, "target")?.expect("cursor").cursor.settled_inbox_seq, 49);
    drop(store);
    Ok(())
}

#[test]
fn append_metadata_does_not_rewrite_ack_history() -> Result {
    for mode in 0..3 {
        let root = fixture("append-work");
        let store = test_store(&root, mode, u64::MAX)?;
        store.record_inbox_entry(&entry(7))?;
        let id = store.inbox_status("target")?.0.expect("E");
        let mut cursor = CursorAckState {
            target_delivery_id: "target".into(),
            issued_inbox_seq: 7,
            ..CursorAckState::default()
        };
        for i in 0..1024 {
            let id = format!("ack-{i:04}-0123456789abcdef");
            cursor.recent_ack_ids.push_back(id.clone());
            cursor.acked_envelope_ids.insert(id);
        }
        store.retain_cursor_checkpoint(&cursor)?;
        let before = {
            let tx = store.db.begin_read()?;
            let table = tx.open_table(ROUTER_CURSOR_STATE_TABLE)?;
            table.get("target")?.expect("history").value().to_vec()
        };
        work::take();
        store.record_inbox_entry(&entry(8))?;
        let append = work::take();
        assert_eq!(
            (append.reads, append.read_bytes, append.writes, append.write_bytes),
            (0, 0, 0, 0)
        );
        assert_eq!(append.metadata_writes, 1);
        assert_eq!(store.inbox_status("target")?, (Some(id), 8));
        let tx = store.db.begin_read()?;
        assert_eq!(
            tx.open_table(ROUTER_CURSOR_STATE_TABLE)?.get("target")?.expect("history").value(),
            before
        );
        drop(tx);
        cursor.last_acknowledged_inbox_seq = Some(8);
        cursor.acked_inbox_seqs.insert(8);
        work::take();
        store.record_ack_increment(&cursor, "incarnation-row")?;
        let ack = work::take();
        assert_eq!(
            ack.reads, 2,
            "one merged history read plus the existing migration settlement read"
        );
        println!(
            "mode={mode}: unchanged history={} bytes, append JSON read/write=0/0, metadata writes=1 (40 bytes), ACK cursor reads={}",
            before.len(),
            ack.reads
        );
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
#[test]
fn missing_incarnation_ack_and_nack_fail_closed() -> Result {
    for shape in ["entry", "cursor", "both"] {
        let root = fixture("missing-E");
        let store = test_store(&root, 0, u64::MAX)?;
        store.record_inbox_entry(&entry(1))?;
        let tx = store.db.begin_write()?;
        tx.open_table(state::TABLE)?.remove("target")?;
        if shape == "entry" {
            tx.open_table(ROUTER_CURSOR_STATE_TABLE)?.remove("target")?;
        } else {
            let legacy = CursorAckState {
                target_delivery_id: "target".into(),
                issued_inbox_seq: 1,
                ..CursorAckState::default()
            };
            tx.open_table(ROUTER_CURSOR_STATE_TABLE)?
                .insert("target", serde_json::to_vec(&legacy)?.as_slice())?;
        }
        if shape == "cursor" {
            crate::router_store::expiry_index::remove_inbox_row(
                &tx,
                &crate::router_store::inbox_entry_storage_key("target", 1),
            )?;
        }
        tx.commit()?;
        let cursor = CursorAckState {
            target_delivery_id: "target".into(),
            last_acknowledged_inbox_seq: Some(1),
            ..CursorAckState::default()
        };
        assert!(matches!(
            store.record_ack_increment(&cursor, "row"),
            Err(NodeCoreError::InboxIncarnationMissing)
        ));
        assert!(matches!(
            store.record_nack_increment(&cursor),
            Err(NodeCoreError::InboxIncarnationMissing)
        ));
        assert_eq!(
            store.load_delivery_state(0)?.0.pull_after("target", 0, 10).len(),
            usize::from(shape != "cursor")
        );
        drop(store);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
