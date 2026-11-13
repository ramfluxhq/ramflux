// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refuse old receipt collections on actual startup, including registration journal replay.
use super::*;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde_json::{Value, json};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("router_snapshot_v1");
const ADMISSIONS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("router_identity_admission_v1");

fn corrupt_collection(value: &mut Value, field: &str, case: u8) -> TestResult {
    let map = value.as_object_mut().ok_or("object")?;
    match case {
        0 => {
            map.remove(field);
        }
        1 => {
            map.insert(field.into(), Value::Null);
        }
        2 => {
            map.insert(field.into(), json!(["bare-proof"]));
        }
        3 => {
            map.insert(
                field.into(),
                json!([{"key":"proof","expires_at":null,"root":null,"source":null}]),
            );
        }
        4 => {
            map.insert(field.into(), json!([{"key":"proof","expires_at":2000}]));
        }
        _ => return Err("fixture case".into()),
    }
    Ok(())
}

#[test]
fn old_registration_receipts_refuse_at_router_startup() -> TestResult {
    for journal in [false, true] {
        for case in 0..5 {
            let directory = tempfile::TempDir::new()?;
            let path = directory.path().join("store.redb");
            let router = RouterCore::new();
            let store = RouterRedbStore::open_without_wal(&path)?;
            let request =
                registration_request(&router, "receipt-owner", "phone", 31, None, "source")?;
            router.register_identity_durable(&request, &store)?;
            let snapshot = serde_json::to_value(router.mvp1_identities_snapshot())?;
            drop(store);
            let db = redb::Database::open(&path)?;
            let tx = db.begin_write()?;
            let bytes;
            let journal_key;
            if journal {
                let mut table = tx.open_table(ADMISSIONS)?;
                let (key, row) = table.first()?.ok_or("admission")?;
                journal_key = Some(key.value());
                let mut entry: Value = serde_json::from_slice(row.value())?;
                drop(key);
                drop(row);
                corrupt_collection(&mut entry["delta"], "receipts", case)?;
                bytes = serde_json::to_vec(&entry)?;
                table.insert(journal_key.ok_or("journal key")?, bytes.as_slice())?;
            } else {
                journal_key = None;
                let mut snapshot = snapshot;
                corrupt_collection(&mut snapshot, "root_seen_proofs", case)?;
                bytes = serde_json::to_vec(&snapshot)?;
                tx.open_table(ADMISSIONS)?.retain(|_, _| false)?;
                tx.open_table(SNAPSHOTS)?.insert("identity_registry", bytes.as_slice())?;
            }
            tx.commit()?;
            drop(db);
            let before = super::persisted_image::image(directory.path())?;
            let error =
                RouterRedbStore::open_without_wal(&path).err().ok_or("old receipts admitted")?;
            let message = error.to_string();
            assert!(
                message.contains("missing field") || message.contains("invalid type"),
                "unexpected refusal: {message}"
            );
            assert_eq!(
                super::persisted_image::image(directory.path())?,
                before,
                "receipt refusal must precede every startup write"
            );
            assert!(
                RouterRedbStore::rotate_inbox_incarnations_at(&path, None, None).is_err(),
                "maintenance must validate receipt snapshots and journals first"
            );
            assert_eq!(
                super::persisted_image::image(directory.path())?,
                before,
                "maintenance changed a table or journal before receipt refusal"
            );
            // No failed decode is replaced by a default registry or a rewritten receipt.
            let db = redb::Database::open(&path)?;
            let tx = db.begin_read()?;
            let persisted = if let Some(key) = journal_key {
                tx.open_table(ADMISSIONS)?.get(key)?.ok_or("journal preserved")?.value().to_vec()
            } else {
                tx.open_table(SNAPSHOTS)?
                    .get("identity_registry")?
                    .ok_or("snapshot preserved")?
                    .value()
                    .to_vec()
            };
            assert_eq!(persisted, bytes);
            drop(tx);
            drop(db);
        }
    }
    Ok(())
}

#[test]
fn explicit_empty_and_current_receipt_collections_reopen_byte_exact() -> TestResult {
    for empty in [false, true] {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("store.redb");
        let router = RouterCore::new();
        let store = RouterRedbStore::open_without_wal(&path)?;
        let request = registration_request(&router, "receipt-owner", "phone", 32, None, "source")?;
        router.register_identity_durable(&request, &store)?;
        let mut value = serde_json::to_value(router.mvp1_identities_snapshot())?;
        if empty {
            value["root_seen_proofs"] = json!([]);
        }
        let receipts = value["root_seen_proofs"].as_array().ok_or("receipts")?;
        for receipt in receipts {
            assert_eq!(receipt.as_object().ok_or("row")?.len(), 4);
            for field in ["key", "root", "source"] {
                assert!(receipt[field].is_string());
            }
            assert!(receipt["expires_at"].as_i64().is_some());
        }
        let bytes = serde_json::to_vec(&value)?;
        drop(store);
        let db = redb::Database::open(&path)?;
        let tx = db.begin_write()?;
        tx.open_table(ADMISSIONS)?.retain(|_, _| false)?;
        tx.open_table(SNAPSHOTS)?.insert("identity_registry", bytes.as_slice())?;
        tx.commit()?;
        drop(db);
        let store = RouterRedbStore::open_without_wal(&path)?;
        assert_eq!(
            serde_json::to_value(store.load_router()?.ok_or("router")?.mvp1_identities_snapshot())?,
            value
        );
        drop(store);
        let db = redb::Database::open(&path)?;
        assert_eq!(
            db.begin_read()?
                .open_table(SNAPSHOTS)?
                .get("identity_registry")?
                .ok_or("snapshot")?
                .value(),
            bytes
        );
        drop(db);
    }
    Ok(())
}

fn stale_journal_fixture(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let router = RouterCore::new();
    let store = RouterRedbStore::open_without_wal(path)?;
    let request =
        registration_request(&router, "repair-owner", "phone", 31, None, "repair-source")?;
    router.register_identity_durable(&request, &store)?;
    let newer =
        registration_request(&router, "repair-owner", "tablet", 32, None, "repair-other-source")?;
    router.mvp1_register_identity(&newer)?;
    let snapshot = serde_json::to_vec(&router.mvp1_identities_snapshot())?;
    drop(store);
    let db = redb::Database::open(path)?;
    let txn = db.begin_write()?;
    // A real valid delta now names the older snapshot base. Operator discard may
    // repair this inconsistency without accepting an obsolete row grammar.
    txn.open_table(SNAPSHOTS)?.insert("identity_registry", snapshot.as_slice())?;
    txn.commit()?;
    Ok(request.principal_commitment)
}

#[test]
fn discard_stale_refuses_retired_tuples_and_receipts_without_any_write() -> TestResult {
    for case in 0..4 {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("router.redb");
        stale_journal_fixture(&path)?;
        let db = redb::Database::open(&path)?;
        let txn = db.begin_write()?;
        match case {
            0 => {
                txn.open_table(crate::ROUTER_REPLAY_TUPLE_TABLE)?
                    .insert("envelope/v2/retired/id", b"200".as_slice())?;
            }
            1 => {
                txn.open_table(crate::ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?.insert(
                    "retired-delivery",
                    serde_json::to_vec(
                        &json!({"assignment":null,"target_delivery_id":"target","expires_at":200}),
                    )?
                    .as_slice(),
                )?;
            }
            2 => {
                let mut table = txn.open_table(SNAPSHOTS)?;
                let mut snapshot: Value = serde_json::from_slice(
                    table.get("identity_registry")?.ok_or("snapshot")?.value(),
                )?;
                corrupt_collection(&mut snapshot, "root_seen_proofs", 2)?;
                table.insert("identity_registry", serde_json::to_vec(&snapshot)?.as_slice())?;
            }
            3 => {
                let mut table = txn.open_table(ADMISSIONS)?;
                let (key, row) = table.first()?.ok_or("stale admission")?;
                let journal_key = key.value();
                let mut entry: Value = serde_json::from_slice(row.value())?;
                drop(key);
                drop(row);
                corrupt_collection(entry.get_mut("delta").ok_or("delta")?, "receipts", 2)?;
                table.insert(journal_key, serde_json::to_vec(&entry)?.as_slice())?;
            }
            _ => return Err("unknown fixture".into()),
        }
        txn.commit()?;
        drop(db);
        let before = super::persisted_image::image(directory.path())?;
        assert!(
            RouterRedbStore::discard_stale_identity_journal(&path).is_err(),
            "DiscardStale must not bypass retired tuple or receipt grammar"
        );
        assert_eq!(
            super::persisted_image::image(directory.path())?,
            before,
            "refused DiscardStale rewrote journal/accounting/budgets or another persisted table/file"
        );
    }
    Ok(())
}

#[test]
fn discard_stale_current_formats_repairs_the_journal_without_replaying_stale_authority()
-> TestResult {
    let directory = tempfile::TempDir::new()?;
    let path = directory.path().join("router.redb");
    let root = stale_journal_fixture(&path)?;
    assert!(
        matches!(
            RouterRedbStore::open_without_wal(&path),
            Err(NodeCoreError::IdentityAdmissionJournalBaseMismatch { .. })
        ),
        "current control must reach the repairable base mismatch"
    );
    let report = RouterRedbStore::discard_stale_identity_journal(&path)?;
    assert_eq!(report.discarded_rows, 1, "valid stale delta must be discarded");
    assert_eq!(
        report.affected_root_ids,
        vec![root.clone()],
        "repair must report the authenticated affected root"
    );
    let store = RouterRedbStore::open_without_wal(&path)?;
    assert_eq!(store.pending_identity_admission_count()?, 0, "repair must clear the stale journal");
    let router = store.load_router()?.ok_or("repaired router")?;
    assert_eq!(
        router.signed_device_set(&root).ok_or("current signed set")?.device_set_epoch,
        2,
        "repair must preserve the newer snapshot epoch rather than replay the stale epoch-one delta"
    );
    Ok(())
}
