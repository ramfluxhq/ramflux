// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! All-column privacy checks and transaction/late-write invariants for the footprint contract.
use super::*;
use crate::{AccountDbKey, AccountIndex, EventStore};
use serde_json::json;

#[test]
fn message_copy_upserts_keep_registration_idempotent() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-upsert")?;
    db.send_direct_message("thread", "message", "peer", b"content")?;
    for attempt in 0..3 {
        db.persist_actor_state(
            "routed/committed/receipt",
            &json!({"routing":{"message_id":"message"},"entry":{"envelope":{
                "envelope_id":"wire","payload_hash":"payload"}},"projected":attempt>0}),
        )?;
        db.persist_actor_state(
            "delivery-receipt/pending/receipt",
            &json!({"message":"message","status_id":"receipt","attempts":attempt}),
        )?;
        assert_eq!(
            db.load_actor_state::<serde_json::Value>("delivery-receipt/pending/receipt")?
                .map(|value| value["attempts"].clone()),
            Some(json!(attempt))
        );
    }
    db.delete_direct_message("thread", "message", "local", "delete")?;
    assert!(!db.actor_state_exists("routed/committed/receipt")?);
    assert!(!db.actor_state_exists("delivery-receipt/pending/receipt")?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn message_copy_stores_erase_all_columns_for_own_peer_dm_and_group_across_restart()
-> Result<(), StorageError> {
    for own in [false, true] {
        for group in [false, true] {
            let (root, db) = crate::tests::test_db(&format!("footprint-generic-{own}-{group}"))?;
            let sender = if own { "sibling-private-device" } else { "peer-private-device" };
            let principal = if own { "principal" } else { "peer-private-root" };
            db.upsert_device_directory_entry(sender, principal, "verified", 1)?;
            db.persist_client_record(
                "identity",
                principal,
                &json!({"principal":principal,"device":sender}),
            )?;
            if group {
                db.create_group("group", sender)?;
            }
            let conversation = if group { "group" } else { "thread" };
            db.send_direct_message(conversation, "projection-id", sender, b"private-content")?;
            let hash = ramflux_crypto::blake3_256_base64url(
                "ramflux.sdk.receipt.v3",
                &ramflux_protocol::canonical_json_bytes(&(principal, sender, "wire-private-id"))?,
            );
            seed_copies(&db, &hash, principal, sender, conversation)?;
            let forbidden = vec![
                sender.to_owned(),
                principal.to_owned(),
                "wire-private-id".into(),
                hash,
                "logical-private-id".into(),
                "private-content".into(),
            ];
            let before = identity_rows(&db)?;
            db.delete_direct_message(conversation, "projection-id", "local", "delete-id")?;
            assert_eq!(before, identity_rows(&db)?);
            assert_erased(&db, &forbidden)?;
            assert_eq!(db.direct_message_by_id("projection-id")?.map(|p| p.is_own), Some(own));
            drop(db);
            let db = AccountDb::open(
                &AccountIndex::open(&root)?,
                "acct",
                &AccountDbKey::derive("acct", b"storage-test-secret"),
            )?;
            assert_eq!(before, identity_rows(&db)?);
            assert_erased(&db, &forbidden)?;
            drop(db);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

fn seed_copies(
    db: &AccountDb,
    hash: &str,
    principal: &str,
    sender: &str,
    conversation: &str,
) -> Result<(), StorageError> {
    let receipt = format!("routed/committed/{hash}");
    let envelope = json!({"envelope_id":"wire-private-id","source_principal_id":principal,"source_device_id":sender,"payload_hash":"payload-private-hash","encrypted_payload":"private-content"});
    // Some copies precede commit/decryption: provisional aliases must be adopted atomically.
    db.append_event(
        &format!("gateway/{receipt}"),
        "gateway.deliver.opaque",
        &serde_json::to_vec(&envelope)?,
    )?;
    db.append_journal("unrouted:wire-private-id", "message.unrouted", &envelope, 1, None)?;
    for (table, key) in [
        ("runtime_unrouted", "envelope_id"),
        ("runtime_inbox_retry", "envelope_key"),
        ("runtime_inbox_dead_letter", "envelope_key"),
    ] {
        let entry = serde_json::to_vec(&json!({"envelope":envelope}))?;
        let sql = match table {
            "runtime_unrouted" => format!(
                "INSERT INTO {table}({key},inbox_seq,entry_json,received_at) VALUES(?1,1,?2,1)"
            ),
            "runtime_inbox_retry" => format!(
                "INSERT INTO {table}({key},entry_json,attempts,next_at,created_at) VALUES(?1,?2,1,1,1)"
            ),
            _ => format!(
                "INSERT INTO {table}({key},entry_json,error_code,received_at) VALUES(?1,?2,'failed',1)"
            ),
        };
        db.connection.execute(&sql, params![receipt, entry])?;
    }
    seed_envelope_stores(db, sender, &receipt)?;
    db.persist_actor_state(
        &receipt,
        &json!({"routing":{"message_id":"projection-id"},"entry":{"envelope":envelope}}),
    )?;
    db.persist_actor_state(&format!("routed/projection/{hash}"), &"projection-id")?;
    db.persist_actor_state("routed/message-owner/projection-id", &sender)?;
    db.persist_actor_state("routed/message-metadata/projection-id",&json!({"message_id":"projection-id","group_id":"group","group_message_id":"logical-private-id","sender":sender}))?;
    db.persist_actor_state(
        "attachment/reference/object-selector",
        &json!({"reference":{"object_id":"object-selector","owner":sender}}),
    )?;
    db.persist_actor_state("attachment/chunk/object-selector/manifest/0", &"private-content")?;
    db.persist_actor_state("attachment/reference-by-sender/private", &"object-selector")?;
    db.persist_client_record(
        "object",
        "object-selector",
        &json!({"message_id":"projection-id","owner":sender}),
    )?;
    db.persist_actor_state(
        "delivery-receipt/pending/status",
        &json!({"status_id":"status","message":"projection-id","sender":sender}),
    )?;
    db.persist_receipt_state("delivery-receipt/status/status", &json!({"state":"sent"}), 1)?;
    db.persist_message_watermark(
        "projection-id",
        conversation,
        "routed/commit-watermark/conversation",
        &receipt,
    )?;
    db.connection.execute_batch("CREATE TABLE backup_archived_actor_state(source TEXT,state_kind TEXT,state_json BLOB,PRIMARY KEY(source,state_kind)); CREATE TABLE backup_archived_local_event AS SELECT '' AS source,* FROM local_event_log WHERE 0;")?;
    db.connection.call(|raw| super::install(raw))?;
    db.connection.execute_batch("INSERT INTO backup_archived_actor_state SELECT 'archive',state_kind,state_json FROM runtime_actor_state; INSERT INTO backup_archived_local_event SELECT 'archive',* FROM local_event_log;")?;
    Ok(())
}

fn seed_envelope_stores(db: &AccountDb, sender: &str, event: &str) -> Result<(), StorageError> {
    db.connection.execute("INSERT INTO raw_envelope_log VALUES('wire-private-id',?1,'target',NULL,'dm',1,x'01',x'02')",params![sender])?;
    db.connection.execute_batch("INSERT INTO outbox_queue VALUES('queued','wire-private-id','target','dm',x'01','pending',0,NULL,1,1); INSERT INTO cursor_checkpoint VALUES('cursor','target',1,'wire-private-id',1); INSERT INTO device_inbox_cursor VALUES('target','cursor',1,'wire-private-id',1,1); INSERT INTO ack_state VALUES('ack','wire-private-id','target',NULL,1); INSERT INTO nack_state VALUES('nack','wire-private-id','target','failed',NULL,1);")?;
    db.connection.execute(
        "INSERT INTO event_causal_dependency VALUES(?1,?1,'known')",
        params![format!("gateway/{event}")],
    )?;
    Ok(())
}

fn identity_rows(db: &AccountDb) -> Result<Vec<Vec<u8>>, StorageError> {
    let mut result = Vec::new();
    for table in [
        "device_directory",
        "device_identity",
        "local_event_counter",
        "group_member_projection",
        "group_member_device_key",
    ] {
        result.extend(dump(db, &format!("SELECT * FROM {table} ORDER BY rowid"))?);
    }
    result.extend(dump(db,"SELECT state_kind,state_json FROM runtime_actor_state WHERE state_kind GLOB 'directory/identity/*' ORDER BY state_kind")?);
    Ok(result)
}
fn dump(db: &AccountDb, sql: &str) -> Result<Vec<Vec<u8>>, StorageError> {
    let sql = sql.to_owned();
    Ok(db.connection.call(move |raw| {
        let mut q = raw.prepare(&sql)?;
        let columns = q.column_count();
        q.query_map([], |r| {
            let mut bytes = Vec::new();
            for column in 0..columns {
                bytes.extend_from_slice(format!("{:?}\0", r.get_ref(column)?).as_bytes());
            }
            Ok(bytes)
        })?
        .collect::<rusqlite::Result<_>>()
    })?)
}
fn assert_erased(db: &AccountDb, forbidden: &[String]) -> Result<(), StorageError> {
    db.checkpoint_retired_secrets()?;
    let forbidden = forbidden.to_vec();
    db.connection.call(move |raw| {
    let mut q=raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let tables =
        q.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    drop(q);
    for table in tables {
        let filter =
            if matches!(table.as_str(), "runtime_actor_state" | "backup_archived_actor_state") {
                " WHERE state_kind NOT GLOB 'directory/identity/*'"
            } else if table.contains("message")
                || table.contains("receipt")
                || table.contains("journal")
                || table.contains("event_log")
                || table.starts_with("runtime_inbox_")
                || matches!(
                    table.as_str(),
                    "runtime_unrouted" | "runtime_outbox" | "raw_envelope_log" | "outbox_queue" | "ack_state" | "nack_state" | "event_causal_dependency" | "cursor_checkpoint" | "device_inbox_cursor" | "backup_archived_local_event"
                )
            {
                ""
            } else {
                continue;
            };
        let mut q = raw.prepare(&format!("SELECT * FROM {table}{filter}"))?;
        let names = q.column_names().iter().map(ToString::to_string).collect::<Vec<_>>();
        let rows = q
            .query_map([], |r| {
                (0..names.len())
                    .map(|i| match r.get_ref(i)? {
                        rusqlite::types::ValueRef::Text(bytes)
                        | rusqlite::types::ValueRef::Blob(bytes) => {
                            Ok(String::from_utf8_lossy(bytes).into_owned())
                        }
                        _ => Ok(String::new()),
                    })
                    .collect::<rusqlite::Result<Vec<_>>>()
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for row in rows {
            // Independent identity invalidations are exempt, just like their source rows.
            if table == "runtime_outbox"
                && row.iter().any(|v| {
                    matches!(
                        v.as_str(),
                        "device_directory" | "device_identity" | "group_member_projection"
                    ) || v.contains("directory/identity/")
                })
            {
                continue;
            }
            for (name, value) in names.iter().zip(row) {
                for secret in &forbidden {
                    assert!(!value.contains(secret), "residual in {table}.{name}: {secret}");
                }
            }
        }
    }
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM message_footprint WHERE message_id='projection-id'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
    })?;
    Ok(())
}

#[test]
fn footprint_registration_rolls_back_and_late_copies_cannot_recreate_deleted_content()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-rollback-late")?;
    db.send_direct_message("thread", "message", "peer", b"secret")?;
    let result: Result<(), StorageError> = db.write_transaction(|| {
        db.persist_actor_state("routed/message-owner/message", &"private-source")?;
        Err(StorageError::AuthorizationRejected)
    });
    assert!(result.is_err());
    assert_eq!(db.connection.query_row("SELECT count(*) FROM message_footprint WHERE kind='actor' AND locator='routed/message-owner/message'",[],|r|r.get::<_,i64>(0))?,0);
    db.delete_direct_message("thread", "message", "local", "delete")?;
    db.persist_actor_state("routed/message-owner/message", &"private-source")?;
    db.persist_actor_state(
        "delivery-receipt/pending/late",
        &json!({"message":"message","sender":"private-source"}),
    )?;
    assert!(!db.actor_state_exists("routed/message-owner/message")?);
    assert!(!db.actor_state_exists("delivery-receipt/pending/late")?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn equal_wire_ids_do_not_share_routed_copy_ownership() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-wire-collision")?;
    for (message, payload) in [("first", "payload-one"), ("second", "payload-two")] {
        db.send_direct_message("thread", message, "peer", b"secret")?;
        db.persist_actor_state(&format!("routed/committed/{message}"),&json!({"routing":{"message_id":message},"entry":{"envelope":{"envelope_id":"shared-wire-id","payload_hash":payload}}}))?;
    }
    db.delete_direct_message("thread", "first", "local", "delete")?;
    assert!(!db.actor_state_exists("routed/committed/first")?);
    assert!(db.actor_state_exists("routed/committed/second")?);
    assert!(!db.message_is_deleted("second")?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn removing_retry_work_removes_its_provisional_footprints() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-retry-retirement")?;
    let entry = serde_json::to_vec(
        &json!({"envelope":{"envelope_id":"wire","payload_hash":"hash","encrypted_payload":"bytes"}}),
    )?;
    assert_ne!(db.defer_inbox_entry("retry", &entry, 1)?, 0);
    db.remove_inbox_retry("retry")?;
    assert_eq!(
        db.connection.query_row(
            "SELECT count(*) FROM message_footprint WHERE kind='retry' AND locator='retry'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
