// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! All-column privacy checks and transaction/late-write invariants for the footprint contract.
use super::*;
use crate::{AccountDbKey, AccountIndex, EventStore};
use serde_json::json;

const AUDIT_IDENTITY_TABLES: &[&str] = &[
    "device_directory",
    "device_identity",
    "local_event_counter",
    "friend_link_projection",
    "contact_request_projection",
    "contact_request_decision",
    "contact_link_decision",
    "contact_root_binding",
    "shared_group_member_projection",
    "group_member_projection",
    "group_member_device_key",
    "runtime_account_identity",
    "runtime_inbox_changes",
    "root_group_control_event_seen",
];
const AUDIT_IDENTITY_ACTOR_FILTER: &str = "state_kind GLOB 'directory/identity/*' OR state_kind GLOB 'directory/device/*' OR state_kind GLOB 'directory/contact/*' OR state_kind GLOB 'directory/commitment/*' OR state_kind GLOB 'directory/conversation/*' OR state_kind GLOB 'directory/group/*' OR state_kind GLOB 'directory/group-local/*' OR state_kind GLOB 'directory/group-name/*' OR state_kind GLOB 'identity/*' OR state_kind GLOB 'authority/*'";
const AUDIT_IDENTITY_EVENT_FILTER: &str = "event_type GLOB 'identity.*' OR event_type GLOB 'device.*' OR event_type GLOB 'prekey.*' OR event_type GLOB 'x3dh.prekey.*' OR event_type IN ('dm.ratchet_session','group.sender_key.state','group.member.route')";
// Static migration descriptions are schema metadata, never account or message copies.
const AUDIT_STRUCTURAL_TABLES: &[&str] = &["schema_migration"];

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
        // Only independent account authority, contact, and membership state is exempt.
        // The matching outbox invalidations are exempt by named source or identity actor key.
        if AUDIT_IDENTITY_TABLES.contains(&table.as_str())
            || AUDIT_STRUCTURAL_TABLES.contains(&table.as_str())
        {
            continue;
        }
        let filter = if matches!(
            table.as_str(),
            "runtime_actor_state" | "backup_archived_actor_state"
        ) {
            format!(" WHERE NOT ({AUDIT_IDENTITY_ACTOR_FILTER})")
        } else if table == "runtime_outbox" {
            let actor_key = AUDIT_IDENTITY_ACTOR_FILTER
                .replace("state_kind", "json_extract(keys_json,'$.state_kind')");
            format!(
                " WHERE table_name NOT IN ({})
                  AND NOT (table_name='runtime_actor_state' AND (({actor_key}) OR EXISTS(
                   SELECT 1 FROM runtime_actor_state a WHERE a.rowid=runtime_outbox.row_id
                    AND ({AUDIT_IDENTITY_ACTOR_FILTER}))))
                  AND NOT (table_name='local_event_log' AND EXISTS(
                   SELECT 1 FROM local_event_log e WHERE e.rowid=runtime_outbox.row_id
                    AND ({AUDIT_IDENTITY_EVENT_FILTER})))",
                AUDIT_IDENTITY_TABLES
                    .iter()
                    .map(|table| format!("'{table}'"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        } else if matches!(table.as_str(), "local_event_log" | "backup_archived_local_event") {
            format!(" WHERE NOT ({AUDIT_IDENTITY_EVENT_FILTER})")
        } else if table == "runtime_journal" {
            " WHERE topic NOT IN ('safety.changed','account.state')".to_owned()
        } else {
            String::new()
        };
        let quoted = table.replace('"', "\"\"");
        let mut q = raw.prepare(&format!("SELECT * FROM \"{quoted}\"{filter}"))?;
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
            let context = row.clone();
            for (name, value) in names.iter().zip(row) {
                for secret in &forbidden {
                    assert!(
                        !value.contains(secret),
                        "residual in {table}.{name}: {secret}; row={context:?}"
                    );
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
fn dropping_explicit_registration_is_detected_as_an_erasure_residual() -> Result<(), StorageError> {
    const MUTATION: &str = "RAMFLUX_TEST_DROP_MESSAGE_REGISTRATION";
    if std::env::var_os(MUTATION).is_none() {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "account_db::message_footprint::tests::dropping_explicit_registration_is_detected_as_an_erasure_residual",
                "--nocapture",
            ])
            .env(MUTATION, "1")
            .status()?;
        assert!(!status.success(), "the erasure audit accepted a missing registration");
        return Ok(());
    }
    let (root, db) = crate::tests::test_db("footprint-registration-mutation")?;
    db.send_direct_message("thread", "message", "peer", b"secret")?;
    db.persist_actor_state("routed/message-owner/message", &"private-source")?;
    db.delete_direct_message("thread", "message", "local", "delete")?;
    let audit = assert_erased(&db, &["private-source".to_owned()]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    audit?;
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

#[test]
fn deleting_a_pointer_target_preserves_unread_and_other_message_receipts()
-> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-conversation-pointers")?;
    let identity = ramflux_crypto::create_identity_root("reader", [0x73; 32]);
    let reader =
        ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&identity, "device")?;
    for message in ["m1", "m2", "m3"] {
        db.send_direct_message("tip", message, "peer", b"secret")?;
    }
    db.mark_read("tip", &reader, "m3")?;
    db.mark_delivered("tip", &reader, "m3", 30, 300)?;
    assert!(!db.conversation_projection("tip", Some(&reader))?.is_unread);

    db.delete_direct_message("tip", "m3", "local", "delete-m3")?;
    let projection = db.conversation_projection("tip", Some(&reader))?;
    assert_eq!(projection.read_through_message_id.as_deref(), Some("m2"));
    assert_eq!(projection.delivered_through_message_id.as_deref(), Some("m2"));
    assert!(!projection.is_unread);
    for message in ["m1", "m2"] {
        let receipts =
            db.direct_message_by_id(message)?.ok_or(StorageError::AuthorizationRejected)?.receipts;
        assert_eq!(receipts.len(), 1, "receipt for {message}");
        assert_eq!(receipts[0].state, "read");
    }

    for message in ["x1", "x2", "x3"] {
        db.send_direct_message("middle", message, "peer", b"secret")?;
    }
    db.mark_read("middle", &reader, "x3")?;
    db.mark_delivered("middle", &reader, "x3", 40, 300)?;
    db.delete_direct_message("middle", "x2", "local", "delete-x2")?;
    let projection = db.conversation_projection("middle", Some(&reader))?;
    assert_eq!(projection.read_through_message_id.as_deref(), Some("x3"));
    assert_eq!(projection.delivered_through_message_id.as_deref(), Some("x3"));
    assert!(!projection.is_unread);
    for message in ["x1", "x3"] {
        assert_eq!(
            db.direct_message_by_id(message)?
                .ok_or(StorageError::AuthorizationRejected)?
                .receipts
                .len(),
            1,
            "receipt for {message}"
        );
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
