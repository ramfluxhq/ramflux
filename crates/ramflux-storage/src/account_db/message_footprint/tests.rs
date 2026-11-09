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
    let (residuals, footprint_count) = db.connection.call(move |raw| {
    let mut q=raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let tables =
        q.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    drop(q);
    let mut residuals = Vec::new();
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
        let names = q.column_names().map(ToString::to_string).collect::<Vec<_>>();
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
                    if value.contains(secret) {
                        residuals.push(format!(
                            "residual in {table}.{name}: {secret}; row={context:?}"
                        ));
                    }
                }
            }
        }
    }
    let footprint_count = raw.query_row(
        "SELECT count(*) FROM message_footprint WHERE message_id='projection-id'",
        [],
        |r| r.get::<_, i64>(0)
    )?;
    Ok((residuals, footprint_count))
    })?;
    assert!(residuals.is_empty(), "{}", residuals.join("\n"));
    assert_eq!(footprint_count, 0);
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
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "account_db::message_footprint::tests::dropping_explicit_registration_is_detected_as_an_erasure_residual",
                "--nocapture",
            ])
            .env(MUTATION, "1")
            .output()?;
        assert!(!output.status.success(), "the erasure audit accepted a missing registration");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("residual in runtime_actor_state.state_json: private-source"),
            "the erasure audit failed for an unexpected reason: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
fn sent_copy_envelopes_do_not_claim_an_unrelated_message_owner() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-sent-copy-owner")?;
    for message in ["logical", "envelope"] {
        db.send_direct_message("thread", message, "sender", b"body")?;
    }
    db.persist_message_actor_state(
        "logical",
        "own-device/send/plain",
        &json!({"intent":{"id":"envelope","owner_record":["message","logical"]}}),
    )?;
    db.persist_actor_state(
        "own-device/send/surface",
        &json!({"intent":{"id":"envelope","owner_record":["surface","surface-id"]}}),
    )?;
    db.delete_direct_message("thread", "logical", "local", "delete-logical")?;
    assert!(!db.actor_state_exists("own-device/send/plain")?);
    assert!(db.actor_state_exists("own-device/send/surface")?);
    assert!(!db.message_is_deleted("envelope")?);
    db.delete_direct_message("thread", "envelope", "local", "delete-envelope")?;
    assert!(!db.actor_state_exists("own-device/send/surface")?);
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

#[test]
fn replay_quarantine_envelope_is_footprinted_and_erased() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-replay-quarantine")?;
    db.send_direct_message("thread", "message", "peer", b"secret")?;
    let old = "routed/committed/quarantined";
    let quarantined =
        format!("legacy/replay/committed/{}", ramflux_protocol::encode_base64url(old.as_bytes()));
    let envelope = json!({"routing":{"message_id":"message"},"entry":{"envelope":{
        "envelope_id":"wire-private-id","payload_hash":"payload-private-hash",
        "encrypted_payload":"quarantined-private-content"}}});
    db.persist_actor_state(old, &envelope)?;
    // The same two writes the SDK identity upgrade performs when it quarantines a receipt.
    db.persist_actor_state(&quarantined, &envelope)?;
    db.remove_actor_state(old)?;
    let owner = |db: &AccountDb, kind: &str, locator: &str| -> Result<Vec<String>, StorageError> {
        let mut query = db.connection.prepare(
            "SELECT message_id FROM message_footprint WHERE kind=?1 AND locator=?2 \
             ORDER BY message_id",
        )?;
        let rows = query.query_map(params![kind, locator], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    };
    assert_eq!(owner(&db, "actor", &quarantined)?, vec!["message".to_owned()]);
    assert_eq!(
        db.connection.query_row(
            "SELECT message_id FROM message_copy_binding WHERE copy_id='payload:payload-private-hash'",
            [],
            |row| row.get::<_, String>(0)
        )?,
        "message"
    );
    assert!(db.actor_state_exists(&quarantined)?);
    db.delete_direct_message("thread", "message", "local", "delete")?;
    assert!(!db.actor_state_exists(&quarantined)?);
    assert_erased(&db, &["quarantined-private-content".to_owned(), "wire-private-id".to_owned()])?;
    drop(db);
    let db = AccountDb::open(
        &AccountIndex::open(&root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    assert!(!db.actor_state_exists(&quarantined)?);
    assert_erased(&db, &["quarantined-private-content".to_owned(), "wire-private-id".to_owned()])?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) fn actor_owners(db: &AccountDb, locator: &str) -> Result<Vec<String>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT message_id FROM message_footprint WHERE kind='actor' AND locator=?1 \
         ORDER BY message_id",
    )?;
    let rows = query.query_map(params![locator], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub(super) fn full_envelope() -> serde_json::Value {
    json!({"source_principal_id":"principal-private","source_device_id":"device-private",
        "signing_key_id":"key-private","payload_hash":"payload-private-hash",
        "created_at":1,"ttl":2,"encrypted_payload":"unlisted-private-content"})
}

#[test]
fn admits_predicate_controls_are_isolated() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-admits-controls")?;
    db.send_direct_message("thread", "message", "peer", b"secret")?;
    // Listed prefix without any envelope is registered.
    db.persist_actor_state("routed/message-owner/message", &"private-source")?;
    assert_eq!(actor_owners(&db, "routed/message-owner/message")?, vec!["message".to_owned()]);
    // Unlisted prefix with a complete envelope at a fixed path is registered and owned by M.
    db.persist_actor_state(
        "zz-new/x",
        &json!({"routing":{"message_id":"message"},"entry":{"envelope":full_envelope()}}),
    )?;
    assert_eq!(
        actor_owners(&db, "zz-new/x")?,
        vec!["copy:payload:payload-private-hash".to_owned(), "message".to_owned()]
    );
    // Unlisted prefix with an incomplete or off-path envelope is not registered.
    let mut incomplete = full_envelope();
    incomplete.as_object_mut().map(|fields| fields.remove("ttl"));
    db.persist_actor_state(
        "zz-new/incomplete",
        &json!({"routing":{"message_id":"message"},"entry":{"envelope":incomplete}}),
    )?;
    db.persist_actor_state(
        "zz-new/planted",
        &json!({"routing":{"message_id":"message"},"ext":{"envelope":full_envelope()}}),
    )?;
    assert_eq!(actor_owners(&db, "zz-new/incomplete")?, Vec::<String>::new());
    assert_eq!(actor_owners(&db, "zz-new/planted")?, Vec::<String>::new());
    db.delete_direct_message("thread", "message", "local", "delete")?;
    assert!(!db.actor_state_exists("zz-new/x")?);
    assert!(!db.actor_state_exists("routed/message-owner/message")?);
    assert!(db.actor_state_exists("zz-new/incomplete")?);
    assert!(db.actor_state_exists("zz-new/planted")?);
    drop(db);
    let db = AccountDb::open(
        &AccountIndex::open(&root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    assert!(!db.actor_state_exists("zz-new/x")?);
    assert!(db.actor_state_exists("zz-new/incomplete")?);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) fn audit(db: &AccountDb) -> Result<Vec<String>, StorageError> {
    Ok(db.connection.call(|raw| audit::unregistered_envelope_copies(raw, 16))?)
}

pub(super) fn envelope_value(message: &str) -> serde_json::Value {
    json!({"routing":{"message_id":message},"entry":{"envelope":full_envelope()}})
}

#[test]
fn envelope_writers_are_registered() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-envelope-writers")?;
    db.send_direct_message("thread", "message", "peer", b"secret")?;
    // (a)(b)(c) An unlisted prefix is owned by M, erased by deletion and absent after reopen.
    db.persist_actor_state("zz-new/x", &envelope_value("message"))?;
    assert_eq!(
        actor_owners(&db, "zz-new/x")?,
        vec!["copy:payload:payload-private-hash".to_owned(), "message".to_owned()]
    );
    // (d) Every runtime chokepoint leaves the audit empty.
    db.persist_actor_state("routed/committed/listed", &envelope_value("message"))?;
    db.persist_actor_state_batch(&[("zz-new/batch".to_owned(), envelope_value("message"))])?;
    db.persist_message_actor_state("message", "zz-new/message", &envelope_value("message"))?;
    let quarantined = format!(
        "legacy/replay/committed/{}",
        ramflux_protocol::encode_base64url(b"routed/committed/old")
    );
    db.persist_actor_state(&quarantined, &envelope_value("message"))?;
    db.append_event("event-envelope", "text", &serde_json::to_vec(&full_envelope())?)?;
    assert_eq!(audit(&db)?, Vec::<String>::new());
    // (e) Archive tables: only the unconditional local-event trigger is in scope here.
    db.connection.execute_batch(
        "CREATE TABLE backup_archived_local_event AS SELECT '' AS source,* FROM local_event_log WHERE 0;",
    )?;
    db.connection.call(|raw| super::install(raw))?;
    db.connection.execute_batch(
        "INSERT INTO backup_archived_local_event SELECT 'archive',* FROM local_event_log;",
    )?;
    assert_eq!(audit(&db)?, Vec::<String>::new());
    db.delete_direct_message("thread", "message", "local", "delete")?;
    for key in ["zz-new/x", "zz-new/batch", "zz-new/message", "routed/committed/listed"] {
        assert!(!db.actor_state_exists(key)?, "{key} survived deletion");
    }
    assert!(!db.actor_state_exists(&quarantined)?);
    drop(db);
    let db = AccountDb::open(
        &AccountIndex::open(&root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )?;
    assert!(!db.actor_state_exists("zz-new/x")?);
    assert_eq!(audit(&db)?, Vec::<String>::new());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn envelope_audit_reports_an_unregistered_copy() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-envelope-audit")?;
    db.connection.execute(
        "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES('zz-new/raw',?1)",
        params![serde_json::to_vec(&envelope_value("message"))?],
    )?;
    assert_eq!(audit(&db)?, vec!["runtime_actor_state:zz-new/raw".to_owned()]);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn envelope_merge_import_leaves_no_unregistered_copy() -> Result<(), StorageError> {
    let root = crate::tests::temp_root("footprint-envelope-merge");
    let source_index = AccountIndex::open(root.join("source"))?;
    let local_index = AccountIndex::open(root.join("local"))?;
    source_index.create_account("account", "root")?;
    local_index.create_account("account", "root")?;
    let source = AccountDb::open(&source_index, "account", &AccountDbKey::generate()?)?;
    let local = AccountDb::open(&local_index, "account", &AccountDbKey::generate()?)?;
    source.send_direct_message("thread", "message", "peer", b"secret")?;
    source.persist_actor_state("zz-new/merged", &envelope_value("message"))?;
    source.append_event("event-merged", "text", &serde_json::to_vec(&full_envelope())?)?;
    let incoming = root.join("incoming.db");
    let snapshot = source.write_backup_snapshot(&incoming)?;
    let path = root.join("merged.db");
    let target = local.write_backup_snapshot(&path)?;
    let mut merged = crate::BackupDatabase::open(&path, &target.key)?;
    merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
    // (f) Incoming rows were footprinted at the source; the merge must keep them registered.
    let imported: i64 = merged.db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind='zz-new/merged'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(imported, 1);
    assert_eq!(audit::unregistered_envelope_copies(&merged.db, 16)?, Vec::<String>::new());
    drop(merged);
    drop(source);
    drop(local);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn envelope_history_import_leaves_no_unregistered_copy() -> Result<(), StorageError> {
    let (source_root, source, _device) = crate::tests::signed_test_db("footprint-history-source")?;
    source.append_event("history-envelope", "text", &serde_json::to_vec(&full_envelope())?)?;
    let bundle = source.export_history_bundle("device", "target-device")?;
    assert_eq!(bundle.encrypted_event_batch.len(), 1);
    let (target_root, target) = crate::tests::test_db("footprint-history-target")?;
    target.import_history_bundle(&bundle)?;
    assert!(target.event_body("history-envelope")?.is_some());
    assert_eq!(audit(&target)?, Vec::<String>::new());
    drop(target);
    drop(source);
    std::fs::remove_dir_all(target_root)?;
    std::fs::remove_dir_all(source_root)?;
    Ok(())
}

#[test]
fn envelope_audit_honours_its_limit() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-envelope-audit-limit")?;
    let found = |db: &AccountDb, limit: usize| -> Result<Vec<String>, StorageError> {
        Ok(db.connection.call(move |raw| audit::unregistered_envelope_copies(raw, limit))?)
    };
    assert_eq!(found(&db, 1)?, Vec::<String>::new());
    for name in ["a", "b", "c"] {
        db.connection.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![format!("zz-new/{name}"), serde_json::to_vec(&envelope_value("message"))?],
        )?;
    }
    assert_eq!(found(&db, 0)?, Vec::<String>::new());
    assert_eq!(found(&db, 1)?.len(), 1);
    assert_eq!(found(&db, 2)?.len(), 2);
    assert_eq!(found(&db, 16)?.len(), 3);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn archive_filter(table: &str) -> &'static str {
    if table == "backup_archived_actor_state" {
        "state_kind='zz-new/archived'"
    } else {
        "event_id='event-archived'"
    }
}

#[test]
fn envelope_merge_relocates_incoming_archive_rows_and_erases_them() -> Result<(), StorageError> {
    let root = crate::tests::temp_root("footprint-envelope-archive-merge");
    let mut dbs = Vec::new();
    for name in ["origin", "middle", "final"] {
        let index = AccountIndex::open(root.join(name))?;
        index.create_account("account", "root")?;
        dbs.push(AccountDb::open(&index, "account", &AccountDbKey::generate()?)?);
    }
    let [origin, middle, last] = &dbs[..] else { unreachable!() };
    for db in [origin, middle, last] {
        db.send_direct_message("thread", "message", "peer", b"secret")?;
    }
    // The committed receipt binds payload -> M, so the event copy is owned by M directly.
    origin.persist_actor_state("routed/committed/bound", &envelope_value("message"))?;
    origin.persist_actor_state("zz-new/archived", &envelope_value("message"))?;
    origin.append_event("event-archived", "text", &serde_json::to_vec(&full_envelope())?)?;
    // Stage 1 puts the origin rows into the middle generation's archive tables.
    let first = root.join("origin.db");
    let origin_snapshot = origin.write_backup_snapshot(&first)?;
    let middle_path = root.join("middle.db");
    let middle_snapshot = middle.write_backup_snapshot(&middle_path)?;
    let mut generation = crate::BackupDatabase::open(&middle_path, &middle_snapshot.key)?;
    generation.merge_backup(&first, &origin_snapshot.key, || Ok(()))?;
    // Keep only the archived copies so the next merge relocates archive-to-archive rows.
    generation.db.execute_batch(
        "DELETE FROM runtime_actor_state WHERE state_kind='zz-new/archived';
         DELETE FROM local_event_log WHERE event_id='event-archived';",
    )?;
    let archived = |db: &rusqlite::Connection, table: &str| -> rusqlite::Result<i64> {
        db.query_row(
            &format!("SELECT count(*) FROM {table} WHERE {}", archive_filter(table)),
            [],
            |row| row.get(0),
        )
    };
    assert_eq!(archived(&generation.db, "backup_archived_actor_state")?, 1);
    assert_eq!(archived(&generation.db, "backup_archived_local_event")?, 1);
    drop(generation);
    // Stage 2: the final account imports a snapshot whose archive tables hold footprinted rows.
    let final_path = root.join("final.db");
    let final_snapshot = last.write_backup_snapshot(&final_path)?;
    let mut merged = crate::BackupDatabase::open(&final_path, &final_snapshot.key)?;
    merged.merge_backup(&middle_path, &middle_snapshot.key, || Ok(()))?;
    let owners = |db: &rusqlite::Connection,
                  kind: &str,
                  table: &str,
                  owner: &str|
     -> rusqlite::Result<i64> {
        db.query_row(
            &format!(
                "SELECT count(*) FROM {table} a JOIN message_footprint f \
                 ON f.kind=?1 AND f.locator=CAST(a.rowid AS TEXT) AND f.message_id=?2 \
                 WHERE a.source LIKE '%/%' AND {} AND CAST(a.{} AS TEXT) LIKE '%private%'",
                archive_filter(table)
                    .replace("state_kind", "a.state_kind")
                    .replace("event_id", "a.event_id"),
                if kind == "archived_actor" { "state_json" } else { "event_body" }
            ),
            params![kind, owner],
            |row| row.get(0),
        )
    };
    let check_present = |db: &rusqlite::Connection| -> rusqlite::Result<()> {
        assert_eq!(archived(db, "backup_archived_actor_state")?, 1);
        assert_eq!(archived(db, "backup_archived_local_event")?, 1);
        assert_eq!(owners(db, "archived_actor", "backup_archived_actor_state", "message")?, 1);
        assert_eq!(owners(db, "archived_event", "backup_archived_local_event", "message")?, 1);
        Ok(())
    };
    check_present(&merged.db)?;
    assert_eq!(audit::unregistered_envelope_copies(&merged.db, 16)?, Vec::<String>::new());
    merged
        .db
        .execute("UPDATE direct_message_projection SET deleted=1 WHERE message_id='message'", [])?;
    for table in ["backup_archived_actor_state", "backup_archived_local_event"] {
        assert_eq!(archived(&merged.db, table)?, 0, "{table} survived deletion");
    }
    drop(merged);
    let reopened = crate::BackupDatabase::open(&final_path, &final_snapshot.key)?;
    for table in ["backup_archived_actor_state", "backup_archived_local_event"] {
        assert_eq!(archived(&reopened.db, table)?, 0, "{table} returned after reopen");
    }
    drop(reopened);
    drop(dbs);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

const ARCHIVE_TRIGGERS: [&str; 2] = [
    "footprint_backup_archived_actor_state_INSERT",
    "footprint_backup_archived_actor_state_UPDATE",
];

fn trigger_sql(db: &AccountDb, name: &str) -> Result<String, StorageError> {
    Ok(db.connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
        params![name],
        |row| row.get(0),
    )?)
}

pub(super) fn archived_owners(
    db: &AccountDb,
    state_kind: &str,
) -> Result<Vec<String>, StorageError> {
    let mut query = db.connection.prepare(
        "SELECT f.message_id FROM backup_archived_actor_state a JOIN message_footprint f \
         ON f.kind='archived_actor' AND f.locator=CAST(a.rowid AS TEXT) \
         WHERE a.state_kind=?1 ORDER BY f.message_id",
    )?;
    let rows = query.query_map(params![state_kind], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub(super) fn archive_row_count(db: &AccountDb, state_kind: &str) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT count(*) FROM backup_archived_actor_state WHERE state_kind=?1",
        params![state_kind],
        |row| row.get(0),
    )?)
}

pub(super) fn insert_archived(
    db: &AccountDb,
    state_kind: &str,
    message: &str,
) -> Result<(), StorageError> {
    db.connection.execute(
        "INSERT INTO backup_archived_actor_state(source,state_kind,state_json) VALUES('s',?1,?2)",
        params![state_kind, serde_json::to_vec(&envelope_value(message))?],
    )?;
    Ok(())
}

/// Builds a database whose archive triggers carry the pre-fix guard (listed prefixes only).
pub(super) fn old_archive_trigger_fixture(
    name: &str,
) -> Result<(std::path::PathBuf, AccountDb), StorageError> {
    let (root, db) = crate::tests::test_db(name)?;
    db.connection.execute_batch(
        "CREATE TABLE backup_archived_actor_state(source TEXT,state_kind TEXT,state_json BLOB,PRIMARY KEY(source,state_kind));",
    )?;
    db.connection.call(|raw| super::install(raw))?;
    let old_prefix =
        schema::ACTOR_PREFIX_GUARD.replace(" OR NEW.state_kind GLOB 'legacy/replay/*'", "");
    for trigger in ARCHIVE_TRIGGERS {
        let current = trigger_sql(&db, trigger)?;
        let old = current.replace(&schema::actor_guard(), &old_prefix);
        assert_ne!(old, current, "the fixture must differ from the renewed definition");
        db.connection.execute_batch(&format!("DROP TRIGGER {trigger}; {old};"))?;
        assert!(!trigger_sql(&db, trigger)?.contains("signing_key_id"));
    }
    Ok((root, db))
}

pub(super) fn reopen(root: &std::path::Path, db: AccountDb) -> Result<AccountDb, StorageError> {
    drop(db);
    AccountDb::open(
        &AccountIndex::open(root)?,
        "acct",
        &AccountDbKey::derive("acct", b"storage-test-secret"),
    )
}

#[test]
fn archive_footprint_triggers_renewed_on_open() -> Result<(), StorageError> {
    let (root, db) = old_archive_trigger_fixture("footprint-archive-renewal")?;
    db.send_direct_message("thread", "live", "peer", b"secret")?;
    // Under the old triggers an unlisted prefix and a quarantined row are not registered.
    insert_archived(&db, "zz-new/old", "live")?;
    insert_archived(&db, "legacy/replay/committed/old", "live")?;
    assert_eq!(archived_owners(&db, "zz-new/old")?, Vec::<String>::new());
    let db = reopen(&root, db)?;
    // (a) The new definitions replace the old ones.
    for trigger in ARCHIVE_TRIGGERS {
        let sql = trigger_sql(&db, trigger)?;
        assert!(sql.contains("legacy/replay/") && sql.contains("signing_key_id"), "{trigger}");
    }
    // (c) A new INSERT registers; an UPDATE registers a row the old trigger missed.
    insert_archived(&db, "zz-new/inserted", "live")?;
    insert_archived(&db, "legacy/replay/committed/inserted", "live")?;
    assert_eq!(
        archived_owners(&db, "zz-new/inserted")?,
        vec!["copy:payload:payload-private-hash".to_owned(), "live".to_owned()]
    );
    assert_eq!(archived_owners(&db, "legacy/replay/committed/inserted")?.len(), 2);
    db.connection.execute(
        "UPDATE backup_archived_actor_state SET state_json=state_json WHERE state_kind='zz-new/old'",
        [],
    )?;
    assert_eq!(archived_owners(&db, "zz-new/old")?.len(), 2);
    // (d) Deleting the live owner erases the registered archived copies, also after reopen.
    db.delete_direct_message("thread", "live", "local", "delete")?;
    for kind in ["zz-new/inserted", "legacy/replay/committed/inserted", "zz-new/old"] {
        assert_eq!(archive_row_count(&db, kind)?, 0, "{kind} survived deletion");
    }
    let db = reopen(&root, db)?;
    assert_eq!(archive_row_count(&db, "zz-new/inserted")?, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn archive_footprint_triggers_renewed_on_open_registers_existing_rows() -> Result<(), StorageError>
{
    let (root, db) = old_archive_trigger_fixture("footprint-archive-existing")?;
    db.send_direct_message("thread", "live", "peer", b"secret")?;
    insert_archived(&db, "zz-new/existing", "live")?;
    insert_archived(&db, "legacy/replay/committed/existing", "live")?;
    // A pre-fix database has never run the completing migration.
    db.connection.execute(
        "DELETE FROM message_footprint_migration WHERE name LIKE 'footprint_replay_migration:v1%'",
        [],
    )?;
    let db = reopen(&root, db)?;
    // (b) The completing migration registers existing rows (P03a-0d).
    assert_eq!(archived_owners(&db, "zz-new/existing")?.len(), 2);
    db.delete_direct_message("thread", "live", "local", "delete")?;
    assert_eq!(archive_row_count(&db, "zz-new/existing")?, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn lazily_created_archive_registers_retired_outbound_copies() -> Result<(), StorageError> {
    let (root, db) = crate::tests::test_db("footprint-lazy-retirement")?;
    db.send_direct_message("thread", "message", "peer", b"secret")?;
    let sent = json!({"intent":{"id":"message"},"entry":{"envelope":full_envelope()}});
    db.persist_actor_state("own-device/send/x", &sent)?;
    let absent: bool = db.connection.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_master WHERE name='backup_archived_actor_state')",
        [],
        |row| row.get(0),
    )?;
    assert!(absent);
    db.retire_outbound_for_recovery("head")?;
    assert!(!db.actor_state_exists("own-device/send/x")?);
    assert!(archived_owners(&db, "own-device/send/x")?.contains(&"message".to_owned()));
    assert_eq!(audit(&db)?, Vec::<String>::new());
    db.delete_direct_message("thread", "message", "local", "delete")?;
    assert_eq!(archive_row_count(&db, "own-device/send/x")?, 0);
    let db = reopen(&root, db)?;
    assert_eq!(archive_row_count(&db, "own-device/send/x")?, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn lazily_created_archive_registers_merge_local_copies() -> Result<(), StorageError> {
    let root = crate::tests::temp_root("footprint-lazy-merge");
    let source_index = AccountIndex::open(root.join("source"))?;
    let local_index = AccountIndex::open(root.join("local"))?;
    source_index.create_account("account", "root")?;
    local_index.create_account("account", "root")?;
    let source = AccountDb::open(&source_index, "account", &AccountDbKey::generate()?)?;
    let local = AccountDb::open(&local_index, "account", &AccountDbKey::generate()?)?;
    local.send_direct_message("thread", "message", "peer", b"secret")?;
    local.persist_actor_state("group-transfer/local", &envelope_value("message"))?;
    let incoming = root.join("incoming.db");
    let snapshot = source.write_backup_snapshot(&incoming)?;
    let path = root.join("merged.db");
    let target = local.write_backup_snapshot(&path)?;
    let mut merged = crate::BackupDatabase::open(&path, &target.key)?;
    assert!(!super::schema::exists(&merged.db, "backup_archived_actor_state")?);
    merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
    let owned = |db: &rusqlite::Connection| -> rusqlite::Result<i64> {
        db.query_row(
            "SELECT count(*) FROM backup_archived_actor_state a JOIN message_footprint f \
             ON f.kind='archived_actor' AND f.locator=CAST(a.rowid AS TEXT) \
             AND f.message_id='message' WHERE a.state_kind='group-transfer/local'",
            [],
            |row| row.get(0),
        )
    };
    assert_eq!(owned(&merged.db)?, 1);
    assert_eq!(audit::unregistered_envelope_copies(&merged.db, 16)?, Vec::<String>::new());
    merged
        .db
        .execute("UPDATE direct_message_projection SET deleted=1 WHERE message_id='message'", [])?;
    let remaining = |db: &rusqlite::Connection| -> rusqlite::Result<i64> {
        db.query_row(
            "SELECT count(*) FROM backup_archived_actor_state WHERE state_kind='group-transfer/local'",
            [],
            |row| row.get(0),
        )
    };
    assert_eq!(remaining(&merged.db)?, 0);
    drop(merged);
    let reopened = crate::BackupDatabase::open(&path, &target.key)?;
    assert_eq!(remaining(&reopened.db)?, 0);
    drop(reopened);
    drop(source);
    drop(local);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn envelope_sql_predicate_matches_the_rust_predicate() -> Result<(), StorageError> {
    use serde_json::Value;
    let fields = [
        "source_principal_id",
        "source_device_id",
        "signing_key_id",
        "payload_hash",
        "created_at",
        "ttl",
    ];
    let wrap = |path: &str, envelope: Value| -> Value {
        match path {
            "root" => envelope,
            "envelope" => json!({ "envelope": envelope }),
            "entry" => json!({"entry":{"envelope":envelope}}),
            "ext" => json!({"ext":{"envelope":envelope}}),
            "entry_direct" => json!({"entry": envelope}),
            "nested" => json!({"entry":{"envelope":{"envelope":envelope}}}),
            _ => unreachable!(),
        }
    };
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    for path in ["root", "envelope", "entry", "ext", "entry_direct", "nested"] {
        cases.push((format!("{path} full"), serde_json::to_vec(&wrap(path, full_envelope()))?));
        for field in fields {
            let mut missing = full_envelope();
            missing.as_object_mut().map(|fields| fields.remove(field));
            cases.push((
                format!("{path} missing {field}"),
                serde_json::to_vec(&wrap(path, missing))?,
            ));
            for wrong in
                [json!(null), json!(true), json!([1]), json!({"a":1}), json!(1), json!("s")]
            {
                let mut changed = full_envelope();
                changed[field] = wrong.clone();
                cases.push((
                    format!("{path} {field}={wrong}"),
                    serde_json::to_vec(&wrap(path, changed))?,
                ));
            }
        }
    }
    let mut float = full_envelope();
    float["created_at"] = json!(1.5);
    cases.push(("float created_at".into(), serde_json::to_vec(&float)?));
    for raw in ["{", "", "not json", "[]", "null", "\"text\"", "7"] {
        cases.push((format!("raw {raw:?}"), raw.as_bytes().to_vec()));
    }
    // Two fixed paths present at once, one of them incomplete, is still complete.
    cases.push((
        "complete beside incomplete".into(),
        serde_json::to_vec(&json!({"envelope":{"ttl":1},"entry":{"envelope":full_envelope()}}))?,
    ));
    let (root, db) = crate::tests::test_db("footprint-envelope-parity")?;
    db.connection.execute_batch("CREATE TEMP TABLE parity(state_json BLOB);")?;
    let sql = format!(
        "SELECT {} FROM parity",
        super::schema::envelope_sql("state_json").replace("NEW.", "parity.")
    );
    let (mut agree, mut accepted) = (0, 0);
    for (name, body) in &cases {
        db.connection.execute("DELETE FROM parity", [])?;
        db.connection.execute("INSERT INTO parity VALUES(?1)", params![body])?;
        // A trigger WHEN clause treats NULL as false, so NULL counts as rejection here.
        let sql_says = db
            .connection
            .query_row(&sql, [], |row| row.get::<_, Option<i64>>(0))?
            .is_some_and(|v| v != 0);
        let rust_says =
            serde_json::from_slice::<Value>(body).is_ok_and(|v| super::value_holds_envelope(&v));
        assert_eq!(sql_says, rust_says, "SQL and Rust predicates disagree for {name}");
        agree += 1;
        accepted += i32::from(rust_says);
    }
    assert!(agree > 100);
    // Accepted: three fixed paths x (full + six same-type replacements) = 21, the float
    // created_at and the complete-beside-incomplete case; every other control is rejected.
    assert_eq!(accepted, 23);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
