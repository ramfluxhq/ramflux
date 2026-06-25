#![cfg(test)]
#![allow(clippy::wildcard_imports)]
use super::*;
use serde::{Deserialize, Serialize};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root(test_name: &str) -> PathBuf {
    let nanos =
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("ramflux-storage-{test_name}-{}-{nanos}", std::process::id()))
}

fn test_db(test_name: &str) -> Result<(PathBuf, AccountDb), StorageError> {
    let root = temp_root(test_name);
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let db = AccountDb::open(&index, "acct", &key)?;
    Ok((root, db))
}

fn signed_test_db(
    test_name: &str,
) -> Result<(PathBuf, AccountDb, ramflux_crypto::DeviceBranch), StorageError> {
    let root = temp_root(test_name);
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let device = ramflux_crypto::create_device_branch("principal", "device", 1, [0x42; 32]);
    let db = AccountDb::open(&index, "acct", &key)?.with_device_signer(device.clone());
    Ok((root, db, device))
}

#[cfg(not(feature = "sqlcipher"))]
#[test]
fn account_db_open_fails_closed_without_sqlcipher() -> Result<(), StorageError> {
    let root = temp_root("no-sqlcipher-fail-closed");
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let rejected = AccountDb::open(&index, "acct", &key);
    assert!(matches!(
        rejected,
        Err(StorageError::EncryptionUnavailable { mode: EncryptionMode::InsecureTestSqlite })
    ));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

const ACCOUNT_INDEX_TABLES: &[&str] =
    &["account_index_migration", "local_account", "active_account_state", "app_setting"];

const RAMFLUX_LOCAL_TABLES: &[&str] = &[
    "schema_migration",
    "account_key_check",
    "device_identity",
    "lineage_checkpoint",
    "home_node_binding",
    "session_capability_cache",
    "raw_envelope_log",
    "local_event_log",
    "event_causal_dependency",
    "event_tombstone",
    "projection_checkpoint",
    "conversation_projection",
    "message_projection",
    "friend_projection",
    "group_projection",
    "group_member_projection",
    "receipt_projection",
    "conversation_tombstone",
    "device_inbox_cursor",
    "outbox_queue",
    "ack_state",
    "nack_state",
    "sync_checkpoint",
    "object_index",
    "object_manifest",
    "object_key_slot",
    "object_chunk",
    "object_transfer_state",
    "object_tombstone",
    "self_device_control_log",
    "a2ui_surface_cache",
    "mcp_server_registry",
    "mcp_tool_manifest",
    "mcp_grant",
    "mcp_standing_approval",
    "bot_manifest_cache",
    "bot_install_grant",
    "audit_log",
];

fn table_exists(connection: &rusqlite::Connection, table_name: &str) -> Result<bool, StorageError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        rusqlite::params![table_name],
        |row| row.get(0),
    )?;
    Ok(count == 1)
}

fn migration_versions(db: &AccountDb) -> Result<Vec<i64>, StorageError> {
    let mut statement = db
        .connection
        .prepare("SELECT schema_version FROM schema_migration ORDER BY schema_version")?;
    let rows = statement.query_map([], |row| row.get::<_, i64>(0))?;
    let mut versions = Vec::new();
    for row in rows {
        versions.push(row?);
    }
    Ok(versions)
}

fn event_signature_status(
    db: &AccountDb,
    event_id: &str,
) -> Result<(Vec<u8>, String, i64), StorageError> {
    Ok(db.connection.query_row(
        "SELECT signature, signature_status, created_at FROM local_event_log WHERE event_id = ?1",
        rusqlite::params![event_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

fn message_created_at(
    db: &AccountDb,
    conversation_id: &str,
    message_id: &str,
) -> Result<i64, StorageError> {
    Ok(db.connection.query_row(
        "SELECT created_at FROM direct_message_projection
          WHERE conversation_id = ?1 AND message_id = ?2",
        rusqlite::params![conversation_id, message_id],
        |row| row.get(0),
    )?)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestMcpGrant {
    grant_id: String,
    server_id: String,
    tool_name: String,
    tool_scope: Option<String>,
    revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestMcpAudit {
    event_type: String,
    grant_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestMcpTool {
    server_id: String,
    tool_name: String,
    capability: String,
    risk_level: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TestEncryptedObject {
    object_id: String,
    manifest_hash: String,
    nonce: String,
    ciphertext: Vec<u8>,
    plaintext_hash: String,
    tombstoned: bool,
    backup_excluded: bool,
}

#[test]
fn client_local_db_design_tables_are_present() -> Result<(), StorageError> {
    let root = temp_root("table-presence");
    let index = AccountIndex::open(&root)?;
    for table in ACCOUNT_INDEX_TABLES {
        assert!(table_exists(index.connection(), table)?, "missing account_index table {table}");
    }
    index.create_account("acct", "principal")?;
    let key = AccountDbKey::derive("acct", b"storage-table-presence");
    let db = AccountDb::open(&index, "acct", &key)?;
    for table in RAMFLUX_LOCAL_TABLES {
        assert!(table_exists(&db.connection, table)?, "missing ramflux_local table {table}");
    }
    assert_eq!(ACCOUNT_INDEX_TABLES.len(), 4);
    assert_eq!(RAMFLUX_LOCAL_TABLES.len(), 38);
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn mcp_grant_audit_and_tools_roundtrip() -> Result<(), StorageError> {
    let (_root, db) = test_db("mcp-persistence")?;
    let grant = TestMcpGrant {
        grant_id: "grant_mcp_1".to_owned(),
        server_id: "srv".to_owned(),
        tool_name: "notes".to_owned(),
        tool_scope: Some("conversation:1".to_owned()),
        revoked: false,
    };
    db.upsert_mcp_grant(&McpGrantWrite {
        grant_id: &grant.grant_id,
        target_ai_device_id: "ai_device",
        source_app_device_id: "app_device",
        capability: "read_conversation",
        risk_level: "low",
        registry_hash: "registry_hash",
        tool_manifest_set_hash: "manifest_hash",
        expires_at: 4_000_000_000,
        signature: "sig",
        created_at: 1_900_000_000,
        revoked: false,
        grant: &grant,
    })?;
    let loaded = db.load_mcp_grants::<TestMcpGrant>()?;
    assert_eq!(loaded.get("grant_mcp_1"), Some(&grant));

    db.set_mcp_grant_revoked("grant_mcp_1")?;
    let revoked = db.load_mcp_grants::<TestMcpGrant>()?;
    assert!(revoked["grant_mcp_1"].revoked);

    let audit_a = TestMcpAudit { event_type: "mcp.approval.request".to_owned(), grant_id: None };
    let audit_b = TestMcpAudit {
        event_type: "mcp.approval.granted".to_owned(),
        grant_id: Some("grant_mcp_1".to_owned()),
    };
    db.append_mcp_audit(&McpAuditWrite {
        audit: &audit_a,
        audit_type: &audit_a.event_type,
        actor_device_id: "device",
        subject_hash: None,
        redacted_summary: "request",
        created_at: 1_900_000_001,
    })?;
    db.append_mcp_audit(&McpAuditWrite {
        audit: &audit_b,
        audit_type: &audit_b.event_type,
        actor_device_id: "device",
        subject_hash: None,
        redacted_summary: "granted",
        created_at: 1_900_000_002,
    })?;
    assert_eq!(db.load_mcp_audit::<TestMcpAudit>()?, vec![audit_a, audit_b]);

    let tool = TestMcpTool {
        server_id: "srv".to_owned(),
        tool_name: "notes".to_owned(),
        capability: "read_conversation".to_owned(),
        risk_level: "low".to_owned(),
    };
    db.upsert_mcp_tool(&McpToolWrite {
        tool_manifest_hash: "tool_hash_1",
        server_id: &tool.server_id,
        tool_name: &tool.tool_name,
        required_capability: &tool.capability,
        risk_level: &tool.risk_level,
        manifest: &tool,
        updated_at: 1_900_000_003,
    })?;
    assert_eq!(db.load_mcp_tools::<TestMcpTool>()?, vec![tool.clone()]);
    db.remove_mcp_tool(&tool.server_id, &tool.tool_name)?;
    assert!(db.load_mcp_tools::<TestMcpTool>()?.is_empty());

    let standing = TestMcpGrant {
        grant_id: "standing_mcp_1".to_owned(),
        server_id: "srv".to_owned(),
        tool_name: "notes".to_owned(),
        tool_scope: Some("conversation:1".to_owned()),
        revoked: false,
    };
    db.upsert_mcp_standing_approval(&McpStandingApprovalWrite {
        standing_approval_id: &standing.grant_id,
        server_id: &standing.server_id,
        tool_name: &standing.tool_name,
        capability: "read_conversation",
        risk_level: "low",
        registry_hash: "registry_hash",
        tool_manifest_set_hash: "manifest_hash",
        expires_at: 4_000_000_000,
        created_at: 1_900_000_004,
        created_by_device_id: "app_device",
        revoked: false,
        approval: &standing,
    })?;
    let loaded_standing = db.load_mcp_standing_approvals::<TestMcpGrant>()?;
    assert_eq!(loaded_standing.get("standing_mcp_1"), Some(&standing));
    db.set_mcp_standing_approval_revoked("standing_mcp_1")?;
    let revoked_standing = db.load_mcp_standing_approvals::<TestMcpGrant>()?;
    assert!(revoked_standing["standing_mcp_1"].revoked);
    Ok(())
}

#[test]
fn object_store_objects_keys_and_tombstones_roundtrip() -> Result<(), StorageError> {
    let (_root, db) = test_db("object-store-persistence")?;
    let object = TestEncryptedObject {
        object_id: "object_persist_1".to_owned(),
        manifest_hash: "manifest_hash_1".to_owned(),
        nonce: "nonce_1".to_owned(),
        ciphertext: b"ciphertext".to_vec(),
        plaintext_hash: "plaintext_hash_1".to_owned(),
        tombstoned: false,
        backup_excluded: false,
    };
    let content_key = [0x5a; 32];

    db.upsert_object(&ObjectWrite {
        object_id: &object.object_id,
        manifest_hash: &object.manifest_hash,
        nonce: &object.nonce,
        ciphertext: &object.ciphertext,
        plaintext_hash: &object.plaintext_hash,
        tombstoned: object.tombstoned,
        backup_excluded: object.backup_excluded,
        content_key: Some(&content_key),
        object: &object,
        updated_at: 1_900_000_004,
    })?;
    let (objects, keys) = db.load_objects::<TestEncryptedObject>()?;
    assert_eq!(objects, vec![object.clone()]);
    assert_eq!(keys.get("object_persist_1"), Some(&content_key));

    db.set_object_tombstoned("object_persist_1")?;
    let (objects, keys) = db.load_objects::<TestEncryptedObject>()?;
    assert!(objects[0].tombstoned);
    assert_eq!(keys.get("object_persist_1"), Some(&content_key));
    Ok(())
}

#[test]
fn account_db_clock_controls_default_storage_timestamps() -> Result<(), StorageError> {
    let (root, mut db) = test_db("clock-controls-created-at")?;
    db.set_clock(AccountClock::fixed(1_900_000_123));
    db.send_direct_message("conv_clock", "msg_clock", "alice", b"encrypted")?;
    assert_eq!(message_created_at(&db, "conv_clock", "msg_clock")?, 1_900_000_123);

    db.set_clock(AccountClock::sequence(1_900_000_200));
    db.send_direct_message("conv_clock", "msg_clock_2", "alice", b"encrypted")?;
    db.send_direct_message("conv_clock", "msg_clock_3", "alice", b"encrypted")?;
    assert_eq!(message_created_at(&db, "conv_clock", "msg_clock_2")?, 1_900_000_200);
    assert_eq!(message_created_at(&db, "conv_clock", "msg_clock_3")?, 1_900_000_201);
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn account_db_default_clock_uses_real_recent_time() -> Result<(), StorageError> {
    let (root, db) = test_db("clock-real-created-at")?;
    db.send_direct_message("conv_real_clock", "msg_real_clock", "alice", b"encrypted")?;
    let created_at = message_created_at(&db, "conv_real_clock", "msg_real_clock")?;
    assert!(created_at > 1_700_000_000);
    assert_ne!(created_at, 1_760_000_000);
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn account_db_key_generate_is_random_and_aead_wrap_rejects_tamper() -> Result<(), StorageError> {
    let first = AccountDbKey::generate()?;
    let second = AccountDbKey::generate()?;
    assert_ne!(first, second);

    let vault_secret = [0x77; 32];
    let (nonce, wrapped_key) = encryption::wrap_with_vault_secret(&vault_secret, first.bytes())?;
    let wrapped = WrappedAccountDbKey {
        key_wrapping_provider: "platform-local-vault".to_owned(),
        key_wrapping_ref: "platform-local-vault:acct".to_owned(),
        nonce,
        wrapped_key,
    };
    assert_eq!(encryption::unwrap_with_vault_secret(&vault_secret, &wrapped)?, first);

    let mut tampered_key = wrapped.clone();
    tampered_key.wrapped_key[0] ^= 0x01;
    assert!(matches!(
        encryption::unwrap_with_vault_secret(&vault_secret, &tampered_key),
        Err(StorageError::KeyWrappingFailed(_))
    ));

    let mut tampered_nonce = wrapped;
    tampered_nonce.nonce[0] ^= 0x01;
    assert!(matches!(
        encryption::unwrap_with_vault_secret(&vault_secret, &tampered_nonce),
        Err(StorageError::KeyWrappingFailed(_))
    ));
    Ok(())
}

#[test]
fn account_index_persists_wrapped_db_key_material() -> Result<(), StorageError> {
    let root = temp_root("wrapped-key-index");
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    assert_eq!(index.load_wrapped_db_key("acct")?, None);

    let db_key = AccountDbKey::generate()?;
    let vault_secret = [0x88; 32];
    let (nonce, wrapped_key) = encryption::wrap_with_vault_secret(&vault_secret, db_key.bytes())?;
    let wrapped = WrappedAccountDbKey {
        key_wrapping_provider: "platform-local-vault".to_owned(),
        key_wrapping_ref: "platform-local-vault:acct".to_owned(),
        nonce,
        wrapped_key,
    };
    index.store_wrapped_db_key("acct", &wrapped)?;
    assert_eq!(index.load_wrapped_db_key("acct")?, Some(wrapped));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn file_vault_secret_source_persists_unique_0600_account_secrets() -> Result<(), StorageError> {
    let root = temp_root("file-vault-secret");
    let source = FileVaultSecretSource::new(&root);

    let first = source.vault_secret("acct_a")?;
    let first_again = source.vault_secret("acct_a")?;
    let second = source.vault_secret("acct_b")?;

    assert_eq!(first, first_again);
    assert_ne!(first, second);
    assert_eq!(fs::read(source.vault_secret_path("acct_a"))?, first);
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(source.vault_secret_path("acct_a"))?.permissions().mode() & 0o777,
        0o600
    );
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn append_event_with_device_signer_writes_verifiable_signature() -> Result<(), StorageError> {
    let (root, db, device) = signed_test_db("append-signature")?;
    db.append_event("evt_signed_1", "test.event", b"{\"ok\":true}")?;
    let (signature_bytes, status, created_at) = event_signature_status(&db, "evt_signed_1")?;
    let signature = String::from_utf8_lossy(&signature_bytes).into_owned();
    assert_eq!(status, "self");
    assert!(!signature.is_empty());
    assert!(created_at > 1_700_000_000);
    assert_ne!(created_at, 1_760_000_000);

    let body = event_store::local_event_signing_body(event_store::LocalEventSigningInput {
        event_id: "evt_signed_1",
        event_type: "test.event",
        actor_principal_id: "principal",
        actor_device_id: "device",
        device_counter: 1,
        lamport_time: 1,
        created_at,
        event_body: b"{\"ok\":true}",
    });
    let public_key =
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
    ramflux_crypto::verify_device_branch_signature(&public_key, &body, &signature)?;
    let tampered = event_store::local_event_signing_body(event_store::LocalEventSigningInput {
        event_id: "evt_signed_1",
        event_type: "test.event",
        actor_principal_id: "principal",
        actor_device_id: "device",
        device_counter: 1,
        lamport_time: 1,
        created_at,
        event_body: b"{\"ok\":false}",
    });
    assert!(
        ramflux_crypto::verify_device_branch_signature(&public_key, &tampered, &signature).is_err()
    );
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn history_import_verifies_event_signatures_and_rejects_forgery() -> Result<(), StorageError> {
    let (source_root, source_db, _device) = signed_test_db("history-source-signature")?;
    source_db.append_event("evt_history_1", "test.history", b"history-body")?;
    let bundle = source_db.export_history_bundle("device", "target-device")?;
    assert_eq!(bundle.encrypted_event_batch.len(), 1);
    assert!(!bundle.encrypted_event_batch[0].signature.is_empty());

    let target_root = temp_root("history-target-signature");
    let target_index = AccountIndex::open(&target_root)?;
    target_index.create_account("acct", "principal")?;
    let target_key = AccountDbKey::derive("acct", b"storage-test-secret");
    let target_db = AccountDb::open(&target_index, "acct", &target_key)?;
    target_db.import_history_bundle(&bundle)?;
    let (_signature_bytes, status, _created_at) =
        event_signature_status(&target_db, "evt_history_1")?;
    assert_eq!(status, "verified");

    let mut forged = bundle;
    forged.encrypted_event_batch[0].event_body = b"forged-body".to_vec();
    forged.checkpoint_hash = history_hash::history_bundle_hash(
        &forged.source_device_id,
        &forged.target_device_id,
        &forged.encrypted_event_batch,
        &forged.projection_checkpoints,
    )?;
    assert!(target_db.import_history_bundle(&forged).is_err());
    let _ = fs::remove_dir_all(source_root);
    let _ = fs::remove_dir_all(target_root);
    Ok(())
}

#[test]
fn history_import_rejects_bundle_when_event_actor_differs_from_source_device()
-> Result<(), StorageError> {
    let (source_root, source_db) = test_db("history-source-actor-mismatch")?;
    source_db.append_event("evt_history_actor_mismatch", "test.history", b"history-body")?;
    let bundle = source_db.export_history_bundle("source-device", "target-device")?;
    assert_eq!(bundle.encrypted_event_batch.len(), 1);
    assert_eq!(bundle.encrypted_event_batch[0].actor_device_id, "device");
    assert_ne!(bundle.encrypted_event_batch[0].actor_device_id, bundle.source_device_id);
    assert_eq!(
        bundle.checkpoint_hash,
        history_hash::history_bundle_hash(
            &bundle.source_device_id,
            &bundle.target_device_id,
            &bundle.encrypted_event_batch,
            &bundle.projection_checkpoints,
        )?
    );

    let (target_root, target_db) = test_db("history-target-actor-mismatch")?;
    let rejected = target_db.import_history_bundle(&bundle);
    assert!(matches!(rejected, Err(StorageError::HistoryBundleHashMismatch)));
    let _ = fs::remove_dir_all(source_root);
    let _ = fs::remove_dir_all(target_root);
    Ok(())
}

#[test]
fn wrong_account_db_key_is_rejected() -> Result<(), StorageError> {
    let root = temp_root("wrong-key");
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    let key = AccountDbKey::derive("acct", b"correct-secret");
    let _db = AccountDb::open(&index, "acct", &key)?;
    let wrong_key = AccountDbKey::derive("acct", b"wrong-secret");
    let rejected = AccountDb::open(&index, "acct", &wrong_key);
    assert!(matches!(rejected, Err(StorageError::AccountKeyMismatch | StorageError::Sqlite(_))));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn rekey_provider_failure_rolls_back_db_key_and_wrapped_key() -> Result<(), StorageError> {
    let root = temp_root("rekey-rollback");
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    let key = AccountDbKey::derive("acct", b"old-secret");
    let new_key = AccountDbKey::derive("acct", b"new-secret");
    let mut provider = LocalVaultKeyWrappingProvider::new([0x42; 32]);
    let previous_wrapped = provider.wrap_account_db_key("acct", &key)?;
    let mut db = AccountDb::open(&index, "acct", &key)?;

    provider.fail_next_wrap();
    let failed = db.rekey_with_wrapping(&new_key, &mut provider, &previous_wrapped);
    assert!(matches!(failed, Err(StorageError::KeyWrappingFailed(_))));
    assert_eq!(provider.wrapped_key("acct"), Some(&previous_wrapped));
    drop(db);

    let reopened = AccountDb::open(&index, "acct", &key)?;
    assert_eq!(reopened.encryption_mode(), EncryptionMode::SqlCipher);
    assert!(AccountDb::open(&index, "acct", &new_key).is_err());
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn account_db_migrations_are_replayable() -> Result<(), StorageError> {
    let (root, db) = test_db("migration-replay")?;
    let before = migration_versions(&db)?;
    drop(db);
    let index = AccountIndex::open(&root)?;
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let reopened = AccountDb::open(&index, "acct", &key)?;
    assert_eq!(migration_versions(&reopened)?, before);
    assert_eq!(before, vec![1, 2]);
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn group_pending_undecrypted_is_bounded_per_group() -> Result<(), StorageError> {
    let (root, db) = test_db("pending-bounded")?;
    let inserted =
        u64::try_from(GROUP_PENDING_UNDECRYPTED_PER_GROUP_LIMIT + 10).unwrap_or(u64::MAX);
    for index in 0..inserted {
        db.upsert_group_pending_undecrypted(&GroupPendingUndecryptedRecord {
            group_id: "group_a".to_owned(),
            conversation_id: "conv_a".to_owned(),
            group_key_epoch: 1,
            message_id: format!("msg_{index:04}"),
            sender_id: "alice".to_owned(),
            inbox_seq: index,
            envelope_json: b"{}".to_vec(),
            created_at: 1_760_000_000 + i64::try_from(index).unwrap_or(i64::MAX),
        })?;
    }

    assert_eq!(
        db.group_pending_undecrypted_count("group_a")?,
        GROUP_PENDING_UNDECRYPTED_PER_GROUP_LIMIT
    );
    let pending = db.group_pending_undecrypted("group_a", 1)?;
    assert!(!pending.iter().any(|record| record.message_id == "msg_0000"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn group_sender_key_counter_seen_rejects_replay() -> Result<(), StorageError> {
    let (root, db) = test_db("sender-counter")?;
    let record = GroupSenderKeyCounterRecord {
        group_id: "group_a".to_owned(),
        group_key_epoch: 7,
        sender_id: "alice".to_owned(),
        counter: 42,
        message_id: "msg_first".to_owned(),
        seen_at: 1_760_000_000,
    };

    assert!(!db.group_sender_key_counter_seen("group_a", 7, "alice", 42)?);
    assert!(db.record_group_sender_key_counter(&record)?);
    assert!(db.group_sender_key_counter_seen("group_a", 7, "alice", 42)?);
    let replay = GroupSenderKeyCounterRecord { message_id: "msg_replay".to_owned(), ..record };
    assert!(!db.record_group_sender_key_counter(&replay)?);
    let _ = fs::remove_dir_all(root);
    Ok(())
}
