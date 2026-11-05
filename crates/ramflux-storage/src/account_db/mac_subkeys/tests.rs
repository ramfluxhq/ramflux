// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::{AccountDb, AccountIndex};
use std::fmt::Write;

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) fn migrated_db(tag: &str) -> Result<(std::path::PathBuf, AccountDb), StorageError> {
    let root = crate::tests::temp_root(tag);
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    let key = AccountDbKey::from_bytes([0x42; 32]);
    let db = AccountDb::open(&index, "acct", &key)?;
    // Recreate the pre-migration encrypted fixture, then use production migration.
    db.connection.execute_batch(
        "DROP TRIGGER account_mac_marker_insert; DROP TRIGGER account_mac_marker_delete; DROP TABLE account_mac_marker_bundle; DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
    )?;
    drop(db);
    let db = AccountDb::open(&index, "acct", &key)?;
    Ok((root, db))
}

#[test]
fn mac_subkey_bundle_migration_preserves_all_caller_bytes_and_replays() -> TestResult {
    let (root, db) = migrated_db("mac-migration")?;
    for label in LABELS {
        let mut derived = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<Sha256>::new(None, &[0x42; 32]).expand(label, derived.as_mut())?;
        let mut old = HmacSha256::new_from_slice(derived.as_ref())?;
        old.update(b"value");
        assert_eq!(
            db.account_mac(label, b"value")?,
            ramflux_protocol::encode_base64url(old.finalize().into_bytes())
        );
    }
    drop(db);
    let db = AccountDb::open(
        &AccountIndex::open(&root)?,
        "acct",
        &AccountDbKey::from_bytes([0x42; 32]),
    )?;
    assert_eq!(
        db.account_mac(LABELS[0], b"message-golden")?,
        "7tkgKbZENWssE__yM22Lxml0UyZPLzZFfPBKNe9YgSg"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn mac_subkey_bundle_migration_is_atomic_on_interruption() -> TestResult {
    let (root, db) = migrated_db("mac-atomic")?;
    db.connection.execute_batch(
        "DROP TRIGGER account_mac_marker_insert; DROP TRIGGER account_mac_marker_delete; DROP TABLE account_mac_marker_bundle; DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
    )?;
    db.connection.call(|raw| {
        assert!(
            initialize_with_fault(raw, &AccountDbKey::from_bytes([0x42; 32]), false, true).is_err()
        );
        assert!(!raw.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='account_mac_bundle')",
            [],
            |r| r.get::<_, bool>(0)
        )?);
        assert!(!raw.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migration WHERE schema_version=14)",
            [],
            |r| r.get::<_, bool>(0)
        )?);
        Ok(())
    })?;
    drop(db);
    let db = AccountDb::open(
        &AccountIndex::open(&root)?,
        "acct",
        &AccountDbKey::from_bytes([0x42; 32]),
    )?;
    assert_eq!(
        db.account_mac(LABELS[0], b"message-golden")?,
        "7tkgKbZENWssE__yM22Lxml0UyZPLzZFfPBKNe9YgSg"
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn mac_subkey_bundle_new_accounts_use_independent_random_subkeys() -> TestResult {
    let (first_root, first) = crate::tests::test_db("mac-random-first")?;
    let (second_root, second) = crate::tests::test_db("mac-random-second")?;
    for label in LABELS {
        assert_ne!(first.account_mac(label, b"value")?, second.account_mac(label, b"value")?);
    }
    drop(first);
    drop(second);
    std::fs::remove_dir_all(first_root)?;
    std::fs::remove_dir_all(second_root)?;
    Ok(())
}

#[test]
fn mac_subkey_bundle_debug_is_redacted_and_secret_lifecycle_is_zeroizing() -> TestResult {
    fn protected(_: &Zeroizing<[u8; 192]>) {}
    let bundle = Bundle::derive(&[0x42; 32])?;
    protected(&bundle.keys);
    assert_eq!(format!("{bundle:?}"), "MacSubkeyBundle([redacted])");
    Ok(())
}

fn assert_deleted(db: &AccountDb) -> Result<(), StorageError> {
    assert!(db.message_is_deleted("erased")?);
    assert!(db.envelope_refers_to_deleted_message("envelope")?);
    assert!(!db.message_is_deleted("fresh")?);
    db.send_direct_message_with_metadata(
        "thread",
        "erased",
        "peer",
        b"replayed",
        &crate::MessageMetadata::default(),
    )?;
    assert!(db.direct_message_by_id("erased")?.is_none());
    db.send_direct_message_with_metadata(
        "thread",
        "fresh",
        "peer",
        b"fresh",
        &crate::MessageMetadata::default(),
    )?;
    assert!(db.direct_message_by_id("fresh")?.is_some());
    db.connection.execute("DELETE FROM direct_message_projection WHERE message_id='fresh'", [])?;
    Ok(())
}

fn seed_deleted(db: &AccountDb) -> Result<(), StorageError> {
    db.send_direct_message_with_metadata(
        "thread",
        "erased",
        "peer",
        b"body",
        &crate::MessageMetadata::default(),
    )?;
    db.connection
        .execute("INSERT INTO message_copy_binding VALUES('envelope:envelope','erased')", [])?;
    db.delete_direct_message("thread", "erased", "local", "tombstone")?;
    // The marker must be the only surviving refusal oracle.
    db.connection.execute_batch("DELETE FROM direct_message_projection; DELETE FROM message_tombstone_projection; DELETE FROM event_tombstone; DELETE FROM conversation_tombstone;")?;
    assert_deleted(db)
}

#[test]
fn rekey_keeps_deleted_messages_deleted() -> TestResult {
    let (root, mut db) = crate::tests::test_db("mac-deletion-rekey")?;
    seed_deleted(&db)?;
    let next = AccountDbKey::generate()?;
    db.rekey(&next)?;
    assert_deleted(&db)?;
    let mut provider = crate::LocalVaultKeyWrappingProvider::new([7; 32]);
    let previous = db.wrap_current_db_key(&[7; 32])?;
    provider.fail_next_wrap();
    assert!(db.rekey_with_wrapping(&AccountDbKey::generate()?, &mut provider, &previous).is_err());
    assert_deleted(&db)?;
    let final_key = AccountDbKey::generate()?;
    db.rekey_with_wrapping(&final_key, &mut provider, &previous)?;
    assert_deleted(&db)?;
    drop(db);
    let db = AccountDb::open(&AccountIndex::open(&root)?, "acct", &final_key)?;
    assert_deleted(&db)?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn mac_subkey_bundle_snapshot_restore_round_trip() -> TestResult {
    let (root, db) = crate::tests::test_db("mac-snapshot")?;
    seed_deleted(&db)?;
    let expected: Vec<_> =
        LABELS.iter().map(|label| db.account_mac(label, b"value")).collect::<Result<_, _>>()?;
    let snapshot_path = root.join("snapshot.db");
    let snapshot = db.write_backup_snapshot(&snapshot_path)?;
    let snapshot_db =
        super::super::backup_database::BackupDatabase::open(&snapshot_path, &snapshot.key)?;
    let copied_path = root.join("copy.db");
    let copied_key = AccountDbKey::generate()?;
    snapshot_db.copy_to(&copied_path, &copied_key)?;
    let copied = super::super::backup_database::BackupDatabase::open(&copied_path, &copied_key)?;
    let rekeyed = AccountDbKey::generate()?;
    copied.rekey(&rekeyed)?;
    drop(copied);
    let copied = super::super::backup_database::BackupDatabase::open(&copied_path, &rekeyed)?;
    for (label, expected) in LABELS.iter().zip(expected) {
        assert_eq!(current_mac(&copied.db, label, b"value")?, expected);
    }
    drop(copied);
    drop(snapshot_db);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_archive_keeps_subkey_bundle_without_source_unlock_capability() -> TestResult {
    let (root, db) = crate::tests::test_db("mac-native")?;
    seed_deleted(&db)?;
    db.persist_actor_state("account/credential", &serde_json::json!({"secret":"credential"}))?;
    let path = root.join("native.db");
    let snapshot = db.write_backup_snapshot(&path)?;
    let archived = super::super::backup_database::BackupDatabase::open(&path, &snapshot.key)?;
    archived.sanitize_native_backup()?;
    drop(archived);
    let archived = super::super::backup_database::BackupDatabase::open(&path, &snapshot.key)?;
    assert!(!archived.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind='account/credential')",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    let bundles = load(&archived.db, "main")?;
    let source_path = db.path.clone();
    for bundle in bundles {
        for candidate in bundle.keys.as_chunks::<32>().0 {
            let key = Zeroizing::new(*candidate);
            let connection = rusqlite::Connection::open(&source_path)?;
            let mut hex = Zeroizing::new(String::new());
            for byte in key.iter() {
                write!(&mut *hex, "{byte:02x}")?;
            }
            connection.execute_batch(&format!("PRAGMA key=\"x'{}'\"", hex.as_str()))?;
            assert!(
                connection
                    .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
                    .is_err()
            );
        }
    }
    // Positive control: the actual source key opens the same encrypted source.
    let source = rusqlite::Connection::open(&source_path)?;
    source.execute_batch(&format!("PRAGMA key=\"x'{}'\"", db.current_key.sqlcipher_hex()))?;
    assert!(
        source.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))? > 0
    );
    drop(source);
    drop(archived);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn marker_key_set_merge_preserves_foreign_message_and_envelope_markers() -> TestResult {
    use super::super::backup_database::BackupDatabase;
    for mode in 0..3 {
        let (root, local) = crate::tests::test_db("mac-merge-local")?;
        let (source_root, source) = crate::tests::test_db("mac-merge-source")?;
        seed_deleted(&source)?;
        let source_path = root.join("incoming.db");
        let incoming = source.write_backup_snapshot(&source_path)?;
        let target_path = root.join("target.db");
        let target = local.write_backup_snapshot(&target_path)?;
        let mut merged = BackupDatabase::open(&target_path, &target.key)?;
        match mode {
            0 => {
                merged.merge_backup(&source_path, &incoming.key, || Ok(()))?;
            }
            1 => {
                merged.merge_native_backup(&source_path, &incoming.key, || Ok(()))?;
            }
            _ => {
                merged.merge_backup_candidate(&source_path, &incoming.key, || Ok(()))?;
            }
        }
        assert_eq!(load(&merged.db, "main")?.len(), 2);
        let keys = all_macs(&merged.db, LABELS[0], b"erased")?;
        assert!(keys.iter().any(|mac| {
            merged
                .db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=?1)",
                    [format!("message/deleted/{mac}")],
                    |r| r.get::<_, bool>(0),
                )
                .unwrap_or(false)
        }));
        merged.merge_backup(&source_path, &incoming.key, || Ok(()))?;
        assert_eq!(load(&merged.db, "main")?.len(), 2);
        drop(merged);
        drop(local);
        drop(source);
        std::fs::remove_dir_all(root)?;
        std::fs::remove_dir_all(source_root)?;
    }
    Ok(())
}

#[test]
fn marker_key_set_limit_refuses_atomically() -> TestResult {
    let (root, db) = crate::tests::test_db("mac-merge-cap")?;
    db.connection.call(|raw| {
        raw.execute_batch("ATTACH DATABASE ':memory:' AS incoming; CREATE TABLE incoming.schema_migration AS SELECT * FROM main.schema_migration")?;
        raw.execute_batch("CREATE TABLE incoming.account_mac_marker_bundle(state_kind TEXT PRIMARY KEY,bundle_id TEXT NOT NULL); CREATE TABLE incoming.account_mac_bundle(bundle_id TEXT PRIMARY KEY,subkeys BLOB NOT NULL,is_current INTEGER NOT NULL)")?;
        for index in 0_u8..15 {
            let bundle = Bundle::derive(&[index;32]).map_err(|_|rusqlite::Error::InvalidQuery)?;
            raw.execute("INSERT INTO account_mac_bundle VALUES(?1,?2,0)", params![bundle.id,bundle.keys.as_slice()])?;
        }
        let extra = Bundle::derive(&[99;32]).map_err(|_|rusqlite::Error::InvalidQuery)?;
        raw.execute("INSERT INTO incoming.account_mac_bundle VALUES(?1,?2,1)", params![extra.id,extra.keys.as_slice()])?;
        assert!(merge(raw).is_err());
        assert_eq!(raw.query_row("SELECT count(*) FROM account_mac_bundle",[],|r|r.get::<_,usize>(0))?,16);
        raw.execute("UPDATE incoming.account_mac_bundle SET bundle_id='malformed'",[])?;
        assert!(merge(raw).is_err());
        raw.execute_batch("DETACH DATABASE incoming")?;
        Ok(())
    })?;
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn rekey_preserves_routed_seen_replay_refusal() -> TestResult {
    let (root, mut db) = crate::tests::test_db("mac-routed-rekey")?;
    let entry = br#"{"envelope_id":"seen-envelope","payload_hash":"hash","encrypted_payload":"ciphertext"}"#;
    let canonical = ramflux_protocol::canonical_json_bytes(&serde_json::from_slice::<
        serde_json::Value,
    >(entry)?)?;
    let marker = db.routed_seen_key(&canonical)?;
    db.persist_actor_state(&marker, &serde_json::json!({"payload_hash":"hash"}))?;
    let mut provider = crate::LocalVaultKeyWrappingProvider::new([9; 32]);
    let mut last_key = AccountDbKey::derive("acct", b"storage-test-secret");
    for stage in 0..3 {
        let next = AccountDbKey::generate()?;
        let previous = db.wrap_current_db_key(&[9; 32])?;
        match stage {
            0 => {
                db.rekey(&next)?;
                last_key = next;
            }
            1 => {
                provider.fail_next_wrap();
                assert!(db.rekey_with_wrapping(&next, &mut provider, &previous).is_err());
            }
            _ => {
                db.rekey_with_wrapping(&next, &mut provider, &previous)?;
                last_key = next;
            }
        }
        drop(db);
        db = AccountDb::open(&AccountIndex::open(&root)?, "acct", &last_key)?;
        assert_eq!(db.routed_seen_key(&canonical)?, marker);
        assert_eq!(db.defer_inbox_entry("seen", entry, 1)?, 0);
        assert_eq!(db.unrouted_count()?, 0);
        assert!(!db.message_is_deleted("seen-envelope")?);
        let unseen = br#"{"envelope_id":"unseen-envelope","payload_hash":"hash","encrypted_payload":"ciphertext"}"#;
        db.hold_unrouted("unseen", 1, unseen, 1)?;
        assert_eq!(db.unrouted_count()?, 1);
        db.connection.execute("DELETE FROM runtime_unrouted", [])?;
    }
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
