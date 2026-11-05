// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::{AccountDb, AccountIndex};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn legacy_db(tag: &str) -> Result<(std::path::PathBuf, AccountDb), StorageError> {
    let root = crate::tests::temp_root(tag);
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    let key = AccountDbKey::from_bytes([0x42; 32]);
    let db = AccountDb::open(&index, "acct", &key)?;
    // An explicit fixed test bundle reproduces the old writer's HKDF keys while
    // seeding real caller rows. Remove it before handing off the v13 fixture.
    db.connection.call(|raw| {
        let bundle = Bundle::derive(&[0x42; 32]);
        raw.execute(
            "UPDATE account_mac_bundle SET bundle_id=?1,subkeys=?2",
            params![bundle.id, bundle.keys.as_slice()],
        )?;
        Ok(())
    })?;
    Ok((root, db))
}

fn remove_bundle_schema(db: &AccountDb) -> Result<(), StorageError> {
    db.connection.execute_batch(
        "DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
    )?;
    Ok(())
}

pub(crate) fn migrated_db(tag: &str) -> Result<(std::path::PathBuf, AccountDb), StorageError> {
    let (root, db) = legacy_db(tag)?;
    remove_bundle_schema(&db)?;
    drop(db);
    let db = AccountDb::open(
        &AccountIndex::open(&root)?,
        "acct",
        &AccountDbKey::from_bytes([0x42; 32]),
    )?;
    Ok((root, db))
}

fn source() -> Result<ramflux_crypto::RootQualifiedDeviceRef, StorageError> {
    Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
        &ramflux_crypto::create_identity_root("migration-principal", [7; 32]),
        "migration-source",
    )?)
}

fn canonical_envelope() -> Result<Vec<u8>, StorageError> {
    Ok(ramflux_protocol::canonical_json_bytes(
        &serde_json::json!({"envelope_id":"migration-envelope","payload_hash":"migration-hash","encrypted_payload":"cipher"}),
    )?)
}

fn caller_inputs() -> Result<[Vec<u8>; 6], StorageError> {
    use sha2::Digest;
    Ok([
        b"erased".to_vec(),
        b"envelope".to_vec(),
        ramflux_protocol::canonical_json_bytes(&("ciphertext", "migration-ciphertext"))?,
        ramflux_protocol::canonical_json_bytes(&(source()?.storage_key(), "migration-copy"))?,
        ramflux_protocol::canonical_json_bytes(&("migration-source", "migration-target"))?,
        Sha256::digest(canonical_envelope()?).to_vec(),
    ])
}

fn caller_outputs(db: &AccountDb) -> Result<[String; 6], StorageError> {
    Ok([
        db.account_mac(LABELS[0], b"erased")?,
        db.account_mac(LABELS[1], b"envelope")?,
        db.own_sent_index_digest("ciphertext", "migration-ciphertext")?,
        db.own_sent_replay_claim(&source()?, "migration-copy")?,
        db.own_sent_receipt_scope("migration-source", "migration-target")?,
        db.routed_seen_key(&canonical_envelope()?)?.trim_start_matches("routed/seen/").to_owned(),
    ])
}

type ActorRows = Vec<(String, Vec<u8>)>;
fn persisted_rows(db: &AccountDb) -> Result<ActorRows, StorageError> {
    Ok(db.connection.prepare("SELECT state_kind,state_json FROM runtime_actor_state WHERE state_kind GLOB 'message/deleted/*' OR state_kind GLOB 'message/deleted-envelope/*' OR state_kind GLOB 'own-device/sent-ciphertext/*' OR state_kind='own-device/message-receipt/migration-copy' OR state_kind GLOB 'routed/seen/*' ORDER BY state_kind")?.query_map([], |r|Ok((r.get(0)?,r.get(1)?)))?.collect::<rusqlite::Result<_>>()?)
}

#[test]
fn mac_subkey_bundle_migration_preserves_all_caller_bytes_and_replays() -> TestResult {
    let (root, db) = legacy_db("mac-migration")?;
    seed_deleted(&db)?;
    db.send_direct_message("thread", "migration-sent", "self", b"ciphertext")?;
    let expected = caller_outputs(&db)?;
    // Independent, unchanged historical HKDF implementation is the oracle for
    // every label, not the new bundle's derivation or its stored bytes.
    for ((label, input), output) in LABELS.iter().zip(caller_inputs()?).zip(&expected) {
        let mut derived = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<Sha256>::new(None, &[0x42; 32]).expand(label, derived.as_mut())?;
        let mut old = HmacSha256::new_from_slice(derived.as_ref())?;
        old.update(&input);
        assert_eq!(*output, ramflux_protocol::encode_base64url(old.finalize().into_bytes()));
    }
    db.persist_message_replay_reference(
        &format!("own-device/sent-ciphertext/{}", expected[2]),
        Some("migration-sent"),
        Some(&expected[3]),
        None,
    )?;
    db.persist_actor_state("own-device/message-receipt/migration-copy",&serde_json::json!({"fingerprint":"migration-fingerprint","private_scope":expected[4],"valid_until":2_000_000_000_i64,"expires_at":2_000_000_300_i64,"acknowledged":true}))?;
    db.persist_actor_state(
        &format!("routed/seen/{}", expected[5]),
        &serde_json::json!({"payload_hash":"migration-hash"}),
    )?;
    let rows = persisted_rows(&db)?;
    assert_eq!(
        rows.len(),
        5,
        "both deletion markers, sent index/claim, receipt scope and routed seen must be persisted"
    );
    for key in [
        format!("message/deleted/{}", expected[0]),
        format!("message/deleted-envelope/{}", expected[1]),
        format!("own-device/sent-ciphertext/{}", expected[2]),
        "own-device/message-receipt/migration-copy".into(),
        format!("routed/seen/{}", expected[5]),
    ] {
        assert!(rows.iter().any(|(stored, _)| *stored == key), "old caller row missing: {key}");
    }
    remove_bundle_schema(&db)?;
    assert_eq!(
        db.connection
            .query_row("SELECT MAX(schema_version) FROM schema_migration", [], |r| r
                .get::<_, i64>(0))?,
        13
    );
    drop(db);
    let key = AccountDbKey::from_bytes([0x42; 32]);
    for _ in 0..2 {
        let db = AccountDb::open(&AccountIndex::open(&root)?, "acct", &key)?;
        assert_eq!(caller_outputs(&db)?, expected);
        assert_eq!(
            persisted_rows(&db)?,
            rows,
            "migration/replay/reopen rewrote persisted caller bytes"
        );
        assert_deleted(&db)?;
        assert_eq!(db.defer_inbox_entry("migration-seen", &canonical_envelope()?, 1)?, 0);
        let index = db
            .load_actor_state::<crate::MessageReplayReference>(&format!(
                "own-device/sent-ciphertext/{}",
                expected[2]
            ))?
            .ok_or("sent index")?;
        assert_eq!(index.message_id(), Some("migration-sent"));
        assert_eq!(index.binding(), Some(expected[3].as_str()));
        drop(db);
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn mac_subkey_bundle_migration_is_atomic_on_interruption() -> TestResult {
    let (root, db) = migrated_db("mac-atomic")?;
    db.connection.execute_batch(
        "DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
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
    let first_outputs = caller_outputs(&first)?;
    let second_outputs = caller_outputs(&second)?;
    for (a, b) in first_outputs.iter().zip(&second_outputs) {
        assert_ne!(a, b);
    }
    for db in [&first, &second] {
        db.connection.call(|raw| {
            let bundle=load(raw).map_err(|_|rusqlite::Error::InvalidQuery)?;
            // Inventory the sole new key-material row. No root, seed, PRK or DB
            // key column exists, and no application value contains DB unlock material.
            let columns=raw.prepare("SELECT name FROM pragma_table_info('account_mac_bundle')")?.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(columns,["bundle_id","subkeys","is_current"]);
            let key=AccountDbKey::derive("acct",b"storage-test-secret");
            let (prk,_)=hkdf::Hkdf::<Sha256>::extract(None,key.bytes());
            let prk=Zeroizing::new(<[u8;32]>::from(prk));
            assert!(!bundle.keys.windows(32).any(|part|part==key.bytes() || part==prk.as_ref()));
            let tables=raw.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for table in tables {
                let mut query=raw.prepare(&format!("SELECT * FROM \"{}\"",table.replace('"',"\"\"")))?;
                let count=query.column_count();
                let mut rows=query.query([])?;
                while let Some(row)=rows.next()? {
                    for column in 0..count {
                        if let rusqlite::types::ValueRef::Blob(bytes)=row.get_ref(column)? {
                            assert!(!bytes.windows(32).any(|part|part==key.bytes() || part==prk.as_ref()),"unlock material persisted in {table}");
                        }
                    }
                }
            }
            Ok(())
        })?;
    }
    drop(first);
    drop(second);
    for (root, expected) in [(&first_root, first_outputs), (&second_root, second_outputs)] {
        let db = AccountDb::open(
            &AccountIndex::open(root)?,
            "acct",
            &AccountDbKey::derive("acct", b"storage-test-secret"),
        )?;
        assert_eq!(caller_outputs(&db)?, expected, "new account authority changed on reopen");
        drop(db);
    }
    std::fs::remove_dir_all(first_root)?;
    std::fs::remove_dir_all(second_root)?;
    Ok(())
}

#[test]
fn mac_subkey_bundle_debug_is_redacted_and_secret_lifecycle_is_zeroizing() {
    fn protected(_: &Zeroizing<[u8; 192]>) {}
    let bundle = Bundle::derive(&[0x42; 32]);
    protected(&bundle.keys);
    assert_eq!(format!("{bundle:?}"), "MacSubkeyBundle([redacted])");
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
    let before = persisted_rows(&db)?;
    let mut provider = crate::LocalVaultKeyWrappingProvider::new([7; 32]);
    let mut last_key = AccountDbKey::derive("acct", b"storage-test-secret");
    for stage in 0..3 {
        let next = AccountDbKey::generate()?;
        let previous = db.wrap_current_db_key(&[7; 32])?;
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
        assert_deleted(&db)?;
        drop(db);
        db = AccountDb::open(&AccountIndex::open(&root)?, "acct", &last_key)?;
        assert_deleted(&db)?;
        assert_eq!(persisted_rows(&db)?, before, "rekey/failed wrapping rewrote marker rows");
    }
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
    let source_bundle = db.connection.call(|raw| Ok(load(raw)))??;
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
    assert!(load(&copied.db)?.keys == source_bundle.keys, "snapshot/copy changed the bundle");
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
