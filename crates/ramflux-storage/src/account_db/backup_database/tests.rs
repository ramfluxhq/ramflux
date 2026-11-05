// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::{AccountDb, AccountIndex, ObjectWrite};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// Same real v12 ledger/index shape as the selector upgrade fixture. There are
// no v13 table or column additions; schema validation verifies this input.
fn legacy_input(db: &AccountDb) -> Result<(), StorageError> {
    db.upsert_object(&ObjectWrite {
        object_id: "legacy",
        manifest_hash: "manifest",
        nonce: "",
        ciphertext: b"",
        plaintext_hash: "",
        tombstoned: true,
        backup_excluded: false,
        content_key: None,
        object: &json!({}),
        updated_at: 1,
    })?;
    db.connection.execute("UPDATE object_index SET manifest_hash=zeroblob(32),chunk_manifest_hash=zeroblob(32) WHERE object_id='legacy'", [])?;
    db.persist_actor_state("attachment/reference/legacy", &json!({"legacy":true}))?;
    db.connection.execute_batch("DROP TABLE IF EXISTS account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14; DELETE FROM schema_migration WHERE schema_version=13; DROP INDEX IF EXISTS runtime_outbox_object_selector;")?;
    db.connection.execute(
        "UPDATE schema_migration SET checksum=?1 WHERE schema_version=1",
        params![crate::schema_object_erasure::V12_SENTINEL],
    )?;
    db.connection.call(|raw| Ok(crate::schema_object_erasure::validate(raw)))??;
    Ok(())
}

#[test]
fn pre_normalization_preserves_original_counts_until_strict_validation() -> TestResult {
    for inherited_v13 in [false, true] {
        let (root, db) = crate::tests::test_db(&format!("restore-input-{inherited_v13}"))?;
        legacy_input(&db)?;
        let path = db.path.clone();
        drop(db);
        let key = AccountDbKey::derive("acct", b"storage-test-secret");
        if inherited_v13 {
            // The actual live P1 upgrade retains the inherited unowned actor.
            drop(AccountDb::open(&AccountIndex::open(&root)?, "acct", &key)?);
        }
        let opened =
            BackupDatabase::open_restore_input(&path, &key, BackupOpenMode::PreNormalization);
        assert!(opened.is_ok(), "pre-normalization input must reach the normalizer");
        let input = opened?;
        let original = input.original_input().clone();
        assert_eq!(original.schema_version, if inherited_v13 { 14 } else { 12 });
        assert_eq!(original.unowned_legacy_actor_count, 1);
        assert_eq!(original.counts.attachments, 1);
        assert_eq!(input.counts()?, original.counts);
        assert!(matches!(
            BackupDatabase::open(&path, &key),
            Err(StorageError::ObjectOwnershipUnverified { .. })
        ));
        let copy = root.join("private.db");
        input.copy_to(&copy, &key)?;
        let stage = input.reopen_restore_input(&copy, &key, BackupOpenMode::PreNormalization)?;
        assert_eq!(stage.original_input(), &original);
        assert!(stage.reopen_restore_input(&copy, &key, BackupOpenMode::Normalized).is_err());
        // Simulate the later private normalizer's row omission, not an input scrub.
        stage.db.execute_batch("DELETE FROM runtime_actor_state WHERE state_kind='attachment/reference/legacy'; DELETE FROM object_index WHERE object_id='legacy';")?;
        assert_eq!(stage.counts()?.attachments, 0);
        assert_eq!(stage.original_input(), &original);
        let normalized = stage.reopen_restore_input(&copy, &key, BackupOpenMode::Normalized)?;
        assert_eq!(normalized.original_input(), &original);
        assert_eq!(normalized.counts()?.attachments, 0);
        // Its private copy changed; the original input still fails strict validation.
        assert!(matches!(
            BackupDatabase::open(&path, &key),
            Err(StorageError::ObjectOwnershipUnverified { .. })
        ));
        drop(normalized);
        drop(stage);
        drop(input);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn pre_normalization_keeps_authentication_and_schema_refusals() -> TestResult {
    let (root, db) = crate::tests::test_db("restore-input-refusals")?;
    let path = db.path.clone();
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    drop(db);
    let input = BackupDatabase::open_restore_input(&path, &key, BackupOpenMode::PreNormalization)?;
    assert!(
        BackupDatabase::open_restore_input(
            &path,
            &AccountDbKey::generate()?,
            BackupOpenMode::PreNormalization
        )
        .is_err()
    );
    input
        .db
        .execute("UPDATE schema_migration SET checksum='invalid' WHERE schema_version=13", [])?;
    assert!(matches!(
        BackupDatabase::open_restore_input(&path, &key, BackupOpenMode::PreNormalization),
        Err(StorageError::MigrationChecksumMismatch { .. })
    ));
    drop(input);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
