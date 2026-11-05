// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy input compatibility and interrupted-stage origin retention.
use super::*;

// Pre-object-erasure (v11) ledger: no v12/v13 rows, no retention tables. Before PR11
// the observation ran after `upgrade_private` created those tables; PR11 runs the
// unowned-actor query against the raw input first.
#[test]
fn probe_p211_pre_v12_input_still_opens() -> TestResult {
    let (root, db) = crate::tests::test_db("p211-v11")?;
    db.connection.execute_batch("DROP TABLE IF EXISTS account_mac_bundle; DELETE FROM schema_migration WHERE schema_version>=12; DROP INDEX IF EXISTS runtime_outbox_object_selector; UPDATE schema_migration SET checksum='2026-06-14-account-core-v1' WHERE schema_version=1; DROP TABLE object_message_reference; DROP TABLE object_retention_reference;")?;
    let path = db.path.clone();
    drop(db);
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let result = BackupDatabase::open_restore_input(&path, &key, BackupOpenMode::PreNormalization);
    eprintln!("v11 input open: {:?}", result.as_ref().map(|d| d.original_input().schema_version));
    let opened = result?;
    assert_eq!(opened.original_input().schema_version, 11);
    drop(opened);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// S8 retry on the same private stage after a post-upgrade fault (the stage is not
// discarded). Does the original v12 classification survive the second open?
#[test]
fn probe_p211_retry_on_same_stage_reports_original_version() -> TestResult {
    let (root, db) = crate::tests::test_db("p211-same-stage")?;
    legacy_input(&db)?;
    let source = db.path.clone();
    drop(db);
    let key = AccountDbKey::derive("acct", b"storage-test-secret");
    let stage = root.join("stage.db");
    std::fs::copy(&source, &stage)?;
    FAIL_UPGRADE.set(true);
    let failed = BackupDatabase::open_restore_input(&stage, &key, BackupOpenMode::PreNormalization);
    FAIL_UPGRADE.set(false);
    assert!(failed.is_err());
    let retry = BackupDatabase::open_restore_input(&stage, &key, BackupOpenMode::PreNormalization)?;
    eprintln!("same-stage retry schema_version={}", retry.original_input().schema_version);
    assert_eq!(
        retry.original_input().schema_version,
        12,
        "v12 classification replaced by post-upgrade value"
    );
    drop(retry);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
