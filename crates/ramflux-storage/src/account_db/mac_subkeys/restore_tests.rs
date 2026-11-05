// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Archive boundaries, fresh generation installation and bounded foreign authority.
use super::tests::{assert_deleted, seed_deleted};
use super::*;
use crate::{AccountDb, AccountIndex, BackupDatabase};
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn install(
    root: &std::path::Path,
    source: &BackupDatabase,
) -> Result<(AccountDb, AccountDbKey), StorageError> {
    let index = AccountIndex::open(root)?;
    let path = "accounts/acct/generation-restored/account.db";
    std::fs::create_dir_all(root.join("accounts/acct/generation-restored"))?;
    let key = AccountDbKey::generate()?;
    source.copy_to(&root.join(path), &key)?;
    let (nonce, wrapped_key) = crate::wrap_with_vault_secret(&[9; 32], key.bytes())?;
    index.install_backup_generation(&crate::BackupIndexInstall {
        account_id: "acct",
        principal_commitment: "principal",
        db_relative_path: path,
        object_relative_path: "accounts/acct/generation-restored",
        manifest_json: b"{}",
        wrapped_key: &crate::WrappedAccountDbKey {
            key_wrapping_provider: "local-vault".into(),
            key_wrapping_ref: "test".into(),
            nonce,
            wrapped_key,
        },
    })?;
    drop(index);
    let db = AccountDb::open(&AccountIndex::open(root)?, "acct", &key)?;
    Ok((db, key))
}

pub(super) fn assert_fresh_install(root: &std::path::Path, source: &BackupDatabase) -> TestResult {
    let (db, key) = install(root, source)?;
    assert_deleted(&db)?;
    drop(db);
    let db = AccountDb::open(&AccountIndex::open(root)?, "acct", &key)?;
    assert_deleted(&db)?;
    Ok(())
}

#[test]
fn native_archive_keeps_subkey_bundle_without_source_unlock_capability() -> TestResult {
    let (root, db) = crate::tests::test_db("mac-native-archive")?;
    seed_deleted(&db)?;
    db.persist_actor_state("account/credential", &"credential-canary")?;
    db.persist_actor_state("sync/cursor", &7)?;
    let bundle = db.connection.call(|raw| Ok(load(raw)))??;
    // Retain a closed source copy encrypted with the real source key.
    db.checkpoint_retired_secrets()?;
    let source_copy = root.join("source-retained.db");
    let source_path = AccountIndex::open(&root)?.account("acct")?.db_relative_path;
    std::fs::copy(root.join(source_path), &source_copy)?;
    let source_key = AccountDbKey::derive("acct", b"storage-test-secret");
    assert!(BackupDatabase::open(&source_copy, &source_key).is_ok());
    let serialized = Zeroizing::new(bundle.keys.to_vec());
    let mut candidates =
        vec![Zeroizing::new(<[u8; 32]>::from(Sha256::digest(serialized.as_slice())))];
    for key in serialized.as_chunks::<32>().0 {
        let mut candidate = Zeroizing::new([0; 32]);
        candidate.copy_from_slice(key);
        candidates.push(candidate);
    }
    for candidate in candidates {
        assert!(BackupDatabase::open(&source_copy, &AccountDbKey::from_bytes(*candidate)).is_err());
    }
    // Also attempt the serialized bundle verbatim as a SQLCipher passphrase.
    let probe = Connection::open(&source_copy)?;
    let mut passphrase = Zeroizing::new(String::new());
    for byte in serialized.iter() {
        use std::fmt::Write;
        write!(&mut *passphrase, "{byte:02x}")?;
    }
    let sql = Zeroizing::new(format!("PRAGMA key=\"x'{}'\"", passphrase.as_str()));
    probe.execute_batch(&sql)?;
    assert!(
        probe.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, u64>(0)).is_err()
    );
    drop(probe);
    let path = root.join("native.db");
    let snapshot = db.write_backup_snapshot(&path)?;
    let archive = BackupDatabase::open(&path, &snapshot.key)?;
    archive.sanitize_native_backup()?;
    drop(archive);
    let archive = BackupDatabase::open(&path, &snapshot.key)?;
    assert!(load(&archive.db)?.keys == bundle.keys, "sanitization changed the bundle");
    assert_eq!(archive.db.query_row("SELECT count(*) FROM runtime_actor_state WHERE state_kind IN ('account/credential','sync/cursor')",[],|r|r.get::<_,u64>(0))?,0);
    assert_fresh_install(&root.join("fresh-native"), &archive)?;
    drop(archive);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn snapshot(
    root: &std::path::Path,
    tag: &str,
) -> Result<(std::path::PathBuf, AccountDbKey), StorageError> {
    let (source_root, db) = crate::tests::test_db(tag)?;
    seed_deleted(&db)?;
    let seen = db.routed_seen_key(&ramflux_protocol::canonical_json_bytes(
        &json!({"envelope_id":"fresh","encrypted_payload":"x","payload_hash":"foreign-hash"}),
    )?)?;
    db.persist_actor_state(&seen, &json!({"payload_hash":"foreign-hash"}))?;
    let legacy = ramflux_crypto::blake3_256_base64url("ramflux.deleted-message.v1", b"legacy");
    db.persist_actor_state(&format!("message/deleted/{legacy}"), &json!({"version":1}))?;
    let path = root.join(format!("{tag}.db"));
    let copy = db.write_backup_snapshot(&path)?;
    drop(db);
    std::fs::remove_dir_all(source_root)?;
    Ok((path, copy.key))
}

#[test]
fn marker_key_set_merge_preserves_foreign_message_and_envelope_markers() -> TestResult {
    let root = crate::tests::temp_root("mac-foreign-merge");
    std::fs::create_dir_all(&root)?;
    let (source, key) = snapshot(&root, "mac-foreign-source")?;
    let source_hash = Sha256::digest(std::fs::read(&source)?);
    for mode in 0..3 {
        let (target, target_key) = snapshot(&root, &format!("mac-target-{mode}"))?;
        let mut merged = BackupDatabase::open(&target, &target_key)?;

        match mode {
            0 => {
                merged.merge_backup(&source, &key, || Ok(()))?;
            }
            1 => {
                merged.merge_native_backup(&source, &key, || Ok(()))?;
            }
            _ => {
                merged.merge_backup_candidate(&source, &key, || Ok(()))?;
            }
        }
        merged.merge_backup(&source, &key, || Ok(()))?;
        assert_eq!(merge::load_set(&merged.db, "main")?.len(), 2);
        let fresh_root = root.join(format!("installed-{mode}"));
        let (mut db, _) = install(&fresh_root, &merged)?;
        // Remove local-authority markers: only the imported foreign bundle can refuse.
        let local = load(&merged.db)?;
        for (label, prefix, value) in [
            (LABELS[0], "message/deleted/", b"erased".as_slice()),
            (LABELS[1], "message/deleted-envelope/", b"envelope".as_slice()),
        ] {
            db.remove_actor_state(&format!("{prefix}{}", local.mac(label, value)?))?;
        }
        assert_deleted(&db)?;
        assert!(db.message_is_deleted("legacy")?);
        let entry =
            br#"{"envelope_id":"fresh","encrypted_payload":"x","payload_hash":"foreign-hash"}"#;
        // Retained source-derived replay rows are discoverable with foreign MACs.
        let canonical = ramflux_protocol::canonical_json_bytes(&serde_json::from_slice::<
            serde_json::Value,
        >(entry)?)?;
        db.remove_actor_state(&db.routed_seen_key(&canonical)?)?;
        let markers = db.routed_seen_keys(&canonical)?;
        assert!(markers.iter().any(|m| db.actor_state_exists(m).unwrap_or(false)));
        let retained =
            db.inbox_envelope_marker(entry)?.ok_or(StorageError::AuthorizationRejected)?;
        assert!(db.actor_state_exists(&retained)?);
        let new_key = AccountDbKey::generate()?;
        db.rekey(&new_key)?;
        drop(db);
        let db = AccountDb::open(&AccountIndex::open(&fresh_root)?, "acct", &new_key)?;
        assert_deleted(&db)?;
        drop(db);
        // Merge the already merged input into a third account: transitive authority.
        let (third, third_key) = snapshot(&root, &format!("mac-third-{mode}"))?;
        let mut transitive = BackupDatabase::open(&third, &third_key)?;
        transitive.merge_backup(&target, &target_key, || Ok(()))?;
        assert_eq!(merge::load_set(&transitive.db, "main")?.len(), 3);
        for bundle in [load(&transitive.db)?, local] {
            for (label, prefix, value) in [
                (LABELS[0], "message/deleted/", b"erased".as_slice()),
                (LABELS[1], "message/deleted-envelope/", b"envelope".as_slice()),
            ] {
                transitive.db.execute(
                    "DELETE FROM runtime_actor_state WHERE state_kind=?1",
                    [format!("{prefix}{}", bundle.mac(label, value)?)],
                )?;
            }
        }
        assert_fresh_install(&root.join(format!("transitive-{mode}")), &transitive)?;
    }
    assert_eq!(Sha256::digest(std::fs::read(source)?), source_hash, "source archive changed");
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn marker_key_set_limit_refuses_atomically() -> TestResult {
    let root = crate::tests::temp_root("mac-limit");
    std::fs::create_dir_all(&root)?;
    let (target, key) = snapshot(&root, "mac-cap-target")?;
    let mut merged = BackupDatabase::open(&target, &key)?;
    // Use the real public merge for each of the sixteen independent complete bundles.
    for n in 0..15 {
        let (source, source_key) = snapshot(&root, &format!("mac-cap-{n}"))?;
        merged.merge_backup(&source, &source_key, || Ok(()))?;
    }
    assert_eq!(merge::load_set(&merged.db, "main")?.len(), 16);
    let (source, source_key) = snapshot(&root, "mac-cap-overflow")?;
    let before = database_digest(&merged.db)?;
    let source_before = std::fs::read(&source)?;
    assert!(merged.merge_backup(&source, &source_key, || Ok(())).is_err());
    assert_eq!(database_digest(&merged.db)?, before);
    assert_eq!(std::fs::read(&source)?, source_before);
    drop(merged);
    for fault in 0..6 {
        let (target, target_key) = snapshot(&root, &format!("mac-invalid-target-{fault}"))?;
        let (source, source_key) = snapshot(&root, &format!("mac-invalid-source-{fault}"))?;
        let mut target = BackupDatabase::open(&target, &target_key)?;
        let incoming = BackupDatabase::open(&source, &source_key)?;
        match fault {
            0 => {
                incoming.db.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE account_mac_bundle SET subkeys=x'01'")?;
            }
            1 => {
                incoming.db.execute("UPDATE account_mac_bundle SET bundle_id='malformed'", [])?;
            }
            2 | 3 => {
                incoming.db.execute_batch("CREATE TABLE account_mac_marker_bundle(state_kind TEXT PRIMARY KEY,bundle_id TEXT NOT NULL)")?;
                let id = load(&incoming.db)?.id;
                let marker = if fault == 2 {
                    "unknown-label/value".to_owned()
                } else {
                    let local = load(&target.db)?;
                    format!("message/deleted/{}", local.mac(LABELS[0], b"erased")?)
                };
                incoming.db.execute(
                    "INSERT INTO account_mac_marker_bundle VALUES(?1,?2)",
                    params![marker, id],
                )?;
            }
            4 => {
                incoming.db.execute_batch("CREATE TABLE account_mac_marker_bundle(state_kind TEXT PRIMARY KEY,bundle_id TEXT NOT NULL)")?;
                let marker =
                    format!("message/deleted/{}", load(&incoming.db)?.mac(LABELS[0], b"erased")?);
                incoming.db.execute(
                    "INSERT INTO account_mac_marker_bundle VALUES(?1,'missing-bundle')",
                    [marker],
                )?;
            }
            _ => {
                incoming.db.execute_batch("CREATE TABLE account_mac_marker_bundle(state_kind TEXT,bundle_id TEXT NOT NULL)")?;
                let bundle = load(&incoming.db)?;
                let marker = format!("message/deleted/{}", bundle.mac(LABELS[0], b"erased")?);
                for _ in 0..2 {
                    incoming.db.execute(
                        "INSERT INTO account_mac_marker_bundle VALUES(?1,?2)",
                        params![marker, bundle.id],
                    )?;
                }
            }
        }
        let source_before = database_digest(&incoming.db)?;
        let target_before = database_digest(&target.db)?;
        for mode in 0..3 {
            let result = match mode {
                0 => target.merge_backup(&source, &source_key, || Ok(())),
                1 => target.merge_native_backup(&source, &source_key, || Ok(())),
                _ => target.merge_backup_candidate(&source, &source_key, || Ok(())),
            };
            assert!(result.is_err(), "invalid foreign authority accepted: {fault}/{mode}");
            assert_eq!(
                database_digest(&target.db)?,
                target_before,
                "target changed: {fault}/{mode}"
            );
            assert_eq!(
                database_digest(&incoming.db)?,
                source_before,
                "source changed: {fault}/{mode}"
            );
        }
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Hash borrowed values directly: the witness never exports plaintext secret table values.
fn database_digest(db: &Connection) -> Result<[u8; 32], StorageError> {
    let mut digest = Sha256::new();
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for table in tables {
        digest.update(table.as_bytes());
        let mut query = db.prepare(&format!(
            "SELECT * FROM \"{}\" ORDER BY rowid",
            table.replace('\"', "\"\"")
        ))?;
        let count = query.column_count();
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            for n in 0..count {
                use rusqlite::types::ValueRef;
                match row.get_ref(n)? {
                    ValueRef::Null => digest.update([0]),
                    ValueRef::Integer(v) => {
                        digest.update([1]);
                        digest.update(v.to_le_bytes());
                    }
                    ValueRef::Real(v) => {
                        digest.update([2]);
                        digest.update(v.to_le_bytes());
                    }
                    ValueRef::Text(v) => {
                        digest.update([3]);
                        digest.update(v.len().to_le_bytes());
                        digest.update(v);
                    }
                    ValueRef::Blob(v) => {
                        digest.update([4]);
                        digest.update(v.len().to_le_bytes());
                        digest.update(v);
                    }
                }
            }
        }
    }
    Ok(digest.finalize().into())
}

#[test]
fn pre_bundle_merge_does_not_invent_archive_marker_authority() -> TestResult {
    for version in [12, 13] {
        let (root, source) = crate::tests::test_db(&format!("mac-raw-prebundle-{version}"))?;
        seed_deleted(&source)?;
        source.connection.execute_batch(
            "DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
        )?;
        if version == 12 {
            source.connection.execute_batch("DELETE FROM schema_migration WHERE schema_version=13; DROP INDEX IF EXISTS runtime_outbox_object_selector;")?;
            source.connection.execute(
                "UPDATE schema_migration SET checksum=?1 WHERE schema_version=1",
                params![crate::schema_object_erasure::V12_SENTINEL],
            )?;
        }
        let path = root.join("archive.db");
        let archive = source.write_backup_snapshot(&path)?;
        let archive_hash = Sha256::digest(std::fs::read(&path)?);
        for mode in 0..3 {
            let (local_root, local) =
                crate::tests::test_db(&format!("mac-raw-local-{version}-{mode}"))?;
            let target = root.join(format!("target-{mode}.db"));
            let snapshot = local.write_backup_snapshot(&target)?;
            let mut merged = BackupDatabase::open(&target, &snapshot.key)?;
            let before = load(&merged.db)?;
            match mode {
                0 => {
                    merged.merge_backup(&path, &archive.key, || Ok(()))?;
                }
                1 => {
                    merged.merge_native_backup(&path, &archive.key, || Ok(()))?;
                }
                _ => {
                    merged.merge_backup_candidate(&path, &archive.key, || Ok(()))?;
                }
            }
            assert_eq!(merge::load_set(&merged.db, "main")?.len(), 1);
            assert!(load(&merged.db)?.keys == before.keys, "raw archive replaced local authority");
            let installed_root = root.join(format!("installed-{mode}"));
            let (restored, _) = install(&installed_root, &merged)?;
            assert!(!restored.message_is_deleted("erased")?);
            assert!(!restored.envelope_refers_to_deleted_message("envelope")?);
            drop(restored);
            drop(merged);
            drop(local);
            std::fs::remove_dir_all(local_root)?;
        }
        assert_eq!(Sha256::digest(std::fs::read(&path)?), archive_hash);
        drop(source);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn merge_mode(
    target: &mut BackupDatabase,
    path: &std::path::Path,
    key: &AccountDbKey,
    mode: u8,
) -> TestResult {
    match mode {
        0 => {
            target.merge_backup(path, key, || Ok(()))?;
        }
        1 => {
            target.merge_native_backup(path, key, || Ok(()))?;
        }
        _ => {
            target.merge_backup_candidate(path, key, || Ok(()))?;
        }
    }
    assert_eq!(merge::load_set(&target.db, "main")?.len(), 1);
    assert_eq!(
        target.db.query_row("SELECT count(*) FROM account_mac_marker_bundle", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn pre_bundle_staged_restore_can_repeat_without_synthesized_authority() -> TestResult {
    for version in [12, 13] {
        let (root, source) = crate::tests::test_db(&format!("mac-staged-prebundle-{version}"))?;
        seed_deleted(&source)?;
        source.connection.execute_batch(
            "DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
        )?;
        if version == 12 {
            source.connection.execute_batch("DELETE FROM schema_migration WHERE schema_version=13; DROP INDEX IF EXISTS runtime_outbox_object_selector;")?;
            source.connection.execute(
                "UPDATE schema_migration SET checksum=?1 WHERE schema_version=1",
                params![crate::schema_object_erasure::V12_SENTINEL],
            )?;
        }
        let archive_path = root.join("original.db");
        let archive = source.write_backup_snapshot(&archive_path)?;
        let original_hash = Sha256::digest(std::fs::read(&archive_path)?);
        for mode in 0..3 {
            let (local_root, local) =
                crate::tests::test_db(&format!("mac-staged-target-{version}-{mode}"))?;
            let target_path = root.join(format!("target-{mode}.db"));
            let target_snapshot = local.write_backup_snapshot(&target_path)?;
            let mut target = BackupDatabase::open(&target_path, &target_snapshot.key)?;
            let current = load(&target.db)?.id;
            let mut fresh = None;
            for round in 0..2 {
                let stage_path = root.join(format!("stage-{mode}-{round}.db"));
                std::fs::copy(&archive_path, &stage_path)?;
                // Same production boundary used by the SDK's open_checked_input.
                let stage = BackupDatabase::open_restore_input(
                    &stage_path,
                    &archive.key,
                    crate::BackupOpenMode::PreNormalization,
                )?;
                assert_eq!(stage.original_input().counts, archive.counts);
                assert_eq!(
                    stage.db.query_row(
                        "SELECT count(*) FROM account_mac_legacy_origin WHERE kind='bundle'",
                        [],
                        |r| r.get::<_, u64>(0)
                    )?,
                    1
                );
                if round == 0 {
                    let install_root = root.join(format!("fresh-{mode}"));
                    let (installed, _) = install(&install_root, &stage)?;
                    assert!(!installed.message_is_deleted("erased")?);
                    assert!(!installed.envelope_refers_to_deleted_message("envelope")?);
                    let fresh_path = root.join(format!("fresh-target-{mode}.db"));
                    let fresh_snapshot = installed.write_backup_snapshot(&fresh_path)?;
                    fresh = Some((
                        BackupDatabase::open(&fresh_path, &fresh_snapshot.key)?,
                        install_root,
                    ));
                }
                drop(stage);
                let staged_hash = Sha256::digest(std::fs::read(&stage_path)?);
                merge_mode(&mut target, &stage_path, &archive.key, mode)?;
                assert_eq!(load(&target.db)?.id, current);
                merge_mode(
                    &mut fresh.as_mut().ok_or("missing installed target")?.0,
                    &stage_path,
                    &archive.key,
                    mode,
                )?;
                assert_eq!(Sha256::digest(std::fs::read(&stage_path)?), staged_hash);
                // A merge/reopen must not turn the unmatched markers into current-key associations.
                drop(target);
                target = BackupDatabase::open(&target_path, &target_snapshot.key)?;
            }
            for (label, merged) in [
                ("merged", &target),
                ("fresh-merged", &fresh.as_ref().ok_or("missing installed target")?.0),
            ] {
                let (installed, _) = install(&root.join(format!("{label}-{mode}")), merged)?;
                assert!(!installed.message_is_deleted("erased")?);
                assert!(!installed.envelope_refers_to_deleted_message("envelope")?);
                // A newly written marker still uses the adopted current authority.
                installed.send_direct_message("thread", "new-message", "peer", b"body")?;
                installed.delete_direct_message(
                    "thread",
                    "new-message",
                    "local",
                    "new-tombstone",
                )?;
                assert!(installed.message_is_deleted("new-message")?);
            }
            drop(fresh);
            drop(target);
            drop(local);
            std::fs::remove_dir_all(local_root)?;
        }
        assert_eq!(Sha256::digest(std::fs::read(&archive_path)?), original_hash);
        drop(source);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn unmatched_archive_copy_keeps_known_marker_authority() -> TestResult {
    let (root, source) = crate::tests::test_db("mac-known-unmatched-copy")?;
    seed_deleted(&source)?;
    let target_path = root.join("known.db");
    let target_snapshot = source.write_backup_snapshot(&target_path)?;
    source.connection.execute_batch(
        "DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version=14;",
    )?;
    let archive_path = root.join("archive.db");
    let snapshot = source.write_backup_snapshot(&archive_path)?;
    let stage = BackupDatabase::open_restore_input(
        &archive_path,
        &snapshot.key,
        crate::BackupOpenMode::PreNormalization,
    )?;
    drop(stage);
    let mut target = BackupDatabase::open(&target_path, &target_snapshot.key)?;
    for _ in 0..2 {
        target.merge_backup(&archive_path, &snapshot.key, || Ok(()))?;
    }
    assert_eq!(merge::load_set(&target.db, "main")?.len(), 1);
    assert_eq!(
        target.db.query_row(
            "SELECT count(*) FROM account_mac_legacy_origin WHERE kind='marker'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    let (restored, _) = install(&root.join("installed"), &target)?;
    assert_deleted(&restored)?;
    drop(restored);
    drop(target);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
