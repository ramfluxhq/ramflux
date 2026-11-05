// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real legacy producers distinguish omission from losing an incoming restriction.
use super::*;
use ramflux_storage::{AccountDb, AccountDbKey};

const SELECTOR: &str = "private-canary";
const BODY: &[u8] = b"unowned-reference-body-canary";

fn client(root: &Path, native: bool) -> TestResult<RamfluxClient> {
    if !native {
        return Ok(initialized_at_scale(
            root,
            AccountIndex::open(root)?,
            Scale { messages: 1, contacts: 0, groups: 0, file_bytes: None },
        )?
        .client);
    }
    let vault = crate::custody::tests::TestVault::default();
    let account =
        crate::custody::tests::create(root, "account", &vault, crate::custody::network_now()?)?;
    let mut client = RamfluxClient::new();
    client.open_account_index(root)?;
    client.seal_new_account_data(
        "account",
        &account.record().body.account_anchor,
        b"local-secret",
    )?;
    client.unlock_account("account", b"local-secret")?;
    Ok(client)
}
fn legacy(db: &AccountDb, revoke: bool) -> TestResult {
    db.persist_actor_state("attachment/reference/private-canary", &json!({"reference":{"object_id":"wire","manifest_hash":"manifest"},"secret":"unowned-reference-body-canary"}))?;
    db.persist_client_record(
        "object",
        SELECTOR,
        &json!({"owner":"peer","message_id":"owner","manifest_hash":"manifest"}),
    )?;
    db.persist_actor_state("attachment/reference-by-slot/private-canary", &json!(SELECTOR))?;
    if revoke {
        db.set_object_tombstoned_with_revocation(SELECTOR, Some("peer"), Some("revoke"), 1)?;
    }
    Ok(())
}
fn archive(
    client: &RamfluxClient,
    root: &Path,
    id: &str,
    revoke: bool,
) -> TestResult<ramflux_storage::AccountBackupSnapshot> {
    let index = AccountIndex::open(root)?;
    index.create_account(id, &client.account_index()?.account(id)?.principal_commitment)?;
    let path = root.join(index.account(id)?.db_relative_path);
    std::fs::create_dir_all(path.parent().ok_or("parent")?)?;
    let seed = root.join("seed.db");
    let saved = client.account_db()?.write_backup_snapshot(&seed)?;
    let key = AccountDbKey::generate()?;
    BackupDatabase::open(&seed, &saved.key)?.copy_to(&path, &key)?;
    let source = AccountDb::open(&index, id, &key)?;
    legacy(&source, revoke)?;
    Ok(source.write_backup_snapshot(&root.join("archive.db"))?)
}
fn run_review(kind: PathKind, revoke: bool) -> TestResult {
    let original = tempfile::tempdir()?;
    let input = tempfile::tempdir()?;
    let fresh = tempfile::tempdir()?;
    let native = matches!(kind, PathKind::Native);
    let mut client = client(original.path(), native)?;
    producers(&mut client)?;
    let id = if native { "account" } else { "alice" };
    let identity = crate::bus::backup_jobs::capture_identity(&client, original.path(), id)?;
    let native_key = if native {
        Some(crate::bus::backup_jobs::NativeInstallKey {
            account_id: id.into(),
            key: crate::bus::backup_jobs::install::existing_key(
                client.account_index()?,
                original.path(),
                id,
                b"local-secret",
            )?,
        })
    } else {
        None
    };
    let saved = archive(&client, input.path(), id, revoke)?;
    let source = input.path().join("archive.db");
    if native {
        BackupDatabase::open_restore_input(&source, &saved.key, BackupOpenMode::PreNormalization)?
            .sanitize_native_backup()?;
    }
    let source_bytes = std::fs::read(&source)?;
    assert_input(&source, &saved.key, revoke)?;
    let root = if matches!(kind, PathKind::Fresh) { fresh.path() } else { original.path() };
    let index = AccountIndex::open(root)?;
    let previous = index.account(id).ok();
    let jobs = BackupJobs::new(root, index.clone())?;
    let job = jobs.start(crate::backup::BackupJobKind::Restore, "archive.rfb".into())?;
    let dir = jobs.directory(&job.job_id)?;
    std::fs::copy(&source, dir.join("account.db"))?;
    let metadata = format::Metadata {
        identity,
        database_key: *saved.key.bytes(),
        ca_pem: b"test-ca".to_vec(),
    };
    let master = [8; 32];
    format::save_metadata(&dir.join("identity.sealed"), &master, &metadata)?;
    let staging = crate::backup::VerifiedBackupStaging::new(
        dir,
        master,
        crate::bus::backup_jobs::service::now(),
    )?;
    drop(client);
    let result = jobs.install_generation_mode(&job, staging, native_key, None, true);
    assert_eq!(std::fs::read(&source)?, source_bytes);
    if revoke {
        assert!(
            matches!(
                result,
                Err(SdkError::Storage(
                    ramflux_storage::StorageError::ObjectOwnershipUnverified { .. }
                ))
            ),
            "incoming restriction must refuse atomically: {result:?}"
        );
        assert_eq!(index.account(id).ok(), previous);
    } else {
        result?;
        let key = crate::bus::backup_jobs::install::existing_key(
            &index,
            root,
            id,
            if native { b"local-secret" } else { b"account-test-secret" },
        )?;
        let path = root.join(index.account(id)?.db_relative_path);
        BackupDatabase::open(&path, &key)?.check_integrity()?;
        let live = AccountDb::open(&index, id, &key)?;
        live.checkpoint_retired_secrets()?;
        let copied = root.join("verified.db");
        let snapshot = live.write_backup_snapshot(&copied)?;
        for (path, key) in [(&path, &key), (&copied, &snapshot.key)] {
            let db = raw(path, key)?;
            assert_eq!(db.query_row("SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/private-canary'",[],|r|r.get::<_,u64>(0))?,0);
            scan(&db)?;
        }
    }
    Ok(())
}
fn assert_input(source: &Path, key: &AccountDbKey, revoke: bool) -> TestResult {
    let before = raw(source, key)?;
    assert_eq!(
        before.query_row(
            "SELECT count(*) FROM object_index WHERE object_id=?1 AND tombstoned=1",
            [SELECTOR],
            |r| r.get::<_, u64>(0)
        )?,
        u64::from(revoke)
    );
    assert_eq!(
        before.query_row(
            "SELECT count(*) FROM message_footprint WHERE kind='revocation_selector'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        u64::from(revoke)
    );
    assert_eq!(
        before.query_row(
            "SELECT count(*) FROM object_retention_reference WHERE selector=?1",
            [SELECTOR],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    if !revoke {
        for table in ["object_erasure_fence", "object_erasure_lookup"] {
            assert_eq!(
                before.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, u64>(0))?,
                0,
                "omission must not be masked by a fence or lookup"
            );
        }
    }
    drop(before);
    Ok(())
}
fn scan(db: &rusqlite::Connection) -> TestResult {
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for table in tables {
        let mut q = db.prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))?;
        let columns = q.column_count();
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            for c in 0..columns {
                if let rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) =
                    row.get_ref(c)?
                {
                    assert!(!b.windows(BODY.len()).any(|w| w == BODY), "unowned body in {table}");
                }
            }
        }
    }
    Ok(())
}
#[test]
fn incoming_legacy_revocation_refuses_full_and_native_install_atomically() -> TestResult {
    for kind in [PathKind::Full, PathKind::Native] {
        run_review(kind, true)?;
    }
    Ok(())
}
#[test]
fn unowned_reference_without_placeholder_omitted_full_native_fresh() -> TestResult {
    for kind in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        run_review(kind, false)?;
    }
    Ok(())
}

fn install_chain_fresh(
    root: &Path,
    source: &Path,
    saved: &ramflux_storage::AccountBackupSnapshot,
    identity: format::Identity,
) -> TestResult<(AccountIndex, AccountDbKey)> {
    let index = AccountIndex::open(root)?;
    let jobs = BackupJobs::new(root, index.clone())?;
    let job = jobs.start(crate::backup::BackupJobKind::Restore, "first.rfb".into())?;
    let dir = jobs.directory(&job.job_id)?;
    std::fs::copy(source, dir.join("account.db"))?;
    let metadata = format::Metadata {
        identity,
        database_key: *saved.key.bytes(),
        ca_pem: b"test-ca".to_vec(),
    };
    let master = [8; 32];
    format::save_metadata(&dir.join("identity.sealed"), &master, &metadata)?;
    let staging = crate::backup::VerifiedBackupStaging::new(
        dir,
        master,
        crate::bus::backup_jobs::service::now(),
    )?;
    jobs.install_generation_mode(&job, staging, None, None, true)?;
    let key = crate::bus::backup_jobs::install::existing_key(
        &index,
        root,
        "alice",
        b"account-test-secret",
    )?;
    Ok((index, key))
}
fn registration(db: &rusqlite::Connection) -> TestResult<(u64, u64, u64, u64)> {
    Ok((
        db.query_row("SELECT count(*) FROM object_index WHERE object_id='private-canary' AND tombstoned=1",[],|r|r.get(0))?,
        db.query_row("SELECT count(*) FROM message_footprint WHERE kind='revocation_selector' AND json_extract(locator,'$.selector')='private-canary'",[],|r|r.get(0))?,
        db.query_row("SELECT count(*) FROM message_copy_binding WHERE copy_id='object:private-canary'",[],|r|r.get(0))?,
        db.query_row("SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/private-canary'",[],|r|r.get(0))?,
    ))
}
#[test]
fn fresh_restore_backup_registered_placeholder_refuses_full_and_native_merge() -> TestResult {
    let original = tempfile::tempdir()?;
    let input = tempfile::tempdir()?;
    let fresh = tempfile::tempdir()?;
    let mut client = client(original.path(), false)?;
    producers(&mut client)?;
    let identity = crate::bus::backup_jobs::capture_identity(&client, original.path(), "alice")?;
    let first = archive(&client, input.path(), "alice", true)?;
    let first_path = input.path().join("archive.db");
    let first_bytes = std::fs::read(&first_path)?;
    let (index, key) = install_chain_fresh(fresh.path(), &first_path, &first, identity)?;
    assert_eq!(std::fs::read(&first_path)?, first_bytes);
    let installed = fresh.path().join(index.account("alice")?.db_relative_path);
    assert_eq!(registration(&raw(&installed, &key)?)?, (1, 1, 1, 0));
    let restored = AccountDb::open(&index, "alice", &key)?;
    restored.checkpoint_retired_secrets()?;
    let second_path = input.path().join("second-generation.db");
    let second = restored.write_backup_snapshot(&second_path)?;
    assert_eq!(registration(&raw(&second_path, &second.key)?)?, (1, 1, 1, 0));
    let second_bytes = std::fs::read(&second_path)?;
    let selected = client.account_index()?.account("alice")?;
    for native in [false, true] {
        let target_path =
            input.path().join(if native { "native-target.db" } else { "full-target.db" });
        let target = client.account_db()?.write_backup_snapshot(&target_path)?;
        let mut stage = BackupDatabase::open_restore_input(
            &target_path,
            &target.key,
            BackupOpenMode::PreNormalization,
        )?;
        let before = registration(&raw(&target_path, &target.key)?)?;
        assert_eq!(before, (0, 0, 0, 0), "target must predate the revocation");
        let result = if native {
            stage.merge_native_backup_candidate(&second_path, &second.key, || Ok(()))
        } else {
            stage.merge_backup_candidate(&second_path, &second.key, || Ok(()))
        };
        assert!(
            matches!(result, Err(ramflux_storage::StorageError::ObjectOwnershipUnverified { .. })),
            "registered second-generation input must refuse: {result:?}"
        );
        assert_eq!(registration(&raw(&target_path, &target.key)?)?, before);
        stage.check_integrity()?;
        assert_eq!(std::fs::read(&second_path)?, second_bytes);
        assert_eq!(client.account_index()?.account("alice")?, selected);
    }
    Ok(())
}

// Native restores require independently installed local authority. Seed only the
// private data generation with the same single-input normalizer used by fresh restore.
fn native_fresh_target(
    root: &Path,
    index: &AccountIndex,
    key: &AccountDbKey,
    source: &Path,
    saved: &ramflux_storage::AccountBackupSnapshot,
) -> TestResult {
    let previous = index.account("account")?;
    let directory = root.join("accounts/account/fresh-normalized");
    std::fs::create_dir_all(&directory)?;
    let target = directory.join("account.db");
    BackupDatabase::open_restore_input(source, &saved.key, BackupOpenMode::PreNormalization)?
        .copy_to(&target, key)?;
    let mut stage =
        BackupDatabase::open_restore_input(&target, key, BackupOpenMode::PreNormalization)?;
    stage.normalize_backup_candidate()?;
    stage.check_integrity()?;
    drop(stage);
    let wrapped = index.load_wrapped_db_key("account")?.ok_or("wrapped key")?;
    let marker = serde_json::to_vec(
        &json!({"schema":"ramflux.local.native_data_generation.v1","local_account_id":"account","account_anchor":previous.principal_commitment}),
    )?;
    index.install_backup_generation(&ramflux_storage::BackupIndexInstall {
        account_id: "account",
        principal_commitment: &previous.principal_commitment,
        db_relative_path: "accounts/account/fresh-normalized/account.db",
        object_relative_path: "accounts/account/fresh-normalized",
        manifest_json: &marker,
        wrapped_key: &wrapped,
    })?;
    Ok(())
}

fn restored_target_older_install(native: bool) -> TestResult {
    let original = tempfile::tempdir()?;
    let older_dir = tempfile::tempdir()?;
    let revoked_dir = tempfile::tempdir()?;
    let fresh = tempfile::tempdir()?;
    let mut client = client(original.path(), native)?;
    producers(&mut client)?;
    let id = if native { "account" } else { "alice" };
    let identity = crate::bus::backup_jobs::capture_identity(&client, original.path(), id)?;
    let older = archive(&client, older_dir.path(), id, false)?;
    let revoked = archive(&client, revoked_dir.path(), id, true)?;
    let older_path = older_dir.path().join("archive.db");
    let revoked_path = revoked_dir.path().join("archive.db");
    if native {
        BackupDatabase::open_restore_input(
            &older_path,
            &older.key,
            BackupOpenMode::PreNormalization,
        )?
        .sanitize_native_backup()?;
    }
    let older_bytes = std::fs::read(&older_path)?;
    let revoked_bytes = std::fs::read(&revoked_path)?;
    let (root, index, key) = if native {
        let index = client.account_index()?.clone();
        let key = crate::bus::backup_jobs::install::existing_key(
            &index,
            original.path(),
            id,
            b"local-secret",
        )?;
        drop(client);
        native_fresh_target(original.path(), &index, &key, &revoked_path, &revoked)?;
        (original.path(), index, key)
    } else {
        drop(client);
        // Capture an independent metadata value for the first SDK install.
        let first_identity = serde_json::from_slice(&serde_json::to_vec(&identity)?)?;
        let (index, key) =
            install_chain_fresh(fresh.path(), &revoked_path, &revoked, first_identity)?;
        (fresh.path(), index, key)
    };
    let before = index.account(id)?;
    let before_path = root.join(&before.db_relative_path);
    assert_eq!(registration(&raw(&before_path, &key)?)?, (1, 1, 1, 0));
    let jobs = BackupJobs::new(root, index.clone())?;
    let job = jobs.start(crate::backup::BackupJobKind::Restore, "older.rfb".into())?;
    let directory = jobs.directory(&job.job_id)?;
    std::fs::copy(&older_path, directory.join("account.db"))?;
    let metadata = format::Metadata {
        identity,
        database_key: *older.key.bytes(),
        ca_pem: b"test-ca".to_vec(),
    };
    let master = [8; 32];
    format::save_metadata(&directory.join("identity.sealed"), &master, &metadata)?;
    let staging = crate::backup::VerifiedBackupStaging::new(
        directory,
        master,
        crate::bus::backup_jobs::service::now(),
    )?;
    let native_key =
        native.then(|| crate::bus::backup_jobs::NativeInstallKey { account_id: id.into(), key });
    jobs.install_generation_mode(&job, staging, native_key, None, true)?;
    let selected = index.account(id)?;
    assert_ne!(selected.db_relative_path, before.db_relative_path);
    let selected_key = crate::bus::backup_jobs::install::existing_key(
        &index,
        root,
        id,
        if native { b"local-secret" } else { b"account-test-secret" },
    )?;
    let selected_path = root.join(&selected.db_relative_path);
    assert_eq!(registration(&raw(&selected_path, &selected_key)?)?, (1, 1, 1, 0));
    BackupDatabase::open(&selected_path, &selected_key)?.check_integrity()?;
    let restored = AccountDb::open(&index, id, &selected_key)?;
    restored.checkpoint_retired_secrets()?;
    let second_path = older_dir.path().join("second-generation.db");
    let second = restored.write_backup_snapshot(&second_path)?;
    assert_eq!(registration(&raw(&second_path, &second.key)?)?, (1, 1, 1, 0));
    assert_eq!(std::fs::read(&older_path)?, older_bytes);
    assert_eq!(std::fs::read(&revoked_path)?, revoked_bytes);
    Ok(())
}

#[test]
fn fresh_restored_target_keeps_revocation_on_older_full_and_native_install() -> TestResult {
    for native in [false, true] {
        restored_target_older_install(native)?;
    }
    Ok(())
}
