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
