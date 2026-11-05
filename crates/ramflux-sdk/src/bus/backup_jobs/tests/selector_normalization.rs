// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate installation through encrypted private generations and durable index publication.
use super::*;
use crate::bus::backup_jobs::{format, service::BackupJobs, test_install::InstallPoint};
use ramflux_storage::{BackupDatabase, BackupOpenMode};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug)]
enum PathKind {
    Fresh,
    Full,
    Native,
}

fn raw(path: &Path, key: &ramflux_storage::AccountDbKey) -> TestResult<rusqlite::Connection> {
    use std::fmt::Write;
    let mut hex = zeroize::Zeroizing::new(String::new());
    for b in key.bytes() {
        write!(&mut *hex, "{b:02x}")?;
    }
    let db = rusqlite::Connection::open(path)?;
    let sql = zeroize::Zeroizing::new(format!("PRAGMA key=\"x'{}'\"", hex.as_str()));
    db.execute_batch(&sql)?;
    Ok(db)
}

fn producers(client: &mut RamfluxClient) -> TestResult {
    client.account_db()?.send_direct_message("thread", "owner", "peer", b"body")?;
    client.account_db()?.send_direct_message("thread", "other-owner", "peer", b"body")?;
    client.prepare_history_transport("history-owned", br#"{"message_id":"owner"}"#, &[])?;
    let object = client.put_encrypted_object("attachment-owned", b"attachment")?;
    let mut sender = ramflux_crypto::DmSession::initiator([7; 32], [1; 32], [2; 32], [3; 32])?;
    let slot = crate::SdkObjectKeySlot {
        schema: "ramflux.sdk.object_key_slot.dm.v1".into(),
        version: 1,
        object_id: object.object_id.clone(),
        conversation_id: "thread".into(),
        recipient_device_id: "device".into(),
        source_principal_commitment: None,
        x3dh: None,
        ciphertext: sender.encrypt(&[9; 32], b"fixture")?,
    };
    let reference = SdkDmAttachmentRef {
        schema: "ramflux.sdk.dm_attachment_ref.v1".into(),
        version: 1,
        object_id: object.object_id,
        manifest_hash: object.manifest_hash,
        plaintext_hash: object.plaintext_hash,
        cipher_size: object.ciphertext.len() as u64,
        chunk_size: 64,
        total_chunks: 1,
        relay_endpoint: "https://relay.invalid".into(),
        owner_home_node_id: None,
        relay_audience_node_id: None,
        owner_principal_id: "peer".into(),
        owner_device_epoch: 1,
        access_grant: None,
        key_slot: slot,
    };
    client.persist_received_reference_prepared(&reference, "peer", "thread", "owner", None)?;
    Ok(())
}

fn run(
    kind: PathKind,
    version: i64,
    unwrapped: bool,
    fault: Option<InstallPoint>,
    invalid: Option<&str>,
) -> TestResult {
    OPEN_LOG.with(|log| log.borrow_mut().clear());
    let source_root = tempfile::tempdir()?;
    let target_root = tempfile::tempdir()?;
    let source_index = AccountIndex::open(source_root.path())?;
    let mut state = initialized_at_scale(
        source_root.path(),
        source_index,
        Scale { messages: 1, contacts: 0, groups: 0, file_bytes: None },
    )?;
    producers(&mut state.client)?;
    if matches!(kind, PathKind::Fresh) {
        fresh_restrictions(&mut state.client)?;
    }
    if matches!(kind, PathKind::Native) {
        drop(state);
        return native_case(
            source_root.path(),
            target_root.path(),
            (version, unwrapped, fault, invalid),
        );
    }
    let id = "alice";
    let manifest =
        read_local_bus_account_manifest(&local_bus_account_manifest_path(source_root.path(), id))?;
    let identity = format::Identity::Legacy { manifest: Box::new(manifest) };
    let target_index = AccountIndex::open(target_root.path())?;
    if matches!(kind, PathKind::Full) {
        initialize_local(target_root.path(), &target_index)?;
        prepare_local_inherited(version, target_root.path(), &target_index)?;
    }
    let jobs = BackupJobs::new(target_root.path(), target_index.clone())?;
    let job = jobs.start(
        crate::backup::BackupJobKind::Restore,
        target_root.path().join("archive.rfb").to_string_lossy().into_owned(),
    )?;
    let dir = jobs.directory(&job.job_id)?;
    let path = dir.join("account.db");
    let saved = state.client.account_db()?.write_backup_snapshot(&path)?;
    drop(state);
    prepare_input(&path, &saved.key, version, unwrapped, invalid)?;
    check_input(&path, &saved.key)?;
    let before = std::fs::read(&path)?;
    let source_copy = source_root.path().join("unchanged.db");
    std::fs::write(&source_copy, &before)?;
    std::fs::copy(&source_copy, &path)?;
    let metadata = format::Metadata {
        identity,
        database_key: *saved.key.bytes(),
        ca_pem: b"test-ca".to_vec(),
    };
    let staging = worker_staging(&jobs, &job, &dir, &metadata)?;
    let archive_before = std::fs::read(&job.path)?;
    let previous = target_index.account(id).ok().map(|r| r.db_relative_path);
    let seen = install_hook(&jobs, &target_index, id, fault)?;
    let result = jobs.install_generation_mode(&job, staging, None, None, true);
    assert_eq!(std::fs::read(&job.path)?, archive_before);
    if invalid.is_some() {
        assert!(matches!(
            result,
            Err(SdkError::Storage(
                ramflux_storage::StorageError::ObjectOwnershipUnverified { .. }
                    | ramflux_storage::StorageError::AuthorizationRejected
            ))
        ));
    } else if fault.is_some() {
        assert!(result.is_err());
    } else {
        result?;
    }
    assert_eq!(std::fs::read(&source_copy)?, before);
    let selected = target_index.account(id).ok().map(|r| r.db_relative_path);
    if fault == Some(InstallPoint::BeforeCommit) || invalid.is_some() {
        assert_eq!(selected, previous);
    } else {
        assert!(selected.is_some());
        assert_installed(&target_index, target_root.path(), id, b"account-test-secret")?;
    }
    if invalid.is_none() {
        let seen = seen.lock().map_err(|_| "seen")?;
        assert!(seen.contains(&fault.unwrap_or(InstallPoint::BeforeCommit)));
    }
    Ok(())
}

fn corrupt(db: &rusqlite::Connection, what: &str) -> TestResult {
    match what {
        "hash" => {
            db.execute_batch("UPDATE object_message_reference SET reference_hash='wrong' WHERE reference_hash IN (SELECT reference_hash FROM object_retention_reference WHERE selector='history-owned'); UPDATE object_reference_actor SET reference_hash='wrong' WHERE reference_hash IN (SELECT reference_hash FROM object_retention_reference WHERE selector='history-owned'); UPDATE object_retention_reference SET reference_hash='wrong' WHERE selector='history-owned';")?;
        }
        "owner" => {
            db.execute("UPDATE object_message_reference SET message_id='other-owner' WHERE reference_hash IN (SELECT reference_hash FROM object_retention_reference WHERE selector='history-owned')",[])?;
        }
        _ => {
            db.execute("UPDATE object_retention_reference SET reference_json=x'7b7d' WHERE selector='attachment-owned'",[])?;
            db.execute("UPDATE object_message_reference SET metadata_json=x'7b7d' WHERE reference_hash IN (SELECT reference_hash FROM object_retention_reference WHERE selector='attachment-owned')",[])?;
        }
    }
    Ok(())
}
fn assert_clean(db: &rusqlite::Connection) -> TestResult {
    assert_eq!(
        db.query_row("SELECT count(*) FROM object_index WHERE object_id='unowned'", [], |r| r
            .get::<_, u64>(0))?,
        0,
        "omit unresolved placeholder"
    );
    assert_eq!(db.query_row("SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/unowned'",[],|r|r.get::<_,u64>(0))?,0,"fresh normalization must omit inherited actor");
    assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name IN ('backup_reference_admission','backup_selector_admission','backup_lookup_origin','backup_target_delete')",[],|r|r.get::<_,u64>(0))?,0);
    assert_eq!(db.query_row("SELECT count(*) FROM object_message_reference m JOIN object_retention_reference r USING(reference_hash) WHERE m.message_id='owner' AND r.selector IN ('history-owned','attachment-owned')",[],|r|r.get::<_,u64>(0))?,2);
    let transport: (String,String,String) = db.query_row("SELECT r.reference_hash,p.wire_id,p.manifest_hash FROM object_retention_reference r JOIN object_retention_payload p USING(commitment) WHERE r.selector='history-owned' AND CAST(r.reference_json AS TEXT)='{}' AND p.retention_class='transport'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    assert_eq!(
        transport.0,
        ramflux_crypto::blake3_256_base64url(
            "ramflux.object.transport.owner.v1",
            &ramflux_protocol::canonical_json_bytes(&(&transport.1, &transport.2, "owner"))?
        )
    );
    let retired: u64 = db.query_row("SELECT count(*) FROM direct_message_projection WHERE message_id='retired-owner' AND deleted=0",[],|r|r.get(0))?;
    assert_eq!(retired, 0, "single-input marker authority must delete stale projection");
    for table in ["object_erasure_work", "object_reference_erasure_work"] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get::<_, u64>(0))?,
            0
        );
    }
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
                    assert!(
                        !b.windows(b"normalization-only-canary".len())
                            .any(|w| w == b"normalization-only-canary"),
                        "retired canary in {table}"
                    );
                }
            }
        }
    }

    Ok(())
}
fn install_hook(
    jobs: &BackupJobs,
    index: &AccountIndex,
    id: &str,
    fault: Option<InstallPoint>,
) -> TestResult<Arc<Mutex<Vec<InstallPoint>>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = seen.clone();
    let index = index.clone();
    let locks = jobs.generations.clone();
    let id = id.to_owned();
    *jobs.install_hook.lock().map_err(|_| "hook")? = Some(Arc::new(move |point, _| {
        capture.lock().map_err(|_| std::io::ErrorKind::Other)?.push(point);
        if matches!(point, InstallPoint::BeforeCommit | InstallPoint::Committed) {
            let writer_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(index.root().join("accounts").join(&id).join(".writer.lock"))?;
            assert!(writer_file.try_lock().is_err(), "writer lease released before publication");
            assert!(
                locks.try_acquire(&id).map_err(|_| std::io::ErrorKind::Other)?.is_none(),
                "generation lease released before publication"
            );
        }
        if Some(point) == fault {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }));
    Ok(seen)
}

fn run_native(
    client: RamfluxClient,
    identity: format::Identity,
    input: (
        ramflux_storage::AccountBackupSnapshot,
        Option<crate::bus::backup_jobs::NativeInstallKey>,
    ),
    snapshot: &Path,
    root: &Path,
    case: (i64, bool, Option<InstallPoint>, Option<&str>),
) -> TestResult {
    let (saved, key) = input;
    let (version, unwrapped, fault, invalid) = case;
    let index = client.account_index()?.clone();
    let jobs = BackupJobs::new(root, index.clone())?;
    let job = jobs.start(
        crate::backup::BackupJobKind::Restore,
        root.join("archive.rfb").to_string_lossy().into_owned(),
    )?;
    let dir = jobs.directory(&job.job_id)?;
    let before = std::fs::read(snapshot)?;
    std::fs::copy(snapshot, dir.join("account.db"))?;
    prepare_input(&dir.join("account.db"), &saved.key, version, unwrapped, invalid)?;
    check_input(&dir.join("account.db"), &saved.key)?;
    let metadata =
        format::Metadata { identity, database_key: *saved.key.bytes(), ca_pem: Vec::new() };
    let staging = worker_staging(&jobs, &job, &dir, &metadata)?;
    let archive_before = std::fs::read(&job.path)?;
    let previous = index.account("account")?.db_relative_path;
    drop(client);
    let seen = install_hook(&jobs, &index, "account", fault)?;
    let result = jobs.install_generation_mode(&job, staging, key, None, true);
    assert_eq!(std::fs::read(&job.path)?, archive_before);
    assert_eq!(std::fs::read(snapshot)?, before);
    if invalid.is_some() {
        assert!(matches!(
            result,
            Err(SdkError::Storage(
                ramflux_storage::StorageError::ObjectOwnershipUnverified { .. }
                    | ramflux_storage::StorageError::AuthorizationRejected
            ))
        ));
    } else if fault.is_some() {
        assert!(result.is_err());
    } else {
        result?;
    }
    if fault == Some(InstallPoint::BeforeCommit) || invalid.is_some() {
        assert_eq!(index.account("account")?.db_relative_path, previous);
    } else {
        assert_installed(&index, root, "account", b"local-secret")?;
    }
    if invalid.is_none() {
        assert!(seen.lock().map_err(|_| "seen")?.contains(&InstallPoint::BeforeCommit));
    }
    Ok(())
}

#[test]
fn e14_fresh_full_restore_normalizes_before_index_selection() -> TestResult {
    run(PathKind::Fresh, 14, false, None, None)
}
#[test]
fn e14_full_restore_local_then_merge_normalized() -> TestResult {
    run(PathKind::Full, 14, false, None, None)
}
#[test]
fn e14_native_data_restore_uses_two_input_classification() -> TestResult {
    run(PathKind::Native, 14, false, None, None)
}
#[test]
fn e14_fault_before_index_selection() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        run(k, 14, false, Some(InstallPoint::BeforeCommit), None)?;
    }
    Ok(())
}
#[test]
fn e14_fault_after_index_commit() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        run(k, 14, false, Some(InstallPoint::Committed), None)?;
    }
    Ok(())
}
#[test]
fn e14_transport_owner_reference_restores_full_native_fresh() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        for version in [12, 14] {
            run(k, version, false, None, None)?;
        }
    }
    Ok(())
}
#[test]
fn e14_wrapped_and_unwrapped_attachment_references_restore() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        for version in [12, 14] {
            for unwrapped in [false, true] {
                run(k, version, unwrapped, None, None)?;
            }
        }
    }
    Ok(())
}
#[test]
fn e14_reference_validation_rejects_hash_owner_domain_substitution() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        for what in ["hash", "owner", "domain"] {
            run(k, 14, false, None, Some(what))?;
        }
    }
    Ok(())
}

fn native_case(
    source_root: &Path,
    target_root: &Path,
    case: (i64, bool, Option<InstallPoint>, Option<&str>),
) -> TestResult {
    let (version, unwrapped, fault, invalid) = case;
    let vault = crate::custody::tests::TestVault::default();
    let account = crate::custody::tests::create(
        target_root,
        "account",
        &vault,
        crate::custody::network_now()?,
    )?;
    let mut client = RamfluxClient::new();
    client.open_account_index(target_root)?;
    client.seal_new_account_data(
        "account",
        &account.record().body.account_anchor,
        b"local-secret",
    )?;
    client.unlock_account("account", b"local-secret")?;
    producers(&mut client)?;
    // The native archive and target must share their independently held anchor.
    let identity = crate::bus::backup_jobs::capture_identity(&client, target_root, "account")?;
    let key = crate::bus::backup_jobs::install::existing_key(
        client.account_index()?,
        target_root,
        "account",
        b"local-secret",
    )?;
    let native_key =
        Some(crate::bus::backup_jobs::NativeInstallKey { account_id: "account".into(), key });
    let snapshot = source_root.join("native-source.db");
    let saved = client.account_db()?.write_backup_snapshot(&snapshot)?;
    BackupDatabase::open(&snapshot, &saved.key)?.sanitize_native_backup()?;
    if version == 13 {
        let path = target_root.join(client.account_index()?.account("account")?.db_relative_path);
        prepare_input(&path, &native_key.as_ref().ok_or("key")?.key, 13, false, None)?;
    }
    run_native(
        client,
        identity,
        (saved, native_key),
        &snapshot,
        target_root,
        (version, unwrapped, fault, invalid),
    )
}
fn prepare_input(
    path: &Path,
    key: &ramflux_storage::AccountDbKey,
    version: i64,
    unwrapped: bool,
    invalid: Option<&str>,
) -> TestResult {
    let db = raw(path, key)?;
    if version <= 13 {
        // Same pre-v13 ledger reconstruction as storage's selector_upgrade_tests:
        // v13 has no table/column changes; remove its candidate index and v14 bundle.
        db.execute_batch("DROP TABLE account_mac_bundle; DELETE FROM schema_migration WHERE schema_version>12; DROP INDEX IF EXISTS runtime_outbox_object_selector; UPDATE schema_migration SET checksum='2026-06-14-account-core-v1;writer-floor=12;object-erasure-v1' WHERE schema_version=1;")?;
    }
    let retired: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_retention_reference WHERE selector='retired-history')",
        [],
        |r| r.get(0),
    )?;
    if retired {
        let marker =
            ramflux_crypto::blake3_256_base64url("ramflux.deleted-message.v1", b"retired-owner");
        db.execute(
            "INSERT INTO runtime_actor_state VALUES(?1,x'7b7d')",
            [format!("message/deleted/{marker}")],
        )?;
    }
    db.execute("INSERT OR IGNORE INTO object_erasure_fence SELECT commitment FROM object_retention_payload WHERE wire_id='fenced-history'",[])?;
    if unwrapped {
        db.execute("UPDATE object_retention_reference SET reference_json=CAST(json_extract(CAST(reference_json AS TEXT),'$.reference') AS BLOB) WHERE selector='attachment-owned'",[])?;
    }
    if let Some(invalid) = invalid {
        corrupt(&db, invalid)?;
    }
    db.execute(
        "INSERT INTO runtime_actor_state VALUES('attachment/reference/unowned',?1)",
        rusqlite::params![br#"{"private":"normalization-only-canary"}"#.as_slice()],
    )?;
    db.execute("INSERT INTO object_index(object_id,chunk_manifest_hash,object_state,total_cipher_size,chunk_count,created_at,updated_at,manifest_hash,nonce,ciphertext,tombstoned) VALUES('unowned',zeroblob(32),'revoked',0,0,1,1,zeroblob(32),'',x'',1)",[])?;
    drop(db);
    assert_eq!(db_count_unowned(path, key)?, 1);
    if version == 13 {
        drop(BackupDatabase::open_live_restore_input(path, key)?);
    }
    Ok(())
}

fn initialize_local(root: &Path, index: &AccountIndex) -> TestResult {
    drop(initialized_at_scale(
        root,
        index.clone(),
        Scale { messages: 1, contacts: 0, groups: 0, file_bytes: None },
    )?);
    // Each independent fixture encrypted `file` randomly; it is not a shared identity.
    let key = crate::bus::backup_jobs::install::existing_key(
        index,
        root,
        "alice",
        b"account-test-secret",
    )?;
    let db = raw(&root.join(index.account("alice")?.db_relative_path), &key)?;
    db.execute_batch("DELETE FROM object_index WHERE object_id='file'; DELETE FROM object_manifest WHERE object_id='file'; DELETE FROM object_chunk WHERE object_id='file'; DELETE FROM object_key_slot WHERE object_id='file'; DELETE FROM object_retention_payload WHERE wire_id='file';")?;
    Ok(())
}

fn fresh_restrictions(client: &mut RamfluxClient) -> TestResult {
    client.account_db()?.send_direct_message(
        "thread",
        "retired-owner",
        "peer",
        b"normalization-only-canary",
    )?;
    client.prepare_history_transport(
        "retired-history",
        br#"{"message_id":"retired-owner"}"#,
        &[],
    )?;
    let fenced =
        client.prepare_history_transport("fenced-history", br#"{"message_id":"owner"}"#, &[])?;
    client.account_db()?.persist_actor_state(
            "attachment/upload/fenced",
            &json!({"wire_object_id":"fenced-history","manifest_hash":fenced.manifest_hash,"content_key":"normalization-only-canary"}),
        )?;
    Ok(())
}

fn db_count_unowned(path: &Path, key: &ramflux_storage::AccountDbKey) -> TestResult<u64> {
    Ok(raw(path, key)?.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind='attachment/reference/unowned'",
        [],
        |r| r.get(0),
    )?)
}
fn check_input(path: &Path, key: &ramflux_storage::AccountDbKey) -> TestResult {
    let db = raw(path, key)?;
    let version: i64 =
        db.query_row("SELECT max(schema_version) FROM schema_migration", [], |r| r.get(0))?;
    drop(db);
    // Snapshot expected counts before the worker's private schema advance.
    let copy = path.with_extension("original.db");
    std::fs::copy(path, &copy)?;
    let input = BackupDatabase::open_restore_input(&copy, key, BackupOpenMode::PreNormalization)?;
    let counts = input.original_input().counts.clone();
    drop(input);
    std::fs::remove_file(&copy)?;
    std::fs::copy(path, &copy)?;
    let checked = crate::bus::backup_jobs::workers::open_checked_input(
        &copy,
        key,
        &counts,
        BackupOpenMode::PreNormalization,
    )
    .map_err(|e| format!("check worker: {e:?}"))?;
    assert_eq!(checked.original_input().schema_version, version);
    assert_eq!(checked.original_input().unowned_legacy_actor_count, 1);
    assert_eq!(checked.counts()?, counts);
    let copy = path.with_extension("reopen.db");
    checked.copy_to(&copy, key)?;
    let reopened = checked.reopen_restore_input(&copy, key, BackupOpenMode::PreNormalization)?;
    assert_eq!(reopened.original_input(), checked.original_input());
    assert!(reopened.reopen_restore_input(&copy, key, BackupOpenMode::Normalized).is_err());
    drop(reopened);
    std::fs::remove_file(copy)?;
    Ok(())
}

#[test]
fn e14_v12_unowned_actor_with_placeholder_check_and_install_omits() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        run(k, 12, false, None, None)?;
    }
    Ok(())
}
#[test]
fn e14_p1_upgraded_target_inherited_unowned_state_restores() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        run(k, 13, false, None, None)?;
    }
    Ok(())
}
#[test]
fn e14_every_intermediate_reopen_reaches_normalization_before_strict_validation() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        run(k, 12, false, None, None)?;
    }
    Ok(())
}
#[test]
fn e14_malformed_authenticated_graph_still_refuses_atomically() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        run(k, 12, false, None, Some("hash"))?;
    }
    Ok(())
}
#[test]
fn e14_source_archive_hash_unchanged() -> TestResult {
    for k in [PathKind::Fresh, PathKind::Full, PathKind::Native] {
        run(k, 12, false, Some(InstallPoint::BeforeCommit), None)?;
        run(k, 12, false, None, None)?;
    }
    Ok(())
}

thread_local! { static OPEN_LOG: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) }; }
pub(in crate::bus::backup_jobs) fn record_open(event: &'static str) {
    OPEN_LOG.with(|log| log.borrow_mut().push(event));
}
fn assert_open_order() {
    OPEN_LOG.with(|log| {
        let log = log.borrow();
        assert_eq!(log.first(), Some(&"worker-input"));
        let normalized = log.iter().position(|e| *e == "normalized").unwrap_or(usize::MAX);
        assert!(normalized < log.len(), "normalization boundary: {log:?}");
        let strict = log.iter().position(|e| *e == "strict").unwrap_or(usize::MAX);
        assert!(strict < log.len(), "strict reopen: {log:?}");
        assert!(normalized < strict, "{log:?}");
        assert!(log[..normalized].contains(&"stage"), "{log:?}");
        assert!(!log[..normalized].contains(&"strict"), "{log:?}");
    });
}

fn worker_staging(
    jobs: &BackupJobs,
    job: &BackupJob,
    dir: &Path,
    metadata: &format::Metadata,
) -> TestResult<crate::backup::VerifiedBackupStaging> {
    use ramflux_crypto::backup_stream::{BackupContext, encrypt_backup_stream};
    let path = dir.join("account.db");
    let key = ramflux_storage::AccountDbKey::from_bytes(metadata.database_key);
    let count_path = dir.join("count-copy.db");
    std::fs::copy(&path, &count_path)?;
    let counts =
        BackupDatabase::open_restore_input(&count_path, &key, BackupOpenMode::PreNormalization)?
            .counts()?;
    std::fs::remove_file(count_path)?;
    let totals = crate::bus::backup_jobs::workers::archive_totals(
        &counts,
        std::fs::metadata(&path)?.len(),
        0,
    )
    .map_err(|e| format!("totals: {e:?}"))?;
    let context = BackupContext {
        account_id: metadata.identity.account_id().into(),
        created_at: crate::bus::backup_jobs::service::now(),
        totals,
    };
    let secret = "staged-upgrade-recovery-secret";
    let mut output = std::fs::File::create(&job.path)?;
    encrypt_backup_stream(
        &mut format::payload(metadata, &path)?,
        &mut output,
        secret.as_bytes(),
        context,
    )?;
    drop(output);
    let original = std::fs::read(&job.path)?;
    std::fs::remove_dir_all(dir)?;
    jobs.verify_archive_mode(job, zeroize::Zeroizing::new(secret.into()), true)
        .map_err(|e| format!("real check worker: {e:?}"))?;
    assert_eq!(std::fs::read(&job.path)?, original);
    let (_, staging) = jobs.begin_install(&job.job_id)?;
    Ok(staging)
}

fn prepare_local_inherited(version: i64, root: &Path, index: &AccountIndex) -> TestResult {
    if version == 13 {
        let key = crate::bus::backup_jobs::install::existing_key(
            index,
            root,
            "alice",
            b"account-test-secret",
        )?;
        prepare_input(&root.join(index.account("alice")?.db_relative_path), &key, 13, false, None)?;
    }
    Ok(())
}

fn assert_installed(index: &AccountIndex, root: &Path, id: &str, secret: &[u8]) -> TestResult {
    let key = crate::bus::backup_jobs::install::existing_key(index, root, id, secret)?;
    let path = root.join(index.account(id)?.db_relative_path);
    let strict = BackupDatabase::open(&path, &key)?;
    strict.check_integrity()?;
    assert_clean(&raw(&path, &key)?)?;
    assert_open_order();
    drop(strict);
    let live = ramflux_storage::AccountDb::open(index, id, &key)?;
    live.checkpoint_retired_secrets()?;
    let snapshot_path = root.join("post-normalization-snapshot.db");
    let saved = live.write_backup_snapshot(&snapshot_path)?;
    BackupDatabase::open(&snapshot_path, &saved.key)?.check_integrity()?;
    assert_clean(&raw(&snapshot_path, &saved.key)?)?;
    Ok(())
}

#[path = "selector_review_r2.rs"]
mod review_r2;
