// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified-stage metadata is mandatory and bound to rows, origin and legacy classification.
use super::*;
thread_local! { pub(super) static RETRY_UPGRADE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

pub(super) fn assert_observation_refused(change: &str) -> TestResult {
    let source = tempfile::tempdir()?;
    let target = tempfile::tempdir()?;
    let client = initialized_at_scale(
        source.path(),
        AccountIndex::open(source.path())?,
        Scale { messages: 1, contacts: 0, groups: 0, file_bytes: None },
    )?
    .client;
    let identity = crate::bus::backup_jobs::capture_identity(&client, source.path(), "alice")?;
    let index = AccountIndex::open(target.path())?;
    let jobs = BackupJobs::new(target.path(), index.clone())?;
    let job = jobs.start(crate::backup::BackupJobKind::Restore, "observation.rfb".into())?;
    let dir = jobs.directory(&job.job_id)?;
    let saved = client.account_db()?.write_backup_snapshot(&dir.join("account.db"))?;
    let mut observation = BackupDatabase::open_restore_input(
        &dir.join("account.db"),
        &saved.key,
        BackupOpenMode::PreNormalization,
    )?
    .original_input()
    .clone();
    match change {
        "schema" => {
            observation.schema_version = 12;
        }
        "unowned" => {
            observation.unowned_legacy_actor_count += 1;
        }
        "rows" => {
            raw(&dir.join("account.db"), &saved.key)?
                .execute("DELETE FROM direct_message_projection", [])?;
        }
        "missing" => {}
        _ => return Err("unknown observation cell".into()),
    }
    let metadata = format::Metadata {
        identity,
        database_key: *saved.key.bytes(),
        ca_pem: b"test-ca".to_vec(),
    };
    let master = [8; 32];
    format::save_metadata(&dir.join("identity.sealed"), &master, &metadata)?;
    let mut staging = crate::backup::VerifiedBackupStaging::new(
        dir.clone(),
        master,
        crate::bus::backup_jobs::service::now(),
    )?;
    if change != "missing" {
        staging = staging.with_input_observation(observation);
    }
    let result = jobs.install_generation_mode(&job, staging, None, None, true);
    assert!(
        matches!(
            result,
            Err(SdkError::Storage(ramflux_storage::StorageError::AuthorizationRejected))
        ),
        "observation cell {change} must refuse: {result:?}"
    );
    assert!(index.account("alice").is_err());
    assert!(!dir.exists(), "refused staging must be discarded by production ownership");
    Ok(())
}

#[test]
fn candidate_install_requires_original_observation() -> TestResult {
    assert_observation_refused("missing")
}
#[test]
fn candidate_install_refuses_changed_staged_rows_and_classification() -> TestResult {
    for change in ["rows", "unowned"] {
        assert_observation_refused(change)?;
    }
    Ok(())
}
#[test]
fn e14_staged_v12_upgrade_rollback() -> TestResult {
    RETRY_UPGRADE.set(true);
    let result = run(PathKind::Fresh, 12, false, None, None);
    RETRY_UPGRADE.set(false);
    result
}
