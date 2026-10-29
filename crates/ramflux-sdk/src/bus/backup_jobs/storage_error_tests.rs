// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore checks and installation use the same exhaustive storage policy.
use crate::backup::{BackupFailureCode, BackupJob, BackupJobKind};
use crate::storage_failure_fixture::{Fault, Fixture, TestResult};

fn check(fault: Fault, code: BackupFailureCode) -> TestResult {
    let fixture = Fixture::new(fault)?;
    let jobs = super::BackupJobs::new(fixture.root(), fixture.index.clone())?;
    let metadata = super::format::Metadata {
        manifest: fixture.manifest.clone(),
        database_key: [0; 32],
        ca_pem: Vec::new(),
    };
    let Err(failure) = jobs.check_existing_identity(
        &metadata,
        &fixture.root().join("unused-incoming"),
        &ramflux_storage::AccountDbKey::from_bytes([0; 32]),
    ) else {
        return Err("faulted account must fail before staging reads".into());
    };
    assert_eq!(failure.code, code);
    assert_eq!(failure.retryable, matches!(fault, Fault::Busy));

    let error = fixture.error()?;
    match (&error, fault) {
        (ramflux_storage::StorageError::AccountWriterBusy(_), Fault::Busy)
        | (ramflux_storage::StorageError::Io(_), Fault::Io)
        | (ramflux_storage::StorageError::Integrity(_), Fault::Integrity) => {}
        other => return Err(format!("unexpected storage classification: {other:?}").into()),
    }
    let job = jobs.start(BackupJobKind::Restore, "archive.rfb".into())?;
    let directory = jobs.directory(&job.job_id)?;
    let staging_key = [7; 32];
    super::format::save_metadata(&directory.join("identity.sealed"), &staging_key, &metadata)?;
    let staging =
        crate::backup::VerifiedBackupStaging::new(directory, staging_key, super::service::now())?;
    let Err(install_error) = jobs.install_generation(&job, staging) else {
        return Err("faulted installation unexpectedly succeeded".into());
    };
    jobs.fail_install(&job.job_id, &install_error);
    let rows: Vec<BackupJob> = serde_json::from_value(jobs.jobs()?["jobs"].clone())?;
    let failure = rows
        .into_iter()
        .find(|row| row.job_id == job.job_id)
        .ok_or("job")?
        .error
        .ok_or("failure")?;
    assert_eq!(failure.code, code);
    assert_eq!(failure.retryable, matches!(fault, Fault::Busy));
    Ok(())
}

#[test]
fn backup_storage_policy_preserves_real_busy_on_restore_check_and_install() -> TestResult {
    check(Fault::Busy, BackupFailureCode::AccountBusy)
}
#[test]
fn backup_storage_policy_reports_real_lock_io_as_unreadable_on_restore_check_and_install()
-> TestResult {
    check(Fault::Io, BackupFailureCode::Unreadable)
}
#[test]
fn backup_storage_policy_reports_corrupted_mac_as_tampered_on_restore_check_and_install()
-> TestResult {
    check(Fault::Integrity, BackupFailureCode::Tampered)
}
