// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore checks and installation use the same exhaustive storage policy.
use crate::backup::{BackupFailureCode, BackupJob, BackupJobKind};
use crate::storage_failure_fixture::{Fault, Fixture, TestResult};

#[test]
fn restore_preservation_refusal_keeps_ownership_failure_code() -> TestResult {
    let fixture = Fixture::new(Fault::Busy)?;
    let jobs = super::BackupJobs::new(fixture.root(), fixture.index.clone())?;
    let error = ramflux_storage::StorageError::ObjectOwnershipUnverified { schema_version: 13 };
    let worker = super::workers::storage_error(&error);
    assert_eq!(worker.code, BackupFailureCode::ObjectOwnershipUnverified);
    assert!(!worker.retryable);
    let job = jobs.start(BackupJobKind::Restore, "archive.rfb".into())?;
    jobs.fail_install(&job.job_id, &crate::SdkError::Storage(error));
    let rows: Vec<BackupJob> = serde_json::from_value(jobs.jobs()?["jobs"].clone())?;
    let failure = rows
        .into_iter()
        .find(|row| row.job_id == job.job_id)
        .ok_or("job")?
        .error
        .ok_or("failure")?;
    assert_eq!(failure.code, BackupFailureCode::ObjectOwnershipUnverified);
    assert!(!failure.retryable);
    let authorization = super::workers::restore_storage_error(
        &ramflux_storage::StorageError::AuthorizationRejected,
    );
    assert_eq!(authorization.code, BackupFailureCode::AuthorizationRejected);
    assert!(!authorization.retryable);
    assert_eq!(
        super::workers::storage_error(&ramflux_storage::StorageError::AuthorizationRejected).code,
        BackupFailureCode::Unreadable
    );
    Ok(())
}
