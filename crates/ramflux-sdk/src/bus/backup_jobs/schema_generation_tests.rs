// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::backup::{BackupFailureCode, BackupJobKind};
use ramflux_crypto::backup_stream::{BackupContext, encrypt_backup_stream};
use ramflux_protocol::schema_profile::ARCHIVE_GENERATION_KEY;
use ramflux_storage::AccountIndex;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn schema_generation_refuses_mismatched_database_and_archive() -> TestResult {
    let root = crate::bus::runtime_tests::root("archive-generation");
    let index = AccountIndex::open(&root)?;
    let jobs = super::BackupJobs::new(&root, index)?;
    let path = root.join("future.rfb");
    let context = BackupContext {
        account_id: "acct".into(),
        created_at: 1,
        totals: BTreeMap::from([(ARCHIVE_GENERATION_KEY.into(), 1)]),
    };
    // Authenticated future-generation input deliberately has no valid payload or counts.
    // Refusal must precede both payload decoding and staging-directory allocation.
    let mut output = std::fs::File::create(&path)?;
    encrypt_backup_stream(
        &mut &b"invalid application payload"[..],
        &mut output,
        b"schema-generation-test-recovery-secret",
        context,
    )?;
    drop(output);
    let original = std::fs::read(&path)?;
    let job = jobs.start(BackupJobKind::Restore, path.to_string_lossy().into_owned())?;
    let failure = jobs
        .verify_archive(&job, Zeroizing::new("schema-generation-test-recovery-secret".into()))
        .err()
        .ok_or("refusal")?;
    assert_eq!(failure.code, BackupFailureCode::SchemaResetRequired);
    assert_eq!(std::fs::read(&path)?, original);
    assert!(!jobs.root.join(format!("job_{}", job.job_id)).exists());
    let storage =
        ramflux_storage::StorageError::SchemaResetRequired { generation: 1, supported: 0 };
    assert_eq!(
        super::workers::storage_error(&storage).code,
        BackupFailureCode::SchemaResetRequired
    );
    let sdk = crate::SdkError::Storage(storage);
    assert_eq!(crate::bus::io::local_bus_error_code(&sdk), "SchemaResetRequired");
    jobs.fail_install(&job.job_id, &sdk);
    let rows: Vec<crate::backup::BackupJob> = serde_json::from_value(jobs.jobs()?["jobs"].clone())?;
    assert_eq!(
        rows[0].error.as_ref().ok_or("install failure")?.code,
        BackupFailureCode::SchemaResetRequired
    );
    for generation in [None, Some(0), Some(1), Some(u64::MAX)] {
        let context = BackupContext {
            account_id: "acct".into(),
            created_at: 1,
            totals: generation
                .map(|value| BTreeMap::from([(ARCHIVE_GENERATION_KEY.into(), value)]))
                .unwrap_or_default(),
        };
        assert_eq!(
            super::workers::require_archive_generation(&context).is_ok(),
            generation.is_none_or(|value| value == 0)
        );
    }
    Ok(())
}
