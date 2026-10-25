// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_storage::BackupCounts;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn staged(now: u64) -> Result<VerifiedBackup, Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "rf-backup-stage-{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    std::fs::create_dir(&path)?;
    std::fs::write(path.join("encrypted.dat"), b"encrypted fixture")?;
    Ok(VerifiedBackup {
        preview: BackupArchivePreview {
            local_account_id: "restored-account".into(),
            account_label: Some("Archive".into()),
            created_at: 17,
            merge: false,
        },
        counts: BackupCounts {
            contacts: 1001,
            messages: 10001,
            groups: 201,
            attachments: 3,
            attachment_bytes: 1_000_000_000,
            ..BackupCounts::default()
        },
        archive_bytes: 42,
        checks: BackupAttachmentChecks { verified: 3, ..BackupAttachmentChecks::default() },
        staging: VerifiedBackupStaging::new(path, [91; 32], now)?,
    })
}
#[test]
fn daemon_job_rows_are_secret_free_and_advance_only_through_their_own_phases() -> TestResult {
    let mut registry = BackupJobRegistry::default();
    let created = registry.start(BackupJobKind::Backup, "archive.rfb".into(), 3)?;
    assert_eq!(created.state, BackupJobState::Preparing);
    assert!(registry.start(BackupJobKind::Restore, "other".into(), 3).is_err());
    assert!(registry.transition(&created.job_id, BackupJobState::Verified, 4).is_err());
    let writing = registry.writing(&created.job_id, BackupCounts::default(), 4)?;
    assert!(writing.seq > created.seq);
    let done = registry.written(&created.job_id, 17, 5)?;
    assert!(done.seq > writing.seq);
    assert_eq!(done.finished_at, Some(5));
    assert!(registry.cancel(&created.job_id, 6).is_err());
    let encoded = serde_json::to_string(&registry.jobs())?;
    for forbidden in ["passphrase", "root_seed", "account_secret", "staging_key", "rebind_key"] {
        assert!(!encoded.contains(forbidden));
    }
    let second = registry.start(BackupJobKind::Restore, "second".into(), 1)?;
    assert_eq!(
        registry.jobs()[0].job_id,
        second.job_id,
        "clock rollback must not change creation order"
    );
    Ok(())
}
#[test]
fn only_a_fully_verified_restore_can_install_and_installing_cannot_be_cancelled() -> TestResult {
    let mut registry = BackupJobRegistry::default();
    let job = registry.start(BackupJobKind::Restore, "restore.rfb".into(), 10)?;
    assert!(registry.install(&job.job_id, 11).is_err());
    let verified = registry.verified(&job.job_id, staged(10)?, 11)?;
    assert_eq!(verified.counts.as_ref().map(|c| c.messages), Some(10001));
    let (installing, stage) = registry.install(&job.job_id, 12)?;
    assert!(installing.seq > verified.seq);
    assert_eq!(installing.state, BackupJobState::Installing);
    assert!(registry.cancel(&job.job_id, 12).is_err());
    assert!(stage.directory().exists());
    let path = stage.directory().to_owned();
    drop(stage);
    assert!(!path.exists());
    Ok(())
}
#[test]
fn cancel_and_thirty_minute_expiry_destroy_staging_and_release_the_job_slot() -> TestResult {
    let mut registry = BackupJobRegistry::default();
    let job = registry.start(BackupJobKind::Restore, "restore".into(), 10)?;
    let archive = staged(10)?;
    let path = archive.staging.directory().to_owned();
    registry.verified(&job.job_id, archive, 11)?;
    assert!(registry.expire(1809).is_empty());
    assert!(registry.install(&job.job_id, 1810).is_err());
    let expired = registry.expire(1810);
    assert_eq!(expired.len(), 1);
    assert_eq!(
        expired[0].0.error.as_ref().map(|f| f.code),
        Some(BackupFailureCode::StagingExpired)
    );
    drop(expired);
    assert!(!path.exists());
    let next = registry.start(BackupJobKind::Restore, "next".into(), 1811)?;
    let archive = staged(1811)?;
    let path = archive.staging.directory().to_owned();
    registry.verified(&next.job_id, archive, 1812)?;
    let flag = registry.cancellation(&next.job_id)?;
    let (cancelled, discard) = registry.cancel(&next.job_id, 1813)?;
    assert!(flag.load(Ordering::Acquire));
    assert_eq!(cancelled.state, BackupJobState::Cancelled);
    drop(discard);
    assert!(!path.exists());
    Ok(())
}
#[test]
fn any_missing_or_mismatched_attachment_prevents_verified_staging() -> TestResult {
    for missing in [false, true] {
        let mut registry = BackupJobRegistry::default();
        let job = registry.start(BackupJobKind::Restore, "restore".into(), 0)?;
        let mut archive = staged(0)?;
        let path = archive.staging.directory().to_owned();
        if missing {
            archive.checks.missing = 1;
        } else {
            archive.checks.mismatched = 1;
        }
        assert!(registry.verified(&job.job_id, archive, 1).is_err());
        assert_eq!(registry.job(&job.job_id)?.state, BackupJobState::Verifying);
        assert!(!path.exists());
    }
    Ok(())
}
#[test]
fn failure_releases_verified_staging_and_kept_newer_is_a_per_category_object() -> TestResult {
    let mut registry = BackupJobRegistry::default();
    let job = registry.start(BackupJobKind::Restore, "restore".into(), 0)?;
    let archive = staged(0)?;
    let path = archive.staging.directory().to_owned();
    registry.verified(&job.job_id, archive, 1)?;
    let (failed, discard) =
        registry.fail(&job.job_id, BackupFailure::new(BackupFailureCode::RootConflict), 2)?;
    drop(discard);
    assert!(!path.exists());
    let mut row = failed;
    row.kept_newer = Some(BackupCounts { contacts: 3, messages: 4, ..BackupCounts::default() });
    let json = serde_json::to_value(&row)?;
    assert_eq!(json["kept_newer"]["contacts"], 3);
    assert_eq!(json["kept_newer"]["messages"], 4);
    assert_eq!(json["error"]["code"], "root_conflict");
    Ok(())
}
