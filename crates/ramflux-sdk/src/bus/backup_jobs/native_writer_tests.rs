// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native restore retains public-evidence checks while refusing real writer faults.
use super::{AccountDbKey, BackupJobs, DataIdentity, Identity, Metadata, RamfluxClient};
use crate::storage_failure_fixture::{Fault, TestResult, apply_fault};

fn check(fault: Fault) -> TestResult {
    let root = crate::custody::tests::Root::new()?;
    let vault = crate::custody::tests::TestVault::default();
    let account =
        crate::custody::tests::create(&root.0, "acct", &vault, crate::custody::network_now()?)?;
    let mut client = RamfluxClient::new();
    client.open_account_index(&root.0)?;
    client.seal_new_account_data(
        "acct",
        &account.record().body.account_anchor,
        b"account-secret",
    )?;
    let index = client.account_index()?.clone();
    drop(client);
    let _holder = apply_fault(&index, fault)?;
    let jobs = BackupJobs::new(&root.0, index.clone())?;
    let metadata = Metadata {
        identity: Identity::Native {
            native: Box::new(DataIdentity {
                schema: "ramflux.backup.native_data.v1".into(),
                local_account_id: "acct".into(),
                authority: ramflux_protocol::custody::CustodyAuthority {
                    publication: account.publication(),
                    custodian_publication: None,
                },
            }),
        },
        database_key: [0; 32],
        ca_pem: Vec::new(),
    };
    let mut client = RamfluxClient::new();
    client.open_account_index(&root.0)?;
    let error =
        client.unlock_account("acct", b"account-secret").err().ok_or("native unlock must fail")?;
    let expected_bus = match fault {
        Fault::Busy => "account_busy",
        Fault::Io => "storage_unavailable",
        Fault::Integrity => "ValidationFailed",
    };
    assert_eq!(crate::bus::io::local_bus_error_code(&error), expected_bus);
    let preview = jobs.check_existing_identity(
        &metadata,
        &root.0.join("unused"),
        &AccountDbKey::from_bytes([0; 32]),
    );
    if matches!(fault, Fault::Integrity) {
        // Native preview checks independent public evidence, without unwrapping local data keys.
        assert_eq!(preview, Ok(true));
        return Ok(());
    }
    let expected = if matches!(fault, Fault::Busy) {
        crate::backup::BackupFailureCode::AccountBusy
    } else {
        crate::backup::BackupFailureCode::Unreadable
    };
    let failure = preview.err().ok_or("native preview must refuse writer fault")?;
    assert_eq!(failure.code, expected);
    assert_eq!(failure.retryable, matches!(fault, Fault::Busy));
    let Identity::Native { native } = &metadata.identity else {
        return Err("native fixture".into());
    };
    let job = jobs.start(crate::backup::BackupJobKind::Restore, "archive.rfb".into())?;
    let error = jobs
        .install_target(&job, native, None, None)
        .err()
        .ok_or("native install must refuse writer fault")?;
    jobs.fail_install(&job.job_id, &error);
    let jobs: Vec<crate::backup::BackupJob> = serde_json::from_value(jobs.jobs()?["jobs"].clone())?;
    let failure = jobs
        .into_iter()
        .find(|row| row.job_id == job.job_id)
        .ok_or("job")?
        .error
        .ok_or("failure")?;
    assert_eq!(failure.code, expected);
    assert_eq!(failure.retryable, matches!(fault, Fault::Busy));
    assert_eq!(index.account("acct")?.principal_commitment, account.record().body.account_anchor);
    Ok(())
}

#[test]
fn native_writer_busy_is_retryable_on_unlock_preview_and_install() -> TestResult {
    check(Fault::Busy)
}

#[test]
fn native_writer_io_is_unreadable_on_preview_and_install() -> TestResult {
    check(Fault::Io)
}

#[test]
fn native_local_key_failure_blocks_unlock_without_invalidating_public_preview() -> TestResult {
    check(Fault::Integrity)
}
