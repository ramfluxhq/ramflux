// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Storage classifications survive the real account dispatch and restore paths.
use crate::prelude::*;
use crate::storage_failure_fixture::{Fault, Fixture, TestResult};

fn state(fixture: &Fixture) -> LocalBusDaemonState {
    LocalBusDaemonState {
        account_index: Some(fixture.index.clone()),
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(fixture.root().join("bus.sock"), fixture.root()),
        accounts: BTreeMap::new(),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    }
}

fn assert_code(error: &SdkError, fault: Fault) {
    let body = super::io::local_bus_error_body(error);
    let expected = match fault {
        Fault::Busy => "account_busy",
        Fault::Io => "storage_unavailable",
        Fault::Integrity => "ValidationFailed",
    };
    assert_eq!(body.code, expected, "{error:?}");
    match fault {
        Fault::Busy => {
            assert_eq!(body.reason_code.as_deref(), Some("account_busy"));
            assert_eq!(body.retry_after_ms, Some(1_000));
            assert_eq!(body.message, "account in use by another process");
        }
        Fault::Io => {
            assert_eq!(body.cause.as_ref().map(|cause| cause.kind.as_str()), Some("IsADirectory"));
            assert!(body.cause.as_ref().and_then(|cause| cause.raw_os_error).is_some());
            assert_eq!(body.retry_after_ms, None);
        }
        Fault::Integrity => {
            assert_eq!(body.retry_after_ms, None);
            assert!(body.message.contains("wrong passphrase or damaged local key"));
            assert!(!body.message.contains("integrity verification failed"));
        }
    }
}

async fn check_account_surfaces(fault: Fault) -> TestResult {
    let fixture = Fixture::new(fault)?;
    let mut daemon = state(&fixture);
    let create = LocalBusFrame::request(
        "create",
        Some("acct".into()),
        "account",
        "account.create",
        serde_json::to_value(&fixture.manifest)?,
    );
    let Err(error) =
        super::dispatch::account::dispatch_account_bus_request(&create, &mut daemon).await
    else {
        return Err("faulted account creation unexpectedly succeeded".into());
    };
    assert_code(&error, fault);

    let Err(error) =
        super::daemon::restore_local_bus_account_offline(&mut daemon, &fixture.manifest).await
    else {
        return Err("faulted daemon load unexpectedly succeeded".into());
    };
    assert_code(&error, fault);

    let unlock = LocalBusFrame::request(
        "unlock",
        Some("acct".into()),
        "account",
        "account.unlock",
        serde_json::json!({"passphrase":"account-secret"}),
    );
    let Err(error) =
        super::dispatch::account::dispatch_account_bus_request(&unlock, &mut daemon).await
    else {
        return Err("faulted unlock unexpectedly succeeded".into());
    };
    assert_code(&error, fault);

    // Exercise the repeat-unlock branch with an actor entry whose DB is closed.
    // A healthy live DB already owns the process lease and cannot conflict with a child.
    daemon.accounts.insert(
        "acct".into(),
        LocalBusAccountState::disconnected(
            fixture.client()?,
            GatewaySessionConfig::quic(fixture.manifest.gateway.clone()),
            fixture.manifest.principal_commitment.clone(),
        ),
    );
    let Err(error) =
        super::dispatch::account::dispatch_account_bus_request(&unlock, &mut daemon).await
    else {
        return Err("faulted repeated unlock unexpectedly succeeded".into());
    };
    assert_code(&error, fault);

    for old in [Some("account-secret"), None] {
        // With no old passphrase, rotation itself must take the lease before vault I/O.
        // A MAC cannot be checked without an old secret; that branch has no MAC row.
        if old.is_none() && matches!(fault, Fault::Integrity) {
            continue;
        }
        let rotate = LocalBusFrame::request(
            "rotate",
            Some("acct".into()),
            "account",
            "account.passphrase.rotate",
            serde_json::json!({"old_passphrase":old,"new_passphrase":"next-secret"}),
        );
        let Err(error) =
            super::dispatch::account::dispatch_account_bus_request(&rotate, &mut daemon).await
        else {
            return Err("faulted rotation unexpectedly succeeded".into());
        };
        assert_code(&error, fault);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn account_surfaces_report_real_process_contention_as_retryable_busy() -> TestResult {
    check_account_surfaces(Fault::Busy).await
}
#[tokio::test(flavor = "current_thread")]
async fn account_surfaces_report_real_lock_open_failure_as_storage_unavailable() -> TestResult {
    check_account_surfaces(Fault::Io).await
}
#[tokio::test(flavor = "current_thread")]
async fn account_surfaces_preserve_integrity_failure_code_for_corrupted_mac() -> TestResult {
    check_account_surfaces(Fault::Integrity).await
}
