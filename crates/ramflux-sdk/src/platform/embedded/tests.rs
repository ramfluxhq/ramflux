// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Suspension evidence: the data-root lock and every descriptor under the data root are
//! released before `suspend` returns, and are held again after `resume`.

use super::*;
use crate::bus::data_root_lock::DataRootLock;
use crate::custody::tests::Root;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn supervisor(root: &Root) -> EmbeddedSupervisor {
    EmbeddedSupervisor::new(EmbeddedConfig::new(HostPaths { data_root: root.0.clone() }))
}

fn lock_is_held(root: &Root) -> bool {
    matches!(DataRootLock::acquire(&root.0), Err(SdkError::DataRootInUse))
}

#[test]
fn suspend_releases_the_data_root_lock_and_resume_reacquires_it() -> TestResult {
    let root = Root::new()?;
    let host = supervisor(&root);
    assert_eq!(host.state(), LifecycleState::Stopped);
    host.start()?;
    assert_eq!(host.state(), LifecycleState::Running);
    assert!(lock_is_held(&root), "a running supervisor must own the data root");

    let report = host.suspend()?;
    assert!(report.supervisor_joined);
    assert!(report.data_root_lock_released);
    assert!(report.elapsed <= DEFAULT_SUSPEND_DEADLINE);
    assert_eq!(host.state(), LifecycleState::Suspended);
    assert!(lock_is_free(&root.0)?, "the lock file must be unlocked at suspension");
    // A second process (here: a second descriptor) can take the root while suspended.
    drop(DataRootLock::acquire(&root.0)?);

    host.resume()?;
    assert_eq!(host.state(), LifecycleState::Running);
    assert!(lock_is_held(&root), "resume must reacquire the data root");

    host.stop()?;
    assert_eq!(host.state(), LifecycleState::Stopped);
    assert!(lock_is_free(&root.0)?);
    Ok(())
}

#[test]
fn suspend_leaves_no_open_descriptor_under_the_data_root() -> TestResult {
    let root = Root::new()?;
    let host = supervisor(&root);
    host.start()?;
    if let Some(open) = open_descriptors_under(&root.0) {
        assert!(open > 0, "a running supervisor holds at least the lock file");
    }
    host.suspend()?;
    // `None` on hosts without a descriptor table; the lock probe above covers those.
    if let Some(open) = open_descriptors_under(&root.0) {
        assert_eq!(open, 0, "a store or lock descriptor survived suspension");
    }
    host.stop()?;
    Ok(())
}

#[test]
fn repeated_suspend_and_stop_do_not_fail() -> TestResult {
    let root = Root::new()?;
    let host = supervisor(&root);
    host.start()?;
    host.suspend()?;
    let again = host.suspend()?;
    assert!(again.data_root_lock_released);
    host.stop()?;
    host.stop()?;
    assert_eq!(host.state(), LifecycleState::Stopped);
    Ok(())
}

#[test]
fn illegal_transitions_are_refused_and_change_nothing() -> TestResult {
    let root = Root::new()?;
    let host = supervisor(&root);
    assert!(host.resume().is_err(), "resume while stopped");
    assert!(host.suspend().is_err(), "suspend while stopped");
    host.start()?;
    assert!(host.start().is_err(), "start while running");
    assert!(host.resume().is_err(), "resume while running");
    assert_eq!(host.state(), LifecycleState::Running);
    host.stop()?;
    Ok(())
}

#[test]
fn second_supervisor_on_the_same_root_gets_data_root_in_use() -> TestResult {
    let root = Root::new()?;
    let first = supervisor(&root);
    let second = supervisor(&root);
    first.start()?;
    assert!(matches!(second.start(), Err(SdkError::DataRootInUse)));
    assert_eq!(second.state(), LifecycleState::Stopped);
    first.suspend()?;
    // While the first is suspended the root is free, so the second may own it.
    second.start()?;
    assert!(matches!(first.resume(), Err(SdkError::DataRootInUse)));
    assert_eq!(first.state(), LifecycleState::Suspended);
    second.stop()?;
    first.resume()?;
    first.stop()?;
    Ok(())
}

#[test]
fn embedded_supervisor_binds_no_socket_in_the_data_root() -> TestResult {
    let root = Root::new()?;
    let host = supervisor(&root);
    host.start()?;
    for entry in std::fs::read_dir(&root.0)? {
        use std::os::unix::fs::FileTypeExt;
        let entry = entry?;
        assert!(!entry.file_type()?.is_socket(), "found a socket: {:?}", entry.path());
    }
    host.stop()?;
    Ok(())
}

#[test]
fn connect_outside_a_runtime_or_while_suspended_is_refused() -> TestResult {
    let root = Root::new()?;
    let host = supervisor(&root);
    host.start()?;
    assert!(host.connect().is_err(), "no Tokio runtime on this thread");
    host.suspend()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    assert!(runtime.block_on(async { host.connect() }).is_err(), "suspended");
    host.stop()?;
    Ok(())
}

#[tokio::test]
async fn in_process_client_gets_daemon_status_and_fails_after_suspension() -> TestResult {
    let root = Root::new()?;
    let host = std::sync::Arc::new(supervisor(&root));
    host.start()?;
    let mut client = host.connect()?;
    let status = tokio::time::timeout(
        Duration::from_secs(5),
        client.request(None, "daemon", "daemon.status", serde_json::json!({})),
    )
    .await??;
    assert_eq!(status["accounts"], 0);

    let suspending = std::sync::Arc::clone(&host);
    let report = tokio::task::spawn_blocking(move || suspending.suspend()).await??;
    assert!(report.data_root_lock_released);
    let after = tokio::time::timeout(
        Duration::from_secs(5),
        client.request(None, "daemon", "daemon.status", serde_json::json!({})),
    )
    .await?;
    assert!(after.is_err(), "a client of a suspended supervisor must not be answered");

    let resuming = std::sync::Arc::clone(&host);
    tokio::task::spawn_blocking(move || resuming.resume()).await??;
    let mut fresh = host.connect()?;
    let status = tokio::time::timeout(
        Duration::from_secs(5),
        fresh.request(None, "daemon", "daemon.status", serde_json::json!({})),
    )
    .await??;
    assert_eq!(status["accounts"], 0);
    drop(fresh);
    let stopping = std::sync::Arc::clone(&host);
    tokio::task::spawn_blocking(move || stopping.stop()).await??;
    Ok(())
}
