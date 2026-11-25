// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-lifetime suspend. A killed process is a cold start and unlocks again.

use super::super::{CAbiError, RamfluxErrorCode};
use super::RamfluxV2Status;
use super::exports::{call, client};
use super::runtime::{Client, DriveError};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Stop networking, flush databases, and close file descriptors.
/// Unlocked account state, including the database key, stays in memory.
/// Pending operations complete as `RAMFLUX_V2_STATUS_SUSPENDED` (30).
/// A second call while already suspended returns 0.
/// A release failure rolls back parked files and returns `StorageFailed` (8).
/// Diagnostics contain `SuspendFailed` and `suspend_release_failed` or `suspend_rollback_failed`.
/// Call resume after any failure, then reopen the event subscription from its cursor.
/// A live or pending call in any account returns `AccountBusy` (18) before anything is cancelled
/// or parked. Idle suspend is unchanged. Call off the UI thread. A killed process is a cold
/// start and must unlock again.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_client_suspend(handle: u64) -> i32 {
    finish(call(|| {
        let client = client(handle)?;
        refuse_closed(&client)?;
        let _lifecycle = client
            .lifecycle_gate
            .try_lock()
            .map_err(|_| CAbiError::new(RamfluxErrorCode::AccountBusy, "lifecycle_in_progress"))?;
        let was_suspended = client.shared.suspended.load(Ordering::Acquire);
        if !was_suspended {
            probe(&client)?;
        }
        client.shared.cancel_for_suspend();
        let result = drive(&client, false);
        if let Err(error) = &result {
            // Submission failure never reached the lifecycle owner.
            if error.code == RamfluxErrorCode::TransportUnavailable {
                client.shared.suspended.store(was_suspended, Ordering::Release);
            }
            if let Some(diag) = &client.diagnostics {
                diag.record(
                    "E",
                    "sdk.lifecycle",
                    "client.suspend.failed",
                    serde_json::json!({"suspended": client.shared.suspended.load(Ordering::Acquire)}),
                    Some(serde_json::json!({
                        "code": error.status.unwrap_or(error.code as i32),
                        "name": "SuspendFailed",
                        "reason": error.message,
                        "effect": "unknown",
                        "variant": "SuspendFailed"
                    })),
                );
            }
        }
        if let Some(diag) = &client.diagnostics {
            diag.flush();
        }
        result
    }))
}

/// Reopen files and reconnect. Does not ask for the unlock code.
/// Returns 0 when the client was not suspended.
/// A data-root conflict leaves the client suspended.
/// Call off the UI thread.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_client_resume(handle: u64) -> i32 {
    finish(call(|| {
        let client = client(handle)?;
        refuse_closed(&client)?;
        let _lifecycle = client
            .lifecycle_gate
            .try_lock()
            .map_err(|_| CAbiError::new(RamfluxErrorCode::AccountBusy, "lifecycle_in_progress"))?;
        drive(&client, true)?;
        client.shared.suspended.store(false, Ordering::Release);
        Ok(())
    }))
}

fn finish(code: i32) -> i32 {
    if code == RamfluxErrorCode::TransportUnavailable as i32 {
        RamfluxV2Status::Closed as i32
    } else {
        code
    }
}

fn refuse_closed(client: &Client) -> Result<(), CAbiError> {
    if client.closing.load(Ordering::Acquire) || client.shared.closed.load(Ordering::Acquire) {
        return Err(CAbiError::new(RamfluxErrorCode::TransportUnavailable, "client closed"));
    }
    Ok(())
}

/// Refuse suspend while any account has a live or pending call. Nothing has been cancelled yet.
fn probe(client: &Arc<Client>) -> Result<(), CAbiError> {
    match client.probe_live_calls(Duration::from_secs(10)) {
        Err(DriveError::Failed(crate::SdkError::LocalBusRefused { code, .. }))
            if code == "LiveCallActive" =>
        {
            Err(CAbiError::new(RamfluxErrorCode::AccountBusy, "live_call_active"))
        }
        other => map_drive_error(other),
    }
}

fn drive(client: &Arc<Client>, resume: bool) -> Result<(), CAbiError> {
    map_drive_error(client.drive_lifecycle(resume, Duration::from_secs(10)))
}

fn map_drive_error(result: Result<(), DriveError>) -> Result<(), CAbiError> {
    match result {
        Ok(()) => Ok(()),
        Err(DriveError::Unavailable) => {
            Err(CAbiError::new(RamfluxErrorCode::TransportUnavailable, "lifecycle_unavailable"))
        }
        Err(DriveError::TimedOut) => {
            Err(CAbiError::new(RamfluxErrorCode::Timeout, "lifecycle_timed_out"))
        }
        Err(DriveError::Failed(crate::SdkError::LocalBusRefused { code, body, .. }))
            if code == "SuspendFailed" =>
        {
            let reason = body.get("reason").and_then(serde_json::Value::as_str);
            Err(CAbiError::new(
                RamfluxErrorCode::StorageFailed,
                if reason == Some("suspend_rollback_failed") {
                    "suspend_rollback_failed"
                } else {
                    "suspend_release_failed"
                },
            ))
        }
        Err(DriveError::Failed(error)) => {
            let mut mapped = super::super::map_sdk_error(&error);
            mapped.message = "lifecycle_failed".into();
            Err(mapped)
        }
    }
}
