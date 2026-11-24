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
/// Call off the UI thread. A killed process is a cold start and must unlock again.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_client_suspend(handle: u64) -> i32 {
    finish(call(|| {
        let client = client(handle)?;
        refuse_closed(&client)?;
        client.shared.cancel_for_suspend();
        let result = drive(&client, false);
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

fn drive(client: &Arc<Client>, resume: bool) -> Result<(), CAbiError> {
    match client.drive_lifecycle(resume, Duration::from_secs(10)) {
        Ok(()) => Ok(()),
        Err(DriveError::TimedOut) => {
            Err(CAbiError::new(RamfluxErrorCode::Timeout, "lifecycle timed out"))
        }
        Err(DriveError::Failed(error)) => Err(super::super::map_sdk_error(&error)),
    }
}
