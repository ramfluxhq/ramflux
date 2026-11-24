// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cooperative process handoff. Kernel locks, never timestamps or PIDs, own the lease.

use super::data_root_lock::DataRootLock;
use crate::SdkError;
use std::{fs::File, path::Path, sync::Arc, time::Duration};

pub(super) const POLL: Duration = Duration::from_millis(25);
const MAX_WAIT: Duration = Duration::from_secs(5);

/// Priority among processes waiting for the same shared root. All holders cooperate;
/// foreground requests precede notification requests, which precede background work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SessionLeasePriority {
    Background,
    Notification,
    Foreground,
}

const PRIORITIES: [SessionLeasePriority; 3] = [
    SessionLeasePriority::Foreground,
    SessionLeasePriority::Notification,
    SessionLeasePriority::Background,
];

#[derive(Clone, Copy)]
pub(crate) struct SessionLeaseConfig {
    pub priority: SessionLeasePriority,
    pub wait: Duration,
}

impl super::LocalBusConfig {
    /// Opt into cooperative shared-root handoff. A pending request stops the current
    /// daemon, drains its actors and transports, then releases `daemon.lock`. The host
    /// must await daemon completion and start a fresh daemon to regain ownership.
    ///
    /// Admission waits at most five seconds (or the shorter requested budget), returning
    /// `SdkError::LocalBusRefused` with code `SessionLeaseBusy` on contention. A timeout
    /// never steals ownership. Ordinary daemons without this option do not yield.
    #[must_use]
    pub fn with_session_lease(mut self, priority: SessionLeasePriority, wait: Duration) -> Self {
        self.session_lease = Some(SessionLeaseConfig { priority, wait: wait.min(MAX_WAIT) });
        self
    }
}

fn busy() -> SdkError {
    SdkError::LocalBusRefused {
        code: "SessionLeaseBusy".into(),
        message: "shared-root session lease is busy; retry after the holder drains".into(),
        body: Box::new(serde_json::json!({"retry_after_ms": 250})),
    }
}

fn request_file(root: &Path, priority: SessionLeasePriority) -> Result<File, SdkError> {
    let name = match priority {
        SessionLeasePriority::Background => "session-request-background.lock",
        SessionLeasePriority::Notification => "session-request-notification.lock",
        SessionLeasePriority::Foreground => "session-request-foreground.lock",
    };
    Ok(crate::platform::fs::open_owner_only_no_follow(&root.join(name))?)
}

fn requested(root: &Path, priority: SessionLeasePriority) -> Result<bool, SdkError> {
    let file = request_file(root, priority)?;
    match crate::platform::fs::try_lock_exclusive(&file) {
        Ok(()) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn handoff_requested(root: &Path) -> Result<bool, SdkError> {
    for priority in PRIORITIES {
        if requested(root, priority)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn higher_requested(root: &Path, own: SessionLeasePriority) -> Result<bool, SdkError> {
    for priority in PRIORITIES.into_iter().take_while(|priority| *priority > own) {
        if requested(root, priority)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) async fn acquire(
    root: &Path,
    config: SessionLeaseConfig,
) -> Result<Arc<DataRootLock>, SdkError> {
    let deadline = tokio::time::Instant::now() + config.wait;
    let request = request_file(root, config.priority)?;
    crate::platform::fs::try_lock_exclusive(&request).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock { busy() } else { error.into() }
    })?;
    loop {
        if !higher_requested(root, config.priority)? {
            match DataRootLock::try_acquire(root) {
                Ok(lease) if !higher_requested(root, config.priority)? => return Ok(lease),
                Ok(_) | Err(SdkError::DataRootInUse) => {}
                Err(error) => return Err(error),
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(busy());
        }
        tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + POLL)).await;
    }
}
