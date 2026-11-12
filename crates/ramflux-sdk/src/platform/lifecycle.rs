// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Platform-neutral host lifecycle for an in-process supervisor.
//!
//! A phone has no helper process: the app process is the supervisor. The operating system
//! may suspend that process at any time after it leaves the foreground, so the host drives
//! four explicit transitions. `suspend` returns only after every database connection is
//! closed and the data-root lock is released; `resume` reacquires both. State lives in the
//! database, never in the process.

use std::path::PathBuf;
use std::time::Duration;

use crate::SdkError;

/// Where an in-process supervisor is in its host lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    /// Not started, or stopped. No store is open and no lock is held.
    Stopped,
    /// The supervisor thread runs, owns the data-root lock and may hold open stores.
    Running,
    /// The host is in the background. No store is open and no file lock is held.
    Suspended,
}

/// A host lifecycle request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleTransition {
    Start,
    Suspend,
    Resume,
    Stop,
}

impl LifecycleState {
    /// State after `transition`, or `None` when the transition is not legal from `self`.
    ///
    /// `Suspend` while suspended, and `Stop` while stopped, are legal and change nothing, so
    /// a host may repeat them from duplicated platform callbacks.
    #[must_use]
    pub const fn after(self, transition: LifecycleTransition) -> Option<Self> {
        match (self, transition) {
            (Self::Stopped, LifecycleTransition::Start)
            | (Self::Suspended, LifecycleTransition::Resume) => Some(Self::Running),
            (Self::Running | Self::Suspended, LifecycleTransition::Suspend) => {
                Some(Self::Suspended)
            }
            (_, LifecycleTransition::Stop) => Some(Self::Stopped),
            _ => None,
        }
    }
}

/// Evidence returned by a completed suspension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuspendReport {
    /// The supervisor thread exited, which closes every database connection it owned.
    pub supervisor_joined: bool,
    /// A fresh descriptor took and dropped the exclusive data-root lock after the join.
    pub data_root_lock_released: bool,
    /// Wall time the suspension took. The host must finish inside its background task.
    pub elapsed: Duration,
}

/// Directories the host application hands to the supervisor.
///
/// The SDK never guesses a container path on a phone. iOS passes its app-container
/// `Library/Application Support` child; Android passes a child of `getNoBackupFilesDir()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPaths {
    /// Data root: account index, per-account databases, the object spool and `daemon.lock`.
    pub data_root: PathBuf,
}

/// Explicit lifecycle of an in-process supervisor. Every method is synchronous and may be
/// called from any host thread except one the supervisor itself runs on.
pub trait HostLifecycle: Send + Sync {
    /// Acquire the data-root lock and start the supervisor thread.
    ///
    /// # Errors
    /// Returns [`SdkError::DataRootInUse`] when another holder owns the data root, and an
    /// error when the supervisor is not stopped or cannot start.
    fn start(&self) -> Result<(), SdkError>;

    /// Stop the supervisor thread, close every store and release every file lock. Returns
    /// only after the release was observed, or with an error when it was not.
    ///
    /// # Errors
    /// Returns an error when the supervisor is stopped, did not drain before the deadline,
    /// or the data-root lock is still held afterwards.
    fn suspend(&self) -> Result<SuspendReport, SdkError>;

    /// Reacquire the data-root lock and restart the supervisor after a suspension.
    ///
    /// # Errors
    /// Returns an error when the supervisor is not suspended or cannot restart.
    fn resume(&self) -> Result<(), SdkError>;

    /// Stop for good. Legal from every state.
    ///
    /// # Errors
    /// Returns an error when the supervisor did not drain or the lock is still held.
    fn stop(&self) -> Result<(), SdkError>;

    /// Current state.
    fn state(&self) -> LifecycleState;
}

/// Refusal for a transition that is not legal from the current state.
pub(crate) fn illegal(state: LifecycleState, transition: LifecycleTransition) -> SdkError {
    SdkError::LocalBus(format!("lifecycle transition {transition:?} is not legal from {state:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_follows_start_suspend_resume_stop() {
        let running = LifecycleState::Stopped.after(LifecycleTransition::Start);
        assert_eq!(running, Some(LifecycleState::Running));
        let suspended = LifecycleState::Running.after(LifecycleTransition::Suspend);
        assert_eq!(suspended, Some(LifecycleState::Suspended));
        let resumed = LifecycleState::Suspended.after(LifecycleTransition::Resume);
        assert_eq!(resumed, Some(LifecycleState::Running));
        assert_eq!(
            LifecycleState::Running.after(LifecycleTransition::Stop),
            Some(LifecycleState::Stopped)
        );
    }

    #[test]
    fn lifecycle_refuses_start_while_running_and_resume_while_stopped() {
        assert_eq!(LifecycleState::Running.after(LifecycleTransition::Start), None);
        assert_eq!(LifecycleState::Suspended.after(LifecycleTransition::Start), None);
        assert_eq!(LifecycleState::Stopped.after(LifecycleTransition::Resume), None);
        assert_eq!(LifecycleState::Running.after(LifecycleTransition::Resume), None);
        assert_eq!(LifecycleState::Stopped.after(LifecycleTransition::Suspend), None);
    }

    #[test]
    fn repeated_suspend_and_stop_are_idempotent() {
        assert_eq!(
            LifecycleState::Suspended.after(LifecycleTransition::Suspend),
            Some(LifecycleState::Suspended)
        );
        assert_eq!(
            LifecycleState::Stopped.after(LifecycleTransition::Stop),
            Some(LifecycleState::Stopped)
        );
    }
}
