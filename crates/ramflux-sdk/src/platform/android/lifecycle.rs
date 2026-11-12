// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Android process lifecycle mapped onto the platform-neutral host lifecycle.
//!
//! The host forwards four facts and nothing else decides when the store is open:
//!
//! * the application became visible (`ProcessLifecycleOwner` `ON_START`),
//! * the application left the foreground (`ON_STOP`),
//! * the user removed the task or the host is shutting the core down,
//! * the process was created again after the system killed it.
//!
//! Android gives no callback before it kills a cached process, so the only safe state for a
//! background process is "store closed, lock released". `on_background` therefore returns
//! only after the neutral lifecycle observed the release. A process killed later loses
//! nothing: state is the database, and the next start resumes the gateway session.
//!
//! The supervisor is never kept alive by a foreground service for message sync. Doze and
//! App Standby suspend network access for a background process; the connection is expected
//! to die there and is not fought with wake locks or exemptions.

use std::sync::Arc;

use crate::SdkError;
use crate::platform::lifecycle::{HostLifecycle, LifecycleState, SuspendReport};

/// Why the host wants to run while it is not visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackgroundWork {
    /// Receiving or sending chat messages.
    MessageSync,
    /// A 1:1 call that is ringing or connected.
    ActiveCall,
}

/// The manifest `foregroundServiceType` a kind of background work may use, if any.
///
/// Message sync gets none: it happens while the application is visible, or after the user
/// opens a notification. Only a call may hold a foreground service, with the `phoneCall`
/// type the platform reserves for it.
#[must_use]
pub const fn foreground_service_type(work: BackgroundWork) -> Option<&'static str> {
    match work {
        BackgroundWork::MessageSync => None,
        BackgroundWork::ActiveCall => Some("phoneCall"),
    }
}

/// What a lifecycle callback did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleOutcome {
    /// The supervisor was started from the stopped state (first launch or process restore).
    Started,
    /// The supervisor was resumed after a suspension in the same process.
    Resumed,
    /// The supervisor was suspended; the report proves the store is closed.
    Suspended(SuspendReport),
    /// The supervisor was stopped.
    Stopped,
    /// The callback repeated a state the supervisor was already in.
    Unchanged,
}

/// Drives a [`HostLifecycle`] from Android callbacks. Duplicate and out-of-order callbacks
/// are expected from the platform and are absorbed here instead of surfacing as errors.
pub struct AndroidLifecycle<L: HostLifecycle + ?Sized> {
    supervisor: Arc<L>,
}

impl<L: HostLifecycle + ?Sized> AndroidLifecycle<L> {
    #[must_use]
    pub const fn new(supervisor: Arc<L>) -> Self {
        Self { supervisor }
    }

    /// The application is visible. Starts a stopped supervisor (first launch, or a process
    /// the system recreated) and resumes a suspended one.
    ///
    /// # Errors
    /// `DataRootInUse` when another holder owns the data root, and start or resume failures.
    pub fn on_foreground(&self) -> Result<LifecycleOutcome, SdkError> {
        match self.supervisor.state() {
            LifecycleState::Stopped => self.supervisor.start().map(|()| LifecycleOutcome::Started),
            LifecycleState::Suspended => {
                self.supervisor.resume().map(|()| LifecycleOutcome::Resumed)
            }
            LifecycleState::Running => Ok(LifecycleOutcome::Unchanged),
        }
    }

    /// The application left the foreground. Returns after every store is closed and the
    /// data-root lock was observed released.
    ///
    /// # Errors
    /// The suspension did not complete, or the report does not prove the release. The host
    /// must then stop the supervisor rather than leave a lock held in a cached process.
    pub fn on_background(&self) -> Result<LifecycleOutcome, SdkError> {
        if self.supervisor.state() != LifecycleState::Running {
            return Ok(LifecycleOutcome::Unchanged);
        }
        let report = self.supervisor.suspend()?;
        if !(report.supervisor_joined && report.data_root_lock_released) {
            return Err(SdkError::LocalBus(
                "android suspension did not release the data root".to_owned(),
            ));
        }
        Ok(LifecycleOutcome::Suspended(report))
    }

    /// The task was removed, or the host is shutting the core down.
    ///
    /// # Errors
    /// The supervisor did not drain or the lock is still held.
    pub fn on_shutdown(&self) -> Result<LifecycleOutcome, SdkError> {
        if self.supervisor.state() == LifecycleState::Stopped {
            return Ok(LifecycleOutcome::Unchanged);
        }
        self.supervisor.stop().map(|()| LifecycleOutcome::Stopped)
    }

    /// The process was created to deliver a push while the application is not visible.
    /// Version 1 never opens the store for a push: the answer is always `Unchanged`, and
    /// the wake handler posts its notification without the supervisor.
    #[must_use]
    pub fn on_push_wake(&self) -> LifecycleOutcome {
        LifecycleOutcome::Unchanged
    }

    /// Current neutral state.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.supervisor.state()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::platform::lifecycle::{LifecycleTransition, illegal};

    /// A supervisor double that enforces the neutral transition table and records calls.
    struct Recording {
        state: Mutex<LifecycleState>,
        calls: Mutex<Vec<LifecycleTransition>>,
        lock_released: bool,
    }

    impl Recording {
        fn new(lock_released: bool) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(LifecycleState::Stopped),
                calls: Mutex::default(),
                lock_released,
            })
        }

        fn apply(&self, transition: LifecycleTransition) -> Result<(), SdkError> {
            let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let next = state.after(transition).ok_or_else(|| illegal(*state, transition))?;
            *state = next;
            self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(transition);
            Ok(())
        }

        fn calls(&self) -> Vec<LifecycleTransition> {
            self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
        }
    }

    impl HostLifecycle for Recording {
        fn start(&self) -> Result<(), SdkError> {
            self.apply(LifecycleTransition::Start)
        }
        fn suspend(&self) -> Result<SuspendReport, SdkError> {
            self.apply(LifecycleTransition::Suspend)?;
            Ok(SuspendReport {
                supervisor_joined: true,
                data_root_lock_released: self.lock_released,
                elapsed: Duration::from_millis(5),
            })
        }
        fn resume(&self) -> Result<(), SdkError> {
            self.apply(LifecycleTransition::Resume)
        }
        fn stop(&self) -> Result<(), SdkError> {
            self.apply(LifecycleTransition::Stop)
        }
        fn state(&self) -> LifecycleState {
            *self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn foreground_background_foreground_starts_suspends_and_resumes() -> TestResult {
        let supervisor = Recording::new(true);
        let lifecycle = AndroidLifecycle::new(Arc::clone(&supervisor));
        assert_eq!(lifecycle.on_foreground()?, LifecycleOutcome::Started);
        assert!(matches!(lifecycle.on_background()?, LifecycleOutcome::Suspended(_)));
        assert_eq!(lifecycle.on_foreground()?, LifecycleOutcome::Resumed);
        assert_eq!(
            supervisor.calls(),
            vec![
                LifecycleTransition::Start,
                LifecycleTransition::Suspend,
                LifecycleTransition::Resume
            ]
        );
        Ok(())
    }

    #[test]
    fn duplicate_platform_callbacks_change_nothing() -> TestResult {
        let supervisor = Recording::new(true);
        let lifecycle = AndroidLifecycle::new(Arc::clone(&supervisor));
        assert_eq!(lifecycle.on_background()?, LifecycleOutcome::Unchanged);
        assert_eq!(lifecycle.on_shutdown()?, LifecycleOutcome::Unchanged);
        lifecycle.on_foreground()?;
        assert_eq!(lifecycle.on_foreground()?, LifecycleOutcome::Unchanged);
        lifecycle.on_background()?;
        assert_eq!(lifecycle.on_background()?, LifecycleOutcome::Unchanged);
        assert_eq!(supervisor.calls().len(), 2);
        Ok(())
    }

    #[test]
    fn suspension_that_keeps_the_lock_is_an_error() -> TestResult {
        let supervisor = Recording::new(false);
        let lifecycle = AndroidLifecycle::new(Arc::clone(&supervisor));
        lifecycle.on_foreground()?;
        assert!(lifecycle.on_background().is_err());
        Ok(())
    }

    #[test]
    fn process_death_after_background_restarts_from_stopped() -> TestResult {
        let first_process = Recording::new(true);
        let lifecycle = AndroidLifecycle::new(Arc::clone(&first_process));
        lifecycle.on_foreground()?;
        lifecycle.on_background()?;
        // The system kills the cached process here: no callback runs, and the suspended
        // supervisor held neither a store nor a lock.
        drop(lifecycle);

        let restored_process = Recording::new(true);
        let lifecycle = AndroidLifecycle::new(Arc::clone(&restored_process));
        assert_eq!(lifecycle.state(), LifecycleState::Stopped);
        assert_eq!(lifecycle.on_push_wake(), LifecycleOutcome::Unchanged);
        assert!(restored_process.calls().is_empty(), "a push wake opened the store");
        assert_eq!(lifecycle.on_foreground()?, LifecycleOutcome::Started);
        Ok(())
    }

    #[test]
    fn shutdown_stops_from_running_and_from_suspended() -> TestResult {
        for suspend_first in [false, true] {
            let supervisor = Recording::new(true);
            let lifecycle = AndroidLifecycle::new(Arc::clone(&supervisor));
            lifecycle.on_foreground()?;
            if suspend_first {
                lifecycle.on_background()?;
            }
            assert_eq!(lifecycle.on_shutdown()?, LifecycleOutcome::Stopped);
            assert_eq!(lifecycle.state(), LifecycleState::Stopped);
        }
        Ok(())
    }

    #[test]
    fn only_a_call_may_hold_a_foreground_service() {
        assert_eq!(foreground_service_type(BackgroundWork::MessageSync), None);
        assert_eq!(foreground_service_type(BackgroundWork::ActiveCall), Some("phoneCall"));
    }
}
