// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The Android in-process host: validated storage, the embedded supervisor, and the
//! lifecycle and connectivity callbacks wired together.
//!
//! One `AndroidHost` exists per process. The bindings layer creates it from
//! `Application.onCreate`, forwards `ProcessLifecycleOwner` and `ConnectivityManager`
//! callbacks to it, and opens in-process connections through it. It starts nothing until
//! the application is visible.

use std::sync::Arc;

use super::lifecycle::{AndroidLifecycle, LifecycleOutcome};
use super::network::AndroidNetworkTracker;
use super::storage::{AndroidStorage, InstallState};
use crate::platform::embedded::{EmbeddedConfig, EmbeddedSupervisor};
use crate::platform::lifecycle::LifecycleState;
use crate::platform::network::NetworkMonitor;
use crate::{LocalBusClient, NodeProfile, SdkError};

/// The Android host of the in-process supervisor.
pub struct AndroidHost {
    storage: AndroidStorage,
    supervisor: Arc<EmbeddedSupervisor>,
    lifecycle: AndroidLifecycle<EmbeddedSupervisor>,
    network: AndroidNetworkTracker,
    monitor: NetworkMonitor,
}

impl AndroidHost {
    /// Prepare the private directories and build a stopped supervisor over them.
    ///
    /// # Errors
    /// Storage preparation failures, including a filesystem without effective file locks.
    pub fn new(
        storage: AndroidStorage,
        builtin_nodes: Vec<NodeProfile>,
        monitor: NetworkMonitor,
    ) -> Result<Self, SdkError> {
        storage.prepare()?;
        let mut config = EmbeddedConfig::new(storage.host_paths());
        config.builtin_nodes = builtin_nodes;
        let supervisor = Arc::new(EmbeddedSupervisor::new(config));
        Ok(Self {
            storage,
            lifecycle: AndroidLifecycle::new(Arc::clone(&supervisor)),
            supervisor,
            network: AndroidNetworkTracker::new(Arc::new(monitor.clone())),
            monitor,
        })
    }

    /// The application became visible: start or resume the supervisor.
    ///
    /// # Errors
    /// `CustodyVault(Missing)` when vault entries exist without their data root (the host
    /// offers a recovery restore or deleting the orphan), `DataRootInUse`, and start or
    /// resume failures.
    pub fn on_foreground(&self) -> Result<LifecycleOutcome, SdkError> {
        let install = self.storage.require_not_orphaned()?;
        let outcome = self.lifecycle.on_foreground()?;
        if install == InstallState::Fresh && outcome == LifecycleOutcome::Started {
            self.storage.mark_installed()?;
        }
        Ok(outcome)
    }

    /// The application left the foreground: close every store and release the data root.
    ///
    /// # Errors
    /// The suspension did not complete or did not release the lock.
    pub fn on_background(&self) -> Result<LifecycleOutcome, SdkError> {
        self.lifecycle.on_background()
    }

    /// The task was removed or the host shuts down.
    ///
    /// # Errors
    /// The supervisor did not drain or the lock is still held.
    pub fn on_shutdown(&self) -> Result<LifecycleOutcome, SdkError> {
        self.lifecycle.on_shutdown()
    }

    /// Open one in-process connection. Call inside a Tokio runtime; a connection ends at
    /// suspension and is opened again after the next foreground.
    ///
    /// # Errors
    /// The supervisor is not running.
    pub fn connect(&self) -> Result<LocalBusClient, SdkError> {
        self.supervisor.connect()
    }

    /// The tracker the host forwards `ConnectivityManager.NetworkCallback` calls to.
    #[must_use]
    pub const fn network(&self) -> &AndroidNetworkTracker {
        &self.network
    }

    /// The platform-neutral network monitor the tracker reports to. Gateway session
    /// configurations share it through `android::network::mobile_session_config`.
    #[must_use]
    pub const fn network_monitor(&self) -> &NetworkMonitor {
        &self.monitor
    }

    /// Make this host's network monitor and the raced `Auto` order the defaults of every
    /// gateway session the supervisor opens. Call once, before the first `on_foreground`.
    /// Returns `false` when defaults were already installed for this process.
    #[must_use]
    pub fn install_session_defaults(&self) -> bool {
        crate::platform::session_defaults::install_mobile_session_defaults(self.monitor.clone())
    }

    /// The validated storage layout, for the vault installation.
    #[must_use]
    pub const fn storage(&self) -> &AndroidStorage {
        &self.storage
    }

    /// Current neutral lifecycle state.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.lifecycle.state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::android::storage::data_root_lock_is_released;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn host(dir: &std::path::Path) -> Result<AndroidHost, SdkError> {
        AndroidHost::new(AndroidStorage::for_tests(dir), Vec::new(), NetworkMonitor::new())
    }

    /// The real supervisor over the Android storage layout: the data-root lock is held only
    /// while the application is visible.
    #[test]
    fn real_supervisor_holds_the_data_root_only_while_visible() -> TestResult {
        let dir = tempfile::tempdir()?;
        let host = host(dir.path())?;
        let data_root = host.storage().host_paths().data_root;
        assert_eq!(host.state(), LifecycleState::Stopped);
        assert!(data_root_lock_is_released(&data_root)?);

        assert_eq!(host.on_foreground()?, LifecycleOutcome::Started);
        assert!(!data_root_lock_is_released(&data_root)?, "a visible app owns the data root");

        assert!(matches!(host.on_background()?, LifecycleOutcome::Suspended(_)));
        assert!(data_root_lock_is_released(&data_root)?, "a background app holds no lock");
        assert_eq!(host.on_background()?, LifecycleOutcome::Unchanged);

        assert_eq!(host.on_foreground()?, LifecycleOutcome::Resumed);
        assert!(!data_root_lock_is_released(&data_root)?);
        assert_eq!(host.on_shutdown()?, LifecycleOutcome::Stopped);
        assert!(data_root_lock_is_released(&data_root)?);
        Ok(())
    }

    /// Process death while in the background: a new process over the same directories
    /// starts cleanly, and the installation is no longer "fresh".
    #[test]
    fn restored_process_starts_over_the_same_data_root() -> TestResult {
        let dir = tempfile::tempdir()?;
        let first = host(dir.path())?;
        first.on_foreground()?;
        first.on_background()?;
        // The system kills the cached process: nothing runs, nothing is held.
        std::mem::forget(first);

        let restored = host(dir.path())?;
        assert_eq!(restored.storage().install_state()?, InstallState::Established);
        assert_eq!(restored.on_foreground()?, LifecycleOutcome::Started);
        restored.on_shutdown()?;
        Ok(())
    }

    #[test]
    fn orphaned_vault_entries_stop_the_host_before_any_store_opens() -> TestResult {
        let dir = tempfile::tempdir()?;
        let host = host(dir.path())?;
        std::fs::write(host.storage().vault_dir().join("orphan.rfv"), b"wrapped")?;
        assert!(matches!(
            host.on_foreground(),
            Err(SdkError::CustodyVault(crate::custody::CustodyVaultReason::Missing))
        ));
        assert_eq!(host.state(), LifecycleState::Stopped);
        let data_root = host.storage().host_paths().data_root;
        assert!(data_root_lock_is_released(&data_root)?);
        Ok(())
    }

    #[test]
    fn host_tracker_reports_to_the_shared_network_monitor() -> TestResult {
        use crate::platform::android::network::{AndroidNetworkCapabilities, transport};
        use crate::platform::network::NetworkChangeKind;
        let dir = tempfile::tempdir()?;
        let host = host(dir.path())?;
        host.network().on_available(7);
        host.network().on_capabilities_changed(
            7,
            AndroidNetworkCapabilities {
                transports: transport::WIFI,
                internet: true,
                validated: true,
                not_metered: true,
                vpn: false,
            },
        );
        assert!(matches!(host.network_monitor().snapshot().kind, NetworkChangeKind::Available(_)));
        host.network().on_lost(7);
        assert_eq!(host.network_monitor().snapshot().kind, NetworkChangeKind::Lost);
        Ok(())
    }

    #[test]
    fn connect_is_refused_while_the_supervisor_is_not_running() -> TestResult {
        let dir = tempfile::tempdir()?;
        let host = host(dir.path())?;
        assert!(host.connect().is_err());
        Ok(())
    }
}
