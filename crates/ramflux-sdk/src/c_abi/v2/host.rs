// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The one thing C ABI major 2 executes through: an in-process supervisor.

use crate::{HostLifecycle, LocalBusClient, LocalBusCreationClient, SdkError};

/// A supervisor the shim can drive and connect to. The shim holds no account state of its
/// own; this trait is the whole of its backend.
pub trait CoreHost: HostLifecycle + 'static {
    /// Open one in-process connection. Called inside the shim's runtime.
    ///
    /// # Errors
    /// Returns an error when the supervisor is not running.
    fn connect(&self) -> Result<LocalBusClient, SdkError>;

    /// Open one dedicated connection for an account-creation ceremony.
    ///
    /// # Errors
    /// Returns an error when the supervisor is not running.
    fn connect_creation(&self) -> Result<LocalBusCreationClient, SdkError>;
}

#[cfg(unix)]
impl CoreHost for crate::EmbeddedSupervisor {
    fn connect(&self) -> Result<LocalBusClient, SdkError> {
        crate::EmbeddedSupervisor::connect(self)
    }

    fn connect_creation(&self) -> Result<LocalBusCreationClient, SdkError> {
        crate::EmbeddedSupervisor::connect_creation(self)
    }
}

/// Build the production host for a data root.
#[cfg(unix)]
pub(super) fn embedded(
    data_root: std::path::PathBuf,
    suspend_deadline: Option<std::time::Duration>,
) -> std::sync::Arc<dyn CoreHost> {
    let mut config = crate::EmbeddedConfig::new(crate::HostPaths { data_root });
    if let Some(deadline) = suspend_deadline {
        config.suspend_deadline = deadline;
    }
    std::sync::Arc::new(crate::EmbeddedSupervisor::new(config))
}
