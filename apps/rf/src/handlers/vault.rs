// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{RfError, cli::VaultCommand};

#[cfg(target_os = "linux")]
use crate::cli::VaultAction;

pub(crate) async fn handle(command: VaultCommand) -> Result<(), RfError> {
    #[cfg(target_os = "linux")]
    {
        use ramflux_sdk::custody::{LinuxVaultInstallation, LinuxVaultMode};
        let (options, initialize) = match command.action {
            VaultAction::Init(o) => (o, true),
            VaultAction::Status(o) => (o, false),
        };
        let mode =
            LinuxVaultMode::parse(&options.mode).map_err(|e| RfError::Message(e.to_string()))?;
        let result = if initialize {
            LinuxVaultInstallation::initialize(options.vault_root, mode).await
        } else {
            LinuxVaultInstallation::status(options.vault_root, mode).await
        };
        result.map_err(|e| RfError::Message(e.to_string()))?;
        println!("vault_ready {}", mode.strength_class());
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
        Err(RfError::Message("vault_platform_unavailable".into()))
    }
}
