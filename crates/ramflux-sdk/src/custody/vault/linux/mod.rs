// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate Linux configuration. Production provider selection remains disabled.
mod config;
mod error;

pub use config::{LinuxCredentialPaths, LinuxVaultConfig, LinuxVaultMode, LinuxVaultRole};
pub use error::LinuxVaultConfigError;

// Private codec foundation; P03 supplies its first production file-store consumer.
#[cfg(target_os = "linux")]
mod cleanup;
#[cfg(target_os = "linux")]
mod codec;

#[cfg(target_os = "linux")]
mod files;
#[cfg(target_os = "linux")]
mod writer;

#[cfg(target_os = "linux")]
mod durability;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod secret_service;
#[cfg(target_os = "linux")]
mod systemd;
#[cfg(all(target_os = "linux", test))]
mod test_proc;
#[cfg(target_os = "linux")]
pub use init::{LinuxVaultInitError, LinuxVaultInstallation};

#[cfg(target_os = "linux")]
mod data;
#[cfg(target_os = "linux")]
mod primary;
#[cfg(target_os = "linux")]
pub use data::LinuxDataCredentials;
#[cfg(target_os = "linux")]
pub use primary::LinuxPrimaryVault;
