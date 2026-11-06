// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate Linux configuration. Production provider selection remains disabled.
mod config;
mod error;

pub use config::{LinuxCredentialPaths, LinuxVaultConfig, LinuxVaultMode, LinuxVaultRole};
pub use error::LinuxVaultConfigError;

// Private codec foundation; P03 supplies its first production file-store consumer.
#[cfg(all(target_os = "linux", test))]
mod cleanup;
#[cfg(all(target_os = "linux", test))]
mod codec;

#[cfg(all(target_os = "linux", test))]
mod files;
#[cfg(all(target_os = "linux", test))]
mod writer;
