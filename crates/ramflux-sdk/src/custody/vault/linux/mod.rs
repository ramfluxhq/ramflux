// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate Linux configuration. Production provider selection remains disabled.
mod config;
mod error;

pub use config::{LinuxCredentialPaths, LinuxVaultConfig, LinuxVaultMode, LinuxVaultRole};
pub use error::LinuxVaultConfigError;
