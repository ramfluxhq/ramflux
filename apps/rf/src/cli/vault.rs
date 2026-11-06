// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct VaultCommand {
    #[command(subcommand)]
    pub action: VaultAction,
}
#[derive(Subcommand)]
pub(crate) enum VaultAction {
    /// Explicitly initialize/resume a dormant installation, without account enrollment.
    Init(VaultOptions),
    /// Verify an already committed installation and its original credentials.
    Status(VaultOptions),
}
#[derive(Args)]
pub(crate) struct VaultOptions {
    #[arg(long)]
    pub mode: String,
    /// Existing operator-owned 0700 directory outside account backups.
    #[arg(long)]
    pub vault_root: PathBuf,
}
