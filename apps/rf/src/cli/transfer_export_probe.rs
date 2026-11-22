// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Integration-only primary-transfer export probes (rf itest builds only).
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct TransferExportProbeCommand {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    #[command(subcommand)]
    pub(crate) action: TransferExportProbeAction,
}

#[derive(Subcommand)]
pub(crate) enum TransferExportProbeAction {
    /// Export the unlocked account into a private directory (export.db, export.key).
    Write {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Run the recipient's fresh-device check (A4) against this account's database.
    Fresh,
    /// Hardened open of an export file, then a clean copy at a new path.
    Open {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        expected_root: String,
        #[arg(long)]
        clean_copy: PathBuf,
    },
}
