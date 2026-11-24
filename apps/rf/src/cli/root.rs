// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared-root snapshot and one fenced direct-message commit.
#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct RootCommand {
    #[command(subcommand)]
    pub(crate) action: RootAction,
}

#[derive(Subcommand)]
pub(crate) enum RootAction {
    /// Read committed message ids. Does not take the writer lease.
    Snapshot(RootSnapshot),
    /// Commit one direct-message projection, or return `account_busy`.
    Commit(RootCommit),
}

#[derive(Args)]
pub(crate) struct RootSnapshot {
    #[arg(long)]
    pub(crate) data_root: PathBuf,
    #[arg(long)]
    pub(crate) account: String,
    /// Environment variable holding the account code. Defaults to `RAMFLUX_ACCOUNT_PASSPHRASE`.
    #[arg(long)]
    pub(crate) passphrase_env: Option<String>,
}

#[derive(Args)]
pub(crate) struct RootCommit {
    #[arg(long)]
    pub(crate) data_root: PathBuf,
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) message_id: String,
    #[arg(long)]
    pub(crate) sender: String,
    /// Environment variable holding the account code. Defaults to `RAMFLUX_ACCOUNT_PASSPHRASE`.
    #[arg(long)]
    pub(crate) passphrase_env: Option<String>,
}
