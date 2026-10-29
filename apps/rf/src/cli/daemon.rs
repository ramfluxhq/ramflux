// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct DaemonCommand {
    #[command(subcommand)]
    pub(crate) action: DaemonAction,
}

#[derive(Subcommand)]
pub(crate) enum DaemonAction {
    Start(DaemonStart),
    Status,
    Stop,
}

#[derive(Args)]
pub(crate) struct DaemonStart {
    /// Enable the temporary legacy fixture namespace (requires the matching build feature).
    #[arg(long, hide = true)]
    pub(crate) itest_legacy_accounts: bool,
    /// Use a process-local credential vault for integration tests only.
    #[cfg(feature = "itest-memory-vault")]
    #[arg(long)]
    pub(crate) itest_memory_vault: bool,
    /// JSON array of client-supplied built-in profiles with factory public-key pins.
    #[arg(long)]
    pub(crate) builtin_nodes: Option<PathBuf>,
    #[arg(long, default_value = DEFAULT_DATA_ROOT)]
    pub(crate) data_root: PathBuf,
}
