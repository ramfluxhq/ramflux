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
    /// Enable experimental local born-v3 creation; networking remains pending.
    #[arg(long)]
    pub(crate) enable_born_v3_creation: bool,
    /// JSON array of client-supplied built-in profiles with factory public-key pins.
    #[arg(long)]
    pub(crate) builtin_nodes: Option<PathBuf>,
    #[arg(long, default_value = DEFAULT_DATA_ROOT)]
    pub(crate) data_root: PathBuf,
}
