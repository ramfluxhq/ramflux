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
    #[arg(long, default_value = DEFAULT_DATA_ROOT)]
    pub(crate) data_root: PathBuf,
}
