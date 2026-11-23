// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf prx` finds or starts the local PRX daemon. The provider key is never a flag.

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct PrxCommand {
    #[command(subcommand)]
    pub(crate) action: PrxAction,
}

#[derive(Subcommand)]
pub(crate) enum PrxAction {
    /// Find a fresh runtime.json or install and start the user service.
    Bootstrap(PrxBootstrap),
    /// Print the runtime file. The token is not printed.
    Status(PrxStatus),
}

#[derive(Args)]
pub(crate) struct PrxBootstrap {
    /// State directory. The default is `$HOME/.local/share/ramflux/prx`.
    #[arg(long)]
    pub(crate) state_dir: Option<PathBuf>,
    /// Provider id. Required only when `prx init` has not been run.
    #[arg(long)]
    pub(crate) provider: Option<String>,
    /// Model id. Omitted when empty.
    #[arg(long)]
    pub(crate) model: Option<String>,
    /// The model has native tools. Required with `--model` outside the catalog.
    #[arg(long, conflicts_with = "no_native_tools", requires = "model")]
    pub(crate) native_tools: bool,
    /// The model has no native tools. Required with `--model` outside the catalog.
    #[arg(long, conflicts_with = "native_tools", requires = "model")]
    pub(crate) no_native_tools: bool,
    /// `prx` binary. The default is `prx` on `PATH`.
    #[arg(long, default_value = "prx")]
    pub(crate) binary: PathBuf,
}

#[derive(Args)]
pub(crate) struct PrxStatus {
    /// State directory. The default is `$HOME/.local/share/ramflux/prx`.
    #[arg(long)]
    pub(crate) state_dir: Option<PathBuf>,
}
