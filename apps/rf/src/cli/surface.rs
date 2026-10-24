// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use clap::{Args, Subcommand};
use std::path::PathBuf;
#[derive(Args)]
pub(crate) struct SurfaceCommand {
    #[command(subcommand)]
    pub(crate) action: SurfaceAction,
}
#[derive(Subcommand)]
pub(crate) enum SurfaceAction {
    Get {
        #[arg(long)]
        account: String,
        #[arg(long, required_unless_present = "surface_ref", conflicts_with = "surface_ref")]
        surface_id: Option<String>,
        #[arg(long)]
        surface_ref: Option<String>,
        #[arg(long)]
        conversation: Option<String>,
        #[arg(long)]
        author: Option<String>,
        #[arg(long)]
        action_id: Option<String>,
    },
    List {
        #[arg(long)]
        account: String,
        #[arg(long)]
        conversation: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        cursor: Option<String>,
    },
    Send(SurfaceSend),
    Action(SurfaceSend),
}
#[derive(Args)]
pub(crate) struct SurfaceSend {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) message: Option<String>,
    #[arg(long)]
    pub(crate) wire_file: PathBuf,
    #[arg(long)]
    pub(crate) author: Option<String>,
}
