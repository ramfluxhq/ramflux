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
        #[arg(allow_hyphen_values = true, long)]
        account: String,
        #[arg(
            long,
            required_unless_present = "surface_ref",
            conflicts_with = "surface_ref",
            allow_hyphen_values = true
        )]
        surface_id: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        surface_ref: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        conversation: Option<String>,
        #[arg(allow_hyphen_values = true, long)]
        author: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
        action_id: Option<String>,
    },
    List {
        #[arg(allow_hyphen_values = true, long)]
        account: String,
        #[arg(long, allow_hyphen_values = true)]
        conversation: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, allow_hyphen_values = true)]
        cursor: Option<String>,
    },
    /// Ask the author for a signed full state when this recipient is out of sync.
    RequestResync {
        #[arg(allow_hyphen_values = true, long)]
        account: String,
        #[arg(long, allow_hyphen_values = true)]
        surface_ref: String,
    },
    Resync {
        #[arg(allow_hyphen_values = true, long)]
        account: String,
        #[arg(long, allow_hyphen_values = true)]
        surface_ref: String,
        #[arg(long, allow_hyphen_values = true)]
        message: Option<String>,
    },
    /// Send a canonical Surface v3 event or RPC frame.
    Send(SurfaceSend),
    /// Submit a canonical Surface v3 action to its author.
    Action(SurfaceSend),
}
#[derive(Args)]
pub(crate) struct SurfaceSend {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: Option<String>,
    #[arg(long)]
    pub(crate) wire_file: PathBuf,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) author: Option<String>,
}
