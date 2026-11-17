// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf attachment import` streams one received file to a path. `rf attachment enable` pins the
//! home relay's attachment authority for one account.

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct AttachmentCommand {
    #[command(subcommand)]
    pub(crate) action: AttachmentAction,
}

#[derive(Subcommand)]
pub(crate) enum AttachmentAction {
    Import(AttachmentImport),
    Enable(AttachmentEnable),
}

#[derive(Args)]
pub(crate) struct AttachmentEnable {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    /// Read the pin from the home relay through the gateway session.
    #[arg(long)]
    pub(crate) from_node: bool,
    #[arg(long)]
    pub(crate) source: Option<String>,
    #[arg(long)]
    pub(crate) generation: Option<u64>,
    #[arg(long)]
    pub(crate) public_key_hex: Option<String>,
    #[arg(long)]
    pub(crate) home_node_id: Option<String>,
}

#[derive(Args)]
pub(crate) struct AttachmentImport {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long)]
    pub(crate) index: u64,
    #[arg(long)]
    pub(crate) output: PathBuf,
}
