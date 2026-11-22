// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct UsernameCommand {
    #[command(subcommand)]
    pub action: UsernameAction,
}

#[derive(Subcommand)]
pub(crate) enum UsernameAction {
    Set(UsernameSet),
    Resolve(UsernameResolve),
    Status(UsernameStatus),
    Release(UsernameAuthorize),
    Delete(UsernameAuthorize),
    Profile(UsernameProfile),
    Visibility(UsernameVisibility),
}

#[derive(Args)]
pub(crate) struct UsernameAuthorize {
    #[arg(long)]
    pub account: String,
    /// Read recovery words from an owner-only file; otherwise use the private terminal prompt.
    #[arg(long)]
    pub recovery_phrase_file: Option<PathBuf>,
}
#[derive(Args)]
pub(crate) struct UsernameSet {
    pub name: String,
    #[command(flatten)]
    pub authorization: UsernameAuthorize,
}
#[derive(Args)]
pub(crate) struct UsernameResolve {
    pub name: String,
    #[arg(long)]
    pub account: String,
}
#[derive(Args)]
pub(crate) struct UsernameStatus {
    #[arg(long)]
    pub account: String,
    #[arg(long)]
    pub operation_id: Option<String>,
}
#[derive(Args)]
pub(crate) struct UsernameProfile {
    #[arg(long)]
    pub bio: Option<String>,
    #[arg(long)]
    pub display_name: Option<String>,
    #[command(flatten)]
    pub authorization: UsernameAuthorize,
}

#[derive(Args)]
pub(crate) struct UsernameVisibility {
    #[arg(long, required = true, action = clap::ArgAction::Set)]
    pub discoverable: bool,
    #[command(flatten)]
    pub authorization: UsernameAuthorize,
}
