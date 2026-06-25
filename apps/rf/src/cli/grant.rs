// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct GrantCommand {
    #[command(subcommand)]
    pub(crate) action: GrantAction,
}

#[derive(Subcommand)]
pub(crate) enum GrantAction {
    List(AccountSelector),
    Show(GrantSelector),
    Audit(AccountSelector),
    Approve(ApprovalSelector),
    Deny(ApprovalSelector),
    Request(GrantRequest),
    Revoke(GrantRevoke),
}

#[derive(Args)]
pub(crate) struct ApprovalSelector {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) approval: String,
}

#[derive(Args)]
pub(crate) struct GrantSelector {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) grant: String,
}

#[derive(Args)]
pub(crate) struct GrantRequest {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) grant: String,
    #[arg(long)]
    pub(crate) server: Option<String>,
    #[arg(long)]
    pub(crate) tool: Option<String>,
    #[arg(long)]
    pub(crate) capability: Option<String>,
    #[arg(long, default_value_t = false)]
    pub(crate) full_delegation: bool,
}

#[derive(Args)]
pub(crate) struct GrantRevoke {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) grant: String,
}
