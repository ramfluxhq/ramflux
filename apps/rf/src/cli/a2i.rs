// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct A2iCommand {
    #[command(subcommand)]
    pub(crate) action: A2iAction,
}

#[derive(Subcommand)]
pub(crate) enum A2iAction {
    Append(A2iAppend),
    List(AccountSelector),
    Ack(A2iAck),
}

#[derive(Args)]
pub(crate) struct A2iAppend {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) event: String,
    #[arg(long = "type")]
    pub(crate) event_type: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) source_device: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) target_device: String,
    #[arg(long = "control-domain")]
    pub(crate) control_domain: String,
    #[arg(long)]
    pub(crate) action: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) subject: String,
    #[arg(long)]
    pub(crate) created_at: Option<i64>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) target_delivery: Option<String>,
}

#[derive(Args)]
pub(crate) struct A2iAck {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) event: String,
}
