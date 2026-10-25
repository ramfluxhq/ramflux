// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct CallCommand {
    #[command(subcommand)]
    pub(crate) action: CallAction,
}

#[derive(Subcommand)]
pub(crate) enum CallAction {
    Invite(CallInvite),
    Answer(CallAnswer),
    Hangup(CallHangup),
    Reject(CallHangup),
    List(AccountSelector),
}

#[derive(Args)]
pub(crate) struct CallInvite {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
}

#[derive(Args)]
pub(crate) struct CallAnswer {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) call: String,
}

#[derive(Args)]
pub(crate) struct CallHangup {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) call: String,
}

#[derive(Args)]
pub(crate) struct BotCommand {
    #[command(subcommand)]
    pub(crate) action: BotAction,
}

#[derive(Subcommand)]
pub(crate) enum BotAction {
    Trust(BotTrustCommand),
    Install(BotInstall),
    List(AccountSelector),
    Revoke(BotRevoke),
}

#[derive(Args)]
pub(crate) struct BotTrustCommand {
    #[command(subcommand)]
    pub(crate) action: BotTrustAction,
}

#[derive(Subcommand)]
pub(crate) enum BotTrustAction {
    Add(BotTrustAdd),
}

#[derive(Args)]
pub(crate) struct BotTrustAdd {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) bot: String,
    #[arg(long = "public-key", allow_hyphen_values = true)]
    pub(crate) public_key: String,
    #[arg(long = "signing-key-id", allow_hyphen_values = true)]
    pub(crate) signing_key_id: String,
    #[arg(long = "trust-source", default_value = "local_pin")]
    pub(crate) trust_source: String,
}

#[derive(Args)]
pub(crate) struct BotInstall {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) manifest: PathBuf,
    #[arg(long)]
    pub(crate) grant: PathBuf,
    #[arg(long = "consent")]
    pub(crate) consent: Vec<String>,
}

#[derive(Args)]
pub(crate) struct BotRevoke {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) bot: String,
}
