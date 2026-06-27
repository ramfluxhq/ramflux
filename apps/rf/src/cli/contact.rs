// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct ContactCommand {
    #[command(subcommand)]
    pub(crate) action: ContactAction,
}

#[derive(Subcommand)]
pub(crate) enum ContactAction {
    Add(ContactLink),
    Request(ContactFederatedLink),
    Accept(ContactAccept),
    Remove(ContactRemove),
    Block(ContactLinkSelector),
    Unblock(ContactLinkSelector),
    List(AccountSelector),
    Verify(ContactVerify),
    SafetyNumber(ContactSafetySelector),
    Verification(ContactVerificationCommand),
}

#[derive(Args)]
pub(crate) struct ContactLink {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) link: String,
    #[arg(long)]
    pub(crate) requester: String,
    #[arg(long)]
    pub(crate) target: String,
}

#[derive(Args)]
pub(crate) struct ContactAccept {
    #[command(flatten)]
    pub(crate) link: ContactLink,
    #[command(flatten)]
    pub(crate) federated: Option<ContactFederatedArgs>,
}

#[derive(Args)]
pub(crate) struct ContactRemove {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) link: String,
    #[arg(long, default_value = "me")]
    pub(crate) scope: String,
}

#[derive(Args)]
pub(crate) struct ContactLinkSelector {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) link: String,
}

#[derive(Args)]
pub(crate) struct ContactFederatedLink {
    #[command(flatten)]
    pub(crate) link: ContactLink,
    #[command(flatten)]
    pub(crate) federated: ContactFederatedArgs,
}

#[derive(Args, Clone)]
pub(crate) struct ContactFederatedArgs {
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) message: String,
    #[arg(long)]
    pub(crate) envelope: String,
    #[arg(long)]
    pub(crate) source_principal: String,
    #[arg(long)]
    pub(crate) sender: String,
    #[arg(long)]
    pub(crate) recipient_device: String,
    #[arg(long)]
    pub(crate) target_delivery: String,
    #[arg(long)]
    pub(crate) federation_url: String,
    #[arg(long)]
    pub(crate) source_node: String,
    #[arg(long)]
    pub(crate) target_node: String,
    #[arg(long)]
    pub(crate) federation_admin_token: Option<String>,
    #[arg(long)]
    pub(crate) recipient_prekey_url: Option<String>,
    #[arg(long, default_value = "opaque_delivery")]
    pub(crate) federation_capability: String,
}

#[derive(Args)]
pub(crate) struct ContactSafetySelector {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) contact: String,
}

#[derive(Args)]
pub(crate) struct ContactVerify {
    #[command(flatten)]
    pub(crate) selector: ContactSafetySelector,
    #[arg(long)]
    pub(crate) mark_verified: bool,
}

#[derive(Args)]
pub(crate) struct ContactVerificationCommand {
    #[command(subcommand)]
    pub(crate) action: ContactVerificationAction,
}

#[derive(Subcommand)]
pub(crate) enum ContactVerificationAction {
    Status(ContactSafetySelector),
}
