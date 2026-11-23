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
    Add(ContactAdd),
    Card(AccountSelector),
    Request(ContactFederatedLink),
    Accept(ContactAccept),
    Remove(ContactRemove),
    Reject(ContactLinkSelector),
    Block(ContactLinkSelector),
    Unblock(ContactLinkSelector),
    List(AccountSelector),
    Requests(AccountSelector),
    Verify(ContactVerify),
    SafetyNumber(ContactSafetySelector),
    Verification(ContactVerificationCommand),
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("contact_selector").args(["principal", "card", "target", "username"]).required(true).multiple(false)))]
pub(crate) struct ContactAdd {
    /// Exact @username to resolve and add.
    pub(crate) username: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) principal: Option<String>,
    #[arg(long)]
    pub(crate) card: Option<String>,
    #[arg(allow_hyphen_values = true, long, requires = "card")]
    pub(crate) replace_provisional_root: Option<String>,
    #[arg(long, requires_all = ["link", "requester"], allow_hyphen_values = true)]
    pub(crate) target: Option<String>,
    #[arg(allow_hyphen_values = true, long, requires = "target")]
    pub(crate) link: Option<String>,
    #[arg(allow_hyphen_values = true, long, requires = "target")]
    pub(crate) requester: Option<String>,
}

#[derive(Args)]
pub(crate) struct ContactLink {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) link: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) requester: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) target: String,
}

#[derive(Args)]
#[command(group(
    clap::ArgGroup::new("accept_selector")
        .args(["principal", "request", "link", "root"])
        .required(true)
        .multiple(false)
))]
pub(crate) struct ContactAccept {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) principal: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) request: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) link: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) root: Option<String>,
}

#[derive(Args)]
pub(crate) struct ContactRemove {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) link: String,
    #[arg(long, default_value = "me")]
    pub(crate) scope: String,
}

#[derive(Args)]
pub(crate) struct ContactLinkSelector {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
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
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) envelope: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) source_principal: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) sender: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) recipient_device: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) target_delivery: String,
}

#[derive(Args)]
pub(crate) struct ContactSafetySelector {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) contact: String,
}

#[derive(Args)]
pub(crate) struct ContactVerify {
    #[command(flatten)]
    pub(crate) selector: ContactSafetySelector,
    #[arg(long, requires = "expected_safety")]
    pub(crate) mark_verified: bool,
    /// Compare-and-set stamp: the `expected` JSON object shown by `rf contact verify`
    /// (without `--mark-verified`) or `rf contact safety-number`.
    #[arg(long, requires = "mark_verified", value_parser = parse_expected_safety)]
    pub(crate) expected_safety: Option<ramflux_protocol::message::ExpectedContactSafety>,
}

fn parse_expected_safety(
    text: &str,
) -> Result<ramflux_protocol::message::ExpectedContactSafety, String> {
    serde_json::from_str(text).map_err(|error| format!("invalid expected-safety stamp: {error}"))
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
