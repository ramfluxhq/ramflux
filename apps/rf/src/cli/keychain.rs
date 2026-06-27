// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct KeychainCommand {
    #[command(subcommand)]
    pub(crate) action: KeychainAction,
}

#[derive(Subcommand)]
pub(crate) enum KeychainAction {
    Store(KeychainStore),
    Remove(KeychainSelector),
    Status(KeychainSelector),
}

#[derive(Args)]
pub(crate) struct KeychainSelector {
    #[arg(long)]
    pub(crate) account: String,
}

#[derive(Args)]
pub(crate) struct KeychainStore {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) passphrase_env: Option<String>,
    #[arg(long)]
    pub(crate) device_seed_byte_hex: Option<String>,
}
