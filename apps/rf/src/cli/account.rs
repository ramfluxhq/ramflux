// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct AccountCommand {
    #[command(subcommand)]
    pub(crate) action: AccountAction,
}

#[derive(Subcommand)]
pub(crate) enum AccountAction {
    Backup(AccountBackupCommand),
    Create(Box<AccountCreate>),
    Login(Box<AccountCreate>),
    List,
    Lock(AccountLock),
    Passphrase(AccountPassphraseCommand),
    Switch(AccountSelector),
    Status(AccountSelector),
    Unlock(AccountUnlock),
}

#[derive(Args)]
pub(crate) struct AccountSelector {
    #[arg(long)]
    pub(crate) account: String,
}

#[derive(Args)]
pub(crate) struct AccountLock {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) use_keychain: bool,
}

#[derive(Args)]
pub(crate) struct AccountUnlock {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) use_keychain: bool,
    #[arg(long)]
    pub(crate) passphrase_env: Option<String>,
}

#[derive(Args)]
pub(crate) struct AccountCreate {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) principal: String,
    #[arg(long, hide = true)]
    pub(crate) expected_commitment: Option<String>,
    #[arg(long)]
    pub(crate) device: String,
    #[arg(long)]
    pub(crate) target: String,
    #[arg(long, default_value = "rf-local-secret")]
    pub(crate) secret: String,
    #[arg(long)]
    pub(crate) use_keychain: bool,
    #[arg(long, default_value = "attended_cli")]
    pub(crate) client_mode: String,
    #[arg(long, default_value = "127.0.0.1:7443")]
    pub(crate) gateway_addr: String,
    #[arg(long, default_value = "localhost")]
    pub(crate) server_name: String,
    #[arg(long, hide = true)]
    pub(crate) prekey_http_url: Option<String>,
    #[arg(long)]
    pub(crate) ca_cert: PathBuf,
    #[arg(long, default_value = "11")]
    pub(crate) root_seed_byte_hex: String,
    #[arg(long, default_value = "22")]
    pub(crate) device_seed_byte_hex: String,
}

#[derive(Args)]
pub(crate) struct AccountBackupCommand {
    #[command(subcommand)]
    pub(crate) action: AccountBackupAction,
}

#[derive(Subcommand)]
pub(crate) enum AccountBackupAction {
    Export(AccountBackupExport),
    Import(AccountBackupImport),
}

#[derive(Args)]
pub(crate) struct AccountBackupExport {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) out: PathBuf,
    #[arg(long)]
    pub(crate) passphrase_env: Option<String>,
}

#[derive(Args)]
pub(crate) struct AccountBackupImport {
    #[arg(long = "in")]
    pub(crate) input: PathBuf,
    #[arg(long)]
    pub(crate) passphrase_env: Option<String>,
}

#[derive(Args)]
pub(crate) struct AccountPassphraseCommand {
    #[command(subcommand)]
    pub(crate) action: AccountPassphraseAction,
}

#[derive(Subcommand)]
pub(crate) enum AccountPassphraseAction {
    Rotate(AccountPassphraseRotate),
}

#[derive(Args)]
pub(crate) struct AccountPassphraseRotate {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) old_passphrase_env: Option<String>,
    #[arg(long)]
    pub(crate) new_passphrase_env: Option<String>,
}
