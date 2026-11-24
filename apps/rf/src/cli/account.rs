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
    AppLock(AccountAppLockCommand),
    Backup(AccountBackupCommand),
    Create(Box<AccountCreate>),
    ExportAgentCredentials(AccountExportAgentCredentials),
    Recover(AccountSelector),
    List,
    Lock(AccountLock),
    Passphrase(AccountPassphraseCommand),
    Switch(AccountSelector),
    Status(AccountSelector),
    Unlock(AccountUnlock),
}

#[derive(Args)]
pub(crate) struct AccountAppLockCommand {
    #[command(subcommand)]
    pub(crate) action: AccountAppLockAction,
}

#[derive(Subcommand)]
pub(crate) enum AccountAppLockAction {
    State(AccountSelector),
    Set(AccountAppLockSet),
}

#[derive(Args)]
pub(crate) struct AccountAppLockSet {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, action = clap::ArgAction::Set, required = true)]
    pub(crate) enabled: bool,
    #[arg(long)]
    pub(crate) timeout_ms: u64,
}

#[derive(Args)]
pub(crate) struct AccountSelector {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
}

#[derive(Args)]
pub(crate) struct AccountLock {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) use_keychain: bool,
}

#[derive(Args)]
pub(crate) struct AccountUnlock {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) use_keychain: bool,
    #[arg(long)]
    pub(crate) passphrase_env: Option<String>,
}

#[derive(Args)]
pub(crate) struct AccountCreate {
    #[arg(long)]
    pub(crate) display_name: String,
}

#[derive(Args)]
pub(crate) struct AccountExportAgentCredentials {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    /// Select the agent's human custodian explicitly instead of resolving its custody record.
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) custodian: Option<String>,
    #[arg(long)]
    pub(crate) out: PathBuf,
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
    #[arg(allow_hyphen_values = true, long)]
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
    /// Independent local data passphrase for a new installation, never the archive password.
    #[arg(long)]
    pub(crate) new_passphrase_env: Option<String>,
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
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) old_passphrase_env: Option<String>,
    #[arg(long)]
    pub(crate) new_passphrase_env: Option<String>,
}
