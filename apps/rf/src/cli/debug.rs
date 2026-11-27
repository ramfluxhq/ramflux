// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Hidden `rf debug mls ...` commands over the SDK's `debug.mls.*` bus methods (MLS-0c). Built
//! only with `itest-mls-debug`. Blobs are passed as file paths.

use clap::{Args, Subcommand};

use super::PathBuf;

#[derive(Args)]
pub(crate) struct DebugCommand {
    #[command(subcommand)]
    pub(crate) action: DebugAction,
}

#[derive(Subcommand)]
pub(crate) enum DebugAction {
    /// MLS foundation debug driver.
    Mls(MlsCommand),
}

#[derive(Args)]
pub(crate) struct MlsCommand {
    /// Account that owns the MLS state.
    #[arg(long, global = true, allow_hyphen_values = true)]
    pub(crate) account: Option<String>,
    #[command(subcommand)]
    pub(crate) action: MlsAction,
}

#[derive(Subcommand)]
pub(crate) enum MlsAction {
    /// Write a fresh KeyPackage (`device` for a dm, `pseudonym` for a group).
    #[command(name = "key-package")]
    KeyPackage(MlsKeyPackageArgs),
    /// Create a `dm` or a `group` (tier 1000 or 5000).
    Create(MlsCreateArgs),
    /// Add members from KeyPackage files; writes a commit and a Welcome file.
    Add(MlsAddArgs),
    /// Add synthetic pseudonym members in batches (group kind, measurement only).
    #[command(name = "bulk-add")]
    BulkAdd(MlsBulkAddArgs),
    /// Join the group of a Welcome file (the roster check needs a pinned key for groups).
    #[command(visible_aliases = ["accept", "welcome"])]
    Join(MlsJoinArgs),
    /// Encrypt an application message into a file.
    Send(MlsSendArgs),
    /// Process a message file (application, commit or proposal).
    #[command(visible_alias = "receive")]
    Recv(MlsRecvArgs),
    /// Rotate the own leaf; writes the commit file.
    Update(MlsUpdateArgs),
    /// Announce leaving (Remove proposal by reference); another member commits it.
    Leave(MlsOutArgs),
    /// Commit the stored proposals.
    #[command(name = "commit-pending")]
    CommitPending(MlsOutArgs),
    /// Remove the member at a leaf index.
    Remove(MlsRemoveArgs),
    /// Group status, or the account row counts without a group.
    Status(MlsStatusArgs),
    /// Print the BLAKE3 digest of an exporter secret.
    Export(MlsExportArgs),
    /// Run the crypto-basics known-answer vectors of a JSON file.
    Kat(MlsKatArgs),
    /// Pin one signature key (interop peer or group roster).
    Trust(MlsTrustArgs),
}

#[derive(Args)]
pub(crate) struct MlsKeyPackageArgs {
    #[arg(long)]
    pub(crate) kind: String,
    #[arg(long)]
    pub(crate) out: PathBuf,
    /// `credential`, `transplant` or `suite`.
    #[arg(long)]
    pub(crate) tamper: Option<String>,
}

#[derive(Args)]
pub(crate) struct MlsCreateArgs {
    #[arg(long)]
    pub(crate) kind: String,
    #[arg(long)]
    pub(crate) tier: Option<u32>,
}

#[derive(Args)]
pub(crate) struct MlsAddArgs {
    #[arg(long)]
    pub(crate) group_id: String,
    /// KeyPackage file (repeatable).
    #[arg(long = "key-package", required = true)]
    pub(crate) key_packages: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) commit_out: PathBuf,
    #[arg(long)]
    pub(crate) welcome_out: PathBuf,
}

#[derive(Args)]
pub(crate) struct MlsBulkAddArgs {
    #[arg(long)]
    pub(crate) group_id: String,
    #[arg(long)]
    pub(crate) count: u64,
    #[arg(long)]
    pub(crate) batch: u64,
}

#[derive(Args)]
pub(crate) struct MlsJoinArgs {
    #[arg(long)]
    pub(crate) welcome: PathBuf,
}

#[derive(Args)]
pub(crate) struct MlsSendArgs {
    #[arg(long)]
    pub(crate) group_id: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) text: String,
    #[arg(long)]
    pub(crate) aad_hex: Option<String>,
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct MlsRecvArgs {
    #[arg(long)]
    pub(crate) message: PathBuf,
}

#[derive(Args)]
pub(crate) struct MlsUpdateArgs {
    #[arg(long)]
    pub(crate) group_id: String,
    #[arg(long)]
    pub(crate) out: PathBuf,
    /// `credential`: a commit with a damaged credential that is not merged locally.
    #[arg(long)]
    pub(crate) tamper: Option<String>,
}

#[derive(Args)]
pub(crate) struct MlsOutArgs {
    #[arg(long)]
    pub(crate) group_id: String,
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct MlsRemoveArgs {
    #[arg(long)]
    pub(crate) group_id: String,
    #[arg(long)]
    pub(crate) leaf: u32,
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct MlsStatusArgs {
    #[arg(long)]
    pub(crate) group_id: Option<String>,
}

#[derive(Args)]
pub(crate) struct MlsExportArgs {
    #[arg(long)]
    pub(crate) group_id: String,
    #[arg(long)]
    pub(crate) label: String,
    #[arg(long, default_value = "")]
    pub(crate) context_hex: String,
    #[arg(long)]
    pub(crate) len: u32,
}

#[derive(Args)]
pub(crate) struct MlsKatArgs {
    #[arg(long)]
    pub(crate) path: PathBuf,
}

#[derive(Args)]
pub(crate) struct MlsTrustArgs {
    #[arg(long)]
    pub(crate) sig_pk_hex: String,
}
