// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct CentreCommand {
    #[command(subcommand)]
    pub(crate) action: CentreAction,
}

#[derive(Subcommand)]
pub(crate) enum CentreAction {
    /// Print the node public key, `key_gen` and fingerprint of the node signing seed (offline).
    Key(CentreKey),
    /// Print the one-line signed enrolment request for a centre (offline); `--rotate` co-signs a key rotation.
    EnrolRequest(CentreEnrolRequest),
}

#[derive(Args)]
pub(crate) struct CentreKey {
    /// Existing certs/node-identity/node-signing.key, read only.
    #[arg(long)]
    pub(crate) node_signing_seed: PathBuf,
    /// `key_gen` registered for this key at the centre.
    #[arg(long, default_value_t = 1)]
    pub(crate) key_gen: u64,
}

#[derive(Args)]
pub(crate) struct CentreEnrolRequest {
    /// `centre_id` the request is bound to (the one in the invitation; 1-128 printable ASCII).
    #[arg(long)]
    pub(crate) centre: String,
    /// Operator or organisation name for the centre's administrators (1-64 bytes).
    #[arg(long)]
    pub(crate) name: String,
    /// Node domain: lower-case ASCII DNS host name, IDN as A-label, no port, path or IP literal.
    #[arg(long)]
    pub(crate) domain: String,
    /// Node signing seed of the key being enrolled (the new key when rotating).
    #[arg(long)]
    pub(crate) node_signing_seed: PathBuf,
    /// `key_gen` to register for the key (not used with `--rotate`).
    #[arg(long, default_value_t = 1, conflicts_with = "rotate")]
    pub(crate) key_gen: u64,
    /// Rotation request: co-signed by the old key named by `--old-node-signing-seed`; `key_gen` = old + 1.
    #[arg(long, requires = "old_node_signing_seed")]
    pub(crate) rotate: bool,
    /// Node signing seed of the key being replaced (rotation only).
    #[arg(long, requires = "rotate")]
    pub(crate) old_node_signing_seed: Option<PathBuf>,
    /// `key_gen` currently registered for the old key (rotation only); the new key registers old + 1.
    #[arg(long, default_value_t = 1, requires = "rotate")]
    pub(crate) old_key_gen: u64,
}
