// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Preview CLI for the shared native pairing coordinator.
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct PairingCommand {
    #[arg(long)]
    pub(crate) account: String,
    #[command(subcommand)]
    pub(crate) action: PairingAction,
}
#[derive(Args)]
pub(crate) struct PairingOperation {
    #[arg(long)]
    pub(crate) operation_id: String,
    #[arg(long)]
    pub(crate) generation: u64,
}
#[derive(Subcommand)]
pub(crate) enum PairingAction {
    /// Begin enrollment. Write the one-shot invitation only to a new private file.
    Begin {
        #[arg(long)]
        display_name: String,
        #[arg(long, value_delimiter = ',', default_value = "message,register,sync")]
        capabilities: Vec<String>,
        #[arg(long)]
        lease_not_before: u64,
        #[arg(long)]
        lease_expires_at: u64,
        #[arg(long)]
        invitation_out: PathBuf,
    },
    /// Join using a private invitation file; bearer tokens are never accepted in argv.
    Join {
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        invitation_file: PathBuf,
    },
    Confirm {
        #[command(flatten)]
        operation: PairingOperation,
        #[arg(long)]
        transcript_hash: String,
        #[arg(long, action = clap::ArgAction::Set, required = true)]
        matches: bool,
    },
    Approve {
        #[command(flatten)]
        operation: PairingOperation,
        #[arg(long)]
        transcript_hash: String,
        #[arg(long)]
        proposal_hash: String,
        #[arg(long, action = clap::ArgAction::Set, required = true)]
        approved: bool,
    },
    Status(PairingOperation),
    Cancel(PairingOperation),
}
