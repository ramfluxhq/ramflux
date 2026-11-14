// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Preview CLI for the shared native pairing coordinator.
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct PairingCommand {
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) account: String,
    /// Write the seven SAS names to a new private file when no terminal is available.
    #[arg(long, global = true)]
    pub(crate) sas_out: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) action: PairingAction,
}
#[derive(Args)]
pub(crate) struct PairingOperation {
    #[arg(long, allow_hyphen_values = true)]
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
        #[arg(long, allow_hyphen_values = true)]
        transcript_hash: String,
        #[arg(long, action = clap::ArgAction::Set, required = true)]
        matches: bool,
        /// Private SAS file produced by the other device, never a cached local affirmation.
        #[arg(long)]
        peer_sas_file: Option<PathBuf>,
        /// Attest this file came from the physically held peer over a trusted out-of-band path.
        #[arg(long, requires = "peer_sas_file")]
        peer_sas_attended: bool,
    },
    Approve {
        #[command(flatten)]
        operation: PairingOperation,
        #[arg(long, allow_hyphen_values = true)]
        transcript_hash: String,
        #[arg(long, allow_hyphen_values = true)]
        proposal_hash: String,
        #[arg(long, action = clap::ArgAction::Set, required = true)]
        approved: bool,
    },
    Status(PairingOperation),
    /// Show full-transfer stage, durable byte totals and the exact typed refusal.
    TransferStatus(PairingOperation),
    Cancel(PairingOperation),
}
