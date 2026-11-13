// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate-bound source affirmation is separate from initial SAS confirmation.
use super::PairingOperation;
use clap::{Args, Subcommand};
use std::path::PathBuf;
#[derive(Args)]
pub(crate) struct TransferCommand {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long, global = true)]
    pub(crate) sas_out: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) action: TransferAction,
}
#[derive(Subcommand)]
pub(crate) enum TransferAction {
    /// Move the full account to a new device or an existing linked device.
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
        #[arg(long, requires = "destination_epoch")]
        destination_device: Option<String>,
        #[arg(long, requires = "destination_device")]
        destination_epoch: Option<u64>,
        #[arg(long, requires = "destination_device")]
        account_anchor: Option<String>,
    },
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
        #[arg(long)]
        peer_sas_file: Option<PathBuf>,
        #[arg(long, requires = "peer_sas_file")]
        peer_sas_attended: bool,
    },
    /// Prepare B's exact candidate using private attended phrase input.
    Prepare {
        #[command(flatten)]
        operation: PairingOperation,
        #[arg(long)]
        transcript_hash: String,
    },
    Status(PairingOperation),
    Cancel(PairingOperation),
    /// Affirm one resumed source candidate. Positive approval requires an interactive terminal.
    Affirm {
        #[command(flatten)]
        operation: PairingOperation,
        #[arg(long)]
        transcript_hash: String,
        #[arg(long)]
        new_record_hash: String,
        #[arg(long,action=clap::ArgAction::Set,required=true)]
        approved: bool,
    },
}
