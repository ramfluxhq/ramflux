// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub(crate) struct DmCommand {
    #[command(subcommand)]
    pub(crate) action: DmAction,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum DmAction {
    Send(DmSend),
    List(ConversationSelector),
    Read(DmRead),
    Ack(DmAck),
    Delete(DmDelete),
    Receipt(DmReceiptCommand),
    Disappearing(DmDisappearingCommand),
    Mute(DmMute),
}

#[derive(Args)]
pub(crate) struct ConversationSelector {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
}

#[derive(Args)]
pub(crate) struct DmRead {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) relay_service_key: Option<String>,
    /// Wait for deferred attachment fetches for at most this many seconds.
    #[arg(long, value_name = "SECS", default_value_t = 0)]
    pub(crate) wait: u64,
}

#[derive(Args)]
pub(crate) struct DmSend {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
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
    pub(crate) recipient_device: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) recipient_principal_commitment: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) target: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) body: String,
    #[arg(long)]
    pub(crate) attach: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) relay_service_key: Option<String>,
    #[arg(long, default_value_t = 1024)]
    pub(crate) attachment_chunk_size: usize,
    #[arg(long)]
    pub(crate) federation_url: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) source_node: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) target_node: Option<String>,
    #[arg(long)]
    pub(crate) federation_admin_token: Option<String>,
    #[arg(long)]
    pub(crate) recipient_prekey_url: Option<String>,
    #[arg(long, default_value = "opaque_delivery")]
    pub(crate) federation_capability: String,
    #[arg(long, default_value_t = 300)]
    pub(crate) ttl: u32,
}

#[derive(Args)]
pub(crate) struct DmAck {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) envelope: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) receiver_device: String,
    #[arg(long)]
    pub(crate) received_at: Option<i64>,
}

#[derive(Args)]
pub(crate) struct DmDelete {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long, default_value = "own_devices")]
    pub(crate) scope: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) tombstone: Option<String>,
}

#[derive(Args)]
pub(crate) struct DmReceiptCommand {
    #[command(subcommand)]
    pub(crate) action: DmReceiptAction,
}

#[derive(Subcommand)]
pub(crate) enum DmReceiptAction {
    Delivered(DmReceiptDelivered),
    Read(DmReceiptRead),
}

#[derive(Args)]
pub(crate) struct DmReceiptDelivered {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) receiver_device: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) recipient_device: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) target: Option<String>,
    #[arg(long)]
    pub(crate) delivered_at: Option<i64>,
    #[arg(long, default_value_t = 300)]
    pub(crate) ttl_secs: i64,
}

#[derive(Args)]
pub(crate) struct DmReceiptRead {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) reader: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) recipient_device: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) target: Option<String>,
    #[arg(long)]
    pub(crate) read_at: Option<i64>,
}

#[derive(Args)]
pub(crate) struct DmDisappearingCommand {
    #[command(subcommand)]
    pub(crate) action: DmDisappearingAction,
}

#[derive(Subcommand)]
pub(crate) enum DmDisappearingAction {
    Set(DmDisappearingSet),
    Expire(DmDisappearingExpire),
}

#[derive(Args)]
pub(crate) struct DmDisappearingSet {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) ttl_secs: i64,
}

#[derive(Args)]
pub(crate) struct DmDisappearingExpire {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) now: Option<i64>,
}

#[derive(Args)]
pub(crate) struct DmMute {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) unmute: bool,
    #[arg(long)]
    pub(crate) mute_until: Option<i64>,
}

#[cfg(test)]
mod wait_tests {
    use super::*;

    #[test]
    fn attachment_read_wait_defaults_to_zero_and_parses_seconds() -> Result<(), clap::Error> {
        for (extra, expected) in [(vec![], 0), (vec!["--wait", "240"], 240)] {
            let mut args = vec!["rf", "dm", "read", "--account", "bob", "--conversation", "thread"];
            args.extend(extra);
            let cli = Cli::try_parse_from(args)?;
            if let Command::Dm(DmCommand { action: DmAction::Read(read) }) = cli.command {
                assert_eq!(read.wait, expected);
            } else {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::InvalidSubcommand,
                    "expected dm read",
                ));
            }
        }
        assert!(
            Cli::try_parse_from([
                "rf",
                "dm",
                "read",
                "--account",
                "bob",
                "--conversation",
                "thread",
                "--wait",
                "-1"
            ])
            .is_err()
        );
        Ok(())
    }
}
