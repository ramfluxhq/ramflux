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
    Read(ConversationSelector),
    Ack(DmAck),
    Delete(DmDelete),
    Receipt(DmReceiptCommand),
    Disappearing(DmDisappearingCommand),
    Mute(DmMute),
}

#[derive(Args)]
pub(crate) struct ConversationSelector {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
}

#[derive(Args)]
pub(crate) struct DmSend {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) message: String,
    #[arg(long)]
    pub(crate) envelope: String,
    #[arg(long)]
    pub(crate) source_principal: String,
    #[arg(long)]
    pub(crate) sender: String,
    #[arg(long)]
    pub(crate) recipient_device: Option<String>,
    #[arg(long)]
    pub(crate) target: String,
    #[arg(long)]
    pub(crate) body: String,
    #[arg(long)]
    pub(crate) federation_url: Option<String>,
    #[arg(long)]
    pub(crate) source_node: Option<String>,
    #[arg(long)]
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
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) envelope: Option<String>,
    #[arg(long)]
    pub(crate) message: Option<String>,
    #[arg(long)]
    pub(crate) receiver_device: String,
    #[arg(long)]
    pub(crate) received_at: Option<i64>,
}

#[derive(Args)]
pub(crate) struct DmDelete {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) message: String,
    #[arg(long, default_value = "own_devices")]
    pub(crate) scope: String,
    #[arg(long)]
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
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) message: String,
    #[arg(long)]
    pub(crate) receiver_device: String,
    #[arg(long)]
    pub(crate) delivered_at: Option<i64>,
    #[arg(long, default_value_t = 300)]
    pub(crate) ttl_secs: i64,
}

#[derive(Args)]
pub(crate) struct DmReceiptRead {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) message: String,
    #[arg(long)]
    pub(crate) reader: String,
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
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) ttl_secs: i64,
}

#[derive(Args)]
pub(crate) struct DmDisappearingExpire {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) now: Option<i64>,
}

#[derive(Args)]
pub(crate) struct DmMute {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) unmute: bool,
    #[arg(long)]
    pub(crate) mute_until: Option<i64>,
}
