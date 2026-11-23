// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use clap::{Args, Subcommand};

use std::path::PathBuf;
#[derive(Args)]
pub(crate) struct GroupCommand {
    #[command(subcommand)]
    pub(crate) action: GroupAction,
}

#[derive(Subcommand)]
pub(crate) enum GroupAction {
    Create(GroupCreate),
    Rename(GroupRename),
    Send(GroupSend),
    Read(GroupRead),
    Message(GroupMessageCommand),
    List(AccountSelector),
    Members(GroupMembers),
    Member(GroupMemberCommand),
    Role(GroupRoleCommand),
    Disappearing(GroupDisappearingCommand),
    Mute(GroupMute),
}

#[derive(Args)]
pub(crate) struct GroupRename {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) name: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) request_id: Option<String>,
}

#[derive(Args)]
pub(crate) struct GroupCreate {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) creator: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) creator_signing_public_key: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) creator_target_delivery: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) member: Vec<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) member_target_delivery: Option<String>,
}

#[derive(Args)]
pub(crate) struct GroupMembers {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
}

#[derive(Args)]
pub(crate) struct GroupMemberCommand {
    #[command(subcommand)]
    pub(crate) action: GroupMemberAction,
}

#[derive(Subcommand)]
pub(crate) enum GroupMemberAction {
    Add(Box<GroupMemberAdd>),
    Kick(GroupMemberKick),
    Remove(GroupMemberRemove),
    List(GroupMembers),
}

#[derive(Args)]
pub(crate) struct GroupMemberAdd {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) member_device: String,
    #[arg(long, default_value = "member")]
    pub(crate) role: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) member_signing_public_key: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) member_principal_commitment: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) target_delivery: Option<String>,
}

#[derive(Args)]
pub(crate) struct GroupMemberRemove {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) actor: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) member_device: String,
}

#[derive(Args)]
pub(crate) struct GroupMemberKick {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) actor: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) member_device: String,
    #[arg(long)]
    pub(crate) reason: Option<String>,
}

#[derive(Args)]
pub(crate) struct GroupMessageCommand {
    #[command(subcommand)]
    pub(crate) action: GroupMessageAction,
}

#[derive(Subcommand)]
pub(crate) enum GroupMessageAction {
    Delete(GroupMessageDelete),
}

#[derive(Args)]
pub(crate) struct GroupMessageDelete {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long = "scope", alias = "delete-scope", default_value = "everyone", value_parser = ["local", "everyone"])]
    pub(crate) delete_scope: String,
    /// Local retry token; the SDK allocates the generated Delete event.
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) operation_id: Option<String>,
}

#[derive(Args)]
pub(crate) struct GroupRoleCommand {
    #[command(subcommand)]
    pub(crate) action: GroupRoleAction,
}

#[derive(Subcommand)]
pub(crate) enum GroupRoleAction {
    Set(GroupRoleSet),
}

#[derive(Args)]
pub(crate) struct GroupRoleSet {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) actor: String,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) member_device: String,
    #[arg(long)]
    pub(crate) role: String,
}

#[derive(Args)]
pub(crate) struct GroupDisappearingCommand {
    #[command(subcommand)]
    pub(crate) action: GroupDisappearingAction,
}

#[derive(Subcommand)]
pub(crate) enum GroupDisappearingAction {
    Set(GroupDisappearingSet),
    Expire(GroupDisappearingExpire),
}

#[derive(Args)]
pub(crate) struct GroupDisappearingSet {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) ttl_secs: i64,
}

#[derive(Args)]
pub(crate) struct GroupDisappearingExpire {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) now: Option<i64>,
}

#[derive(Args)]
pub(crate) struct GroupMute {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) unmute: bool,
    #[arg(long)]
    pub(crate) mute_until: Option<i64>,
}

#[derive(Args)]
pub(crate) struct GroupSend {
    /// Prepared r4 `MediaRef` JSON, including `large_manifest`. Repeat for multiple attachments.
    #[arg(long)]
    pub(crate) media_ref: Vec<PathBuf>,
    /// File to send. Repeat at most 16 times. Each file is its own prepare.
    #[arg(long)]
    pub(crate) attach: Vec<PathBuf>,
    /// Retired. Present means a content refusal. The value is not read.
    #[arg(long)]
    pub(crate) relay_url: Option<String>,
    /// Retired. Present means a content refusal. The value is not read.
    #[arg(long)]
    pub(crate) attachment_chunk_size: Option<u64>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) message: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) sender: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) body: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) envelope: Option<String>,
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) source_principal: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) target: Option<String>,
    #[arg(long, default_value_t = 3_600)]
    pub(crate) ttl: u32,
}

#[derive(Args)]
pub(crate) struct GroupRead {
    #[arg(allow_hyphen_values = true, long)]
    pub(crate) account: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) group: String,
    #[arg(long, allow_hyphen_values = true)]
    pub(crate) conversation: String,
}
