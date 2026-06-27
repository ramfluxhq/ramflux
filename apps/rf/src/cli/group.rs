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
    Send(GroupSend),
    Read(GroupRead),
    Message(GroupMessageCommand),
    Invite(GroupInviteCommand),
    List(AccountSelector),
    Members(GroupMembers),
    Member(GroupMemberCommand),
    Role(GroupRoleCommand),
    Disappearing(GroupDisappearingCommand),
    Mute(GroupMute),
}

#[derive(Args)]
pub(crate) struct GroupCreate {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) creator: String,
    #[arg(long)]
    pub(crate) creator_signing_public_key: Option<String>,
    #[arg(long)]
    pub(crate) creator_target_delivery: Option<String>,
    #[arg(long)]
    pub(crate) member: Vec<String>,
    #[arg(long)]
    pub(crate) member_target_delivery: Option<String>,
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
}

#[derive(Args)]
pub(crate) struct GroupMembers {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
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
    Ban(GroupMemberBan),
    Kick(GroupMemberKick),
    Remove(GroupMemberRemove),
    List(GroupMembers),
}

#[derive(Args)]
pub(crate) struct GroupMemberAdd {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) member_device: String,
    #[arg(long, default_value = "member")]
    pub(crate) role: String,
    #[arg(long)]
    pub(crate) member_signing_public_key: Option<String>,
    #[arg(long)]
    pub(crate) member_principal_commitment: Option<String>,
    #[arg(long)]
    pub(crate) target_delivery: Option<String>,
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
}

#[derive(Args)]
pub(crate) struct GroupMemberRemove {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) actor: String,
    #[arg(long)]
    pub(crate) member_device: String,
}

#[derive(Args)]
pub(crate) struct GroupMemberKick {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) actor: String,
    #[arg(long)]
    pub(crate) member_device: String,
    #[arg(long)]
    pub(crate) reason: Option<String>,
}

#[derive(Args)]
pub(crate) struct GroupMemberBan {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) actor: String,
    #[arg(long)]
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
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) actor: String,
    #[arg(long)]
    pub(crate) message: String,
    #[arg(long, default_value = "group_tombstone")]
    pub(crate) delete_scope: String,
    #[arg(long)]
    pub(crate) reason: Option<String>,
}

#[derive(Args)]
pub(crate) struct GroupInviteCommand {
    #[command(subcommand)]
    pub(crate) action: GroupInviteAction,
}

#[derive(Subcommand)]
pub(crate) enum GroupInviteAction {
    Create(GroupInviteCreate),
    Accept(GroupInviteAccept),
}

#[derive(Args)]
pub(crate) struct GroupInviteCreate {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) actor: String,
    #[arg(long)]
    pub(crate) invitee_device: String,
    #[arg(long)]
    pub(crate) invitee_signing_public_key: String,
    #[arg(long)]
    pub(crate) invitee_principal_commitment: Option<String>,
    #[arg(long)]
    pub(crate) target_delivery: String,
    #[arg(long, default_value = "member")]
    pub(crate) role: String,
    #[arg(long)]
    pub(crate) expires_at: i64,
    #[arg(long)]
    pub(crate) reason: Option<String>,
}

#[derive(Args)]
pub(crate) struct GroupInviteAccept {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) actor: String,
    #[arg(long)]
    pub(crate) invite_id: String,
    #[arg(long)]
    pub(crate) target_delivery: Option<String>,
    #[arg(long)]
    pub(crate) member_principal_commitment: Option<String>,
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
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) actor: String,
    #[arg(long)]
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
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) ttl_secs: i64,
}

#[derive(Args)]
pub(crate) struct GroupDisappearingExpire {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) now: Option<i64>,
}

#[derive(Args)]
pub(crate) struct GroupMute {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) unmute: bool,
    #[arg(long)]
    pub(crate) mute_until: Option<i64>,
}

#[derive(Args)]
pub(crate) struct GroupSend {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) conversation: String,
    #[arg(long)]
    pub(crate) message: String,
    #[arg(long)]
    pub(crate) sender: String,
    #[arg(long)]
    pub(crate) body: String,
    #[arg(long)]
    pub(crate) envelope: Option<String>,
    #[arg(long)]
    pub(crate) source_principal: Option<String>,
    #[arg(long)]
    pub(crate) target: Option<String>,
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
    #[arg(long, default_value_t = 3_600)]
    pub(crate) ttl: u32,
}

#[derive(Args)]
pub(crate) struct GroupRead {
    #[arg(long)]
    pub(crate) account: String,
    #[arg(long)]
    pub(crate) group: String,
    #[arg(long)]
    pub(crate) conversation: String,
}
