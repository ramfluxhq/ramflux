// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) fn rf_group_create_federation_route(
    create: &GroupCreate,
) -> Result<Option<LocalBusFederationRoute>, RfError> {
    match (
        &create.federation_url,
        &create.source_node,
        &create.target_node,
        &create.recipient_prekey_url,
    ) {
        (None, None, None, None) => Ok(None),
        (Some(federation_url), Some(source_node), Some(target_node), recipient_prekey_url) => {
            Ok(Some(LocalBusFederationRoute {
                federation_url: federation_url.clone(),
                source_node_id: source_node.clone(),
                target_node_id: target_node.clone(),
                required_capability: create.federation_capability.clone(),
                admin_token: create.federation_admin_token.clone(),
                recipient_prekey_url: recipient_prekey_url.clone(),
            }))
        }
        _ => Err(RfError::Message(
            "federated group create requires --federation-url, --source-node, --target-node, and optional --recipient-prekey-url only with that route".to_owned(),
        )),
    }
}

pub(crate) fn rf_group_send_federation_route(
    send: &GroupSend,
) -> Result<Option<LocalBusFederationRoute>, RfError> {
    match (&send.federation_url, &send.source_node, &send.target_node, &send.recipient_prekey_url) {
        (None, None, None, None) => Ok(None),
        (Some(federation_url), Some(source_node), Some(target_node), recipient_prekey_url) => {
            Ok(Some(LocalBusFederationRoute {
                federation_url: federation_url.clone(),
                source_node_id: source_node.clone(),
                target_node_id: target_node.clone(),
                required_capability: send.federation_capability.clone(),
                admin_token: send.federation_admin_token.clone(),
                recipient_prekey_url: recipient_prekey_url.clone(),
            }))
        }
        _ => Err(RfError::Message(
            "federated group send requires --federation-url, --source-node, --target-node, and optional --recipient-prekey-url only with that route".to_owned(),
        )),
    }
}

pub(crate) fn rf_group_member_add_federation_route(
    add: &GroupMemberAdd,
) -> Result<Option<LocalBusFederationRoute>, RfError> {
    match (&add.federation_url, &add.source_node, &add.target_node, &add.recipient_prekey_url) {
        (None, None, None, None) => Ok(None),
        (Some(federation_url), Some(source_node), Some(target_node), recipient_prekey_url) => {
            Ok(Some(LocalBusFederationRoute {
                federation_url: federation_url.clone(),
                source_node_id: source_node.clone(),
                target_node_id: target_node.clone(),
                required_capability: add.federation_capability.clone(),
                admin_token: add.federation_admin_token.clone(),
                recipient_prekey_url: recipient_prekey_url.clone(),
            }))
        }
        _ => Err(RfError::Message(
            "federated group member add requires --federation-url, --source-node, --target-node, and optional --recipient-prekey-url only with that route".to_owned(),
        )),
    }
}

pub(crate) async fn handle_group(socket: PathBuf, command: GroupCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        GroupAction::Create(create) => {
            let federation = rf_group_create_federation_route(&create)?;
            let request = LocalBusGroupCreateRequest {
                group_id: create.group.clone(),
                creator_id: create.creator,
                creator_signing_public_key: create.creator_signing_public_key,
                creator_target_delivery_id: create.creator_target_delivery,
            };
            let mut value = bus
                .request(Some(create.account.clone()), "group", "group.create", &request)
                .await?;
            for member in create.member {
                let add = LocalBusGroupMemberAddRequest {
                    group_id: create.group.clone(),
                    member_id: member,
                    role: "member".to_owned(),
                    member_signing_public_key: None,
                    member_principal_commitment: None,
                    target_delivery_id: create.member_target_delivery.clone(),
                    federation: federation.clone(),
                };
                value = bus
                    .request(Some(create.account.clone()), "group", "group.member.add", &add)
                    .await?;
            }
            print_json(&value)
        }
        GroupAction::Send(send) => {
            let federation = rf_group_send_federation_route(&send)?;
            let request = LocalBusGroupSendRequest {
                group_id: send.group,
                conversation_id: send.conversation,
                message_id: send.message,
                sender_id: send.sender,
                encrypted_body_base64: String::new(),
                plaintext_body_base64: Some(ramflux_protocol::encode_base64url(
                    send.body.as_bytes(),
                )),
                envelope_id: send.envelope,
                source_principal_id: send.source_principal,
                target_delivery_id: send.target,
                federation,
                ttl: Some(send.ttl),
            };
            print_json(&bus.request(Some(send.account), "group", "group.send", &request).await?)
        }
        GroupAction::Read(read) => {
            let request = LocalBusGroupReceiveRequest {
                group_id: read.group,
                conversation_id: read.conversation,
                limit: 100,
            };
            print_json(&with_message_plaintext(
                bus.request(Some(read.account), "group", "group.read", &request).await?,
            ))
        }
        GroupAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "group", "group.list", &serde_json::json!({}))
                .await?,
        ),
        GroupAction::Members(members) => {
            let request = LocalBusGroupRequest { group_id: members.group };
            print_json(
                &bus.request(Some(members.account), "group", "group.members", &request).await?,
            )
        }
        GroupAction::Disappearing(command) => handle_group_disappearing(&mut bus, command).await,
        GroupAction::Mute(mute) => handle_group_mute(&mut bus, mute).await,
        GroupAction::Invite(invite) => handle_group_invite(&mut bus, invite).await,
        GroupAction::Message(message) => handle_group_message(&mut bus, message).await,
        GroupAction::Member(member) => handle_group_member(&mut bus, member).await,
        GroupAction::Role(role) => handle_group_role(&mut bus, role).await,
    }
}

async fn handle_group_member(
    bus: &mut LocalBusClient,
    member: GroupMemberCommand,
) -> Result<(), RfError> {
    match member.action {
        GroupMemberAction::Add(add) => {
            let federation = rf_group_member_add_federation_route(&add)?;
            let request = LocalBusGroupMemberAddRequest {
                group_id: add.group,
                member_id: add.member_device,
                role: add.role,
                member_signing_public_key: add.member_signing_public_key,
                member_principal_commitment: add.member_principal_commitment,
                target_delivery_id: add.target_delivery,
                federation,
            };
            print_json(
                &bus.request(Some(add.account), "group", "group.member.add", &request).await?,
            )
        }
        GroupMemberAction::Remove(remove) => {
            let request = LocalBusGroupMemberRemoveRequest {
                group_id: remove.group,
                actor_id: remove.actor,
                member_id: remove.member_device,
            };
            print_json(
                &bus.request(Some(remove.account), "group", "group.member.remove", &request)
                    .await?,
            )
        }
        GroupMemberAction::Kick(kick) => {
            let request = LocalBusGroupMemberKickRequest {
                group_id: kick.group,
                actor_id: kick.actor,
                member_id: kick.member_device,
                reason: kick.reason,
            };
            print_json(
                &bus.request(Some(kick.account), "group", "group.member.kick", &request).await?,
            )
        }
        GroupMemberAction::Ban(ban) => {
            let request = LocalBusGroupMemberBanRequest {
                group_id: ban.group,
                actor_id: ban.actor,
                member_id: ban.member_device,
                reason: ban.reason,
            };
            print_json(
                &bus.request(Some(ban.account), "group", "group.member.ban", &request).await?,
            )
        }
        GroupMemberAction::List(members) => {
            let request = LocalBusGroupRequest { group_id: members.group };
            print_json(
                &bus.request(Some(members.account), "group", "group.members", &request).await?,
            )
        }
    }
}

async fn handle_group_message(
    bus: &mut LocalBusClient,
    message: GroupMessageCommand,
) -> Result<(), RfError> {
    match message.action {
        GroupMessageAction::Delete(delete) => {
            let request = LocalBusGroupMessageDeleteRequest {
                group_id: delete.group,
                actor_id: delete.actor,
                message_id: delete.message,
                delete_scope: delete.delete_scope,
                reason: delete.reason,
            };
            print_json(
                &bus.request(Some(delete.account), "group", "group.message.delete", &request)
                    .await?,
            )
        }
    }
}

async fn handle_group_invite(
    bus: &mut LocalBusClient,
    invite: GroupInviteCommand,
) -> Result<(), RfError> {
    match invite.action {
        GroupInviteAction::Create(create) => {
            let request = LocalBusGroupInviteCreateRequest {
                group_id: create.group,
                actor_id: create.actor,
                invitee_id: create.invitee_device,
                invitee_signing_public_key: create.invitee_signing_public_key,
                invitee_principal_commitment: create.invitee_principal_commitment,
                target_delivery_id: create.target_delivery,
                role: create.role,
                expires_at: create.expires_at,
                reason: create.reason,
                federation: None,
            };
            print_json(
                &bus.request(Some(create.account), "group", "group.invite.create", &request)
                    .await?,
            )
        }
        GroupInviteAction::Accept(accept) => {
            let request = LocalBusGroupInviteAcceptRequest {
                group_id: accept.group,
                actor_id: accept.actor,
                invite_id: accept.invite_id,
                target_delivery_id: accept.target_delivery,
                member_principal_commitment: accept.member_principal_commitment,
                federation: None,
            };
            print_json(
                &bus.request(Some(accept.account), "group", "group.invite.accept", &request)
                    .await?,
            )
        }
    }
}

async fn handle_group_role(
    bus: &mut LocalBusClient,
    role: GroupRoleCommand,
) -> Result<(), RfError> {
    match role.action {
        GroupRoleAction::Set(set) => {
            let request = LocalBusGroupRoleSetRequest {
                group_id: set.group,
                actor_id: set.actor,
                member_id: set.member_device,
                role: set.role,
            };
            print_json(&bus.request(Some(set.account), "group", "group.role.set", &request).await?)
        }
    }
}

async fn handle_group_disappearing(
    bus: &mut LocalBusClient,
    command: GroupDisappearingCommand,
) -> Result<(), RfError> {
    match command.action {
        GroupDisappearingAction::Set(set) => {
            let request = LocalBusConversationDisappearingSetRequest {
                conversation_id: set.group,
                ttl_secs: set.ttl_secs,
                countdown_mode: "on_send".to_owned(),
                scope: "own_devices".to_owned(),
                updated_at: Some(rf_now_unix_timestamp()),
            };
            print_json(
                &bus.request(
                    Some(set.account),
                    "conversation",
                    "conversation.disappearing.set",
                    &request,
                )
                .await?,
            )
        }
        GroupDisappearingAction::Expire(expire) => {
            let request = LocalBusConversationDisappearingExpireRequest {
                conversation_id: expire.group,
                now: expire.now,
            };
            print_json(
                &bus.request(
                    Some(expire.account),
                    "conversation",
                    "conversation.disappearing.expire",
                    &request,
                )
                .await?,
            )
        }
    }
}

async fn handle_group_mute(bus: &mut LocalBusClient, mute: GroupMute) -> Result<(), RfError> {
    let request = LocalBusConversationMuteRequest {
        conversation_id: mute.group,
        mute_until: mute.mute_until,
        unmute: mute.unmute,
    };
    print_json(
        &bus.request(Some(mute.account), "conversation", "conversation.mute", &request).await?,
    )
}
