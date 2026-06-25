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
            };
            let mut value = bus
                .request(Some(create.account.clone()), "group", "group.create", &request)
                .await?;
            for member in create.member {
                let add = LocalBusGroupMemberAddRequest {
                    group_id: create.group.clone(),
                    member_id: member,
                    role: "member".to_owned(),
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
        GroupAction::Member(member) => handle_group_member(&mut bus, member).await,
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
        GroupMemberAction::List(members) => {
            let request = LocalBusGroupRequest { group_id: members.group };
            print_json(
                &bus.request(Some(members.account), "group", "group.members", &request).await?,
            )
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
