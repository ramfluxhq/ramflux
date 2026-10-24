// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sender-key surface publications using the same routes and controls as group text.
use crate::bus::surface_jobs::Delivery;
use crate::client::surface::{Carrier, PayloadKind};
use crate::prelude::*;
use serde_json::json;

pub(super) struct Plan {
    group: String,
    epoch: u64,
    routes: Vec<LocalBusGroupMemberRoute>,
    pub bytes: usize,
}
pub(super) fn plan(
    account: &LocalBusAccountState,
    carrier: &Carrier,
) -> Result<Option<Plan>, SdkError> {
    // Actions are private direct returns to the author; group publications use sender-key.
    if carrier.payload_kind == PayloadKind::Action {
        return Ok(None);
    }
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &carrier.conversation_id)?
        .ok_or_else(|| SdkError::LocalBus("surface conversation absent".into()))?;
    let Some(group) = thread["group_id"].as_str() else {
        return Ok(None);
    };
    let body: LocalBusGroupSendRequest = serde_json::from_value(
        json!({"group_id":group,"conversation_id":carrier.conversation_id,"message_id":carrier.message_id,"sender_id":carrier.sender_device_id,"encrypted_body_base64":""}),
    )?;
    let routes = super::super::group_delivery::resolve(account, &body)?;
    if !account.client.surface_group_device_allowed(group, &carrier.sender_device_id)? {
        return Err(SdkError::InboundRejected("surface group sender is not a member".into()));
    }
    // Conservative envelope/base64, distribution, federation-copy and job metadata bound.
    // Checked together with own-device jobs before *any* group or pair encryption.
    let routing_bytes = serde_json::to_vec(&routes)?.len().saturating_mul(8);
    let group_bytes = serde_json::to_vec(group)?.len().saturating_mul(12);
    let bytes = routes
        .len()
        .saturating_mul(
            carrier
                .bytes()?
                .len()
                .saturating_mul(12)
                .saturating_add(group_bytes)
                .saturating_add(128 * 1024),
        )
        .saturating_add(routing_bytes);
    Ok(Some(Plan {
        group: group.into(),
        epoch: account.client.group_state(group)?.group_epoch,
        routes,
        bytes,
    }))
}
pub(super) async fn prepare(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
    plan: Plan,
) -> Result<Vec<Delivery>, SdkError> {
    super::super::surface_jobs::admit(account, 1, plan.bytes)?;
    let encrypted = account.client.encrypt_group_message(
        &plan.group,
        &carrier.sender_device_id,
        &carrier.bytes()?,
    )?;
    let distribution = account
        .client
        .export_group_sender_key_distribution(&plan.group, &carrier.sender_device_id)?;
    let distribution_body = serde_json::to_vec(
        &json!({"schema":"ramflux.sdk.group_sender_key.distribution_envelope.v1","version":1,"membership_event_base64":null,"actor_manifest_url":null,"distribution_base64":ramflux_protocol::encode_base64url(&distribution)}),
    )?;
    let mut engine = account.take_live_engine().await?;
    let result = async {
        let mut deliveries = Vec::new();
        for route in plan.routes {
            let ack = format!(
                "surface/group_distribution/{}/{}/{}/{}",
                plan.group, carrier.sender_device_id, route.member_id, plan.epoch
            );
            if !account.client.account_db()?.load_actor_state::<bool>(&ack)?.unwrap_or(false) {
                let conversation = group_sender_key_distribution_conversation_id(
                    &plan.group,
                    &carrier.sender_device_id,
                    &route.member_id,
                );
                deliveries.push(
                    seal_packet(
                        account,
                        &mut engine,
                        carrier,
                        &route,
                        Packet {
                            conversation: &conversation,
                            body: &distribution_body,
                            group: &plan.group,
                            control: true,
                            ack: Some(ack),
                        },
                    )
                    .await?,
                );
            }
            deliveries.push(
                seal_packet(
                    account,
                    &mut engine,
                    carrier,
                    &route,
                    Packet {
                        conversation: &carrier.conversation_id,
                        body: &encrypted,
                        group: &plan.group,
                        control: false,
                        ack: None,
                    },
                )
                .await?,
            );
        }
        Ok::<_, SdkError>(deliveries)
    }
    .await;
    account.put_engine(engine);
    result
}
struct Packet<'a> {
    conversation: &'a str,
    body: &'a [u8],
    group: &'a str,
    control: bool,
    ack: Option<String>,
}
async fn seal_packet(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    carrier: &Carrier,
    route: &LocalBusGroupMemberRoute,
    packet: Packet<'_>,
) -> Result<Delivery, SdkError> {
    let id = crate::new_surface_message_id()?;
    let mut message = GatewayDirectMessage {
        conversation_id: packet.conversation.into(),
        message_id: if packet.control {
            id.clone()
        } else {
            crate::RamfluxClient::surface_timeline_id(carrier)?
        },
        envelope_id: id,
        source_principal_id: carrier.sender_principal_id.clone(),
        sender_id: carrier.sender_device_id.clone(),
        recipient_device_id: Some(route.member_id.clone()),
        target_delivery_id: route
            .target_delivery_id
            .clone()
            .ok_or_else(|| SdkError::LocalBus("group route missing".into()))?,
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 600,
    };
    let kind = if packet.control {
        crate::client::routed::Route::group_control(packet.group)
    } else {
        crate::client::routed::Route::group_message(packet.group)
    };
    let sealed = if let Some(federation) = &route.federation {
        account.client.seal_routed_federated_as(
            engine,
            &message,
            packet.body,
            federation.recipient_prekey_url.as_deref(),
            kind,
        )?
    } else {
        account.client.seal_routed_as(engine, &message, packet.body, kind).await?
    };
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    let envelope = crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?;
    let federation =
        route.federation.clone().map(|route| super::super::surface_jobs::FederatedTarget {
            conversation_id: message.conversation_id,
            message_id: message.message_id,
            recipient_device_id: message.recipient_device_id,
            route,
        });
    Ok(Delivery { envelope, federation, ack_key: packet.ack, attempts: 0, next_at: 0 })
}

#[cfg(test)]
#[path = "surface_group_tests.rs"]
mod tests;
