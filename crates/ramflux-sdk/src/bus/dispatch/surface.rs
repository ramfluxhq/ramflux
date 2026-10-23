// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface authoring through the existing message paths; only the account actor mutates state.
use crate::client::surface::{Carrier, PayloadKind, command_id, invalid};
use crate::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Send {
    conversation_id: String,
    message_id: String,
    wire_base64: String,
}
pub(crate) async fn dispatch_surface(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    connection: &LocalBusConnectionState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let id = request_account_id(request)?;
    let body: Send = serde_json::from_value(request.body.clone())?;
    let raw = ramflux_protocol::decode_base64url(&body.wire_base64)
        .map_err(|_| invalid("invalid surface wire encoding"))?;
    let kind =
        if request.method == "surface.send" { PayloadKind::Event } else { PayloadKind::Action };
    let surface_id = match kind {
        PayloadKind::Event => {
            command_id(ramflux_protocol::A2uiConversationEvent::from_wire_bytes(&raw)?.command())
                .to_owned()
        }
        PayloadKind::Action => {
            ramflux_protocol::A2uiSurfaceAction::from_wire_bytes(&raw)?.surface_id().to_owned()
        }
    };
    let (carrier, thread, preflight) = {
        let account = local_bus_account(state, id)?;
        let client = &account.client;
        let thread = client
            .account_db()?
            .client_record("conversation", &body.conversation_id)?
            .ok_or_else(|| invalid("surface requires an existing conversation"))?;
        let device = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let owner = client
            .surface_state(&surface_id)?
            .map_or_else(|| device.principal_id.clone(), |(record, _)| record.author_principal_id);
        let carrier = client.sign_surface_carrier(Carrier {
            schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
            content_type: "surface".into(),
            payload_kind: kind.clone(),
            conversation_id: body.conversation_id.clone(),
            surface_id: surface_id.clone(),
            message_id: body.message_id.clone(),
            sender_principal_id: device.principal_id.clone(),
            sender_device_id: device.device_id.clone(),
            author_principal_id: owner,
            wire_base64: body.wire_base64,
            signature: String::new(),
        })?;
        let preflight = client.preflight_surface(&carrier)?;
        (carrier, thread, preflight)
    };
    if let Some(receipt) =
        local_bus_account(state, id)?.client.surface_delivery_receipt(&carrier)?
    {
        let mut response = serde_json::to_value(receipt)?;
        response["replayed"] = json!(true);
        return Ok(local_bus_ok(response));
    }
    if !preflight.accepted {
        let result = local_bus_account(state, id)?.client.project_surface_message(
            &body.conversation_id,
            &body.message_id,
            crate::client::surface::SurfaceSender {
                principal: &carrier.sender_principal_id,
                device: &carrier.sender_device_id,
            },
            &carrier.bytes()?,
            true,
        )?;
        return Ok(local_bus_ok(serde_json::to_value(result)?));
    }
    let encoded = ramflux_protocol::encode_base64url(carrier.bytes()?);
    let mut submit = request.clone();
    submit.body = json!({"plaintext_body_base64":encoded});
    let delivered = if let Some(group) = thread["group_id"].as_str() {
        send_group(local_bus_account_mut(state, id)?, &carrier, group, encoded, &mut submit).await?
    } else {
        send_direct(state, connection, id, &carrier, &thread, &mut submit).await?
    };
    let client = &local_bus_account(state, id)?.client;
    let result = client
        .project_surface_message(
            &body.conversation_id,
            &body.message_id,
            crate::client::surface::SurfaceSender {
                principal: &carrier.sender_principal_id,
                device: &carrier.sender_device_id,
            },
            &carrier.bytes()?,
            true,
        )?
        .ok_or_else(|| invalid("surface projection missing"))?;
    client.account_db()?.replace_surface_message_content(
        &body.conversation_id,
        &body.message_id,
        result.fallback_text.as_bytes(),
    )?;
    let mut response = serde_json::to_value(result)?;
    response["surface_id"] = json!(surface_id);
    response["message_id"] = json!(body.message_id);
    response["delivery"] = delivered.response_body;
    Ok(local_bus_ok(response))
}
pub(crate) fn read_surface(
    client: &RamfluxClient,
    request: &LocalBusFrame,
) -> Result<Value, SdkError> {
    match request.method.as_str() {
        "surface.get" => client.surface_get(
            required(&request.body, "surface_id")?,
            request.body["history_after"].as_u64().unwrap_or(0),
            request.body["action_id"].as_str(),
        ),
        "surface.list" => client.surface_list(
            required(&request.body, "conversation_id")?,
            request.body["cursor"].as_str().unwrap_or(""),
            request.body["limit"]
                .as_u64()
                .map(u32::try_from)
                .transpose()
                .map_err(|_| invalid("invalid surface list limit"))?
                .unwrap_or(50),
        ),
        _ => Err(invalid("unsupported surface read")),
    }
}
fn required<'a>(body: &'a Value, field: &str) -> Result<&'a str, SdkError> {
    body.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("surface read identifier required"))
}

async fn send_group(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
    group: &str,
    encoded: String,
    submit: &mut LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let members = account.client.group_state(group)?.members;
    if !members.contains(&carrier.sender_device_id)
        && !members.contains(&carrier.sender_principal_id)
    {
        return Err(invalid("surface sender is not a group member"));
    }
    let mut outgoing = json!({"group_id":group,"conversation_id":carrier.conversation_id,"message_id":carrier.message_id,"sender_id":carrier.sender_device_id,"encrypted_body_base64":"","plaintext_body_base64":encoded});
    if carrier.payload_kind == PayloadKind::Action {
        let record = account
            .client
            .surface_state(&carrier.surface_id)?
            .ok_or_else(|| invalid("unknown surface author"))?
            .0;
        let rows = super::super::group_delivery::directory(&account.client, group)?;
        let route = rows
            .into_iter()
            .find(|row| {
                row["member_id"] == record.author_device_id
                    && row["principal_id"] == record.author_principal_id
                    && row["delivery_target_known"] == true
            })
            .ok_or_else(|| invalid("surface author is not a reachable group member"))?;
        let distribution: LocalBusGroupMemberRoute = serde_json::from_value(route.clone())?;
        super::group::dispatch_group_sender_key_distribution(account, group, distribution, None)
            .await?;
        outgoing["envelope_id"] = json!(format!("surface-action-{}", carrier.message_id));
        outgoing["source_principal_id"] = json!(carrier.sender_principal_id);
        outgoing["target_delivery_id"] = route["target_delivery_id"].clone();
        outgoing["federation"] = route["federation"].clone();
    }
    "group.send".clone_into(&mut submit.method);
    submit.body = outgoing;
    super::group::dispatch_group_send_request(submit, account).await
}
async fn send_direct(
    state: &mut LocalBusDaemonState,
    connection: &LocalBusConnectionState,
    id: &str,
    carrier: &Carrier,
    thread: &Value,
    submit: &mut LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    if thread["kind"] != "direct"
        || !thread["participants"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id == &carrier.sender_principal_id))
    {
        return Err(invalid("surface sender is not a conversation participant"));
    }
    let recipient = if carrier.payload_kind == PayloadKind::Action {
        carrier.author_principal_id.clone()
    } else {
        let peers = thread["participants"]
            .as_array()
            .ok_or_else(|| invalid("direct participants unavailable"))?
            .iter()
            .filter_map(Value::as_str)
            .filter(|p| *p != carrier.sender_principal_id)
            .collect::<Vec<_>>();
        if peers.len() != 1 {
            return Err(invalid("direct surface recipient is ambiguous"));
        }
        peers[0].to_owned()
    };
    let client = &local_bus_account(state, id)?.client;
    let peer = client
        .account_db()?
        .client_record("identity", &recipient)?
        .ok_or_else(|| invalid("surface peer identity unavailable"))?;
    let author_device = if carrier.payload_kind == PayloadKind::Action {
        Some(
            client
                .surface_state(&carrier.surface_id)?
                .ok_or_else(|| invalid("unknown surface author"))?
                .0
                .author_device_id,
        )
    } else {
        None
    };
    let remote = peer["devices"]
        .as_array()
        .and_then(|devices| match &author_device {
            Some(id) => devices.iter().find(|device| device["device_id"] == *id),
            None => devices.first(),
        })
        .ok_or_else(|| invalid("surface peer device unavailable"))?;
    "message.submit".clone_into(&mut submit.method);
    submit.body = json!({"conversation_id":carrier.conversation_id,"message_id":carrier.message_id,"envelope_id":format!("surface-{}",carrier.message_id),"source_principal_id":carrier.sender_principal_id,"sender_id":carrier.sender_device_id,"recipient_device_id":remote["device_id"],"recipient_principal_commitment":peer["contact_identity_commitment"],"target_delivery_id":remote["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":submit.body["plaintext_body_base64"],"created_at":now_unix_timestamp(),"ttl":300});
    super::message::dispatch_message_bus_request(submit, state, connection).await
}
