// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete verified task fan-out, sealed once and queued with the local projection.
use crate::client::task::{Delivery, carrier::Carrier, invalid};
use crate::prelude::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
struct Target {
    device: String,
    delivery: String,
}
pub(crate) async fn send(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
) -> Result<Value, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let prepared = prepare(account, &mut engine, carrier).await;
    account.put_engine(engine);
    let envelopes = prepared?;
    account.client.account_db()?.task_transaction(|| {
        super::super::task_jobs::admit(account,envelopes.len(),0)?;
        let timeline=crate::client::task::timeline_id(carrier)?;
        let outcome=account.client.project_task_message(&Delivery{conversation:&carrier.conversation_id,message:&timeline,principal:&carrier.principal_id,device:&carrier.device_id,at:now_unix_timestamp()},&carrier.bytes()?)?.ok_or_else(||invalid("task projection absent"))?;
        if !outcome.accepted {return Err(invalid(outcome.reject.unwrap_or_else(||"task rejected".into())));}
        if account.client.direct_message_by_id(&timeline)?.is_none(){
            account.client.send_direct_message(&carrier.conversation_id,&timeline,&carrier.device_id,&[])?;
        }
        account.client.account_db()?.replace_surface_message_content(&carrier.conversation_id,&timeline,outcome.fallback_text.as_bytes())?;
        super::super::task_jobs::enqueue(account,envelopes)?;
        Ok(json!({"accepted":true,"task_id":carrier.event()?.event().task_id(),"message_id":carrier.message_id,"delivery_state":"queued","actor_kind_verified":false}))
    })
}
async fn prepare(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    carrier: &Carrier,
) -> Result<Vec<ramflux_protocol::Envelope>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let thread = client
        .account_db()?
        .client_record("conversation", &carrier.conversation_id)?
        .ok_or_else(|| invalid("task conversation missing"))?;
    let group = thread["group_id"].as_str();
    let mut commitments = BTreeMap::new();
    if let Some(group) = group {
        for member in super::super::group_delivery::directory(client, group)? {
            if member["principal_id"] == local.principal_id {
                continue;
            }
            let principal = member["principal_id"]
                .as_str()
                .ok_or_else(|| invalid("task group member principal unavailable"))?;
            let commitment = member["member_principal_commitment"]
                .as_str()
                .ok_or_else(|| invalid("task group member root unavailable"))?;
            commitments.insert(commitment.to_owned(), principal.to_owned());
        }
    } else {
        let participants = thread["participants"]
            .as_array()
            .ok_or_else(|| invalid("task participants missing"))?;
        for principal in
            participants.iter().filter_map(Value::as_str).filter(|id| *id != local.principal_id)
        {
            let identity = client
                .account_db()?
                .client_record("identity", principal)?
                .ok_or_else(|| invalid("task peer identity unavailable"))?;
            let commitment = identity["contact_identity_commitment"]
                .as_str()
                .ok_or_else(|| invalid("task peer root unavailable"))?;
            client.require_accepted_friend_link_for_dm_send(
                &local.principal_id,
                &account.principal_commitment,
                Some(principal),
                commitment,
            )?;
            commitments.insert(commitment.to_owned(), principal.to_owned());
        }
        if commitments.len() != 1 {
            return Err(invalid("task direct peer is ambiguous"));
        }
    }
    // Own terminal delivery is a separate authenticated history control, never a peer role claim.
    commitments.insert(account.principal_commitment.clone(), local.principal_id.clone());
    let mut targets = BTreeMap::new();
    for (commitment, principal) in commitments {
        let manifest =
            client.cache_verified_device_manifest(&engine.config, &commitment, "task_peer").await?;
        if manifest.principal_id != principal {
            return Err(invalid("task recipient root changed"));
        }
        for device in manifest.devices {
            if device.device_id != local.device_id {
                targets.insert(
                    device.device_id.clone(),
                    (
                        Target { device: device.device_id, delivery: device.target_delivery_id },
                        principal == local.principal_id,
                    ),
                );
            }
        }
    }
    super::super::task_jobs::admit(account, targets.len(), 0)?;
    let bytes = carrier.bytes()?;
    let mut envelopes = Vec::new();
    for (_, (target, own)) in targets {
        let (body, route) = if own {
            (
                client.task_own_packet(carrier)?,
                crate::client::routed::Route {
                    kind: crate::client::routed::Kind::Control,
                    group_id: group.map(str::to_owned),
                    attachments: false,
                },
            )
        } else if let Some(group) = group {
            (
                client.encrypt_group_message(group, &local.device_id, &bytes)?,
                crate::client::routed::Route::group_message(group),
            )
        } else {
            (bytes.clone(), crate::client::routed::Route::direct())
        };
        let id = crate::new_surface_message_id()?;
        let mut message = GatewayDirectMessage {
            conversation_id: carrier.conversation_id.clone(),
            message_id: id.clone(),
            envelope_id: id,
            source_principal_id: local.principal_id.clone(),
            sender_id: local.device_id.clone(),
            recipient_device_id: Some(target.device),
            target_delivery_id: target.delivery,
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 3600,
        };
        message.encrypted_body =
            serde_json::to_vec(&client.seal_routed_as(engine, &message, &body, route).await?)?;
        envelopes.push(crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?);
    }
    Ok(envelopes)
}
