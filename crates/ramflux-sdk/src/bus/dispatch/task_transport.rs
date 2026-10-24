// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete verified task fan-out, sealed once and queued atomically with the local projection.
use crate::bus::task_jobs::{Delivery as SealedDelivery, Destination};
use crate::client::task::{Delivery, carrier::Carrier, invalid};
use crate::prelude::*;
use serde_json::{Value, json};
#[derive(Clone)]
pub(super) struct Target {
    pub device: String,
    pub delivery: String,
    pub federation: Option<LocalBusFederationRoute>,
    pub own: bool,
}
pub(crate) async fn send(
    account: &mut LocalBusAccountState,
    c: &Carrier,
) -> Result<Value, SdkError> {
    if let Some(outcome) = account.client.task_delivery_receipt(c)? {
        return Ok(
            json!({"accepted":outcome.accepted,"pending":outcome.pending,"reject":outcome.reject,"message_id":c.message_id,"task_id":c.event()?.event().task_id(),"replayed":true}),
        );
    }
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &c.conversation_id)?
        .ok_or_else(|| invalid("task conversation missing"))?;
    let mut engine = account.take_live_engine().await?;
    let result = prepare(account, &mut engine, c, &thread, false).await;
    account.put_engine(engine);
    let deliveries = result?;
    account.client.account_db()?.write_transaction(||{
        super::super::task_jobs::admit(account,1,0)?;
        let timeline=crate::client::task::timeline_id(c)?;
        let outcome=account.client.project_task_message(&Delivery{conversation:&c.conversation_id,message:&timeline,principal:&c.principal_id,device:&c.device_id,at:now_unix_timestamp()},&c.bytes()?)?.ok_or_else(||invalid("task projection absent"))?;
        if !outcome.accepted{return Err(invalid(outcome.reject.unwrap_or_else(||"task rejected".into())));}
        if account.client.direct_message_by_id(&timeline)?.is_none(){account.client.send_direct_message(&c.conversation_id,&timeline,&c.device_id,&[])?;}
        account.client.account_db()?.replace_surface_message_content(&c.conversation_id,&timeline,outcome.fallback_text.as_bytes())?;
        super::super::task_jobs::enqueue(account,&c.conversation_id,c.event()?.event().task_id(),deliveries)?;
        account.client.set_task_delivery_state(&c.conversation_id,c.event()?.event().task_id(),"queued",None)?;
        Ok(json!({"accepted":true,"task_id":c.event()?.event().task_id(),"message_id":c.message_id,"delivery_state":"queued","actor_kind_verified":false}))
    })
}
pub(super) async fn prepare(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    c: &Carrier,
    thread: &Value,
    own_only: bool,
) -> Result<Vec<SealedDelivery>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let own = client
        .cache_verified_device_manifest(&engine.config, &account.principal_commitment, "task_own")
        .await?;
    if !own.devices.iter().any(|d| d.device_id == local.device_id) {
        return Err(invalid("task source device is not in the active manifest"));
    }
    let mut own_targets = own
        .devices
        .into_iter()
        .filter(|d| d.device_id != local.device_id)
        .map(|d| Target {
            device: d.device_id,
            delivery: d.target_delivery_id,
            federation: None,
            own: true,
        })
        .collect::<Vec<_>>();
    let mut group_plan = None;
    let mut peers = Vec::new();
    if !own_only {
        if let Some(group) = thread["group_id"].as_str() {
            group_plan = Some(super::task_group::plan(account, c, group, &engine.config).await?);
        } else {
            let ids = thread["participants"]
                .as_array()
                .ok_or_else(|| invalid("task direct participants missing"))?;
            let peers_ids = ids
                .iter()
                .filter_map(Value::as_str)
                .filter(|p| *p != local.principal_id)
                .collect::<Vec<_>>();
            if thread["kind"] != "direct"
                || peers_ids.len() != 1
                || !ids.iter().any(|p| p == &local.principal_id)
            {
                return Err(invalid("task direct conversation membership mismatch"));
            }
            let identity = client
                .account_db()?
                .client_record("identity", peers_ids[0])?
                .ok_or_else(|| invalid("task peer identity unavailable"))?;
            let commitment = identity["contact_identity_commitment"]
                .as_str()
                .ok_or_else(|| invalid("task peer root unavailable"))?;
            client.require_accepted_friend_link_for_dm_send(
                &local.principal_id,
                &account.principal_commitment,
                Some(peers_ids[0]),
                commitment,
            )?;
            let federation: Option<LocalBusFederationRoute> = thread["direct_route"]["federation"]
                .as_object()
                .map(|_| serde_json::from_value(thread["direct_route"]["federation"].clone()))
                .transpose()?;
            let manifest = if let Some(route) = &federation {
                let url = route
                    .recipient_prekey_url
                    .as_deref()
                    .ok_or_else(|| invalid("task federated peer prekey URL missing"))?;
                let manifest = crate::client::contact::fetch_verified_device_manifest_from_url(
                    url, commitment,
                )?;
                client.persist_identity_directory(&manifest)?;
                manifest
            } else {
                client
                    .cache_verified_device_manifest(&engine.config, commitment, "task_peer")
                    .await?
            };
            if manifest.principal_id != peers_ids[0] {
                return Err(invalid("task peer principal changed"));
            }
            peers.extend(manifest.devices.into_iter().map(|d| Target {
                device: d.device_id,
                delivery: d.target_delivery_id,
                federation: federation.clone(),
                own: false,
            }));
        }
    }
    let own_packet = if own_targets.is_empty() { None } else { Some(client.task_own_packet(c)?) };
    let group_budget = group_plan.as_ref().map_or(0, |g| g.bytes);
    let estimate = own_packet
        .as_ref()
        .map_or(0, |p| p.len().saturating_mul(4).saturating_mul(own_targets.len()))
        .saturating_add(c.bytes()?.len().saturating_mul(8).saturating_mul(peers.len()))
        .saturating_add(group_budget)
        .saturating_add(128 * 1024);
    super::super::task_jobs::admit(account, 1, estimate)?;
    let mut deliveries = Vec::new();
    if let Some(plan) = group_plan {
        deliveries.extend(super::task_group::prepare(account, engine, c, plan).await?);
    }
    let task_body = c.bytes()?;
    own_targets.append(&mut peers);
    for target in own_targets {
        let (body, kind) = if target.own {
            (
                own_packet.as_deref().ok_or_else(|| invalid("own task packet missing"))?,
                crate::client::routed::Route {
                    kind: crate::client::routed::Kind::Control,
                    group_id: thread["group_id"].as_str().map(str::to_owned),
                    attachments: false,
                },
            )
        } else {
            (task_body.as_slice(), crate::client::routed::Route::direct())
        };
        deliveries.push(seal(account, engine, c, &target, &c.conversation_id, body, kind).await?);
    }
    Ok(deliveries)
}
pub(super) async fn seal(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    c: &Carrier,
    target: &Target,
    conversation: &str,
    body: &[u8],
    kind: crate::client::routed::Route,
) -> Result<SealedDelivery, SdkError> {
    let id = crate::new_surface_message_id()?;
    let mut message = GatewayDirectMessage {
        conversation_id: conversation.into(),
        message_id: id.clone(),
        envelope_id: id,
        source_principal_id: c.principal_id.clone(),
        sender_id: c.device_id.clone(),
        recipient_device_id: Some(target.device.clone()),
        target_delivery_id: target.delivery.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let sealed = if let Some(federation) = &target.federation {
        account.client.seal_routed_federated_as(
            engine,
            &message,
            body,
            federation.recipient_prekey_url.as_deref(),
            kind,
        )?
    } else {
        account.client.seal_routed_as(engine, &message, body, kind).await?
    };
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    let envelope = crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?;
    Ok(SealedDelivery {
        envelope,
        federation: target.federation.clone().map(|route| Destination {
            route,
            conversation_id: conversation.into(),
            message_id: message.message_id,
            device_id: target.device.clone(),
        }),
        attempts: 0,
        next_at: 0,
    })
}
