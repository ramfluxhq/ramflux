// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete verified task fan-out, sealed once and submitted through the ordinary gateway delivery paths.
use crate::bus::task_delivery::{Delivery as SealedDelivery, Destination};
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
    crate::client::task::check_delivery_size(c.bytes()?.len())?;
    if let Some(outcome) = account.client.task_delivery_receipt(c)?
        && !outcome.accepted
    {
        return Err(invalid(outcome.reject.unwrap_or_else(|| "task rejected".into())));
    }
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &c.conversation_id)?
        .ok_or_else(|| invalid("task conversation missing"))?;
    let mut engine = account.take_live_engine().await?;
    let result = prepare(account, &mut engine, c, &thread, Mode::Event).await;
    account.put_engine(engine);
    let deliveries = result?;
    let response = account.client.account_db()?.write_transaction(|| {
        let timeline = crate::client::task::timeline_id(c)?;
        let outcome = account.client.project_task_message(&Delivery {
            conversation: &c.conversation_id,
            message: &timeline,
            principal: &c.principal_id,
            device: &c.device_id,
            at: now_unix_timestamp(),
        }, &c.bytes()?)?.ok_or_else(|| invalid("task projection absent"))?;
        if !outcome.accepted && !outcome.pending {
            return Err(invalid(outcome.reject.unwrap_or_else(|| "task rejected".into())));
        }
        if account.client.direct_message_by_id(&timeline)?.is_none() {
            account.client.send_direct_message(&c.conversation_id,&timeline,&c.device_id,&[])?;
        }
        account.client.account_db()?.replace_surface_message_content(&c.conversation_id,&timeline,outcome.fallback_text.as_bytes())?;
        account.client.set_task_delivery_state(&c.conversation_id,c.event()?.event().task_id(),"sending",None)?;
        Ok(json!({"accepted":outcome.accepted,"pending":outcome.pending,"task_id":c.event()?.event().task_id(),"message_id":c.message_id,"delivery_state":"submitted","actor_kind_verified":false}))
    })?;
    if let Err(error) = super::super::task_delivery::submit_all(account, deliveries).await {
        account.client.set_task_delivery_state(
            &c.conversation_id,
            c.event()?.event().task_id(),
            "failed",
            Some("task_transport_error"),
        )?;
        return Err(error);
    }
    account.client.set_task_delivery_state(
        &c.conversation_id,
        c.event()?.event().task_id(),
        "submitted",
        None,
    )?;
    Ok(response)
}
pub(super) enum Mode<'a> {
    Event,
    Ack(&'a crate::client::task::control::Ack),
    Own,
}
pub(super) async fn prepare(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    c: &Carrier,
    thread: &Value,
    mode: Mode<'_>,
) -> Result<Vec<SealedDelivery>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let mut own_targets = own_targets(account, &engine.config).await?;
    let mut group_plan = None;
    let mut peers = Vec::new();
    if !matches!(mode, Mode::Own) {
        if let Some(group) = thread["group_id"].as_str() {
            group_plan = Some(super::task_group::plan(account, c, group, &engine.config).await?);
        } else {
            peers = direct_targets(account, &engine.config, thread).await?;
        }
    }
    let intent = matches!(mode, Mode::Event)
        && matches!(c.event()?.event(), ramflux_protocol::TaskEventBody::Resolve(_));
    if intent {
        own_targets.clear();
    }
    let task_body = match &mode {
        Mode::Ack(ack) => {
            crate::client::task::control::Control::Ack(Box::new((*ack).clone())).bytes()?
        }
        Mode::Event if intent => crate::client::task::control::Control::Intent {
            carrier_base64: ramflux_protocol::encode_base64url(c.bytes()?),
        }
        .bytes()?,
        _ => c.bytes()?,
    };
    let control = intent || matches!(mode, Mode::Ack(_));
    if control {
        if let Some(plan) = group_plan.take() {
            peers.extend(plan.targets);
        }
        if intent {
            let state =
                client.task_history(&c.conversation_id, c.event()?.event().task_id())?.state()?;
            let task = state.task().ok_or_else(|| invalid("task not found"))?;
            let ramflux_protocol::TaskEventBody::Resolve(resolution) = c.event()?.event().clone()
            else {
                return Err(invalid("task resolve expected"));
            };
            let (executor, _) = client
                .task_history(&c.conversation_id, &task.task_id)?
                .intervention_source(&resolution.step_id, &resolution.target)?;
            peers.retain(|target| target.device == executor);
            if peers.is_empty() && executor != local.device_id {
                return Err(invalid("task executor has no active delivery route"));
            }
        }
    }
    let own_packet = if own_targets.is_empty() { None } else { Some(client.task_own_packets(c)?) };
    crate::client::task::check_delivery_size(task_body.len())?;
    let own_bytes =
        own_packet.as_ref().map_or(0, |pages| pages.iter().map(Vec::len).sum::<usize>());
    let group_targets = group_plan.as_ref().map_or(0, |plan| plan.targets.len().saturating_mul(2));
    let budget = own_bytes
        .saturating_mul(own_targets.len())
        .saturating_add(
            task_body
                .len()
                .saturating_add(4096)
                .saturating_mul(peers.len().saturating_add(group_targets)),
        )
        .saturating_mul(32);
    if budget > 32 * 1024 * 1024 {
        return Err(invalid("task fanout preparation byte budget exceeded"));
    }
    let mut deliveries = Vec::new();
    if let Some(plan) = group_plan {
        deliveries.extend(super::task_group::prepare(account, engine, c, plan).await?);
    }
    own_targets.append(&mut peers);
    for target in own_targets {
        let route = if target.own || control {
            crate::client::routed::Route {
                kind: crate::client::routed::Kind::Control,
                group_id: thread["group_id"].as_str().map(str::to_owned),
                attachments: false,
            }
        } else {
            crate::client::routed::Route::direct()
        };
        if target.own {
            for page in own_packet.as_ref().ok_or_else(|| invalid("own task pages missing"))? {
                deliveries.push(
                    seal(account, engine, &target, &c.conversation_id, page, route.clone()).await?,
                );
            }
        } else {
            deliveries
                .push(seal(account, engine, &target, &c.conversation_id, &task_body, route).await?);
        }
    }
    Ok(deliveries)
}
pub(super) async fn seal(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
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
        source_principal_id: account
            .client
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .principal_id
            .clone(),
        sender_id: account
            .client
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .device_id
            .clone(),
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
    })
}

/// Confirmation and same-root forwarding are bounded independently of inbound processing.
pub(crate) async fn drain_confirmations(
    account: &mut LocalBusAccountState,
) -> Result<usize, SdkError> {
    use crate::client::task::control::{AckJob, ForwardJob};
    let now = now_unix_timestamp();
    let mut sent = 0;
    let jobs =
        account.client.account_db()?.task_record_page::<AckJob>("task/ack/", "task/ack/", 65)?;
    for (key, mut job) in jobs.into_iter().filter(|(_, j)| j.next_at <= now).take(2) {
        if job.attempts >= 8 || now.saturating_sub(job.created_at) > 600 {
            account.client.account_db()?.delete_task_state(&key)?;
            continue;
        }
        let c = job.ack.original()?;
        let result = send_control(account, &c, Mode::Ack(&job.ack)).await;
        if result.is_ok() {
            let original = job.ack.original()?;
            let hash = crate::client::task::certificate::carrier_hash(&original)?;
            account.client.account_db()?.persist_actor_state(
                &crate::client::task::key("ack_sent", &hash),
                &json!({"start":now}),
            )?;
            account.client.account_db()?.prune_task_diagnostics("task/ack_sent/", 1024)?;
            account.client.account_db()?.delete_task_state(&key)?;
            sent += 1;
        } else {
            job.attempts += 1;
            job.next_at = now.saturating_add(2_i64.pow(job.attempts.min(6)));
            account.client.account_db()?.persist_actor_state(&key, &job)?;
        }
    }
    let jobs = account.client.account_db()?.task_record_page::<ForwardJob>(
        "task/forward/",
        "task/forward/",
        65,
    )?;
    for (key, mut job) in jobs.into_iter().filter(|(_, j)| j.next_at <= now).take(2) {
        if job.attempts >= 8 || now.saturating_sub(job.created_at) > 600 {
            account.client.account_db()?.delete_task_state(&key)?;
            continue;
        }
        let history = account.client.task_history(&job.conversation_id, &job.task_id)?;
        if let Some(last) = history.events.last() {
            let result = send_control(account, &last.carrier, Mode::Own).await;
            if result.is_ok() {
                account.client.account_db()?.delete_task_state(&key)?;
                sent += 1;
            } else {
                job.attempts += 1;
                job.next_at = now.saturating_add(2_i64.pow(job.attempts.min(6)));
                account.client.account_db()?.persist_actor_state(&key, &job)?;
            }
        } else {
            account.client.account_db()?.delete_task_state(&key)?;
        }
    }
    Ok(sent)
}
async fn send_control(
    account: &mut LocalBusAccountState,
    c: &Carrier,
    mode: Mode<'_>,
) -> Result<(), SdkError> {
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &c.conversation_id)?
        .ok_or_else(|| invalid("task conversation missing"))?;
    let mut engine = account.take_live_engine().await?;
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        prepare(account, &mut engine, c, &thread, mode),
    )
    .await;
    account.put_engine(engine);
    let deliveries = result
        .map_err(|_| SdkError::InboundPending("task confirmation preparation deferred".into()))??;
    super::super::task_delivery::submit_until(
        account,
        deliveries,
        tokio::time::Instant::now() + Duration::from_secs(1),
    )
    .await?;
    Ok(())
}

async fn direct_targets(
    account: &LocalBusAccountState,
    gateway: &GatewaySessionConfig,
    thread: &Value,
) -> Result<Vec<Target>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
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
        let manifest =
            crate::client::contact::fetch_verified_device_manifest_from_url(url, commitment)?;
        client.persist_identity_directory(&manifest)?;
        manifest
    } else {
        client.cache_verified_device_manifest(gateway, commitment, "task_peer").await?
    };
    if manifest.principal_id != peers_ids[0] {
        return Err(invalid("task peer principal changed"));
    }
    Ok(manifest
        .devices
        .into_iter()
        .map(|d| Target {
            device: d.device_id,
            delivery: d.target_delivery_id,
            federation: federation.clone(),
            own: false,
        })
        .collect())
}

async fn own_targets(
    account: &LocalBusAccountState,
    gateway: &GatewaySessionConfig,
) -> Result<Vec<Target>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let own = client
        .cache_verified_device_manifest(gateway, &account.principal_commitment, "task_own")
        .await?;
    if !own.devices.iter().any(|d| d.device_id == local.device_id) {
        return Err(invalid("task source device is not in the active manifest"));
    }
    Ok(own
        .devices
        .into_iter()
        .filter(|d| d.device_id != local.device_id)
        .map(|d| Target {
            device: d.device_id,
            delivery: d.target_delivery_id,
            federation: None,
            own: true,
        })
        .collect())
}
