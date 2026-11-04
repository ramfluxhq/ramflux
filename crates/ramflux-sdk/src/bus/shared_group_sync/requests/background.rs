// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent group-control delivery and owner processing with row-fenced local checkpoints.

use super::{
    Attempt, BTreeSet, GatewayDirectMessage, GatewaySessionConfig, GroupControlBody,
    GroupControlPacket, LocalBusAccountState, LocalBusFederationRoute, RamfluxClient, SdkError,
    TRANSFER_SEND_PREFIX, active_key, defer, mark_sent, now_unix_timestamp, pending_packets,
    was_delivered,
};
use crate::bus::{
    connection_manager::SessionContext,
    couriers::{federation, primary::PrimarySnapshot, writer::Writer},
};
use crate::client::routed::{SendMaterial, SendMaterialRequest};

#[derive(Clone)]
struct Plan {
    id: String,
    packet: GroupControlPacket,
    state: ramflux_crypto::VerifiedGroupState,
    fingerprint: serde_json::Value,
    config: GatewaySessionConfig,
}
struct Target {
    plan: Plan,
    root: String,
    device: crate::prekey::SdkDeviceManifestEntry,
    message: GatewayDirectMessage,
    route: Option<LocalBusFederationRoute>,
    request: SendMaterialRequest,
    expires_at: i64,
}
#[derive(Clone)]
struct Sealed {
    plan: Plan,
    attempt: Attempt,
}
struct Incoming {
    record: crate::client::shared_group::RequestRecord,
    state_hash: String,
    config: GatewaySessionConfig,
    route: Option<LocalBusFederationRoute>,
    primary: Option<PrimarySnapshot>,
    target: String,
}

pub(crate) async fn pass(context: SessionContext, writer: Writer) -> Result<bool, SdkError> {
    let mut active = process_incoming(&context, &writer).await?;
    let Some(plan) = writer.apply(prepare).await? else { return Ok(active) };
    active = true;
    let captured = plan.clone();
    let saved = writer
        .apply(move |account| {
            Ok(account
                .client
                .account_db()?
                .load_actor_state::<Attempt>(&active_key(&captured.id))?)
        })
        .await?;
    if let Some(attempt) = saved {
        let manifest = federation::manifest(
            &context,
            &plan.config,
            &attempt.root,
            attempt.federation.as_ref(),
        )
        .await;
        let captured = plan.clone();
        let retry =
            writer.apply(move |account| retry(account, captured, attempt, manifest)).await?;
        if let Some(sealed) = retry {
            return submit(&context, &writer, sealed).await.map(|()| active);
        }
    }
    let captured = plan.clone();
    let roots = writer.apply(move |account| roots(account, &captured)).await?;
    for root in roots {
        let captured = plan.clone();
        let owned_root = root.clone();
        let route = writer
            .apply(move |account| {
                if !current(account, &captured)? {
                    return Err(SdkError::NetworkingPending);
                }
                account
                    .client
                    .account_db()?
                    .persist_actor_state(&root_cursor_key(&captured.id), &owned_root)?;
                account.client.shared_group_federation_route(captured.packet.group(), &owned_root)
            })
            .await?;
        let manifest = federation::manifest(&context, &plan.config, &root, route.as_ref()).await;
        let captured = plan.clone();
        let selected =
            writer.apply(move |account| target(account, captured, &root, route, manifest)).await?;
        let Some(mut target) = selected else { continue };
        let request = std::mem::replace(
            &mut target.request,
            SendMaterialRequest { root: None, prekey: None },
        );
        let material = federation::material(
            &context,
            &target.plan.config,
            request,
            crate::bus::connection_manager::CallClass::Bulk,
            target.route.as_ref(),
        )
        .await;
        let Some(sealed) = writer.apply(move |account| seal(account, target, material)).await?
        else {
            return Ok(active);
        };
        submit(&context, &writer, sealed).await?;
        break;
    }
    Ok(active)
}
async fn submit(context: &SessionContext, writer: &Writer, sealed: Sealed) -> Result<(), SdkError> {
    tokio::time::timeout_at(
        context.receipt_deadline(),
        federation::submit(
            context,
            sealed.attempt.envelope.clone(),
            sealed.attempt.federation.clone(),
        ),
    )
    .await
    .map_err(|_| SdkError::InboundPending("group courier submit deadline".into()))??;
    writer
        .apply(move |account| {
            if current(account, &sealed.plan)?
                && account
                    .client
                    .account_db()?
                    .load_actor_state::<serde_json::Value>(&active_key(&sealed.plan.id))?
                    == Some(serde_json::to_value(&sealed.attempt)?)
            {
                mark_sent(&account.client, &sealed.attempt)?;
            }
            Ok(())
        })
        .await
}
fn prepare(account: &mut LocalBusAccountState) -> Result<Option<Plan>, SdkError> {
    let now = now_unix_timestamp();
    let client = &account.client;
    let db = client.account_db()?;
    client.advance_group_transfer_deadlines(now)?;
    db.retain_expiring_actor_states("group-beacon/", now, 4096)?;
    db.retain_expiring_actor_states(TRANSFER_SEND_PREFIX, now, 512)?;
    db.retain_expiring_actor_states("group-courier/sealed/", now, 4096)?;
    let after = db.load_actor_state::<String>("group-courier/cursor")?.unwrap_or_default();
    let mut pending = pending_packets(client, now)?;
    pending.sort_by(|a, b| a.0.cmp(&b.0));
    let Some((id, packet)) =
        pending.iter().find(|(key, _)| *key > after).or_else(|| pending.first()).cloned()
    else {
        return Ok(None);
    };
    db.persist_actor_state("group-courier/cursor", &id)?;
    let Some(state) = db.shared_group_state(packet.group())? else { return Ok(None) };
    defer(client, &id, &packet, now.saturating_add(30))?;
    let Some(fingerprint) = fingerprint(client, &id, &packet)? else { return Ok(None) };
    Ok(Some(Plan { id, packet, state, fingerprint, config: account.gateway_config.clone() }))
}
fn fingerprint(
    client: &RamfluxClient,
    id: &str,
    packet: &GroupControlPacket,
) -> Result<Option<serde_json::Value>, SdkError> {
    match &packet.body {
        GroupControlBody::Request { request, .. } => client
            .group_change_record(request, false)?
            .map(serde_json::to_value)
            .transpose()
            .map_err(SdkError::from),
        GroupControlBody::Result { result } => client
            .group_change_records()?
            .into_iter()
            .find(|record| {
                record.incoming
                    && record.request.request_id == result.request_id
                    && record.request.group_id == result.group_id
                    && record.request.actor.identity == result.requester
            })
            .map(serde_json::to_value)
            .transpose()
            .map_err(SdkError::from),
        GroupControlBody::Transfer { .. } | GroupControlBody::DeviceSet { .. } => {
            Ok(client.account_db()?.load_actor_state(id)?)
        }
    }
}
fn current(account: &LocalBusAccountState, plan: &Plan) -> Result<bool, SdkError> {
    Ok(fingerprint(&account.client, &plan.id, &plan.packet)?.as_ref() == Some(&plan.fingerprint)
        && account
            .client
            .account_db()?
            .shared_group_state(plan.packet.group())?
            .is_some_and(|state| state.snapshot().state_hash == plan.state.snapshot().state_hash))
}
fn root_cursor_key(id: &str) -> String {
    format!(
        "group-courier/root-cursor/{}",
        ramflux_protocol::hash_base64url("ramflux.group.courier.cursor.v1", id.as_bytes())
    )
}
fn roots(account: &LocalBusAccountState, plan: &Plan) -> Result<Vec<String>, SdkError> {
    if !current(account, plan)? {
        return Ok(Vec::new());
    }
    let roots: BTreeSet<String> = match &plan.packet.body {
        GroupControlBody::Request { .. } => {
            BTreeSet::from([plan.state.creator().identity.root_commitment.clone()])
        }
        GroupControlBody::Result { result } => {
            BTreeSet::from([result.requester.root_commitment.clone()])
        }
        GroupControlBody::Transfer { control } => {
            control.targets().into_iter().map(|target| target.root).collect()
        }
        GroupControlBody::DeviceSet { .. } => plan
            .state
            .view()
            .members
            .iter()
            .map(|member| member.identity.root_commitment.clone())
            .collect(),
    };
    let after = account
        .client
        .account_db()?
        .load_actor_state::<String>(&root_cursor_key(&plan.id))?
        .unwrap_or_default();
    Ok(roots
        .iter()
        .filter(|root| **root > after)
        .chain(roots.iter().filter(|root| **root <= after))
        .take(4)
        .cloned()
        .collect())
}
fn allowed(
    client: &RamfluxClient,
    plan: &Plan,
    root: &str,
    device: &str,
) -> Result<bool, SdkError> {
    let own = client.owned_device_identity()?;
    if root == own.root_commitment() && device == own.device_id() {
        return Ok(false);
    }
    if was_delivered(client, &plan.id, &plan.packet, root, device)? {
        return Ok(false);
    }
    match &plan.packet.body {
        GroupControlBody::Result { result } => {
            Ok(root == result.requester.root_commitment && device == result.requester.device_id)
        }
        GroupControlBody::Transfer { control } => Ok(control
            .targets()
            .iter()
            .any(|target| target.root == root && target.device == device)
            && client
                .shared_group_selected_devices(&plan.state)?
                .get(root)
                .is_some_and(|names| names.contains(device))),
        GroupControlBody::Request { .. } => Ok(root
            == plan.state.creator().identity.root_commitment
            && client
                .shared_group_selected_devices(&plan.state)?
                .get(root)
                .is_some_and(|names| names.contains(device))),
        GroupControlBody::DeviceSet { .. } => Ok(client
            .shared_group_selected_devices(&plan.state)?
            .get(root)
            .is_some_and(|names| names.contains(device))),
    }
}
fn retry(
    account: &LocalBusAccountState,
    plan: Plan,
    attempt: Attempt,
    manifest: Result<crate::SdkDeviceManifestResponse, SdkError>,
) -> Result<Option<Sealed>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    let valid = if let Ok(manifest) = manifest {
        account.client.persist_fetched_identity_directory(&manifest)?;
        manifest.devices.iter().any(|device| {
            device.device_id == attempt.device
                && device.target_delivery_id == attempt.envelope.target_delivery_id
        })
    } else {
        false
    };
    if valid
        && attempt.expires_at > now_unix_timestamp()
        && serde_json::to_value(&attempt.packet)? == serde_json::to_value(&plan.packet)?
        && allowed(&account.client, &plan, &attempt.root, &attempt.device)?
    {
        return Ok(Some(Sealed { plan, attempt }));
    }
    account.client.account_db()?.remove_actor_state(&active_key(&plan.id))?;
    Ok(None)
}
fn target(
    account: &LocalBusAccountState,
    plan: Plan,
    root: &str,
    route: Option<LocalBusFederationRoute>,
    manifest: Result<crate::SdkDeviceManifestResponse, SdkError>,
) -> Result<Option<Target>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    let Ok(manifest) = manifest else { return Ok(None) };
    account.client.persist_fetched_identity_directory(&manifest)?;
    account.client.persist_identity_directory(&manifest)?;
    let mut selected = None;
    for device in manifest.devices {
        if allowed(&account.client, &plan, root, &device.device_id)? {
            selected = Some(device);
            break;
        }
    }
    let Some(device) = selected else { return Ok(None) };
    let now = now_unix_timestamp();
    let expires_at = match &plan.packet.body {
        GroupControlBody::Request { request, .. } => request.expires_at,
        GroupControlBody::Result { result } => result.expires_at,
        GroupControlBody::DeviceSet { .. } => now.saturating_add(7 * 86400),
        GroupControlBody::Transfer { control } => control.expires_at().saturating_add(300),
    };
    let message = GatewayDirectMessage {
        conversation_id: plan.state.view().conversation_id.clone(),
        message_id: format!("group_control_{}", crate::new_surface_message_id()?),
        envelope_id: format!("group_control_{}", crate::new_surface_message_id()?),
        source_principal_id: plan.config.principal_id.clone(),
        sender_id: plan.config.device_id.clone(),
        recipient_device_id: Some(device.device_id.clone()),
        recipient_principal_commitment: Some(root.into()),
        target_delivery_id: device.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now,
        ttl: u32::try_from(expires_at.saturating_sub(now).clamp(1, 7 * 86400))
            .map_err(|_| SdkError::LocalBus("group courier TTL overflow".into()))?,
    };
    let request = account.client.routed_send_material_request(&plan.config, &message)?;
    Ok(Some(Target { plan, root: root.into(), device, message, route, request, expires_at }))
}
fn seal(
    account: &LocalBusAccountState,
    target: Target,
    material: Result<SendMaterial, SdkError>,
) -> Result<Option<Sealed>, SdkError> {
    let Target { plan, root, device, mut message, route, expires_at, .. } = target;
    if !current(account, &plan)? || !allowed(&account.client, &plan, &root, &device.device_id)? {
        return Ok(None);
    }
    if serde_json::to_value(
        account.client.shared_group_federation_route(plan.packet.group(), &root)?,
    )? != serde_json::to_value(&route)?
    {
        return Ok(None);
    }
    let sealed = account.client.seal_routed_prepared(
        &plan.config,
        &message,
        &serde_json::to_vec(&plan.packet)?,
        crate::client::routed::Route::group_control(plan.packet.group()),
        material?,
    )?;
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    let attempt = Attempt {
        id: plan.id.clone(),
        packet: plan.packet.clone(),
        root,
        device: device.device_id,
        envelope: crate::dm::gateway_direct_message_envelope(&plan.config, &message, None)?,
        federation: route,
        expires_at,
    };
    account.client.account_db()?.persist_actor_state(&active_key(&plan.id), &attempt)?;
    Ok(Some(Sealed { plan, attempt }))
}
async fn process_incoming(context: &SessionContext, writer: &Writer) -> Result<bool, SdkError> {
    let waiting = writer.apply(incoming).await?;
    let active = !waiting.is_empty();
    for mut item in waiting {
        let Ok(manifest) = federation::manifest(
            context,
            &item.config,
            &item.record.request.actor.identity.root_commitment,
            item.route.as_ref(),
        )
        .await
        else {
            continue;
        };
        let primary = match item.primary.take() {
            Some(primary) => Some(primary.load().await?),
            None => None,
        };
        writer
            .apply(move |account| {
                let client = &account.client;
                let current = client.group_change_record(&item.record.request, true)?;
                if current.map(serde_json::to_value).transpose()?
                    != Some(serde_json::to_value(&item.record)?)
                    || client
                        .account_db()?
                        .shared_group_state(&item.record.request.group_id)?
                        .is_none_or(|state| state.snapshot().state_hash != item.state_hash)
                {
                    return Ok(());
                }
                client.persist_fetched_identity_directory(&manifest)?;
                client.persist_identity_directory(&manifest)?;
                if let Err(error) = client.process_group_request_with_primary(
                    &item.record.request,
                    &item.target,
                    primary.as_ref(),
                ) {
                    tracing::debug!(%error,"group request processing deferred");
                }
                Ok(())
            })
            .await?;
    }
    Ok(active)
}
fn incoming(account: &mut LocalBusAccountState) -> Result<Vec<Incoming>, SdkError> {
    let client = &account.client;
    let now = now_unix_timestamp();
    let own = client.owned_device_identity()?;
    let after = client
        .account_db()?
        .load_actor_state::<String>("group-courier/process-cursor")?
        .unwrap_or_default();
    let mut waiting = Vec::new();
    for record in client.group_change_records()?.into_iter().filter(|record| {
        record.incoming
            && record.result.is_none()
            && record.local_status == "waiting_for_owner"
            && record.request.expires_at > now
    }) {
        waiting.push((
            crate::client::shared_group::request_record_key(&record.request, true)?,
            record,
        ));
    }
    waiting.sort_by(|a, b| a.0.cmp(&b.0));
    let ordered: Vec<_> = waiting
        .iter()
        .filter(|(key, _)| *key > after)
        .chain(waiting.iter().filter(|(key, _)| *key <= after))
        .take(4)
        .cloned()
        .collect();
    let mut output = Vec::new();
    for (id, record) in ordered {
        client.account_db()?.persist_actor_state("group-courier/process-cursor", &id)?;
        let state = client.account_db()?.shared_group_state(&record.request.group_id)?;
        let Some(state) =
            state.filter(|state| state.creator().identity.root_commitment == own.root_commitment())
        else {
            let mut changed = record;
            changed.local_status = "owner_changed".into();
            client.persist_group_request(&changed)?;
            continue;
        };
        let route = client.shared_group_federation_route(
            &record.request.group_id,
            &record.request.actor.identity.root_commitment,
        )?;
        output.push(Incoming {
            record,
            state_hash: state.snapshot().state_hash.clone(),
            config: account.gateway_config.clone(),
            route,
            primary: PrimarySnapshot::prepare(account)?,
            target: account.target_delivery_id.clone(),
        });
    }
    Ok(output)
}
