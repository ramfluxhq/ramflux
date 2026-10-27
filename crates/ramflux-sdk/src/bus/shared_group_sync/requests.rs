// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded creator request courier and device-set hints on existing encrypted pair transport.
use crate::client::shared_group::{
    BeaconRecord, GroupControlBody, GroupControlPacket, TRANSFER_SEND_PREFIX, TransferDelivery,
};
use crate::prelude::*;
use serde::{Deserialize, Serialize};
fn active_key(id: &str) -> String {
    format!(
        "group-courier/sealed/{}",
        ramflux_protocol::hash_base64url("ramflux.group.courier.attempt.v1", id.as_bytes())
    )
}
#[derive(Deserialize, Serialize)]
struct Attempt {
    id: String,
    packet: GroupControlPacket,
    root: String,
    device: String,
    envelope: ramflux_protocol::Envelope,
    federation: Option<LocalBusFederationRoute>,
    expires_at: i64,
}
pub(in crate::bus) async fn flush(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    flush_with_clock(account, now_unix_timestamp).await
}
pub(in crate::bus) async fn flush_with_clock(
    account: &mut LocalBusAccountState,
    mut clock: impl FnMut() -> i64,
) -> Result<usize, SdkError> {
    let now = clock();
    let client = &account.client;
    if let Err(error) = client.advance_group_transfer_deadlines(now) {
        tracing::warn!(%error, "group transfer deadline scan deferred");
    }
    client.account_db()?.retain_expiring_actor_states("group-beacon/", now, 4096)?;
    client.account_db()?.retain_expiring_actor_states(TRANSFER_SEND_PREFIX, now, 512)?;
    client.account_db()?.retain_expiring_actor_states("group-courier/sealed/", now, 4096)?;
    process_incoming(account, now).await?;
    // Processing can create a result in a later clock second. Select work
    // against the current time, including that freshly committed result.
    let now = clock();
    // Fair rotation prevents one offline requester from starving other groups or refusals.
    let after = client
        .account_db()?
        .load_actor_state::<String>("group-courier/cursor")?
        .unwrap_or_default();
    let mut pending = pending_packets(client, now)?;
    pending.sort_by(|a, b| a.0.cmp(&b.0));
    let selected =
        pending.iter().find(|(key, _)| *key > after).or_else(|| pending.first()).cloned();
    let Some((id, packet)) = selected else { return Ok(0) };
    client.account_db()?.persist_actor_state("group-courier/cursor", &id)?;
    let Some(state) = client.account_db()?.shared_group_state(packet.group())? else {
        return Ok(0);
    };
    if let Some(attempt) = client.account_db()?.load_actor_state::<Attempt>(&active_key(&id))? {
        defer(client, &id, &packet, now.saturating_add(30))?;
        if serde_json::to_vec(&attempt.packet)? == serde_json::to_vec(&packet)?
            && attempt.expires_at > now
            && retry_allowed(client, &account.gateway_config, &state, &attempt).await?
        {
            defer(client, &id, &packet, now.saturating_add(30))?;
            return submit(account, attempt).await;
        }
        client.account_db()?.remove_actor_state(&active_key(&id))?;
    }
    let destination = destination(client, &account.gateway_config, &id, &packet, &state).await?;
    defer(client, &id, &packet, now.saturating_add(30))?;
    let Some((root, device)) = destination else { return Ok(0) };
    seal_and_send(account, &id, packet, &state, (root, device)).await
}
async fn seal_and_send(
    account: &mut LocalBusAccountState,
    id: &str,
    packet: GroupControlPacket,
    state: &ramflux_crypto::VerifiedGroupState,
    destination: (String, crate::prekey::SdkDeviceManifestEntry),
) -> Result<usize, SdkError> {
    let now = now_unix_timestamp();
    let (root, device) = destination;
    let client = &account.client;
    let federation = client.shared_group_federation_route(packet.group(), &root)?;
    let expires_at = match &packet.body {
        GroupControlBody::Request { request, .. } => request.expires_at,
        GroupControlBody::Result { result } => result.expires_at,
        GroupControlBody::DeviceSet { .. } => now.saturating_add(7 * 86400),
        GroupControlBody::Transfer { control } => control.expires_at().saturating_add(300),
    };
    let mut message = GatewayDirectMessage {
        conversation_id: state.view().conversation_id.clone(),
        message_id: format!("group_control_{}", crate::new_surface_message_id()?),
        envelope_id: format!("group_control_{}", crate::new_surface_message_id()?),
        source_principal_id: account.gateway_config.principal_id.clone(),
        sender_id: account.gateway_config.device_id.clone(),
        recipient_device_id: Some(device.device_id.clone()),
        recipient_principal_commitment: Some(root.clone()),
        target_delivery_id: device.target_delivery_id,
        encrypted_body: Vec::new(),
        created_at: now,
        ttl: u32::try_from(expires_at.saturating_sub(now).clamp(1, 7 * 86400))
            .map_err(|_| SdkError::LocalBus("group courier TTL overflow".into()))?,
    };
    let mut engine = account.take_live_engine().await?;
    let result = async {
        let route = crate::client::routed::Route::group_control(packet.group());
        let bytes = serde_json::to_vec(&packet)?;
        let sealed = if let Some(federation) = &federation {
            account.client.seal_routed_federated_as(
                &engine,
                &message,
                &bytes,
                federation.recipient_prekey_url.as_deref(),
                route,
            )?
        } else {
            account.client.seal_routed_as(&mut engine, &message, &bytes, route).await?
        };
        message.encrypted_body = serde_json::to_vec(&sealed)?;
        let attempt = Attempt {
            id: id.into(),
            packet,
            root,
            device: device.device_id,
            envelope: crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?,
            federation,
            expires_at,
        };
        account.client.account_db()?.persist_actor_state(&active_key(id), &attempt)?;
        send(&account.client, &mut engine, &attempt).await
    }
    .await;
    account.put_engine(engine);
    result
}
async fn destination(
    client: &RamfluxClient,
    gateway: &GatewaySessionConfig,
    id: &str,
    packet: &GroupControlPacket,
    state: &ramflux_crypto::VerifiedGroupState,
) -> Result<Option<(String, crate::prekey::SdkDeviceManifestEntry)>, SdkError> {
    let own = client.owned_device_identity()?;
    let roots = match &packet.body {
        GroupControlBody::Request { .. } => {
            BTreeSet::from([state.creator().identity.root_commitment.clone()])
        }
        GroupControlBody::Result { result } => {
            BTreeSet::from([result.requester.root_commitment.clone()])
        }
        GroupControlBody::Transfer { control } => {
            control.targets().into_iter().map(|target| target.root).collect()
        }
        GroupControlBody::DeviceSet { .. } => state
            .view()
            .members
            .iter()
            .map(|member| member.identity.root_commitment.clone())
            .collect(),
    };
    let mut destination = None;
    let root_cursor_key = format!(
        "group-courier/root-cursor/{}",
        ramflux_protocol::hash_base64url("ramflux.group.courier.cursor.v1", id.as_bytes())
    );
    let after_root =
        client.account_db()?.load_actor_state::<String>(&root_cursor_key)?.unwrap_or_default();
    let ordered: Vec<_> = roots
        .iter()
        .filter(|root| **root > after_root)
        .chain(roots.iter().filter(|root| **root <= after_root))
        .take(4)
        .cloned()
        .collect();
    for root in ordered {
        client.account_db()?.persist_actor_state(&root_cursor_key, &root)?;
        let Ok(Ok(manifest)) = tokio::time::timeout(
            Duration::from_secs(3),
            client.shared_group_manifest(gateway, packet.group(), &root),
        )
        .await
        else {
            continue;
        };
        client.persist_identity_directory(&manifest)?;
        for device in manifest.devices {
            if root == own.root_commitment() && device.device_id == own.device_id() {
                continue;
            }
            let delivered = was_delivered(client, id, packet, &root, &device.device_id)?;
            if delivered {
                continue;
            }
            if let GroupControlBody::Transfer { control } = &packet.body {
                if !control
                    .targets()
                    .iter()
                    .any(|target| target.root == root && target.device == device.device_id)
                    || client
                        .shared_group_selected_devices(state)?
                        .get(&root)
                        .is_none_or(|names| !names.contains(&device.device_id))
                {
                    continue;
                }
            } else if let GroupControlBody::Result { result } = &packet.body {
                if device.device_id != result.requester.device_id {
                    continue;
                }
            } else if client
                .shared_group_selected_devices(state)?
                .get(&root)
                .is_none_or(|devices| !devices.contains(&device.device_id))
            {
                continue;
            }
            destination = Some((root.clone(), device));
            break;
        }
        if destination.is_some() {
            break;
        }
    }
    Ok(destination)
}

fn pending_packets(
    client: &RamfluxClient,
    now: i64,
) -> Result<Vec<(String, GroupControlPacket)>, SdkError> {
    let mut pending = Vec::new();
    for record in client
        .group_change_records()?
        .into_iter()
        .filter(|record| record.request.expires_at > now && record.next_at <= now)
    {
        let id = crate::client::shared_group::request_record_key(&record.request, record.incoming)?;
        let packet = if record.incoming {
            let Some(result) = &record.result else { continue };
            GroupControlPacket::new(GroupControlBody::Result { result: result.clone() })
        } else {
            if record.result.is_some() {
                continue;
            }
            GroupControlPacket::new(GroupControlBody::Request {
                request: record.request.clone(),
                federation: record.federation.clone(),
            })
        };
        pending.push((id, packet));
    }
    for record in client
        .account_db()?
        .list_actor_states::<BeaconRecord>("group-beacon/")?
        .into_iter()
        .filter(|record| record.next_at <= now)
    {
        pending.push((
            format!("group-beacon/{}", ramflux_protocol::encode_base64url(record.packet.group())),
            record.packet,
        ));
    }
    for id in client.account_db()?.actor_state_key_page(TRANSFER_SEND_PREFIX, 512)? {
        // A failed deadline delivery can appear here again in the same tick.
        let item = (|| -> Result<_, SdkError> {
            let Some(mut record) =
                client.account_db()?.load_actor_state::<TransferDelivery>(&id)?
            else {
                return Ok(None);
            };
            if record.next_at > now
                || record.expires_at <= now
                || !record.control.targets().iter().any(|target| {
                    !record.delivered.contains(&(target.root.clone(), target.device.clone()))
                })
            {
                return Ok(None);
            }
            client.refresh_group_transfer_cancellation(&mut record)?;
            client.account_db()?.persist_actor_state(&id, &record)?;
            Ok(Some(GroupControlPacket::new(GroupControlBody::Transfer {
                control: Box::new(record.control),
            })))
        })();
        match item {
            Ok(Some(packet)) => pending.push((id, packet)),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, item = %id, "group transfer courier item deferred");
            }
        }
    }
    Ok(pending)
}

fn defer(
    client: &RamfluxClient,
    id: &str,
    packet: &GroupControlPacket,
    next: i64,
) -> Result<(), SdkError> {
    match &packet.body {
        GroupControlBody::Request { request, .. } => {
            if let Some(mut record) = client.group_change_record(request, false)? {
                record.next_at = next;
                client.persist_group_request(&record)?;
            }
        }
        GroupControlBody::Result { result } => {
            for mut record in client.group_change_records()?.into_iter().filter(|r| {
                r.incoming
                    && r.request.request_id == result.request_id
                    && r.request.group_id == result.group_id
                    && r.request.actor.identity == result.requester
            }) {
                record.next_at = next;
                client.persist_group_request(&record)?;
            }
        }
        GroupControlBody::Transfer { .. } => {
            if let Some(mut record) =
                client.account_db()?.load_actor_state::<TransferDelivery>(id)?
            {
                record.next_at = next;
                client.account_db()?.persist_actor_state(id, &record)?;
            }
        }
        GroupControlBody::DeviceSet { .. } => {
            if let Some(mut record) = client.account_db()?.load_actor_state::<BeaconRecord>(id)? {
                record.next_at = next;
                client.account_db()?.persist_actor_state(id, &record)?;
            }
        }
    }
    Ok(())
}
async fn submit(account: &mut LocalBusAccountState, attempt: Attempt) -> Result<usize, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = send(&account.client, &mut engine, &attempt).await;
    account.put_engine(engine);
    result
}
async fn send(
    client: &RamfluxClient,
    engine: &mut GatewaySessionEngine,
    attempt: &Attempt,
) -> Result<usize, SdkError> {
    tokio::time::timeout(Duration::from_secs(3), async {
        if let Some(federation) = &attempt.federation {
            if !RamfluxClient::forward_federated_envelope(federation, attempt.envelope.clone())?
                .accepted
            {
                return Err(SdkError::InboundPending("group courier federation refused".into()));
            }
        } else {
            engine.submit_envelope(attempt.envelope.clone()).await?;
        }
        Ok::<(), SdkError>(())
    })
    .await
    .map_err(|_| SdkError::InboundPending("group courier submit deadline".into()))??;
    client.account_db()?.write_transaction(|| -> Result<(), SdkError> {
        match &attempt.packet.body {
            GroupControlBody::Request { request, .. } => {
                if let Some(mut record) = client.group_change_record(request, false)? {
                    record.delivered.insert(format!("{}/{}", attempt.root, attempt.device));
                    client.persist_group_request(&record)?;
                }
            }
            GroupControlBody::Result { result } => {
                for mut record in client.group_change_records()?.into_iter().filter(|r| {
                    r.incoming
                        && r.request.request_id == result.request_id
                        && r.request.group_id == result.group_id
                        && r.request.actor.identity == result.requester
                }) {
                    record.delivered.insert(format!("{}/{}", attempt.root, attempt.device));
                    client.persist_group_request(&record)?;
                }
            }
            GroupControlBody::Transfer { .. } => {
                if let Some(mut record) =
                    client.account_db()?.load_actor_state::<TransferDelivery>(&attempt.id)?
                {
                    record.delivered.insert((attempt.root.clone(), attempt.device.clone()));
                    let all = record.control.targets().iter().all(|target| {
                        record.delivered.contains(&(target.root.clone(), target.device.clone()))
                    });
                    let cancellation = matches!(
                        &record.control.body,
                        crate::client::shared_group::TransferBody::Head { reply } if reply.cancelled
                    );
                    if cancellation {
                        record.next_at = if all { now_unix_timestamp().saturating_add(30) } else { 0 };
                        if all {
                            record.delivered.clone_from(&record.acknowledged);
                        }
                        client.account_db()?.persist_actor_state(&attempt.id, &record)?;
                    } else if all {
                        client.account_db()?.remove_actor_state(&attempt.id)?;
                    } else {
                        client.account_db()?.persist_actor_state(&attempt.id, &record)?;
                    }
                }
            }
            GroupControlBody::DeviceSet { .. } => {
                let id = format!(
                    "group-beacon/{}",
                    ramflux_protocol::encode_base64url(attempt.packet.group())
                );
                if let Some(mut record) =
                    client.account_db()?.load_actor_state::<BeaconRecord>(&id)?
                {
                    record.delivered.insert((attempt.root.clone(), attempt.device.clone()));
                    client.account_db()?.persist_actor_state(&id, &record)?;
                }
            }
        }
        if !matches!(&attempt.packet.body,GroupControlBody::Transfer{control} if matches!(&control.body,crate::client::shared_group::TransferBody::Head{reply} if reply.cancelled)) {
            defer(client, &attempt.id, &attempt.packet, 0)?;
        }
        client.account_db()?.remove_actor_state(&active_key(&attempt.id))?;
        Ok(())
    })?;
    Ok(1)
}

async fn retry_allowed(
    client: &RamfluxClient,
    gateway: &GatewaySessionConfig,
    state: &ramflux_crypto::VerifiedGroupState,
    attempt: &Attempt,
) -> Result<bool, SdkError> {
    let manifest = tokio::time::timeout(
        Duration::from_secs(3),
        client.shared_group_manifest(gateway, attempt.packet.group(), &attempt.root),
    )
    .await
    .map_err(|_| SdkError::InboundPending("group retry manifest deadline".into()))??;
    if !manifest.devices.iter().any(|device| {
        device.device_id == attempt.device
            && device.target_delivery_id == attempt.envelope.target_delivery_id
    }) {
        return Ok(false);
    }
    match &attempt.packet.body {
        GroupControlBody::Request { .. } => Ok(attempt.root
            == state.creator().identity.root_commitment
            && client
                .shared_group_selected_devices(state)?
                .get(&attempt.root)
                .is_some_and(|names| names.contains(&attempt.device))),
        GroupControlBody::Result { result } => Ok(attempt.root == result.requester.root_commitment
            && attempt.device == result.requester.device_id),
        GroupControlBody::Transfer { control } => Ok(control
            .targets()
            .iter()
            .any(|target| target.root == attempt.root && target.device == attempt.device)
            && client
                .shared_group_selected_devices(state)?
                .get(&attempt.root)
                .is_some_and(|names| names.contains(&attempt.device))),
        GroupControlBody::DeviceSet { .. } => Ok(client
            .shared_group_selected_devices(state)?
            .get(&attempt.root)
            .is_some_and(|names| names.contains(&attempt.device))),
    }
}

async fn process_incoming(account: &LocalBusAccountState, now: i64) -> Result<(), SdkError> {
    let client = &account.client;
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
    for (id, record) in ordered {
        client.account_db()?.persist_actor_state("group-courier/process-cursor", &id)?;
        let state = client.account_db()?.shared_group_state(&record.request.group_id)?;
        if state
            .is_none_or(|state| state.creator().identity.root_commitment != own.root_commitment())
        {
            let mut changed = record;
            changed.local_status = "owner_changed".into();
            client.persist_group_request(&changed)?;
            continue;
        }
        let Ok(Ok(manifest)) = tokio::time::timeout(
            Duration::from_secs(3),
            client.shared_group_manifest(
                &account.gateway_config,
                &record.request.group_id,
                &record.request.actor.identity.root_commitment,
            ),
        )
        .await
        else {
            continue;
        };
        client.persist_identity_directory(&manifest)?;
        if let Err(error) =
            client.process_group_request(&record.request, &account.target_delivery_id)
        {
            tracing::debug!(%error,"group request processing deferred");
        }
    }
    Ok(())
}

fn was_delivered(
    client: &RamfluxClient,
    id: &str,
    packet: &GroupControlPacket,
    root: &str,
    device: &str,
) -> Result<bool, SdkError> {
    Ok(match &packet.body {
        GroupControlBody::Request { .. } | GroupControlBody::Result { .. } => {
            let (request, incoming) = match &packet.body {
                GroupControlBody::Request { request, .. } => (request.clone(), false),
                GroupControlBody::Result { result } => {
                    let Some(record) = client.group_change_records()?.into_iter().find(|record| {
                        record.incoming
                            && record.request.request_id == result.request_id
                            && record.request.group_id == result.group_id
                            && record.request.actor.identity == result.requester
                    }) else {
                        return Ok(true);
                    };
                    (record.request, true)
                }
                GroupControlBody::DeviceSet { .. } | GroupControlBody::Transfer { .. } => {
                    unreachable!()
                }
            };
            client
                .group_change_record(&request, incoming)?
                .is_some_and(|record| record.delivered.contains(&format!("{root}/{device}")))
        }
        GroupControlBody::Transfer { .. } => client
            .account_db()?
            .load_actor_state::<TransferDelivery>(id)?
            .is_some_and(|record| record.delivered.contains(&(root.into(), device.into()))),
        GroupControlBody::DeviceSet { .. } => client
            .account_db()?
            .load_actor_state::<BeaconRecord>(id)?
            .is_some_and(|record| record.delivered.contains(&(root.into(), device.into()))),
    })
}
