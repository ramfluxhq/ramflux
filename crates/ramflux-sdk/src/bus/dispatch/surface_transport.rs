// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified all-terminal routing and atomic enqueue of prepared encrypted surface envelopes.
use crate::client::surface::{Carrier, ControlKind, PayloadKind, SurfaceLogicalJob};
use crate::prelude::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[derive(Clone)]
struct Target {
    device: String,
    delivery: String,
    own: bool,
}
struct Prepared {
    envelopes: Vec<ramflux_protocol::Envelope>,
    group_epoch: Option<u64>,
}
fn invalid(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}

pub(crate) async fn send(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
) -> Result<Value, SdkError> {
    let group = super::surface_group::plan(account, carrier)?;
    let reservation = group.as_ref().map_or((0, 0), |plan| (1, plan.bytes));
    let prepared = prepare(account, carrier, group.is_some(), None, reservation).await?;
    let timeline = RamfluxClient::surface_timeline_id(carrier)?;
    let result = account.client.account_db()?.surface_transaction(|| {
        super::super::surface_jobs::admit(account, prepared.envelopes.len(), 0)?;
        let result = account
            .client
            .project_surface_message(
                &carrier.conversation_id,
                &timeline,
                crate::client::surface::SurfaceSender {
                    principal: &carrier.sender_principal_id,
                    device: &carrier.sender_device_id,
                    envelope_id: &carrier.message_id,
                    expires_at: None,
                    group_epoch: prepared.group_epoch,
                },
                &carrier.bytes()?,
                true,
            )?
            .ok_or_else(|| invalid("surface projection absent"))?;
        if result.accepted {
            account.client.retain_authored_surface(carrier)?;
            if account.client.direct_message_by_id(&timeline)?.is_none() {
                let encrypted = prepared
                    .envelopes
                    .first()
                    .map_or_else(Vec::new, |e| e.encrypted_payload.as_bytes().to_vec());
                let metadata = MessageMetadata::default();
                account.client.send_direct_message_with_metadata(
                    &carrier.conversation_id,
                    &timeline,
                    &carrier.sender_device_id,
                    &encrypted,
                    &metadata,
                )?;
            }
            account.client.account_db()?.replace_surface_message_content(
                &carrier.conversation_id,
                &timeline,
                result.fallback_text.as_bytes(),
            )?;
            super::super::surface_jobs::enqueue(account, prepared.envelopes)?;
            if let Some(plan) = group {
                super::super::surface_jobs::enqueue_latest_group(account, carrier, plan)?;
            }
        }
        let mut response = serde_json::to_value(result)?;
        response["surface_id"] = json!(carrier.surface_id);
        response["surface_ref"] = json!(carrier.surface_reference()?);
        response["message_id"] = json!(carrier.message_id);
        response["delivery_state"] = json!("queued");
        Ok::<Value, SdkError>(response)
    })?;
    Ok(result)
}

pub(crate) async fn drain_forwarding(
    account: &mut LocalBusAccountState,
) -> Result<usize, SdkError> {
    let now = now_unix_timestamp();
    let mut jobs = Vec::new();
    for prefix in ["surface/forward_job/", "surface/receipt_job/"] {
        jobs.extend(
            account
                .client
                .account_db()?
                .surface_record_page::<SurfaceLogicalJob>(prefix, prefix, 65)?,
        );
    }
    jobs.sort_by_key(|(_, job)| job.created_at);
    for (key, mut job) in jobs {
        if job.created_at.saturating_add(600) <= now || job.attempts >= 8 {
            account.client.account_db()?.delete_surface_state(&key)?;
            continue;
        }
        if job.next_at > now {
            continue;
        }
        if let Ok(prepared) = prepare(account, &job.carrier, true, job.group_epoch, (0, 0)).await {
            account.client.account_db()?.surface_transaction(|| {
                super::super::surface_jobs::enqueue(account, prepared.envelopes)?;
                account.client.account_db()?.delete_surface_state(&key)?;
                Ok::<_, SdkError>(())
            })?;
        } else {
            job.attempts += 1;
            job.next_at = now.saturating_add(2_i64.pow(job.attempts.min(6)));
            account.client.account_db()?.persist_actor_state(&key, &job)?;
            tracing::debug!("surface forwarding delayed");
        }
        return Ok(1);
    }
    Ok(0)
}

async fn prepare(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
    own_only: bool,
    epoch: Option<u64>,
    reservation: (usize, usize),
) -> Result<Prepared, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result =
        prepare_with_engine(account, &mut engine, carrier, own_only, epoch, reservation).await;
    account.put_engine(engine);
    result
}
async fn prepare_with_engine(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    carrier: &Carrier,
    own_only: bool,
    epoch: Option<u64>,
    reservation: (usize, usize),
) -> Result<Prepared, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let thread = client
        .account_db()?
        .client_record("conversation", &carrier.conversation_id)?
        .ok_or_else(|| invalid("surface conversation absent"))?;
    let group_id = thread["group_id"].as_str().map(str::to_owned);
    let group_epoch = if let Some(group) = &group_id {
        Some(epoch.unwrap_or(client.group_state(group)?.group_epoch))
    } else {
        None
    };
    let mut targets = own_targets(account, engine).await?;
    if !own_only {
        let peers = peer_commitments(account, carrier, &thread)?;
        for (commitment, principal) in peers {
            let manifest = client
                .cache_verified_device_manifest(&engine.config, &commitment, "surface_peer")
                .await?;
            if principal.as_ref().is_some_and(|p| *p != manifest.principal_id) {
                return Err(invalid("surface peer root principal changed"));
            }
            if group_id.is_none() {
                client.require_accepted_friend_link_for_dm_send(
                    &local.principal_id,
                    &account.principal_commitment,
                    Some(&manifest.principal_id),
                    &manifest.principal_commitment,
                )?;
            }
            for device in manifest.devices {
                if device.device_id != local.device_id {
                    targets.push(Target {
                        device: device.device_id,
                        delivery: device.target_delivery_id,
                        own: false,
                    });
                }
            }
        }
    }
    targets.sort_by(|a, b| a.device.cmp(&b.device));
    targets.dedup_by(|a, b| a.device == b.device);
    let payloads = targets
        .into_iter()
        .map(|target| {
            let kind = if target.own { ControlKind::Own } else { ControlKind::Peer };
            let body = client.surface_control_packet(carrier, kind, group_epoch)?.bytes()?;
            Ok::<_, SdkError>((target, body))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let route_bytes = serde_json::to_vec(&group_id)?.len().saturating_mul(8);
    let bytes = payloads.iter().try_fold(reservation.1, |sum, (target, body)| {
        let ids = serde_json::to_vec(&(&target.device, &target.delivery))?.len().saturating_mul(8);
        Ok::<_, SdkError>(
            sum.saturating_add(body.len().saturating_mul(4))
                .saturating_add(ids)
                .saturating_add(route_bytes)
                .saturating_add(64 * 1024),
        )
    })?;
    if reservation.0 > 0 {
        super::super::surface_jobs::admit_group(account, carrier, bytes)?;
        // Own-device copies are separately retained and may not be hidden by coalescing.
        super::super::surface_jobs::admit(
            account,
            payloads.len(),
            bytes.saturating_sub(reservation.1),
        )?;
    } else {
        super::super::surface_jobs::admit(account, payloads.len(), bytes)?;
    }
    let mut envelopes = Vec::new();
    for (target, body) in payloads {
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
            ttl: 600,
        };
        let route = crate::client::routed::Route {
            kind: crate::client::routed::Kind::Control,
            group_id: group_id.clone(),
            attachments: false,
        };
        message.encrypted_body =
            serde_json::to_vec(&client.seal_routed_as(engine, &message, &body, route).await?)?;
        envelopes.push(crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?);
    }
    Ok(Prepared { envelopes, group_epoch })
}
fn peer_commitments(
    account: &LocalBusAccountState,
    carrier: &Carrier,
    thread: &Value,
) -> Result<BTreeMap<String, Option<String>>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let mut peers = BTreeMap::new();
    if let Some(group) = thread["group_id"].as_str() {
        if !client.surface_group_device_allowed(group, &local.device_id)? {
            return Err(invalid("surface sender has no group membership"));
        }
        if carrier.payload_kind == PayloadKind::Action {
            let identity = client
                .account_db()?
                .client_record("identity", &carrier.author_principal_id)?
                .ok_or_else(|| invalid("surface author identity unavailable"))?;
            let commitment = identity["contact_identity_commitment"]
                .as_str()
                .ok_or_else(|| invalid("surface author root missing"))?;
            peers.insert(commitment.into(), Some(carrier.author_principal_id.clone()));
        } else {
            for row in super::super::group_delivery::directory(client, group)? {
                if row["member_id"] == local.device_id || row["principal_id"] == local.principal_id
                {
                    continue;
                }
                let commitment = row["member_principal_commitment"]
                    .as_str()
                    .ok_or_else(|| invalid("group member root unavailable"))?;
                if commitment != account.principal_commitment {
                    peers
                        .insert(commitment.into(), row["principal_id"].as_str().map(str::to_owned));
                }
            }
        }
    } else {
        let participants = thread["participants"]
            .as_array()
            .ok_or_else(|| invalid("surface direct participants absent"))?;
        if thread["kind"] != "direct" || !participants.iter().any(|p| p == &local.principal_id) {
            return Err(invalid("surface direct membership mismatch"));
        }
        let ids = if carrier.payload_kind == PayloadKind::Action {
            vec![carrier.author_principal_id.as_str()]
        } else {
            participants
                .iter()
                .filter_map(Value::as_str)
                .filter(|p| *p != local.principal_id)
                .collect()
        };
        if ids.len() != 1 {
            return Err(invalid("surface direct peer is ambiguous"));
        }
        for id in ids {
            let identity = client
                .account_db()?
                .client_record("identity", id)?
                .ok_or_else(|| invalid("surface peer identity missing"))?;
            peers.insert(
                identity["contact_identity_commitment"]
                    .as_str()
                    .ok_or_else(|| invalid("surface peer root missing"))?
                    .into(),
                Some(id.into()),
            );
        }
    }
    Ok(peers)
}

async fn own_targets(
    account: &LocalBusAccountState,
    engine: &GatewaySessionEngine,
) -> Result<Vec<Target>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let own = client
        .cache_verified_device_manifest(
            &engine.config,
            &account.principal_commitment,
            "surface_own",
        )
        .await?;
    if !own.devices.iter().any(|d| d.device_id == local.device_id) {
        return Err(invalid("surface source device is not authorized"));
    }
    Ok(own
        .devices
        .into_iter()
        .filter(|d| d.device_id != local.device_id)
        .map(|d| Target { device: d.device_id, delivery: d.target_delivery_id, own: true })
        .collect())
}
