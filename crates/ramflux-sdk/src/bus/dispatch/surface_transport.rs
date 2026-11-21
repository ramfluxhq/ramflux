// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface carriers use the ordinary synchronous message and group delivery adapters.
use crate::client::surface::{Carrier, PayloadKind};
use crate::prelude::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn invalid(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}

pub(crate) async fn send(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
) -> Result<Value, SdkError> {
    if carrier.payload_kind.rpc_kind().is_some() || carrier.payload_kind == PayloadKind::Action {
        return send_private(account, carrier).await;
    }
    let bytes = carrier.bytes()?;
    if let Err(error) = crate::client::surface::check_delivery_size(bytes.len()) {
        account.client.surface_outgoing_too_large(carrier)?;
        return Err(error);
    }
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &carrier.conversation_id)?
        .ok_or_else(|| invalid("surface conversation absent"))?;
    let group = thread["group_id"].as_str();
    let group_epoch = group
        .map(|group| account.client.group_state(group).map(|state| state.group_epoch))
        .transpose()?;
    let mut authored = crate::GatewayDirectMessage {
        conversation_id: carrier.conversation_id.clone(),
        message_id: RamfluxClient::surface_timeline_id(carrier)?,
        envelope_id: crate::new_surface_message_id()?,
        source_principal_id: carrier.sender_principal_id.clone(),
        sender_id: carrier.sender_device_id.clone(),
        recipient_device_id: Some(carrier.sender_device_id.clone()),
        recipient_principal_commitment: Some(account.client.own_account_anchor()?),
        target_delivery_id: account.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: account.client.content_ttl()?,
    };
    if group.is_none() {
        Box::pin(prepare_direct_target(account, carrier, &thread, &mut authored)).await?;
    }
    let prepared = account.client.prepare_authored_content(
        &mut authored,
        group,
        &surface_content(carrier, group_epoch)?,
    )?;
    let outcome = account.client.account_db()?.surface_transaction(|| {
        let outcome =
            account.client.stage_surface_outgoing_as(carrier, group_epoch, &authored.message_id)?;
        if outcome.accepted {
            account.client.project_authored_message(&authored, &prepared.exact, &[])?;
            account.client.account_db()?.persist_message_actor_state(
                &authored.message_id,
                &format!(
                    "surface/generated-alias/{}",
                    RamfluxClient::surface_timeline_id(carrier)?
                ),
                &authored.message_id,
            )?;
        }
        Ok::<_, SdkError>(outcome)
    })?;
    if !outcome.accepted {
        return Ok(serde_json::to_value(outcome)?);
    }
    let mut devices = Vec::new();
    let mut failure = None;
    if let Some(group) = group {
        let request = LocalBusFrame::request(
            "surface-group",
            None,
            "ramflux.sdk.v1",
            "group.send",
            json!({"group_id":group,"conversation_id":carrier.conversation_id,"message_id":RamfluxClient::surface_timeline_id(carrier)?,"sender_id":carrier.sender_device_id,"content":surface_content(carrier, group_epoch)?,"encrypted_body_base64":""}),
        );
        if let Err(error) =
            Box::pin(super::group::dispatch_group_send_request(&request, account)).await
        {
            failure = Some(error);
        }
    } else {
        (devices, failure) = Box::pin(send_direct(account, carrier, &thread, &bytes)).await?;
    }
    let delivery = if failure.is_some() { "failed" } else { "submitted" };
    account.client.set_surface_outgoing_state(carrier, delivery)?;
    account.client.set_surface_delivery_devices(carrier, &devices)?;
    #[cfg(test)]
    let own = copy_own_for_test(account, carrier, group_epoch).await;
    #[cfg(not(test))]
    let own = copy_own(account, carrier, group_epoch);
    let own_state = finish_own(account, carrier, own)?;
    if let Some(error) = failure {
        return Err(error);
    }
    let mut response = serde_json::to_value(outcome)?;
    response["surface_id"] = json!(carrier.surface_id);
    response["surface_ref"] = json!(carrier.surface_reference()?);
    response["message_id"] = json!(authored.message_id);
    response["delivery_state"] = json!(delivery);
    response["delivery_devices"] = json!(devices);
    response["own_device_copy_state"] = json!(own_state);
    Ok(response)
}
async fn send_direct(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
    thread: &Value,
    _bytes: &[u8],
) -> Result<(Vec<Value>, Option<SdkError>), SdkError> {
    let mut devices = Vec::new();
    let mut failure = None;
    for (root, principal) in peer_commitments(account, carrier, thread)? {
        let engine = account.session_client().await?;
        let manifest = account
            .client
            .cache_verified_device_manifest(engine.config(), &root, "surface_peer")
            .await;
        account.apply_session_metadata(engine);
        let manifest = match manifest {
            Ok(manifest)
                if !manifest.devices.is_empty()
                    && principal
                        .as_ref()
                        .is_none_or(|principal| *principal == manifest.principal_id) =>
            {
                manifest
            }
            Ok(_) => {
                devices
                    .push(json!({"root":root,"state":"failed","error":"peer_manifest_mismatch"}));
                failure.get_or_insert_with(|| invalid("surface peer manifest mismatch"));
                continue;
            }
            Err(error) => {
                devices.push(
                    json!({"root":root,"state":"failed","error":"peer_manifest_unavailable"}),
                );
                failure.get_or_insert(error);
                continue;
            }
        };
        for device in manifest.devices {
            let id = device.device_id.clone();
            let body: LocalBusMessageSubmitRequest = serde_json::from_value(
                json!({"conversation_id":carrier.conversation_id,"message_id":RamfluxClient::surface_timeline_id(carrier)?,"envelope_id":crate::new_surface_message_id()?,"source_principal_id":carrier.sender_principal_id,"sender_id":carrier.sender_device_id,"recipient_device_id":id,"recipient_principal_commitment":root,"target_delivery_id":device.target_delivery_id,"content":surface_content(carrier, None)?,"encrypted_body_base64":"","created_at":now_unix_timestamp(),"ttl":account.client.content_ttl()?}),
            )?;
            match super::message::submit_message(account, body).await {
                Ok(_) => devices.push(json!({"root":root,"device_id":id,"state":"submitted"})),
                Err(error) => {
                    devices.push(json!({"root":root,"device_id":id,"state":"failed","error":"delivery_failed"}));
                    failure.get_or_insert(error);
                }
            }
        }
    }
    Ok((devices, failure))
}
async fn prepare_direct_target(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
    thread: &Value,
    authored: &mut GatewayDirectMessage,
) -> Result<(), SdkError> {
    let root = peer_commitments(account, carrier, thread)?
        .into_keys()
        .next()
        .ok_or_else(|| invalid("surface direct peer missing"))?;
    let engine = account.session_client().await?;
    let manifest = account
        .client
        .cache_verified_device_manifest(engine.config(), &root, "surface_prepare")
        .await;
    account.apply_session_metadata(engine);
    let manifest = manifest?;
    let target =
        manifest.devices.first().ok_or_else(|| invalid("surface peer has no active device"))?;
    authored.recipient_principal_commitment = Some(root);
    authored.recipient_device_id = Some(target.device_id.clone());
    authored.target_delivery_id.clone_from(&target.target_delivery_id);
    Ok(())
}

fn copy_own(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
    epoch: Option<u64>,
) -> Result<String, SdkError> {
    if !account.client.queue_surface_own_copy(carrier, epoch)? {
        return Ok("failed".into());
    }
    if let Some(handle) = &account.connection {
        handle.wake_couriers();
    }

    super::super::own_device_copy::status(
        &account.client,
        &account.client.surface_generated_message_id(carrier)?,
    )
}

pub(super) async fn submit_pair_control(
    client: &RamfluxClient,
    engine: &mut impl GatewaySessionAccess,
    mut message: GatewayDirectMessage,
    body: &[u8],
    group: Option<&str>,
) -> Result<(), SdkError> {
    use prost::Message as _;
    use ramflux_protocol::message as g;
    g::validation::scan_message("Surface", body, g::registry::COMPILED_LAYER)
        .map_err(|_| invalid("invalid Surface control"))?;
    let surface = g::Surface::decode(body).map_err(|_| invalid("invalid Surface control"))?;
    let requested_group = match surface.payload.as_ref() {
        Some(g::surface::Payload::ResyncRequest(request)) => request.group.clone(),
        _ => None,
    };
    let group = group.or(requested_group.as_deref());
    let prepared = client.prepare_authored_content(
        &mut message,
        group,
        &g::Content { value: Some(g::content::Value::Surface(surface)) },
    )?;
    let route = crate::client::routed::Route::from_inner(&prepared.wire)?;
    let sealed = client.seal_routed_as(engine, &message, &prepared.wire, route).await?;
    // Pair control has no Direct report payload; into_parts still carries committed_a0 (None).
    engine
        .submit_envelope(gateway_envelope_from_sealed(engine.config(), &mut message, sealed, None)?)
        .await?;
    Ok(())
}

fn peer_commitments(
    account: &LocalBusAccountState,
    carrier: &Carrier,
    thread: &Value,
) -> Result<BTreeMap<String, Option<String>>, SdkError> {
    let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let participants = thread["participants"]
        .as_array()
        .ok_or_else(|| invalid("surface direct participants absent"))?;
    if thread["kind"] != "direct" || !participants.iter().any(|id| id == &local.principal_id) {
        return Err(invalid("surface direct membership mismatch"));
    }
    let peers = if carrier.payload_kind == PayloadKind::Action {
        vec![carrier.author_principal_id.as_str()]
    } else {
        participants
            .iter()
            .filter_map(Value::as_str)
            .filter(|id| *id != local.principal_id)
            .collect()
    };
    if peers.len() != 1 {
        return Err(invalid("surface direct peer is ambiguous"));
    }
    let mut roots = BTreeMap::new();
    for peer in peers {
        let identity = account
            .client
            .account_db()?
            .client_record("identity", peer)?
            .ok_or_else(|| invalid("surface peer identity missing"))?;
        let root = identity["contact_identity_commitment"]
            .as_str()
            .ok_or_else(|| invalid("surface peer root missing"))?;
        roots.insert(root.into(), Some(peer.into()));
    }
    Ok(roots)
}

#[cfg(test)]
#[path = "surface_text_fixture.rs"]
pub(crate) mod fixture;
#[cfg(test)]
#[path = "surface_text_tests.rs"]
pub(super) mod tests;

#[cfg(test)]
#[path = "surface_dm_tests.rs"]
mod dm_tests;

#[cfg(test)]
#[path = "surface_own_tests.rs"]
pub(crate) mod own_tests;

#[cfg(test)]
#[path = "surface_resync_tests.rs"]
mod resync_tests;

#[cfg(test)]
#[path = "surface_history_import_tests.rs"]
mod history_import_tests;

#[cfg(test)]
#[path = "surface_group_membership_tests.rs"]
mod membership_tests;

#[cfg(test)]
#[path = "shared_group_transport_tests.rs"]
mod shared_group_transport_tests;

#[cfg(test)]
#[path = "shared_group_federation_tests.rs"]
mod shared_group_federation_tests;

#[cfg(test)]
#[path = "shared_group_sibling_tests.rs"]
mod shared_group_sibling_tests;

#[cfg(test)]
#[path = "shared_group_beacon_tests.rs"]
mod shared_group_beacon_tests;

#[cfg(test)]
#[path = "shared_group_refusal_tests.rs"]
mod shared_group_refusal_tests;
#[cfg(test)]
#[path = "shared_group_request_tests.rs"]
mod shared_group_request_tests;

#[cfg(test)]
#[path = "shared_group_consent_tests.rs"]
mod shared_group_consent_tests;

#[cfg(test)]
#[path = "group/route_tests.rs"]
mod group_route_tests;

#[cfg(test)]
#[path = "own_sent_message_tests.rs"]
mod own_sent_message_tests;

#[cfg(test)]
#[path = "own_sent_availability_tests.rs"]
mod own_sent_availability_tests;

#[cfg(test)]
async fn copy_own_for_test(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
    epoch: Option<u64>,
) -> Result<String, SdkError> {
    copy_own(account, carrier, epoch)?;
    super::super::own_device_copy::flush(account).await?;
    super::super::own_device_copy::status(
        &account.client,
        &account.client.surface_generated_message_id(carrier)?,
    )
}

async fn send_private(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
) -> Result<Value, SdkError> {
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &carrier.conversation_id)?
        .ok_or_else(|| invalid("surface conversation missing"))?;
    let group = thread.get("group_id").and_then(Value::as_str);
    let epoch = group.map(|g| account.client.group_state(g).map(|s| s.group_epoch)).transpose()?;
    let outcome = account.client.stage_surface_outgoing_as(carrier, epoch, &carrier.message_id)?;
    if !outcome.accepted {
        return Ok(serde_json::to_value(outcome)?);
    }
    let root = if carrier.payload_kind == PayloadKind::FunctionCall {
        account
            .client
            .born_v3_account
            .as_ref()
            .and_then(|a| a.record().body.profile.custodian.as_ref())
            .map(|c| c.account_anchor.clone())
            .ok_or_else(|| invalid("agent RPC requires its verified human custodian"))?
    } else {
        account
            .client
            .account_db()?
            .client_record("identity", &carrier.author_principal_id)?
            .and_then(|v| {
                v.get("contact_identity_commitment").and_then(Value::as_str).map(str::to_owned)
            })
            .ok_or_else(|| invalid("surface author identity missing"))?
    };
    let mut engine = account.session_client().await?;
    let result =
        send_private_to_manifest(&account.client, &mut engine, carrier, &root, group).await;
    account.apply_session_metadata(engine);
    let delivery = if result.is_ok() { "submitted" } else { "failed" };
    if carrier.payload_kind == PayloadKind::Action {
        account.client.set_surface_outgoing_state(carrier, delivery)?;
    }
    result?;
    let mut response = serde_json::to_value(outcome)?;
    if let Some(object) = response.as_object_mut() {
        object.insert("delivery_state".into(), json!(delivery));
        object.insert("message_id".into(), json!(carrier.message_id));
    }
    Ok(response)
}

async fn send_private_to_manifest(
    client: &RamfluxClient,
    engine: &mut impl GatewaySessionAccess,
    carrier: &Carrier,
    root: &str,
    group: Option<&str>,
) -> Result<(), SdkError> {
    crate::client::surface::check_delivery_size(carrier.bytes()?.len())?;
    let epoch = group.map(|g| client.group_state(g).map(|s| s.group_epoch)).transpose()?;
    let manifest =
        client.cache_verified_device_manifest(engine.config(), root, "surface_peer").await?;
    let control = client
        .surface_control_packet(carrier, crate::client::surface::ControlKind::Peer, epoch)?
        .bytes()?;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let mut sent = 0usize;
    for device in manifest.devices {
        if let Some(group) = group {
            let identity = client.device_identity_for_root(root, &device.device_id)?;
            if !client.surface_group_device_allowed(group, &identity)? {
                return Err(invalid("surface private destination is outside the group"));
            }
        }
        let message = GatewayDirectMessage {
            conversation_id: carrier.conversation_id.clone(),
            message_id: carrier.message_id.clone(),
            envelope_id: crate::new_surface_message_id()?,
            source_principal_id: local.principal_id.clone(),
            sender_id: local.device_id.clone(),
            recipient_device_id: Some(device.device_id),
            recipient_principal_commitment: Some(root.to_owned()),
            target_delivery_id: device.target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: client.content_ttl()?,
        };
        submit_pair_control(client, engine, message, &control, group).await?;
        sent += 1;
    }
    if sent == 0 {
        return Err(invalid("surface private destination has no active devices"));
    }
    Ok(())
}

fn surface_content(
    carrier: &Carrier,
    epoch: Option<u64>,
) -> Result<ramflux_protocol::message::Content, SdkError> {
    use ramflux_protocol::message as g;
    Ok(g::Content {
        value: Some(g::content::Value::Surface(g::Surface {
            payload: Some(g::surface::Payload::Delivery(g::SurfaceDelivery {
                kind: Some(g::SurfaceControlKind {
                    value: Some(g::surface_control_kind::Value::Peer(g::SurfaceControlKindPeer {})),
                }),
                carrier: Some(carrier.to_generated()?),
                group_epoch: epoch,
                context: None,
                manifests: Vec::new(),
            })),
        })),
    })
}

fn finish_own(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
    own: Result<String, SdkError>,
) -> Result<String, SdkError> {
    match own {
        Ok(state) => Ok(state),
        Err(error) => {
            tracing::warn!(%error,"surface own-device copy could not be staged");
            account.client.set_surface_own_copy_state(carrier, "failed")?;
            Ok("failed".into())
        }
    }
}
