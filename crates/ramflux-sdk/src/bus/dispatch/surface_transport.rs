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
    let outcome = account.client.stage_surface_outgoing(carrier, group_epoch)?;
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
            json!({"group_id":group,"conversation_id":carrier.conversation_id,"message_id":RamfluxClient::surface_timeline_id(carrier)?,"sender_id":carrier.sender_device_id,"plaintext_body_base64":ramflux_protocol::encode_base64url(&bytes),"encrypted_body_base64":""}),
        );
        if let Err(error) = super::group::dispatch_group_send_request(&request, account).await {
            failure = Some(error);
        }
    } else {
        (devices, failure) = send_direct(account, carrier, &thread, &bytes).await?;
    }
    let delivery = if failure.is_some() { "failed" } else { "submitted" };
    account.client.set_surface_outgoing_state(carrier, delivery)?;
    account.client.set_surface_delivery_devices(carrier, &devices)?;
    #[cfg(test)]
    let own = copy_own_for_test(account, carrier, group_epoch).await;
    #[cfg(not(test))]
    let own = copy_own(account, carrier, group_epoch);
    let own_state = match own {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(%error,"surface own-device copy could not be staged");
            account.client.set_surface_own_copy_state(carrier, "failed")?;
            "failed".into()
        }
    };
    if let Some(error) = failure {
        return Err(error);
    }
    let mut response = serde_json::to_value(outcome)?;
    response["surface_id"] = json!(carrier.surface_id);
    response["surface_ref"] = json!(carrier.surface_reference()?);
    response["message_id"] = json!(carrier.message_id);
    response["delivery_state"] = json!(delivery);
    response["delivery_devices"] = json!(devices);
    response["own_device_copy_state"] = json!(own_state);
    Ok(response)
}
async fn send_direct(
    account: &mut LocalBusAccountState,
    carrier: &Carrier,
    thread: &Value,
    bytes: &[u8],
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
                json!({"conversation_id":carrier.conversation_id,"message_id":RamfluxClient::surface_timeline_id(carrier)?,"envelope_id":crate::new_surface_message_id()?,"source_principal_id":carrier.sender_principal_id,"sender_id":carrier.sender_device_id,"recipient_device_id":id,"recipient_principal_commitment":root,"target_delivery_id":device.target_delivery_id,"plaintext_body_base64":ramflux_protocol::encode_base64url(bytes),"encrypted_body_base64":"","created_at":now_unix_timestamp(),"ttl":account.client.content_ttl()?}),
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
        &RamfluxClient::surface_timeline_id(carrier)?,
    )
}

pub(super) async fn submit_pair_control(
    client: &RamfluxClient,
    engine: &mut impl GatewaySessionAccess,
    mut message: GatewayDirectMessage,
    body: &[u8],
    group: Option<&str>,
) -> Result<(), SdkError> {
    let mut route = crate::client::routed::Route::control();
    route.group_id = group.map(str::to_owned);
    let packet = client.seal_routed_as(engine, &message, body, route).await?;
    message.encrypted_body = serde_json::to_vec(&packet)?;
    engine
        .submit_envelope(gateway_direct_message_envelope(engine.config(), &message, None)?)
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
pub(in crate::bus) mod fixture;
#[cfg(test)]
#[path = "surface_text_tests.rs"]
pub(super) mod tests;

#[cfg(test)]
#[path = "surface_dm_tests.rs"]
mod dm_tests;

#[cfg(test)]
#[path = "surface_own_tests.rs"]
mod own_tests;

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
        &RamfluxClient::surface_timeline_id(carrier)?,
    )
}
