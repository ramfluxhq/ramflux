// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface resync replies consume their durable window before background submission.

use super::{pair_material, writer::Writer};
use crate::bus::connection_manager::SessionContext;
use crate::client::{
    routed::{SendMaterial, SendMaterialRequest},
    surface::ResyncReply,
};
use crate::prelude::*;

struct Plan {
    key: String,
    fingerprint: serde_json::Value,
    reply: ResyncReply,
    config: GatewaySessionConfig,
    message: GatewayDirectMessage,
    body: zeroize::Zeroizing<Vec<u8>>,
    request: SendMaterialRequest,
}
pub(crate) async fn pass(context: SessionContext, writer: Writer) -> Result<bool, SdkError> {
    let Some(mut plan) = writer.apply(prepare).await? else { return Ok(false) };
    let request =
        std::mem::replace(&mut plan.request, SendMaterialRequest { root: None, prekey: None });
    let material = tokio::time::timeout(
        context.network_wait(),
        pair_material::fetch(&context, &plan.config, request),
    )
    .await
    .map_err(|_| SdkError::NetworkingPending)?;
    let Some(envelope) = writer.apply(move |account| seal(account, plan, material)).await? else {
        return Ok(true);
    };
    context
        .call(
            move |engine| {
                Box::pin(async move { engine.submit_envelope(envelope).await.map(|_| ()) })
            },
            context.call_deadline(),
        )
        .await?;
    Ok(true)
}
fn prepare(account: &mut LocalBusAccountState) -> Result<Option<Plan>, SdkError> {
    let client = &account.client;
    client.prune_surface_resync_state()?;
    let db = client.account_db()?;
    let Some(key) = db.actor_state_key_page("surface/resync-response/", 1)?.into_iter().next()
    else {
        return Ok(None);
    };
    let Some(fingerprint) = db.load_actor_state::<serde_json::Value>(&key)? else {
        return Ok(None);
    };
    let reply: ResyncReply = serde_json::from_value(fingerprint.clone())?;
    if reply.destination.expires_at <= now_unix_timestamp() {
        db.remove_actor_state(&key)?;
        return Ok(None);
    }
    client.validate_surface_resync_reply(&reply)?;
    let control = client.surface_control_packet(
        &reply.carrier,
        crate::client::surface::ControlKind::Peer,
        reply.destination.epoch,
    )?;
    let body = zeroize::Zeroizing::new(control.bytes()?);
    let config = account.gateway_config.clone();
    let message = GatewayDirectMessage {
        conversation_id: reply.carrier.conversation_id.clone(),
        message_id: reply.carrier.message_id.clone(),
        envelope_id: crate::new_surface_message_id()?,
        source_principal_id: config.principal_id.clone(),
        sender_id: config.device_id.clone(),
        recipient_device_id: Some(reply.destination.device.clone()),
        recipient_principal_commitment: Some(reply.destination.root.clone()),
        target_delivery_id: reply.destination.target.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 600,
    };
    let request = client.routed_send_material_request(&config, &message)?;
    Ok(Some(Plan { key, fingerprint, reply, config, message, body, request }))
}
fn seal(
    account: &LocalBusAccountState,
    mut plan: Plan,
    material: Result<SendMaterial, SdkError>,
) -> Result<Option<ramflux_protocol::Envelope>, SdkError> {
    let db = account.client.account_db()?;
    if db.load_actor_state::<serde_json::Value>(&plan.key)?.as_ref() != Some(&plan.fingerprint) {
        return Ok(None);
    }
    account.client.validate_surface_resync_reply(&plan.reply)?;
    if plan.reply.destination.expires_at <= now_unix_timestamp() {
        db.remove_actor_state(&plan.key)?;
        return Ok(None);
    }
    // Consuming before the first submit preserves the shared anti-amplification window.
    db.remove_actor_state(&plan.key)?;
    let mut route = crate::client::routed::Route::control();
    route.group_id = plan.reply.destination.group;
    let packet = account.client.seal_routed_prepared(
        &plan.config,
        &plan.message,
        &plan.body,
        route,
        material?,
    )?;
    plan.message.encrypted_body = serde_json::to_vec(&packet)?;
    crate::dm::gateway_direct_message_envelope(&plan.config, &plan.message, None).map(Some)
}
