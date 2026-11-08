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
    request: SendMaterialRequest,
}
pub(crate) async fn pass(context: SessionContext, writer: Writer) -> Result<bool, SdkError> {
    let Some(mut plan) = writer.apply(prepare).await? else { return Ok(false) };
    let request =
        std::mem::replace(&mut plan.request, SendMaterialRequest { root: None, prekey: None });
    let material = tokio::time::timeout(
        context.network_wait(),
        pair_material::fetch(
            &context,
            &plan.config,
            request,
            crate::bus::connection_manager::CallClass::Bulk,
        ),
    )
    .await
    .map_err(|_| SdkError::NetworkingPending)?;
    let Some(envelope) = writer.apply(move |account| seal(account, &plan, material)).await? else {
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
    let config = account.gateway_config.clone();
    let request = client.surface_resync_send_material_request(&config, &reply)?;
    Ok(Some(Plan { key, fingerprint, reply, config, request }))
}
fn seal(
    account: &LocalBusAccountState,
    plan: &Plan,
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
    account.client.seal_surface_resync_reply(&plan.config, &plan.reply, material?).map(Some)
}

#[cfg(test)]
pub(crate) async fn drive_once(account: &mut LocalBusAccountState) -> Result<bool, SdkError> {
    let _ = account.session_client().await?;
    let context = account.connection.as_ref().ok_or(SdkError::NetworkingPending)?.test_context();
    let (sender, mut work) = mpsc::channel(2);
    let pass = pass(context.clone(), Writer::new(sender, context.generation));
    tokio::pin!(pass);
    loop {
        tokio::select! {
            result = &mut pass => return result,
            checkpoint = work.recv() => {
                if let Some(crate::bus::connection_manager::AccountWork::Courier(checkpoint)) = checkpoint {
                    checkpoint.apply(account);
                }
            }
        }
    }
}
