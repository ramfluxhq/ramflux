// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned call RPCs and bounded pair-control delivery, without a parallel scheduler.
#[cfg(feature = "test-support")]
pub use driver::lease_outcome::VoiceAdmissionProbe;

use crate::client::call::state::LiveCall;
use crate::client::identity_authority::NativeOperation;
use crate::prelude::*;
use ramflux_protocol::CallEndpoint;
use serde_json::{Value, json};
fn invalid(message: &str) -> SdkError {
    SdkError::LocalBus(format!("voice call: {message}"))
}
fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str, SdkError> {
    body[key]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 512)
        .ok_or_else(|| invalid("missing call argument"))
}
pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account_mut(state, account_id)?;
    recover(account)?;
    let now = now_unix_timestamp();
    if request.method == "call.list" {
        return Ok(local_bus_ok(list(&account.client)?));
    }
    if request.method == "call.invite" {
        return invite(account, request, now).await;
    }
    let id = required(&request.body, "call_id")?;
    if request.method == "call.media.session" {
        let _: LocalBusCallHangupRequest = serde_json::from_value(request.body.clone())?;
        return media(account, id);
    }
    let _: LocalBusCallHangupRequest = serde_json::from_value(request.body.clone())?;
    if request.method == "call.answer" {
        account.client.reserve_call_audio(id)?;
    }
    let mut next =
        account.client.voice_calls.get(id).cloned().ok_or_else(|| invalid("call not live"))?;
    match request.method.as_str() {
        "call.answer"
            if next.media_held
                && next.local == next.callee
                && next.row.state == "incoming_ringing"
                && !next.expired(now) =>
        {
            next.request_answer();
        }
        "call.answer" => next.answer(now)?,
        "call.reject" => next.end(true, now)?,
        "call.hangup" => next.end(false, now)?,
        _ => return Err(invalid("unknown call method")),
    }
    account.client.account_db()?.write_transaction(|| account.client.persist_live_call(&next))?;
    let row = next.row.clone();
    account.client.voice_calls.insert(id.into(), next);
    crate::bus::media::reconcile(account);
    if let Some(handle) = &account.connection {
        handle.wake_couriers();
    }
    #[cfg(test)]
    if drive(account).await.is_err() {
        tracing::warn!("call signaling queued for retry");
    }
    Ok(local_bus_ok(serde_json::to_value(row)?))
}
async fn require_call_agent_operable(account: &LocalBusAccountState) -> Result<(), SdkError> {
    crate::bus::couriers::primary::call_agent_fence(account).await
}

async fn invite(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
    now: i64,
) -> Result<LocalBusDispatchResult, SdkError> {
    require_call_agent_operable(account).await?;
    if account.client.voice_calls.values().any(|c| c.row.state != "ended") {
        return Err(invalid("account busy"));
    }
    let _: LocalBusCallInviteRequest = serde_json::from_value(request.body.clone())?;
    if live_session_lacks_call_resolution(account) {
        return Err(SdkError::CapabilityDenied(
            "voice calls are unavailable: the home node did not negotiate call resolution".into(),
        ));
    }
    let conversation = required(&request.body, "conversation_id")?;
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", conversation)?
        .ok_or_else(|| invalid("conversation missing"))?;
    let config = account.gateway_config.clone();
    let targets = super::task_transport::direct_targets(account, &config, &thread).await?;
    let peer = thread["participants"]
        .as_array()
        .and_then(|p| {
            p.iter().filter_map(Value::as_str).find(|p| *p != account.gateway_config.principal_id)
        })
        .ok_or_else(|| invalid("direct peer missing"))?;
    let target = targets.first().ok_or_else(|| invalid("call target absent"))?;
    let root = target.identity.root_commitment();
    let manifest = account
        .client
        .account_db()?
        .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
            "identity/manifest-root/{root}"
        ))?
        .ok_or_else(|| invalid("peer root missing"))?;
    if targets.iter().any(|target| target.identity.root_commitment() != root)
        || manifest.principal_id != peer
    {
        return Err(invalid("call peer root mismatch"));
    }
    let invited = targets
        .iter()
        .map(|t| CallEndpoint {
            principal_id: peer.into(),
            root_public_key: manifest.root_public_key.clone(),
            device_id: t.device.clone(),
        })
        .collect();
    let id = new_call_id()?;
    account.client.reserve_call_audio(&id)?;
    let mut call = LiveCall::outgoing(
        id.clone(),
        conversation.into(),
        account.client.call_local_endpoint()?,
        invited,
        now,
    )?;
    call.media_held = true;
    for target in call.invited.clone() {
        let key = manifest
            .devices
            .iter()
            .find(|d| d.device_id == target.device_id)
            .ok_or_else(|| invalid("callee device absent"))?
            .branch_public_key
            .clone();
        call.pin_peer(target, key)?;
    }
    account.client.account_db()?.write_transaction(|| account.client.persist_live_call(&call))?;
    let row = call.row.clone();
    account.client.voice_calls.insert(id, call);
    if let Some(handle) = &account.connection {
        handle.wake_couriers();
    }
    #[cfg(test)]
    if drive(account).await.is_err() {
        tracing::warn!("call signaling queued for retry");
    }
    Ok(local_bus_ok(serde_json::to_value(row)?))
}

/// A live session whose gateway granted no call-resolution generation cannot submit any call
/// control. Without a live current session the background signaling pass decides instead.
fn live_session_lacks_call_resolution(account: &LocalBusAccountState) -> bool {
    account.connection.as_ref().is_some_and(|handle| {
        let snapshot = handle.snapshot();
        handle.metadata().is_some_and(|metadata| {
            snapshot.state == crate::bus::connection_manager::NetworkingState::Live
                && metadata.generation == snapshot.generation
                && metadata.session.call_session_generation.is_none()
        })
    })
}

pub(crate) fn recover(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    // Media keys are never recovered from storage: restarting cannot reset an old key's nonce.
    let db = account.client.account_db()?;
    for row in db.voice_call_rows(true)? {
        if !account.client.voice_calls.contains_key(&row.call_id) {
            account.client.retire_call_without_keys(&row.call_id)?;
        }
    }
    Ok(())
}
fn media(account: &mut LocalBusAccountState, id: &str) -> Result<LocalBusDispatchResult, SdkError> {
    // In-process ownership refuses generic export before admission work, key
    // reads, JSON, or the one-shot cache. Direct and compatibility dispatch
    // both reach this function, including a socket that skipped the C ABI.
    if account.client.media_ownership == crate::bus::protocol::MediaOwnership::InProcess {
        return Err(SdkError::LocalBusPermissionDenied);
    }
    account.client.require_native_operation(
        &account.client.owned_device_identity()?,
        NativeOperation::Call,
    )?;
    let c =
        account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("media keys unavailable"))?;
    if c.media_held {
        return Err(invalid("call resolution missing"));
    }
    if c.row.state != "active" || c.media_taken {
        return Err(invalid(
            "media session unavailable; start a fresh call before restarting the media engine",
        ));
    }
    let allocation = c.allocation.as_ref().ok_or_else(|| invalid("allocation unavailable"))?;
    let receive = c.receive_key.as_ref().ok_or_else(|| invalid("receive key unavailable"))?;
    let outgoing = c.local == c.caller;
    let value = json!({"relay":{"endpoint":allocation.endpoint,"token":allocation.token,"rebind_key":allocation.rebind_key,"lease_id":allocation.lease_id,"side":allocation.side},
        "sframe":{"cipher_suite":5,"send":{"kid":u64::from(!outgoing),"base_key":ramflux_protocol::encode_base64url(c.send_key.as_ref())},
        "receive":{"kid":u64::from(outgoing),"base_key":ramflux_protocol::encode_base64url(receive.as_ref())}}});
    // This contract's client always restarts at counter zero. Never return a used key twice.
    c.media_taken = true;
    Ok(local_bus_ok(value))
}
#[path = "call_driver.rs"]
mod driver;
pub(crate) use driver::background::pass as signaling_pass;
#[cfg(test)]
pub(crate) use driver::drive;
pub(crate) use driver::expire_due;

pub(crate) fn list(client: &RamfluxClient) -> Result<Value, SdkError> {
    let live = client.account_db()?.voice_call_rows(true)?;
    let mut calls = crate::client::call::history::listed(client, &live)?;
    calls.sort_by(|left, right| stamp(right).cmp(&stamp(left)));
    Ok(json!({"calls": calls}))
}

fn stamp(row: &Value) -> (i64, &str) {
    (
        row.get("created_at").and_then(Value::as_i64).unwrap_or(0),
        row.get("call_id").and_then(Value::as_str).unwrap_or(""),
    )
}

#[cfg(test)]
#[path = "call_tests.rs"]
pub(super) mod tests;

fn new_call_id() -> Result<String, SdkError> {
    loop {
        let id = ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..16]);
        if !id.starts_with('-') {
            return Ok(id);
        }
    }
}
