// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned call RPCs and bounded pair-control delivery, without a parallel scheduler.
use crate::client::call::state::LiveCall;
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
    if request.method != "call.list" {
        let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(
            &state.config.data_root,
            account_id,
        ))?;
        if manifest.client_mode != LocalBusClientMode::AttendedCli
            || manifest.kind.as_deref().unwrap_or("human") != "human"
        {
            return Err(SdkError::CapabilityDenied(
                "voice calls require an attended human account".into(),
            ));
        }
    }
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
        return media(account, id, request.body["counter_lease_v1"].as_bool() == Some(true));
    }
    let _: LocalBusCallHangupRequest = serde_json::from_value(request.body.clone())?;
    let mut next =
        account.client.voice_calls.get(id).cloned().ok_or_else(|| invalid("call not live"))?;
    match request.method.as_str() {
        "call.answer" => next.answer(now)?,
        "call.reject" => next.end(true, now)?,
        "call.hangup" => next.end(false, now)?,
        _ => return Err(invalid("unknown call method")),
    }
    account
        .client
        .account_db()?
        .write_transaction(|| account.client.persist_call_row(&next.row))?;
    let row = next.row.clone();
    account.client.voice_calls.insert(id.into(), next);
    if drive(account).await.is_err() {
        tracing::warn!("call signaling queued for retry");
    }
    Ok(local_bus_ok(serde_json::to_value(row)?))
}
async fn invite(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
    now: i64,
) -> Result<LocalBusDispatchResult, SdkError> {
    if account.client.voice_calls.values().any(|c| c.row.state != "ended") {
        return Err(invalid("account busy"));
    }
    let _: LocalBusCallInviteRequest = serde_json::from_value(request.body.clone())?;
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
    let manifest = account
        .client
        .account_db()?
        .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
            "identity/manifest/{peer}"
        ))?
        .ok_or_else(|| invalid("peer root missing"))?;
    let invited = targets
        .iter()
        .map(|t| CallEndpoint {
            principal_id: peer.into(),
            root_public_key: manifest.root_public_key.clone(),
            device_id: t.device.clone(),
        })
        .collect();
    let id = ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..16]);
    let mut call = LiveCall::outgoing(
        id.clone(),
        conversation.into(),
        account.client.call_local_endpoint()?,
        invited,
        now,
    )?;
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
    account
        .client
        .account_db()?
        .write_transaction(|| account.client.persist_call_row(&call.row))?;
    let row = call.row.clone();
    account.client.voice_calls.insert(id, call);
    if drive(account).await.is_err() {
        tracing::warn!("call signaling queued for retry");
    }
    Ok(local_bus_ok(serde_json::to_value(row)?))
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
fn media(
    account: &mut LocalBusAccountState,
    id: &str,
    supports_counter_lease: bool,
) -> Result<LocalBusDispatchResult, SdkError> {
    let c =
        account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("media keys unavailable"))?;
    if c.row.state != "active" || (c.media_taken && (!supports_counter_lease || !c.media_leased)) {
        return Err(invalid(
            "media session unavailable; start a fresh call before restarting the media engine",
        ));
    }
    let allocation = c.allocation.as_ref().ok_or_else(|| invalid("allocation unavailable"))?;
    let receive = c.receive_key.as_ref().ok_or_else(|| invalid("receive key unavailable"))?;
    let outgoing = c.local == c.caller;
    let counter_start = c.media_counter;
    let next_counter = counter_start
        .checked_add(1 << 32)
        .ok_or_else(|| invalid("media counter leases exhausted"))?;
    let value = json!({"relay":{"endpoint":allocation.endpoint,"token":if outgoing {&allocation.caller_token}else{&allocation.callee_token}},
        "sframe":{"cipher_suite":5,"send":{"kid":u64::from(!outgoing),"counter_start":counter_start,"counter_end":next_counter-1,"base_key":ramflux_protocol::encode_base64url(c.send_key.as_ref())},
        "receive":{"kid":u64::from(outgoing),"base_key":ramflux_protocol::encode_base64url(receive.as_ref())}}});
    // This contract's client always restarts at counter zero. Never return a used key twice.
    c.media_taken = true;
    c.media_leased = supports_counter_lease;
    c.media_counter = next_counter;
    Ok(local_bus_ok(value))
}
#[path = "call_driver.rs"]
mod driver;
pub(crate) use driver::{drive, expire_due};

pub(crate) fn list(client: &RamfluxClient) -> Result<Value, SdkError> {
    let mut rows = client.account_db()?.voice_call_rows(false)?;
    rows.sort_by_key(|r| std::cmp::Reverse((r.created_at, r.call_id.clone())));
    Ok(json!({"calls":rows}))
}

#[cfg(test)]
#[path = "call_tests.rs"]
mod tests;
