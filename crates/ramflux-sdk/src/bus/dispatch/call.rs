// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned call RPCs and bounded pair-control delivery, without a parallel scheduler.
use crate::client::call::{self, state::LiveCall};
use crate::prelude::*;
use ramflux_protocol::{
    CallEndpoint, VoiceAllocationRequest, VoiceLeaseRequest, VoiceLeaseResponse,
};
use serde_json::{Value, json};
fn invalid(message: &str) -> SdkError {
    SdkError::LocalBus(format!("voice call: {message}"))
}
fn required<'a>(body: &'a Value, key: &str) -> Result<&'a str, SdkError> {
    body[key].as_str().filter(|s| !s.is_empty()).ok_or_else(|| invalid("missing call argument"))
}
pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, request_account_id(request)?)?;
    recover(account)?;
    let now = now_unix_timestamp();
    if request.method == "call.list" {
        let mut rows = account.client.account_db()?.voice_call_rows(false)?;
        rows.sort_by_key(|r| std::cmp::Reverse((r.created_at, r.call_id.clone())));
        rows.truncate(128);
        return Ok(local_bus_ok(json!({"calls":rows})));
    }
    if request.method == "call.invite" {
        if account.client.voice_calls.values().any(|c| c.row.state != "ended") {
            return Err(invalid("account busy"));
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
                p.iter()
                    .filter_map(Value::as_str)
                    .find(|p| *p != account.gateway_config.principal_id)
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
        let call = LiveCall::outgoing(
            id.clone(),
            conversation.into(),
            account.client.call_local_endpoint()?,
            invited,
            now,
        )?;
        account
            .client
            .account_db()?
            .write_transaction(|| account.client.persist_call_row(&call.row))?;
        let row = call.row.clone();
        account.client.voice_calls.insert(id, call);
        drive(account).await?;
        return Ok(local_bus_ok(serde_json::to_value(row)?));
    }
    let id = required(&request.body, "call_id")?;
    if request.method == "call.media.session" {
        return media(account, id, request.body["counter_lease_v1"].as_bool() == Some(true));
    }
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
    drive(account).await?;
    Ok(local_bus_ok(serde_json::to_value(row)?))
}
fn recover(account: &mut LocalBusAccountState) -> Result<(), SdkError> {
    // Media keys are never recovered from storage: restarting cannot reset an old key's nonce.
    let db = account.client.account_db()?;
    for mut row in db.voice_call_rows(true)? {
        if row.state != "ended" && !account.client.voice_calls.contains_key(&row.call_id) {
            row.state = "ended".into();
            row.end_reason = Some("failed".into());
            row.ended_at = Some(now_unix_timestamp());
            row.seq = row.seq.checked_add(1).ok_or_else(|| invalid("sequence exhausted"))?;
            db.write_transaction(|| account.client.persist_call_row(&row))?;
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
    if c.row.state != "active" || (c.media_taken && !supports_counter_lease) {
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
    c.media_counter = next_counter;
    Ok(local_bus_ok(value))
}
fn scope(c: &LiveCall) -> VoiceAllocationRequest {
    VoiceAllocationRequest {
        call_id: c.row.call_id.clone(),
        caller: c.caller.clone(),
        callee: c.callee.clone(),
    }
}
pub(crate) async fn drive(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    recover(account)?;
    let ids = account.client.voice_calls.keys().cloned().collect::<Vec<_>>();
    let mut count = 0;
    for id in ids {
        let mut next =
            account.client.voice_calls.get(&id).cloned().ok_or_else(|| invalid("call vanished"))?;
        let now = now_unix_timestamp();
        next.expire(now)?;
        if next.local == next.caller && next.row.state == "connecting" && next.receive_key.is_some()
        {
            let mut engine = account.take_live_engine().await?;
            let result =
                engine.voice_lease(VoiceLeaseRequest::Allocate { scope: scope(&next) }).await;
            account.put_engine(engine);
            match result {
                Ok(VoiceLeaseResponse::Allocation { allocation }) => {
                    next.activate(allocation, now)?;
                }
                Ok(_) | Err(_) => next.end(false, now)?,
            }
        } else if next.local == next.caller
            && next.row.state == "active"
            && next.next_lease_refresh <= now
        {
            let mut engine = account.take_live_engine().await?;
            let result = engine.voice_lease(VoiceLeaseRequest::Renew { scope: scope(&next) }).await;
            account.put_engine(engine);
            if matches!(result, Ok(VoiceLeaseResponse::Status { .. })) {
                next.next_lease_refresh = now.saturating_add(20);
            } else {
                next.end(false, now)?;
            }
        }
        let old = &account.client.voice_calls[&id].row;
        if next.row != *old {
            account
                .client
                .account_db()?
                .write_transaction(|| account.client.persist_call_row(&next.row))?;
        }
        account.client.voice_calls.insert(id.clone(), next);
        count += flush(account, &id).await?;
    }
    // Public rows are persisted; finished runtime keys and bearer credentials can be destroyed.
    account.client.voice_calls.retain(|_, c| c.row.state != "ended" || !c.pending.is_empty());
    Ok(count)
}
async fn flush(account: &mut LocalBusAccountState, id: &str) -> Result<usize, SdkError> {
    let pending = account.client.voice_calls[id].pending.clone();
    if pending.is_empty() {
        return Ok(0);
    }
    let c = &account.client.voice_calls[id];
    let conversation = c.row.conversation_id.clone();
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &conversation)?
        .ok_or_else(|| invalid("call conversation absent"))?;
    let targets =
        super::task_transport::direct_targets(account, &account.gateway_config, &thread).await?;
    let mut engine = account.take_live_engine().await?;
    let result = async {
        let mut deliveries = Vec::new();
        for mut control in pending {
            let target_device = if control.sender == control.caller {
                &control.callee.device_id
            } else {
                &control.caller.device_id
            };
            let target = targets
                .iter()
                .find(|t| &t.device == target_device)
                .ok_or_else(|| invalid("call target no longer active"))?;
            let local =
                account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            control.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
                &call::signing_bytes(&control)?,
                local,
            );
            let bytes = call::bytes(&control)?;
            deliveries.push(
                super::task_transport::seal(
                    account,
                    &mut engine,
                    target,
                    &conversation,
                    &bytes,
                    crate::client::routed::Route::control(),
                )
                .await?,
            );
        }
        Ok::<_, SdkError>(deliveries)
    }
    .await;
    account.put_engine(engine);
    let deliveries = result?;
    let n = super::super::task_delivery::submit_all(account, deliveries).await?;
    account.client.voice_calls.get_mut(id).ok_or_else(|| invalid("call vanished"))?.pending.clear();
    Ok(n)
}
