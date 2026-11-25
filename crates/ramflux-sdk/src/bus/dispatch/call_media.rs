// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public `call.media.*` controls. They run on the account writer, which owns the engine
//! and the SDK authority; the host supplies only the closed bodies below.

use crate::bus::media::{MediaCommand, apply};
use crate::bus::protocol::MediaOwnership;
use crate::client::call::media_contract::{
    ActiveBody, MutedBody, OpenBody, RouteBody, TokenBody, media_view,
};
use crate::client::call::media_owner::OwnedMedia;
use crate::client::call::pcm_bridge::{self, PcmCapture, PcmPlayback};
use crate::client::identity_authority::NativeOperation;
use crate::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn invalid(message: &str) -> SdkError {
    SdkError::LocalBus(format!("voice call: {message}"))
}

fn parse<T: DeserializeOwned>(body: &Value) -> Result<T, SdkError> {
    serde_json::from_value(body.clone()).map_err(|_| invalid("media body"))
}

/// Entry for every `call.media.*` method. Refuses unless this process owns in-process media.
pub(super) fn dispatch(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    if account.client.media_ownership != MediaOwnership::InProcess {
        return Err(SdkError::LocalBusPermissionDenied);
    }
    account.client.require_native_operation(
        &account.client.owned_device_identity()?,
        NativeOperation::Call,
    )?;
    let value = match request.method.as_str() {
        "call.media.open" => open(account, &parse(&request.body)?)?,
        "call.media.status" => status(account, parse::<TokenBody>(&request.body)?.media_token)?,
        "call.media.set_muted" => set_muted(account, &parse(&request.body)?)?,
        "call.media.audio_active" => audio_active(account, &parse(&request.body)?)?,
        "call.media.audio_route" => audio_route(account, &parse(&request.body)?)?,
        "call.media.close" => close(account, parse::<TokenBody>(&request.body)?.media_token)?,
        _ => return Err(invalid("unknown media method")),
    };
    Ok(local_bus_ok(value))
}

/// Open the one in-process session. Re-reading an already admitted open for this call returns
/// its current view without a second take or engine; otherwise the sequence is checked first.
fn open(account: &mut LocalBusAccountState, body: &OpenBody) -> Result<Value, SdkError> {
    if let Some(owned) = account
        .client
        .in_process_media
        .as_deref()
        .filter(|owned| owned.receipt.call_id == body.call_id)
    {
        let token = owned.token();
        return view(account, token, &body.call_id);
    }
    let call =
        account.client.voice_calls.get(&body.call_id).ok_or_else(|| invalid("call not live"))?;
    if call.row.seq != body.expected_seq {
        return Err(SdkError::EditConflict {
            target: body.call_id.clone(),
            expected: body.expected_seq,
            received: call.row.seq,
        });
    }
    apply(
        account,
        MediaCommand::Open {
            call_id: body.call_id.clone(),
            expected_seq: body.expected_seq,
            capture: Box::new(PcmCapture),
            playback: Box::new(PcmPlayback),
        },
    )?;
    let token = owned_by_call(account, &body.call_id)?.token();
    view(account, token, &body.call_id)
}

fn owned_by_call<'a>(
    account: &'a LocalBusAccountState,
    call_id: &str,
) -> Result<&'a OwnedMedia, SdkError> {
    account
        .client
        .in_process_media
        .as_deref()
        .filter(|owned| owned.receipt.call_id == call_id)
        .ok_or_else(|| invalid("media session unavailable"))
}

/// Resolve a token to its owned session, if this writer still holds it.
fn owned_by_token(account: &LocalBusAccountState, token: u64) -> Result<&OwnedMedia, SdkError> {
    account.client.media_by_token(token).ok_or_else(|| invalid("media session unavailable"))
}

/// Resolve the token and check the I/O generation against the engine's current fence.
fn binding(
    account: &LocalBusAccountState,
    token: u64,
    io_generation: u64,
) -> Result<String, SdkError> {
    let call_id = owned_by_token(account, token)?.receipt.call_id.clone();
    let current = account.client.in_process_media_status(&call_id)?;
    if io_generation != current.gate.generation {
        return Err(invalid("stale io generation"));
    }
    Ok(call_id)
}

fn view(account: &LocalBusAccountState, token: u64, call_id: &str) -> Result<Value, SdkError> {
    let owned = owned_by_token(account, token)?;
    let status = account.client.in_process_media_status(call_id)?;
    let seq = account.client.voice_calls.get(call_id).map_or(0, |call| call.row.seq);
    Ok(media_view(&status, token, seq, owned.host_state()))
}

/// Journal the `M` row now (controls and close). Stats-only changes go through `observe`.
fn finish(account: &LocalBusAccountState, token: u64, call_id: &str) -> Result<Value, SdkError> {
    owned_by_token(account, token)?;
    account.client.flush_media_journal(true)?;
    view(account, token, call_id)
}

/// Status read. Journals the row if it is due (a control change at once, stats at most once per
/// interval) and returns the current counters either way; the media tick journals a stats change
/// whose window closed without a further read.
fn observe(account: &LocalBusAccountState, token: u64, call_id: &str) -> Result<Value, SdkError> {
    owned_by_token(account, token)?;
    account.client.flush_media_journal(false)?;
    view(account, token, call_id)
}

fn status(account: &mut LocalBusAccountState, token: u64) -> Result<Value, SdkError> {
    let call_id = owned_by_token(account, token)?.receipt.call_id.clone();
    apply(account, MediaCommand::Status { call_id: call_id.clone() })?;
    observe(account, token, &call_id)
}

fn set_muted(account: &mut LocalBusAccountState, body: &MutedBody) -> Result<Value, SdkError> {
    let call_id = binding(account, body.media_token, body.io_generation)?;
    let owned = owned_by_token(account, body.media_token)?;
    owned.set_engine_muted(body.muted)?;
    owned.update_host(|host| host.muted = body.muted);
    finish(account, body.media_token, &call_id)
}

fn audio_active(account: &mut LocalBusAccountState, body: &ActiveBody) -> Result<Value, SdkError> {
    let call_id = binding(account, body.media_token, body.io_generation)?;
    if body.active {
        // Host readiness is required to activate, never to grant: the SDK gate decides.
        let owned = owned_by_token(account, body.media_token)?;
        if !owned.host_state().ready_for_audio()
            || !pcm_bridge::fenced(body.media_token, body.io_generation)
        {
            return Err(invalid("audio route or permission not ready"));
        }
    }
    apply(account, MediaCommand::AudioActive { call_id: call_id.clone(), active: body.active })?;
    finish(account, body.media_token, &call_id)
}

/// Records the applied OS route. An accepted change rotates the I/O generation: audio closes,
/// both queues are flushed and the host must read the new generation before it activates.
fn audio_route(account: &mut LocalBusAccountState, body: &RouteBody) -> Result<Value, SdkError> {
    let call_id = binding(account, body.media_token, body.io_generation)?;
    let owned = owned_by_token(account, body.media_token)?;
    if body.route_generation <= owned.host_state().route_generation {
        return Err(invalid("stale route generation"));
    }
    owned.update_host(|host| {
        host.route_generation = body.route_generation;
        host.route = body.route;
        host.aec = body.aec;
        host.permission = body.microphone_permission;
    });
    owned.rotate_io();
    finish(account, body.media_token, &call_id)
}

fn close(account: &mut LocalBusAccountState, token: u64) -> Result<Value, SdkError> {
    let call_id = owned_by_token(account, token)?.receipt.call_id.clone();
    let status = apply(account, MediaCommand::Close { call_id: call_id.clone() })?;
    finish(account, token, &call_id)?;
    if !status.drained {
        return Err(invalid("media drain pending"));
    }
    Ok(json!({"media_token": token.to_string(), "phase": "closed", "drained": true}))
}
