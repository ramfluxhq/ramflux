// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One public call summary per call, stored as a generated conversation row.
//! The row carries no media key, lease, signature or control, and writing it does not ring.
use super::state::LiveCall;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use ramflux_protocol::{CallRow, VoiceCallFailureReason};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_RINGING: usize = 96;
const MAX_LISTED: u32 = 128;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct Parties {
    caller_principal_id: String,
    caller_device_id: String,
    callee_principal_id: String,
    ringing_device_ids: Vec<String>,
    answered_device_id: String,
}

fn refused(message: &str) -> SdkError {
    SdkError::InboundRejected(format!("voice call summary: {message}"))
}

fn parties_key(call_id: &str) -> String {
    format!("voice/parties/{call_id}")
}

fn summary_key(call_id: &str) -> String {
    format!("voice/summary-id/{call_id}")
}

fn push_device(devices: &mut Vec<String>, device_id: &str) {
    if device_id.is_empty()
        || devices.iter().any(|old| old == device_id)
        || devices.len() == MAX_RINGING
    {
        return;
    }
    devices.push(device_id.to_owned());
}

fn parties_from_live(call: &LiveCall) -> Parties {
    let mut ringing = Vec::new();
    for peer in &call.invited {
        push_device(&mut ringing, &peer.device_id);
    }
    if call.local != call.caller {
        push_device(&mut ringing, &call.local.device_id);
    }
    let answered_device_id = if call.row.end_reason.as_deref() == Some("completed") {
        if call.local == call.caller {
            call.callee.device_id.clone()
        } else {
            call.local.device_id.clone()
        }
    } else {
        String::new()
    };
    Parties {
        caller_principal_id: call.caller.principal_id.clone(),
        caller_device_id: call.caller.device_id.clone(),
        callee_principal_id: call.callee.principal_id.clone(),
        ringing_device_ids: ringing,
        answered_device_id,
    }
}

fn infer_parties(client: &RamfluxClient, row: &CallRow) -> Result<Parties, SdkError> {
    let device = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    if row.direction == "outgoing" {
        Ok(Parties {
            caller_principal_id: device.principal_id.clone(),
            caller_device_id: device.device_id.clone(),
            callee_principal_id: row.peer_id.clone(),
            ..Parties::default()
        })
    } else {
        Ok(Parties {
            caller_principal_id: row.peer_id.clone(),
            callee_principal_id: device.principal_id.clone(),
            ..Parties::default()
        })
    }
}

fn load_parties(client: &RamfluxClient, row: &CallRow) -> Result<Parties, SdkError> {
    if let Some(saved) = client.account_db()?.load_actor_state(&parties_key(&row.call_id))? {
        return Ok(saved);
    }
    infer_parties(client, row)
}

/// Remember the devices invited for this call. Device ids only; no keys.
/// # Errors
/// Returns storage errors.
pub(crate) fn remember(client: &RamfluxClient, call: &LiveCall) -> Result<(), SdkError> {
    client
        .account_db()?
        .persist_actor_state(&parties_key(&call.row.call_id), &parties_from_live(call))?;
    Ok(())
}

fn outcome_code(reason: Option<&str>) -> i32 {
    let outcome = match reason {
        Some("completed") => g::CallSummaryOutcome::Completed,
        Some("timeout" | "missed") => g::CallSummaryOutcome::Missed,
        Some("declined" | "busy") => g::CallSummaryOutcome::Declined,
        Some("cancelled") => g::CallSummaryOutcome::Cancelled,
        Some("answered_elsewhere") => g::CallSummaryOutcome::AnsweredElsewhere,
        _ => g::CallSummaryOutcome::Failed,
    };
    outcome as i32
}

fn failure_code(reason: Option<VoiceCallFailureReason>) -> i32 {
    let failure = match reason {
        Some(VoiceCallFailureReason::AuthorityUnavailable) => {
            g::CallSummaryFailure::AuthorityUnavailable
        }
        Some(VoiceCallFailureReason::AuthorityRefused) => g::CallSummaryFailure::AuthorityRefused,
        Some(VoiceCallFailureReason::RelayUnavailable) => g::CallSummaryFailure::RelayUnavailable,
        Some(VoiceCallFailureReason::MediaLeaseExpired) => g::CallSummaryFailure::MediaLeaseExpired,
        Some(VoiceCallFailureReason::DaemonRestarted) => g::CallSummaryFailure::DaemonRestarted,
        Some(VoiceCallFailureReason::SignalingUnavailable) | None => {
            g::CallSummaryFailure::SignalingUnavailable
        }
    };
    failure as i32
}

fn duration_seconds(answered_at: Option<i64>, ended_at: Option<i64>) -> u64 {
    match (answered_at, ended_at) {
        (Some(start), Some(end)) if end >= start => u64::try_from(end - start).unwrap_or(u64::MAX),
        _ => 0,
    }
}

fn summary_from(row: &CallRow, parties: &Parties) -> Result<g::CallSummary, SdkError> {
    let call_id =
        ramflux_protocol::decode_base64url(&row.call_id).map_err(|_| refused("call id"))?;
    if call_id.len() != 16 || row.conversation_id.is_empty() {
        return Err(refused("call id or conversation"));
    }
    let outcome = outcome_code(row.end_reason.as_deref());
    let failed = outcome == g::CallSummaryOutcome::Failed as i32;
    let completed = outcome == g::CallSummaryOutcome::Completed as i32;
    Ok(g::CallSummary {
        call_id,
        caller: Some(g::CallSummaryParticipant {
            principal_id: parties.caller_principal_id.clone(),
            device_id: parties.caller_device_id.clone(),
        }),
        callee_principal_id: parties.callee_principal_id.clone(),
        answered_device_id: (completed && !parties.answered_device_id.is_empty())
            .then(|| parties.answered_device_id.clone()),
        ringing_device_ids: parties.ringing_device_ids.clone(),
        outcome,
        failure: if failed { failure_code(row.failure_reason) } else { 0 },
        duration_seconds: duration_seconds(row.answered_at, row.ended_at),
        created_at: row.created_at,
        answered_at: row.answered_at,
        ended_at: row.ended_at.unwrap_or(row.created_at),
    })
}

fn winner_device(summary: &g::CallSummary) -> Option<&str> {
    if summary.outcome == g::CallSummaryOutcome::Completed as i32 {
        summary.answered_device_id.as_deref().filter(|device| !device.is_empty())
    } else {
        None
    }
}

fn keep_stored(stored: &g::CallSummary, incoming: &g::CallSummary) -> bool {
    match (winner_device(stored), winner_device(incoming)) {
        (Some(saved), Some(next)) => saved != next,
        (Some(_), None) => true,
        _ => false,
    }
}

fn stored_summary(bytes: &[u8]) -> Result<Option<g::CallSummary>, SdkError> {
    let (_, content) = RamfluxClient::decode_generated_inner(bytes)?;
    Ok(match content.value {
        Some(g::content::Value::Call(call)) => match call.payload {
            Some(g::call::Payload::Summary(summary)) => Some(summary),
            _ => None,
        },
        _ => None,
    })
}

fn encode_summary(
    identity: g::EventIdentity,
    summary: g::CallSummary,
) -> Result<Vec<u8>, SdkError> {
    let call = g::Call { payload: Some(g::call::Payload::Summary(summary)) };
    RamfluxClient::validate_generated_call(&call)?;
    RamfluxClient::encode_generated_inner(
        identity,
        &g::Content { value: Some(g::content::Value::Call(call)) },
    )
}

fn load_identity(
    client: &RamfluxClient,
    call_id: &str,
) -> Result<Option<g::EventIdentity>, SdkError> {
    let Some(identity) =
        client.account_db()?.load_actor_state::<g::EventIdentity>(&summary_key(call_id))?
    else {
        return Ok(None);
    };
    g::identity::verify(&identity).map_err(|_| refused("stored summary identity"))?;
    Ok(Some(identity))
}

fn allocate_identity(
    client: &RamfluxClient,
    conversation: &str,
) -> Result<g::EventIdentity, SdkError> {
    client.allocate_generated_identity(
        conversation,
        crate::client::generated_identity::now_ms(),
        true,
    )
}

fn write_first(
    client: &RamfluxClient,
    row: &CallRow,
    message_id: &str,
    identity: &g::EventIdentity,
    body: &[u8],
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let owner = client.owned_device_identity()?;
    let sender = owner.device_id().to_owned();
    let metadata = ramflux_storage::MessageMetadata::default();
    db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
        conversation_id: &row.conversation_id,
        message_id,
        sender_id: &sender,
        encrypted_body: body,
        metadata: &metadata,
        created_at: row.created_at,
    })?;
    db.store_message_content(&row.conversation_id, message_id, body)?;
    db.persist_actor_state(&format!("routed/generated-identity/{message_id}"), identity)?;
    db.mark_generated_message_owned(message_id, &owner)?;
    db.persist_actor_state(&summary_key(&row.call_id), identity)?;
    Ok(())
}

fn write_summary(
    client: &RamfluxClient,
    row: &CallRow,
    summary: g::CallSummary,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let identity = match load_identity(client, &row.call_id)? {
        Some(identity) => identity,
        None => allocate_identity(client, &row.conversation_id)?,
    };
    let message_id = ramflux_protocol::encode_base64url(&identity.id);
    if db.message_is_deleted(&message_id)? {
        return Ok(());
    }
    if let Some(bytes) = db.message_content(&message_id)?
        && let Some(stored) = stored_summary(&bytes)?
        && keep_stored(&stored, &summary)
    {
        return Ok(());
    }
    let body = encode_summary(identity.clone(), summary)?;
    if db.direct_message_by_id(&message_id)?.is_some() {
        db.replace_call_summary_body(&row.conversation_id, &message_id, &body)?;
        db.persist_actor_state(&summary_key(&row.call_id), &identity)?;
    } else {
        write_first(client, row, &message_id, &identity, &body)?;
    }
    Ok(())
}

/// Store or replace the ended call's summary in the same transaction as the caller.
/// # Errors
/// Refuses an unusable id, an unverified stored identity, or a storage failure.
/// A deleted summary is left deleted.
pub(crate) fn publish(client: &RamfluxClient, row: &CallRow) -> Result<(), SdkError> {
    if row.state != "ended" {
        return Ok(());
    }
    let summary = summary_from(row, &load_parties(client, row)?)?;
    write_summary(client, row, summary)
}

fn viewer(client: &RamfluxClient) -> Option<(String, String)> {
    client
        .device_branch
        .as_ref()
        .map(|device| (device.principal_id.clone(), device.device_id.clone()))
}

/// Derived direction, and answered-elsewhere when this device rang but did not answer.
/// A non-summary is left unchanged. No control is applied and nothing rings.
#[must_use]
pub(crate) fn present(client: &RamfluxClient, content: &mut g::Content) -> Option<String> {
    let Some(g::content::Value::Call(call)) = content.value.as_mut() else {
        return None;
    };
    let Some(g::call::Payload::Summary(summary)) = call.payload.as_mut() else {
        return None;
    };
    let (principal, device) = viewer(client)?;
    let outgoing = summary.caller.as_ref().is_some_and(|caller| caller.principal_id == principal);
    if summary.outcome == g::CallSummaryOutcome::Completed as i32
        && summary.ringing_device_ids.iter().any(|id| id == &device)
        && summary.answered_device_id.as_deref() != Some(device.as_str())
    {
        summary.outcome = g::CallSummaryOutcome::AnsweredElsewhere as i32;
    }
    Some(if outgoing { "outgoing" } else { "incoming" }.to_owned())
}

fn outcome_name(outcome: i32) -> &'static str {
    match g::CallSummaryOutcome::try_from(outcome) {
        Ok(g::CallSummaryOutcome::Completed) => "completed",
        Ok(g::CallSummaryOutcome::Missed) => "missed",
        Ok(g::CallSummaryOutcome::Declined) => "declined",
        Ok(g::CallSummaryOutcome::Cancelled) => "cancelled",
        Ok(g::CallSummaryOutcome::AnsweredElsewhere) => "answered_elsewhere",
        Ok(g::CallSummaryOutcome::Failed | g::CallSummaryOutcome::Unspecified) | Err(_) => "failed",
    }
}

fn failure_name(failure: i32) -> Option<VoiceCallFailureReason> {
    Some(match g::CallSummaryFailure::try_from(failure).ok()? {
        g::CallSummaryFailure::AuthorityUnavailable => VoiceCallFailureReason::AuthorityUnavailable,
        g::CallSummaryFailure::AuthorityRefused => VoiceCallFailureReason::AuthorityRefused,
        g::CallSummaryFailure::RelayUnavailable => VoiceCallFailureReason::RelayUnavailable,
        g::CallSummaryFailure::MediaLeaseExpired => VoiceCallFailureReason::MediaLeaseExpired,
        g::CallSummaryFailure::DaemonRestarted => VoiceCallFailureReason::DaemonRestarted,
        g::CallSummaryFailure::SignalingUnavailable => VoiceCallFailureReason::SignalingUnavailable,
        g::CallSummaryFailure::Unspecified => return None,
    })
}

fn listed_summary(
    client: &RamfluxClient,
    summary: &g::CallSummary,
    conversation: &str,
    message_id: &str,
) -> Value {
    let mut content = g::Content {
        value: Some(g::content::Value::Call(g::Call {
            payload: Some(g::call::Payload::Summary(summary.clone())),
        })),
    };
    let direction = present(client, &mut content).unwrap_or_else(|| "incoming".to_owned());
    let shown = match content.value {
        Some(g::content::Value::Call(call)) => match call.payload {
            Some(g::call::Payload::Summary(shown)) => shown,
            _ => summary.clone(),
        },
        _ => summary.clone(),
    };
    json!({
        "call_id": ramflux_protocol::encode_base64url(&summary.call_id),
        "conversation_id": conversation,
        "message_id": message_id,
        "state": "ended",
        "direction": direction,
        "end_reason": outcome_name(shown.outcome),
        "failure_reason": failure_name(shown.failure),
        "outcome": outcome_name(shown.outcome),
        "duration_seconds": shown.duration_seconds,
        "created_at": shown.created_at,
        "answered_at": shown.answered_at,
        "ended_at": shown.ended_at,
        "caller_principal_id": shown.caller.as_ref().map(|caller| caller.principal_id.clone()),
        "caller_device_id": shown.caller.as_ref().map(|caller| caller.device_id.clone()),
        "callee_principal_id": shown.callee_principal_id,
        "answered_device_id": shown.answered_device_id,
        "ringing_device_ids": shown.ringing_device_ids,
    })
}

fn summary_row(
    client: &RamfluxClient,
    call_id: &str,
    live: &[CallRow],
) -> Result<Option<Value>, SdkError> {
    if live.iter().any(|row| row.call_id == call_id) {
        return Ok(None);
    }
    let Some(identity) = load_identity(client, call_id)? else {
        return Ok(None);
    };
    let db = client.account_db()?;
    let message_id = ramflux_protocol::encode_base64url(&identity.id);
    if db.message_is_deleted(&message_id)? {
        return Ok(None);
    }
    let Some(message) = db.direct_message_by_id(&message_id)? else {
        return Err(refused("summary projection missing"));
    };
    if message.deleted {
        return Ok(None);
    }
    let Some(bytes) = db.message_content(&message_id)? else {
        return Err(refused("summary content missing"));
    };
    let Some(summary) = stored_summary(&bytes)? else {
        return Err(refused("summary payload missing"));
    };
    Ok(Some(listed_summary(client, &summary, &identity.conversation_id, &message_id)))
}

/// Ended calls as one summary each. Live rows stay the machine record. Tombstones are omitted.
/// # Errors
/// Returns storage errors and refuses a summary row whose body is not a summary.
pub(crate) fn listed(client: &RamfluxClient, live: &[CallRow]) -> Result<Vec<Value>, SdkError> {
    let db = client.account_db()?;
    let mut calls = Vec::new();
    for row in live {
        calls.push(serde_json::to_value(row)?);
    }
    for key in db.actor_state_key_page("voice/summary-id/", MAX_LISTED)? {
        let Some(call_id) = key.strip_prefix("voice/summary-id/") else {
            continue;
        };
        if let Some(summary) = summary_row(client, call_id, live)? {
            calls.push(summary);
        }
    }
    Ok(calls)
}
