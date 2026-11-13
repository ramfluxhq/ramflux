// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persist a caller-signed `CallIntentV1` before the control envelope is dispatched.
//!
//! The signed object is reused on retry. `call_ref` is not minted again for the same
//! call and target. A callee control, a non-terminal action, or an expired deadline
//! returns `None` so the envelope still sends without call priority.

use crate::SdkError;
use crate::bus::state::LocalBusAccountState;
use ramflux_protocol::{
    CallAction, CallControl, CallIntentAction, CallIntentKind, CallIntentV1,
    GATEWAY_CALL_INTENT_AUDIENCE, SignedCallIntentV1, WakeSignatureAlg, call_intent_digest,
    call_intent_signing_bytes,
};
use serde::{Deserialize, Serialize};

/// Callee binding copied from the verified device manifest.
pub(crate) struct IntentTarget {
    pub(crate) device_id: String,
    pub(crate) qualified_device: String,
    pub(crate) epoch: u64,
    pub(crate) delivery_id: String,
}

/// Envelope that carries the signed intent, plus the signed object itself.
pub(crate) struct BoundCallIntent {
    pub(crate) envelope_id: String,
    pub(crate) signed: SignedCallIntentV1,
}

#[derive(Clone, Deserialize, Serialize)]
struct StoredCallIntent {
    envelope_id: String,
    signed: SignedCallIntentV1,
}

/// Original Start bound to this call and its verified peer device.
pub(crate) fn start_for_control(
    account: &LocalBusAccountState,
    call: &super::state::LiveCall,
    target_device: &str,
) -> Result<Option<SignedCallIntentV1>, SdkError> {
    if call.local == call.caller {
        Ok(load(account, &storage_key(&call.row.call_id, target_device, "start"))?
            .map(|stored| stored.signed))
    } else {
        Ok(call.call_start.clone())
    }
}

/// Load or sign the intent for this caller control and persist it before return.
///
/// # Errors
/// Returns an error when the account store or the device branch cannot sign.
pub(crate) fn bind_call_intent(
    account: &LocalBusAccountState,
    control: &CallControl,
    target: &IntentTarget,
    now: u64,
) -> Result<Option<BoundCallIntent>, SdkError> {
    let Some(action) = caller_action(control) else {
        return Ok(None);
    };
    let created_at = u64::try_from(control.created_at).unwrap_or(u64::MAX);
    let expires_at = created_at.saturating_add(ramflux_protocol::CALL_MAX_LIFETIME_SECONDS);
    if created_at > now.saturating_add(ramflux_protocol::CLOCK_UNCERTAINTY_SECONDS)
        || now >= expires_at
    {
        return Ok(None);
    }
    match action {
        CallIntentAction::Start => bind_start(account, control, target, created_at, expires_at),
        CallIntentAction::Cancel => bind_cancel(account, control, target, now),
    }
}

/// Device epoch stored with the fetched manifest, when that manifest is present.
///
/// # Errors
/// Returns an error when the account store cannot be read.
#[cfg(test)]
pub(crate) fn manifest_device_epoch(
    account: &LocalBusAccountState,
    root: &str,
    device_id: &str,
) -> Result<Option<u64>, SdkError> {
    let key = format!("identity/manifest-root/{root}");
    let Some(manifest) =
        account.client.account_db()?.load_actor_state::<crate::SdkDeviceManifestResponse>(&key)?
    else {
        return Ok(None);
    };
    Ok(manifest
        .devices
        .into_iter()
        .find(|device| device.device_id == device_id)
        .map(|device| device.device_epoch))
}

fn caller_action(control: &CallControl) -> Option<CallIntentAction> {
    if control.sender != control.caller {
        return None;
    }
    match &control.body {
        CallAction::Invite { .. } => Some(CallIntentAction::Start),
        CallAction::Reject
        | CallAction::Hangup
        | CallAction::Timeout
        | CallAction::Failed
        | CallAction::Busy
        | CallAction::AnsweredElsewhere => Some(CallIntentAction::Cancel),
        CallAction::Ringing
        | CallAction::Answer { .. }
        | CallAction::Ack { .. }
        | CallAction::Ready { .. }
        | CallAction::Rekey { .. }
        | CallAction::RekeyAck { .. } => None,
    }
}

fn bind_start(
    account: &LocalBusAccountState,
    control: &CallControl,
    target: &IntentTarget,
    created_at: u64,
    expires_at: u64,
) -> Result<Option<BoundCallIntent>, SdkError> {
    let key = storage_key(&control.call_id, &target.device_id, "start");
    if let Some(stored) = load(account, &key)? {
        return Ok(reusable(&stored, target));
    }
    let envelope_id = crate::new_surface_message_id()?;
    let call_ref = mint_call_ref()?;
    let body = intent_body(
        account,
        target,
        &IntentTimes {
            call_ref: &call_ref,
            source_event_id: &envelope_id,
            action: CallIntentAction::Start,
            seq: 0,
            created_at,
            issued_at: created_at,
            expires_at,
            start_digest: None,
        },
    )?;
    let signed = sign(account, body)?;
    store(account, &key, &envelope_id, &signed)?;
    Ok(Some(BoundCallIntent { envelope_id, signed }))
}

fn bind_cancel(
    account: &LocalBusAccountState,
    control: &CallControl,
    target: &IntentTarget,
    now: u64,
) -> Result<Option<BoundCallIntent>, SdkError> {
    let cancel_key = storage_key(&control.call_id, &target.device_id, "cancel");
    if let Some(stored) = load(account, &cancel_key)? {
        return Ok(reusable(&stored, target));
    }
    let Some(start) = load(account, &storage_key(&control.call_id, &target.device_id, "start"))?
    else {
        return Ok(None);
    };
    if reusable(&start, target).is_none() {
        return Ok(None);
    }
    let start_digest = call_intent_digest(&start.signed)?;
    let envelope_id = crate::new_surface_message_id()?;
    let issued_at = now.max(start.signed.body.created_at);
    let body = intent_body(
        account,
        target,
        &IntentTimes {
            call_ref: &start.signed.body.call_ref,
            source_event_id: &start.signed.body.source_event_id,
            action: CallIntentAction::Cancel,
            seq: 1,
            created_at: start.signed.body.created_at,
            issued_at,
            expires_at: start.signed.body.expires_at,
            start_digest: Some(start_digest),
        },
    )?;
    if body.validate_times(now).is_err() {
        return Ok(None);
    }
    let signed = sign(account, body)?;
    store(account, &cancel_key, &envelope_id, &signed)?;
    Ok(Some(BoundCallIntent { envelope_id, signed }))
}

fn reusable(stored: &StoredCallIntent, target: &IntentTarget) -> Option<BoundCallIntent> {
    let body = &stored.signed.body;
    if body.target_delivery_id != target.delivery_id
        || body.target_epoch != target.epoch
        || body.target_device != target.qualified_device
    {
        return None;
    }
    Some(BoundCallIntent { envelope_id: stored.envelope_id.clone(), signed: stored.signed.clone() })
}

struct IntentTimes<'a> {
    call_ref: &'a str,
    source_event_id: &'a str,
    action: CallIntentAction,
    seq: u64,
    created_at: u64,
    issued_at: u64,
    expires_at: u64,
    start_digest: Option<String>,
}

fn intent_body(
    account: &LocalBusAccountState,
    target: &IntentTarget,
    times: &IntentTimes<'_>,
) -> Result<CallIntentV1, SdkError> {
    let branch = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let signing_key_id =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    Ok(CallIntentV1 {
        version: 1,
        signing_key_id,
        signature_alg: WakeSignatureAlg::Ed25519,
        audience: GATEWAY_CALL_INTENT_AUDIENCE.to_owned(),
        sender_device: account.client.owned_device_identity()?.storage_key().to_owned(),
        sender_epoch: branch.device_epoch,
        target_device: target.qualified_device.clone(),
        target_epoch: target.epoch,
        target_delivery_id: target.delivery_id.clone(),
        call_ref: times.call_ref.to_owned(),
        source_event_id: times.source_event_id.to_owned(),
        kind: CallIntentKind::OneToOne,
        action: times.action,
        seq: times.seq,
        created_at: times.created_at,
        issued_at: times.issued_at,
        expires_at: times.expires_at,
        start_digest: times.start_digest.clone(),
    })
}

fn sign(
    account: &LocalBusAccountState,
    body: CallIntentV1,
) -> Result<SignedCallIntentV1, SdkError> {
    let branch = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let bytes = call_intent_signing_bytes(&body)?;
    let signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(&bytes, branch);
    Ok(SignedCallIntentV1 { body, signature })
}

fn mint_call_ref() -> Result<String, SdkError> {
    let bytes = ramflux_crypto::random_32()?;
    let prefix =
        bytes.get(..16).ok_or_else(|| SdkError::LocalBus("call ref entropy short".into()))?;
    Ok(ramflux_protocol::encode_base64url(prefix))
}

fn storage_key(call_id: &str, device_id: &str, action: &str) -> String {
    format!("voice/intent/{call_id}/{device_id}/{action}")
}

fn load(account: &LocalBusAccountState, key: &str) -> Result<Option<StoredCallIntent>, SdkError> {
    Ok(account.client.account_db()?.load_actor_state(key)?)
}

fn store(
    account: &LocalBusAccountState,
    key: &str,
    envelope_id: &str,
    signed: &SignedCallIntentV1,
) -> Result<(), SdkError> {
    account.client.account_db()?.persist_actor_state(
        key,
        &StoredCallIntent { envelope_id: envelope_id.to_owned(), signed: signed.clone() },
    )?;
    Ok(())
}
