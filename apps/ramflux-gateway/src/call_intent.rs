// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verify a caller-signed `CallIntentV1` before the gateway admits it.

use ramflux_protocol::{
    CallIntentAction, DeliveryClass, GATEWAY_CALL_INTENT_AUDIENCE, SignedCallIntentV1,
    call_intent_digest, call_intent_signing_bytes,
};

use crate::state::GatewaySessionRuntime;

/// Checked start digest. Cancel returns the digest carried on the cancel body.
pub(crate) struct VerifiedIntent {
    pub(crate) start_digest: String,
}

pub(crate) struct CallCompletion {
    pub(crate) decision: ramflux_protocol::CallResolution,
    pub(crate) cancellation: Option<(SignedCallIntentV1, String, String)>,
}

pub(crate) fn complete_resolution(
    context: &crate::state::GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> Result<CallCompletion, ramflux_node_core::NodeCoreError> {
    let now = ramflux_node_core::now_unix_seconds();
    let call_context = submit.call_context.as_ref().ok_or_else(|| {
        ramflux_node_core::NodeCoreError::InvalidConfiguration("call resolution refused".into())
    })?;
    let request_expires_at = u64::try_from(submit.signed_request.expires_at)
        .map_err(|_| ramflux_node_core::send_authority::SendAuthorityError::Invalid)?;
    let lookup = ramflux_node_core::WakeOwnerLookup {
        owner_device: runtime.source_identity.storage_key(),
        owner_epoch: runtime.device_epoch,
        wake_id: submit.wake_id.as_deref(),
        call_ref: submit.call_ref.as_deref(),
        now,
    };
    let wake_id = if submit.call_intent.is_none() {
        context.store.validate_call_owner_context(&lookup, call_context)?;
        if let Some(action) = submit.call_terminal.as_deref() {
            context.store.apply_owner_terminal_with_expiry(&lookup, action, request_expires_at)?
        } else {
            context.store.admit_call_context_request(
                call_context,
                lookup.owner_device,
                lookup.owner_epoch,
                request_expires_at,
                now,
            )?;
            None
        }
    } else {
        None
    };
    let decision = context.store.resolve_call_context(
        call_context,
        lookup.owner_device,
        lookup.owner_epoch,
        now,
    )?;
    let cancellation = if let Some(wake_id) = wake_id {
        context.store.resolve_wake_for_owner(&lookup)?.and_then(|resolved| {
            ramflux_protocol::call_intent_digest(&resolved.signed_start)
                .ok()
                .map(|digest| (resolved.signed_start, digest, wake_id))
        })
    } else {
        None
    };
    Ok(CallCompletion { decision, cancellation })
}

/// Authenticate every call field, including nulls, before admitting its replay key.
pub(crate) fn authenticated_submit_body(
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> anyhow::Result<serde_json::Value> {
    let call = submit.call_intent.is_some()
        || submit.call_ref.is_some()
        || submit.wake_id.is_some()
        || submit.call_terminal.is_some()
        || submit.call_context.is_some();
    if !call {
        return Ok(serde_json::to_value(&submit.envelope)?);
    }
    let context =
        submit.call_context.as_ref().ok_or_else(|| anyhow::anyhow!("call_context_missing"))?;
    context.validate()?;
    if runtime.call_session_generation.as_ref() != Some(&context.session_generation)
        || context.session_id != runtime.session_id
        || context.request_id != submit.signed_request.request_id
        || context.envelope_id != submit.envelope.envelope_id
        || submit.call_ref.as_ref() != Some(&context.call_ref)
    {
        anyhow::bail!("call_context_mismatch");
    }
    if let Some(intent) = submit.call_intent.as_deref() {
        if (intent.body.action == CallIntentAction::Start
            && (submit.call_terminal.is_some() || submit.wake_id.is_some()))
            || (intent.body.action == CallIntentAction::Cancel
                && submit.call_terminal.as_deref().is_some_and(|action| action != "end"))
        {
            anyhow::bail!("contradictory call action");
        }
        let digest = match intent.body.action {
            CallIntentAction::Start => call_intent_digest(intent)?,
            CallIntentAction::Cancel => intent
                .body
                .start_digest
                .clone()
                .ok_or_else(|| anyhow::anyhow!("call_start_missing"))?,
        };
        if digest != context.start_digest || intent.body.call_ref != context.call_ref {
            anyhow::bail!("call_start_mismatch");
        }
    }
    Ok(serde_json::to_value(ramflux_protocol::CallSubmitBody {
        envelope: &submit.envelope,
        call_intent: submit.call_intent.as_deref(),
        wake_id: submit.wake_id.as_deref(),
        call_ref: &context.call_ref,
        call_terminal: submit.call_terminal.as_deref(),
        call_context: context,
    })?)
}

/// Verify the signature, audience, session bind, and envelope bind.
///
/// # Errors
/// Returns an error when the intent is forged, expired, or not a one-to-one call
/// for this envelope.
pub(crate) fn verify_submission(
    runtime: &GatewaySessionRuntime,
    envelope: &ramflux_protocol::Envelope,
    signed: &SignedCallIntentV1,
    target_owner_epoch: u64,
    owner_device: &str,
    now: u64,
) -> anyhow::Result<VerifiedIntent> {
    if envelope.encrypted_payload.len() > 32768
        || ramflux_protocol::canonical_json_bytes(signed)?.len() > 8192
    {
        anyhow::bail!("call intent rejected");
    }
    if envelope.delivery_class != DeliveryClass::OpaqueEvent {
        anyhow::bail!("call intent rejected");
    }
    signed.body.validate_shape().map_err(|_source| anyhow::anyhow!("call intent rejected"))?;
    signed.body.validate_times(now).map_err(|_source| anyhow::anyhow!("call intent rejected"))?;
    let source_created = u64::try_from(envelope.created_at).unwrap_or(u64::MAX);
    let source_expires = source_created.saturating_add(u64::from(envelope.ttl));
    let start = matches!(signed.body.action, CallIntentAction::Start);
    if signed.body.audience != GATEWAY_CALL_INTENT_AUDIENCE
        || signed.body.signing_key_id != runtime.branch_public_key
        || signed.body.sender_device != runtime.source_identity.storage_key()
        || signed.body.sender_epoch != runtime.device_epoch
        || signed.body.target_delivery_id != envelope.target_delivery_id
        || signed.body.target_epoch != target_owner_epoch
        || signed.body.target_device != owner_device
        || (start && signed.body.created_at != source_created)
        || (start && signed.body.expires_at > source_expires)
    {
        anyhow::bail!("call intent rejected");
    }
    let bytes = call_intent_signing_bytes(&signed.body)
        .map_err(|_source| anyhow::anyhow!("call intent rejected"))?;
    ramflux_crypto::verify_canonical_signature(
        &bytes,
        &signed.signature,
        &runtime.branch_public_key,
    )
    .map_err(|_source| anyhow::anyhow!("call intent rejected"))?;
    let start_digest = match signed.body.action {
        CallIntentAction::Start => {
            if signed.body.source_event_id != envelope.envelope_id {
                anyhow::bail!("call intent rejected");
            }
            call_intent_digest(signed).map_err(|_source| anyhow::anyhow!("call intent rejected"))?
        }
        CallIntentAction::Cancel => signed
            .body
            .start_digest
            .clone()
            .ok_or_else(|| anyhow::anyhow!("call intent rejected"))?,
    };
    Ok(VerifiedIntent { start_digest })
}
