// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admit one offline wake before the gateway acks or sends it.
//!
//! The public wake id comes from the durable dedup table. `WakeV2` is signed with the
//! gateway service key over `domain || 0x00 || JCS(body)`. A missing target owner epoch
//! is refused by the caller. This module does not invent epoch 0.

use ramflux_node_core::{
    CallGrant, GatewayRedbStore, NodeServiceSigningKey, WakeAdmitOutcome, WakeAdmitRequest,
    WakeDedupTerminal,
};
use ramflux_protocol::{
    MESSAGE_MAX_LIFETIME_SECONDS, NOTIFY_WAKE_AUDIENCE, WakeAction, WakeClass, WakeSignatureAlg,
    WakeV2, effective_expiry, wake_request_digest,
};

pub(crate) struct OfflineWakeInput<'a> {
    pub(crate) source_identity: &'a str,
    pub(crate) source_epoch: u64,
    pub(crate) target_owner_epoch: u64,
    pub(crate) target_delivery_id: &'a str,
    pub(crate) envelope: &'a ramflux_protocol::Envelope,
    pub(crate) now: u64,
}

/// Sign and commit one message wake, or return `None` when nothing may be sent.
///
/// `None` covers an expired source, a terminal duplicate, a digest conflict, and RNG failure.
///
/// # Errors
/// Returns an error when the store commit fails. Contract failures are a skip, not an error.
pub(crate) fn signed_offline_wake(
    store: &GatewayRedbStore,
    signer: &NodeServiceSigningKey,
    input: &OfflineWakeInput<'_>,
) -> anyhow::Result<Option<ramflux_protocol::SignedWakeV2>> {
    let grant = store.call_grant(
        input.source_identity,
        input.source_epoch,
        &input.envelope.envelope_id,
        input.target_delivery_id,
        input.now,
    )?;
    let (class, created_at, expires_at, digest) = match grant {
        CallGrant::Silent => return Ok(None),
        CallGrant::Message => {
            let Some(expires_at) = message_deadline(input) else {
                return Ok(None);
            };
            (WakeClass::Message, source_created_at(input.envelope)?, expires_at, None)
        }
        CallGrant::Wake { digest, created_at, expires_at } => {
            let Some(source_expires) = source_expires(input) else {
                return Ok(None);
            };
            let expires_at = expires_at.min(source_expires);
            (WakeClass::CallWake, created_at, expires_at, Some(digest))
        }
    };
    let mut body = WakeV2 {
        version: 2,
        signing_key_id: signer.signing_key_id().to_owned(),
        signature_alg: WakeSignatureAlg::Ed25519,
        audience: NOTIFY_WAKE_AUDIENCE.to_owned(),
        action: WakeAction::Enqueue,
        wake_id: String::new(),
        target_delivery_id: input.target_delivery_id.to_owned(),
        target_owner_epoch: input.target_owner_epoch,
        source_event_id: input.envelope.envelope_id.clone(),
        class,
        created_at,
        expires_at,
        call_intent_digest: digest,
    };
    if body.validate_times(input.now).is_err() {
        return Ok(None);
    }
    let lookup = admit_request(input, expires_at, "lookup");
    if let Some(existing) = store.lookup_wake(&lookup)? {
        let resigned = resign(signer, &mut body, &existing)?;
        return match resigned {
            Some(signed_wake) => finish_call_wake(store, input, signed_wake),
            None => Ok(None),
        };
    }
    let Some(wake_id) = mint_wake_id() else {
        return Ok(None);
    };
    body.wake_id = wake_id;
    let signed_wake = match signer.sign_wake_v2(&body) {
        Ok(signed_wake) => signed_wake,
        Err(_error) => return Ok(None),
    };
    let request_digest = match wake_request_digest(&signed_wake) {
        Ok(request_digest) => request_digest,
        Err(_error) => return Ok(None),
    };
    let request = admit_request(input, expires_at, &request_digest);
    match store.commit_signed_wake(&request, &signed_wake.body.wake_id) {
        Ok(WakeAdmitOutcome::Created(_)) => finish_call_wake(store, input, signed_wake),
        Ok(WakeAdmitOutcome::Existing(existing)) => {
            let resigned = resign(signer, &mut body, &existing)?;
            match resigned {
                Some(signed_wake) => finish_call_wake(store, input, signed_wake),
                None => Ok(None),
            }
        }
        Err(ramflux_node_core::NodeCoreError::InvalidConfiguration(reason))
            if reason == "wake dedup conflict" =>
        {
            match store.lookup_wake(&request)? {
                Some(existing) => {
                    let resigned = resign(signer, &mut body, &existing)?;
                    match resigned {
                        Some(signed_wake) => finish_call_wake(store, input, signed_wake),
                        None => Ok(None),
                    }
                }
                None => Ok(None),
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn resign(
    signer: &NodeServiceSigningKey,
    body: &mut WakeV2,
    existing: &ramflux_node_core::WakeDedupRecord,
) -> anyhow::Result<Option<ramflux_protocol::SignedWakeV2>> {
    if existing.terminal != WakeDedupTerminal::Open {
        return Ok(None);
    }
    body.wake_id.clone_from(&existing.wake_id);
    body.expires_at = existing.deadline;
    let signed_wake = signer.sign_wake_v2(body).map_err(|error| anyhow::anyhow!(error))?;
    let digest = wake_request_digest(&signed_wake).map_err(|error| anyhow::anyhow!(error))?;
    if digest != existing.request_digest {
        return Ok(None);
    }
    Ok(Some(signed_wake))
}

fn admit_request(input: &OfflineWakeInput<'_>, deadline: u64, digest: &str) -> WakeAdmitRequest {
    WakeAdmitRequest {
        source_identity: input.source_identity.to_owned(),
        source_envelope_id: input.envelope.envelope_id.clone(),
        target_owner_epoch: input.target_owner_epoch,
        target_delivery_id: input.target_delivery_id.to_owned(),
        deadline,
        request_digest: digest.to_owned(),
    }
}

fn source_created_at(envelope: &ramflux_protocol::Envelope) -> anyhow::Result<u64> {
    u64::try_from(envelope.created_at).map_err(|_source| anyhow::anyhow!("wake time rejected"))
}

/// Sign `WakeV2(action=cancel)` for a wake that was already committed.
///
/// A contract or signing failure returns `None`. The caller has already stored the tombstone.
pub(crate) fn signed_cancel_wake(
    signer: &NodeServiceSigningKey,
    intent: &ramflux_protocol::SignedCallIntentV1,
    start_digest: &str,
    wake_id: &str,
    target_owner_epoch: u64,
    now: u64,
) -> Option<ramflux_protocol::SignedWakeV2> {
    let body = &intent.body;
    let wake = WakeV2 {
        version: 2,
        signing_key_id: signer.signing_key_id().to_owned(),
        signature_alg: WakeSignatureAlg::Ed25519,
        audience: NOTIFY_WAKE_AUDIENCE.to_owned(),
        action: WakeAction::Cancel,
        wake_id: wake_id.to_owned(),
        target_delivery_id: body.target_delivery_id.clone(),
        target_owner_epoch,
        source_event_id: body.source_event_id.clone(),
        class: WakeClass::CallWake,
        created_at: body.created_at,
        expires_at: body.expires_at,
        call_intent_digest: Some(start_digest.to_owned()),
    };
    if wake.validate_shape().is_err() || wake.validate_times(now).is_err() {
        return None;
    }
    signer.sign_wake_v2(&wake).ok()
}

fn finish_call_wake(
    store: &GatewayRedbStore,
    input: &OfflineWakeInput<'_>,
    signed_wake: ramflux_protocol::SignedWakeV2,
) -> anyhow::Result<Option<ramflux_protocol::SignedWakeV2>> {
    if signed_wake.body.call_intent_digest.is_some() {
        match store.bind_call_wake_id(
            input.source_identity,
            input.source_epoch,
            &input.envelope.envelope_id,
            input.target_delivery_id,
            &signed_wake.body.wake_id,
        ) {
            Ok(()) => {}
            Err(ramflux_node_core::NodeCoreError::InvalidConfiguration(reason))
                if reason == "call wake cancelled" =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(Some(signed_wake))
}

fn source_expires(input: &OfflineWakeInput<'_>) -> Option<u64> {
    let created_at = u64::try_from(input.envelope.created_at).ok()?;
    created_at.checked_add(u64::from(input.envelope.ttl))
}

fn message_deadline(input: &OfflineWakeInput<'_>) -> Option<u64> {
    let created_at = u64::try_from(input.envelope.created_at).ok()?;
    let source_expires = source_expires(input)?;
    if created_at >= source_expires {
        return None;
    }
    let signed = effective_expiry(source_expires, input.now, WakeClass::Message)
        .min(created_at.saturating_add(MESSAGE_MAX_LIFETIME_SECONDS));
    (created_at < signed && signed <= source_expires).then_some(signed)
}

fn mint_wake_id() -> Option<String> {
    let bytes = ramflux_crypto::random_32().ok()?;
    let prefix = bytes.get(..16)?;
    Some(ramflux_protocol::encode_base64url(prefix))
}
