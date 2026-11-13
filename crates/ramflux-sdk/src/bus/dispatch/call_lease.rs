// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Each account claims its own relay secrets; only public offers/consent travel to the peer.
use super::lease_outcome::apply_result;
use super::{invalid, scope};
use crate::client::call::state::LiveCall;
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;
use ramflux_protocol::VoiceLeaseRequest;
use ramflux_protocol::{VoiceCallFailureReason, VoiceLeaseConsent};
pub(super) async fn maintain_lease(
    account: &mut LocalBusAccountState,
    next: &mut LiveCall,
    now: i64,
) -> Result<(), SdkError> {
    if next.media_lost()
        || next.next_lease_refresh > now
        || !matches!(next.row.state.as_str(), "connecting" | "active")
    {
        return Ok(());
    }
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &next.row.conversation_id)?
        .ok_or_else(|| invalid("call conversation absent"))?;
    let targets = match crate::bus::dispatch::task_transport::direct_targets(
        account,
        &account.gateway_config,
        &thread,
    )
    .await
    {
        Ok(targets) => targets,
        Err(error @ (SdkError::Storage(_) | SdkError::Io(_))) => return Err(error),
        Err(error)
            if crate::error_policy::approval_retryable(&error)
                && crate::error_policy::security_code(&error).is_none() =>
        {
            next.next_lease_refresh = now.saturating_add(5);
            return Ok(());
        }
        Err(_) => {
            next.fail(VoiceCallFailureReason::AuthorityUnavailable, now)?;
            return Ok(());
        }
    };
    let peer = if next.local == next.caller { &next.callee } else { &next.caller };
    let record = account
        .client
        .trusted_device(HeadUse::NewAuthorization, &account.client.call_device_identity(peer)?)?;
    if !targets.iter().any(|t| t.device == peer.device_id)
        || !record["signing_public_key"]
            .as_str()
            .is_some_and(|key| next.peer_key_matches(peer, key))
    {
        next.fail(VoiceCallFailureReason::AuthorityRefused, now)?;
        return Ok(());
    }
    if next.local == next.callee {
        return claim_callee(account, next, now).await;
    }
    if next.row.state == "connecting" && next.receive_key.is_some() {
        let mut engine = match account.session_client().await {
            Ok(engine) => engine,
            Err(error) if error.gateway_writer_busy() => {
                apply_result(next, Err(error), None, now)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let result = engine.voice_lease(VoiceLeaseRequest::Allocate { scope: scope(next) }).await;
        account.apply_session_metadata(engine);
        apply_result(next, result, None, now)?;
    } else if next.row.state == "active" {
        let Some(consent) = next.lease_consent.clone() else {
            next.next_lease_refresh = now.saturating_add(2);
            return Ok(());
        };
        let mut engine = match account.session_client().await {
            Ok(engine) => engine,
            Err(error) if error.gateway_writer_busy() => {
                apply_result(next, Err(error), None, now)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let result =
            engine.voice_lease(VoiceLeaseRequest::Renew { consent: Box::new(consent) }).await;
        account.apply_session_metadata(engine);
        apply_result(next, result, None, now)?;
    }
    Ok(())
}

async fn claim_callee(
    account: &mut LocalBusAccountState,
    next: &mut LiveCall,
    now: i64,
) -> Result<(), SdkError> {
    let Some(offer) = next.lease_offer.clone() else { return Ok(()) };
    if next.allocation.as_ref().is_some_and(|a| a.expires_at >= offer.expires_at) {
        next.next_lease_refresh = now.saturating_add(20);
        return Ok(());
    }
    let mut consent = next.lease_consent.clone().unwrap_or(VoiceLeaseConsent {
        scope: scope(next),
        lease_id: offer.lease_id,
        expires_at: offer.hard_expires_at,
        signature: String::new(),
    });
    if consent.signature.is_empty() {
        let branch = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        consent.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &ramflux_protocol::voice_lease_consent_bytes(&consent)?,
            branch,
        );
    }
    let mut engine = match account.session_client().await {
        Ok(engine) => engine,
        Err(error) if error.gateway_writer_busy() => {
            apply_result(next, Err(error), None, now)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let result =
        engine.voice_lease(VoiceLeaseRequest::Accept { consent: Box::new(consent.clone()) }).await;
    account.apply_session_metadata(engine);
    apply_result(next, result, Some(consent), now)?;
    Ok(())
}
