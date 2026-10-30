// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Each account claims its own relay secrets; only public offers/consent travel to the peer.
use super::{invalid, scope};
use crate::client::call::state::LiveCall;
use crate::prelude::*;
use ramflux_protocol::{CallAction, VoiceCallFailureReason, VoiceLeaseConsent};
use ramflux_protocol::{VoiceLeaseRequest, VoiceLeaseResponse};
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
    let record = account.client.trusted_device(&account.client.call_device_identity(peer)?)?;
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
        let mut engine = account.take_live_engine().await?;
        let result = engine.voice_lease(VoiceLeaseRequest::Allocate { scope: scope(next) }).await;
        account.put_engine(engine);
        match result {
            Ok(VoiceLeaseResponse::Allocation { allocation }) => next.activate(allocation, now)?,
            Ok(VoiceLeaseResponse::Refused { reason }) => next.fail(reason, now)?,
            _ => next.fail(VoiceCallFailureReason::SignalingUnavailable, now)?,
        }
    } else if next.row.state == "active" {
        let Some(consent) = next.lease_consent.clone() else {
            next.next_lease_refresh = now.saturating_add(2);
            return Ok(());
        };
        #[cfg(all(feature = "itest-local-mint", ramflux_itest, not(ramflux_production)))]
        super::refresh_barrier::wait().await?;
        let mut engine = account.take_live_engine().await?;
        let result =
            engine.voice_lease(VoiceLeaseRequest::Renew { consent: Box::new(consent) }).await;
        account.put_engine(engine);
        match result {
            Ok(VoiceLeaseResponse::Status { status }) => {
                if let Some(allocation) = next.allocation.as_mut() {
                    allocation.expires_at = status.expires_at;
                }
                let allocation = next
                    .allocation
                    .as_ref()
                    .ok_or_else(|| invalid("renewed lease missing"))?
                    .for_callee();
                let ack =
                    next.control(CallAction::Ack { allocation: Box::new(allocation) }, now)?;
                next.pending.push(ack);
                next.next_lease_refresh = now.saturating_add(20);
            }
            Ok(VoiceLeaseResponse::Refused { reason }) => {
                next.lease_refused(reason, now)?;
                #[cfg(all(feature = "itest-local-mint", ramflux_itest, not(ramflux_production)))]
                super::refresh_barrier::refused().await?;
            }
            _ => next.next_lease_refresh = now.saturating_add(5),
        }
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
    #[cfg(all(feature = "itest-local-mint", ramflux_itest, not(ramflux_production)))]
    if next.row.state == "active" {
        super::refresh_barrier::wait().await?;
    }
    let mut engine = account.take_live_engine().await?;
    let result =
        engine.voice_lease(VoiceLeaseRequest::Accept { consent: Box::new(consent.clone()) }).await;
    account.put_engine(engine);
    match result {
        Ok(VoiceLeaseResponse::Allocation { allocation }) => {
            next.accept_lease(allocation, consent, now)?;
        }
        Ok(VoiceLeaseResponse::Refused { reason }) => {
            next.lease_refused(reason, now)?;
            #[cfg(all(feature = "itest-local-mint", ramflux_itest, not(ramflux_production)))]
            super::refresh_barrier::refused().await?;
        }
        _ => next.fail(VoiceCallFailureReason::SignalingUnavailable, now)?,
    }
    Ok(())
}
