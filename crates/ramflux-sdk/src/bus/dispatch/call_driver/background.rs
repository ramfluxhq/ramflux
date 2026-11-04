// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent call signaling and lease exchanges with whole-call snapshot fences.

use super::{invalid, recover, scope};
use crate::bus::dispatch::task_transport::{self, DirectTargetInput, Target};
use crate::bus::{
    connection_manager::SessionContext,
    couriers::{federation, writer::Writer},
};
use crate::client::{
    call::{self, state::LiveCall},
    identity_authority::NativeOperation,
    routed::{SendMaterial, SendMaterialRequest},
};
use crate::prelude::*;
use ramflux_protocol::{
    CallAction, VoiceCallFailureReason, VoiceLeaseConsent, VoiceLeaseRequest, VoiceLeaseResponse,
};

#[derive(Clone)]
struct Plan {
    original: LiveCall,
    thread: serde_json::Value,
    config: GatewaySessionConfig,
}
struct Prepared {
    plan: Plan,
    input: Result<DirectTargetInput, SdkError>,
}
struct Lease {
    plan: Plan,
    next: LiveCall,
    request: VoiceLeaseRequest,
    consent: Option<VoiceLeaseConsent>,
}
struct Control {
    plan: Plan,
    target: Target,
    message: GatewayDirectMessage,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    request: SendMaterialRequest,
}

pub(crate) async fn pass(context: SessionContext, writer: Writer) -> Result<bool, SdkError> {
    let ids = writer
        .apply(|account| {
            recover(account)?;
            super::expire_due(account)?;
            Ok(account.client.voice_calls.keys().cloned().collect::<Vec<_>>())
        })
        .await?;
    let mut active = false;
    for id in ids {
        let owned_id = id.clone();
        let prepared = writer.apply(move |account| prepare(account, &owned_id)).await?;
        let Some(prepared) = prepared else { continue };
        let lease_due = !prepared.plan.original.media_lost()
            && prepared.plan.original.next_lease_refresh <= now_unix_timestamp()
            && matches!(prepared.plan.original.row.state.as_str(), "connecting" | "active");
        let manifest = if lease_due {
            match prepared.input {
                Ok(input) => {
                    federation::manifest(
                        &context,
                        &prepared.plan.config,
                        &input.root,
                        input.federation.as_ref(),
                    )
                    .await
                }
                Err(error) => Err(error),
            }
        } else {
            Err(SdkError::NetworkingPending)
        };
        let result =
            writer.apply(move |account| prepare_lease(account, prepared.plan, manifest)).await;
        match result {
            Ok(Some(lease)) => {
                exchange_lease(&context, &writer, lease).await?;
                active = true;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(%error,"call relay lease deferred");
            }
        }
        // Completion of the delivery attempt, including failure, always precedes release.
        let sent = send_controls(&context, &writer, &id).await;
        release(&context, &writer, &id).await?;
        if let Err(error) = sent {
            tracing::debug!(%error,"call control delivery deferred");
        } else {
            active |= sent?;
        }
    }
    writer
        .apply(|account| {
            account.client.voice_calls.retain(|_, call| {
                call.row.state != "ended"
                    || !call.pending.is_empty()
                    || call.release_until > now_unix_timestamp().unsigned_abs()
            });
            Ok(())
        })
        .await?;
    Ok(active)
}
fn prepare(account: &LocalBusAccountState, id: &str) -> Result<Option<Prepared>, SdkError> {
    let Some(call) = account.client.voice_calls.get(id) else { return Ok(None) };
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &call.row.conversation_id)?
        .ok_or_else(|| invalid("call conversation absent"))?;
    let input = task_transport::direct_target_input(account, &thread);
    Ok(Some(Prepared {
        plan: Plan { original: call.clone(), thread, config: account.gateway_config.clone() },
        input,
    }))
}
fn current(account: &LocalBusAccountState, plan: &Plan) -> Result<bool, SdkError> {
    Ok(account.client.voice_calls.get(&plan.original.row.call_id) == Some(&plan.original)
        && account
            .client
            .account_db()?
            .client_record("conversation", &plan.original.row.conversation_id)?
            .as_ref()
            == Some(&plan.thread))
}
fn install(account: &mut LocalBusAccountState, next: LiveCall) -> Result<(), SdkError> {
    if account.client.voice_calls.get(&next.row.call_id).is_none_or(|old| old.row != next.row) {
        account
            .client
            .account_db()?
            .write_transaction(|| account.client.persist_call_row(&next.row))?;
    }
    account.client.voice_calls.insert(next.row.call_id.clone(), next);
    Ok(())
}
fn prepare_lease(
    account: &mut LocalBusAccountState,
    plan: Plan,
    manifest: Result<crate::SdkDeviceManifestResponse, SdkError>,
) -> Result<Option<Lease>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    let mut next = plan.original.clone();
    let now = now_unix_timestamp();
    if next.media_lost()
        || next.next_lease_refresh > now
        || !matches!(next.row.state.as_str(), "connecting" | "active")
    {
        return Ok(None);
    }
    let targets = match manifest.and_then(|manifest| {
        account.client.persist_fetched_identity_directory(&manifest)?;
        task_transport::direct_targets_from_manifest(account, &plan.thread, manifest)
    }) {
        Ok(targets) => targets,
        Err(error @ (SdkError::Storage(_) | SdkError::Io(_))) => return Err(error),
        Err(error)
            if crate::error_policy::approval_retryable(&error)
                && crate::error_policy::security_code(&error).is_none() =>
        {
            next.next_lease_refresh = now.saturating_add(5);
            install(account, next)?;
            return Ok(None);
        }
        Err(_) => {
            next.fail(VoiceCallFailureReason::AuthorityUnavailable, now)?;
            install(account, next)?;
            return Ok(None);
        }
    };
    let peer = if next.local == next.caller { &next.callee } else { &next.caller };
    let record = account.client.trusted_device(&account.client.call_device_identity(peer)?)?;
    if !targets.iter().any(|target| target.device == peer.device_id)
        || !record["signing_public_key"]
            .as_str()
            .is_some_and(|key| next.peer_key_matches(peer, key))
    {
        next.fail(VoiceCallFailureReason::AuthorityRefused, now)?;
        install(account, next)?;
        return Ok(None);
    }
    let (request, consent) = if next.local == next.callee {
        let Some(offer) = next.lease_offer.clone() else { return Ok(None) };
        if next
            .allocation
            .as_ref()
            .is_some_and(|allocation| allocation.expires_at >= offer.expires_at)
        {
            next.next_lease_refresh = now.saturating_add(20);
            install(account, next)?;
            return Ok(None);
        }
        let mut consent = next.lease_consent.clone().unwrap_or(VoiceLeaseConsent {
            scope: scope(&next),
            lease_id: offer.lease_id,
            expires_at: offer.hard_expires_at,
            signature: String::new(),
        });
        if consent.signature.is_empty() {
            consent.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
                &ramflux_protocol::voice_lease_consent_bytes(&consent)?,
                account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            );
        }
        (VoiceLeaseRequest::Accept { consent: Box::new(consent.clone()) }, Some(consent))
    } else if next.row.state == "connecting" && next.receive_key.is_some() {
        (VoiceLeaseRequest::Allocate { scope: scope(&next) }, None)
    } else if next.row.state == "active" {
        let Some(consent) = next.lease_consent.clone() else {
            next.next_lease_refresh = now.saturating_add(2);
            install(account, next)?;
            return Ok(None);
        };
        (VoiceLeaseRequest::Renew { consent: Box::new(consent) }, None)
    } else {
        return Ok(None);
    };
    Ok(Some(Lease { plan, next, request, consent }))
}
async fn exchange_lease(
    context: &SessionContext,
    writer: &Writer,
    lease: Lease,
) -> Result<(), SdkError> {
    #[cfg(all(feature = "itest-local-mint", ramflux_itest, not(ramflux_production)))]
    if lease.next.row.state == "active" {
        super::refresh_barrier::wait().await?;
    }
    let request = lease.request;
    let result = context
        .call(
            move |engine| Box::pin(async move { engine.voice_lease(request).await }),
            context.call_deadline(),
        )
        .await;
    let refused = matches!(result, Ok(VoiceLeaseResponse::Refused { .. }));
    let applied = writer
        .apply(move |account| {
            if !current(account, &lease.plan)? {
                return Ok(false);
            }
            let now = now_unix_timestamp();
            let mut next = lease.next;
            if next.local == next.callee {
                match result {
                    Ok(VoiceLeaseResponse::Allocation { allocation }) => next.accept_lease(
                        allocation,
                        lease.consent.ok_or_else(|| invalid("callee lease consent absent"))?,
                        now,
                    )?,
                    Ok(VoiceLeaseResponse::Refused { reason }) => {
                        next.lease_refused(reason, now)?;
                    }
                    _ => next.fail(VoiceCallFailureReason::SignalingUnavailable, now)?,
                }
            } else if next.row.state == "connecting" && next.receive_key.is_some() {
                match result {
                    Ok(VoiceLeaseResponse::Allocation { allocation }) => {
                        next.activate(allocation, now)?;
                    }
                    Ok(VoiceLeaseResponse::Refused { reason }) => next.fail(reason, now)?,
                    _ => next.fail(VoiceCallFailureReason::SignalingUnavailable, now)?,
                }
            } else {
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
                        let ack = next
                            .control(CallAction::Ack { allocation: Box::new(allocation) }, now)?;
                        next.pending.push(ack);
                        next.next_lease_refresh = now.saturating_add(20);
                    }
                    Ok(VoiceLeaseResponse::Refused { reason }) => {
                        next.lease_refused(reason, now)?;
                    }
                    _ => next.next_lease_refresh = now.saturating_add(5),
                }
            }
            install(account, next)?;
            Ok(true)
        })
        .await?;
    #[cfg(all(feature = "itest-local-mint", ramflux_itest, not(ramflux_production)))]
    if applied && refused {
        super::refresh_barrier::refused().await?;
    }
    #[cfg(not(all(feature = "itest-local-mint", ramflux_itest, not(ramflux_production))))]
    let _ = (applied, refused);
    Ok(())
}
async fn send_controls(
    context: &SessionContext,
    writer: &Writer,
    id: &str,
) -> Result<bool, SdkError> {
    let owned_id = id.to_owned();
    let Some(prepared) = writer.apply(move |account| prepare(account, &owned_id)).await? else {
        return Ok(false);
    };
    let plan = prepared.plan;
    if plan.original.retry_at > now_unix_timestamp() {
        return Ok(false);
    }
    let result = async {
        if plan.original.pending.is_empty() {
            return Ok(false);
        }
        let input = prepared.input?;
        let manifest =
            federation::manifest(context, &plan.config, &input.root, input.federation.as_ref())
                .await?;
        let captured = plan.clone();
        let controls =
            writer.apply(move |account| prepare_controls(account, &captured, manifest)).await?;
        let Some(controls) = controls else { return Ok(false) };
        for mut control in controls {
            let request = std::mem::replace(
                &mut control.request,
                SendMaterialRequest { root: None, prekey: None },
            );
            let material = federation::material(
                context,
                &plan.config,
                request,
                control.target.federation.as_ref(),
            )
            .await?;
            let route = control.target.federation.clone();
            let envelope =
                writer.apply(move |account| seal_control(account, control, material)).await?;
            let Some(envelope) = envelope else { return Ok(false) };
            federation::submit(context, envelope, route).await?;
        }
        Ok(true)
    }
    .await;
    let success = result.is_ok();
    writer
        .apply(move |account| {
            if !current(account, &plan)? {
                return Ok(());
            }
            let now = now_unix_timestamp();
            let mut next = plan.original;
            if success {
                next.pending.clear();
                next.retry_attempts = 0;
                next.retry_at = 0;
            } else {
                next.retry_attempts = next.retry_attempts.saturating_add(1);
                next.retry_at =
                    now.saturating_add(1_i64 << next.retry_attempts.saturating_sub(1).min(4));
                if next.row.state == "ended"
                    && now.saturating_sub(next.row.ended_at.unwrap_or(now)) >= 60
                {
                    next.pending.clear();
                }
            }
            install(account, next)
        })
        .await?;
    result
}
fn prepare_controls(
    account: &LocalBusAccountState,
    plan: &Plan,
    manifest: crate::SdkDeviceManifestResponse,
) -> Result<Option<Vec<Control>>, SdkError> {
    if !current(account, plan)? {
        return Ok(None);
    }
    account.client.require_native_operation(
        &account.client.owned_device_identity()?,
        NativeOperation::Call,
    )?;
    let targets = {
        account.client.persist_fetched_identity_directory(&manifest)?;
        task_transport::direct_targets_from_manifest(account, &plan.thread, manifest)
    }?;
    let mut controls = Vec::new();
    for mut control in plan.original.pending.clone() {
        let recipient = if control.sender == control.caller {
            &control.callee.device_id
        } else {
            &control.caller.device_id
        };
        let target = targets
            .iter()
            .find(|target| target.device == *recipient)
            .ok_or_else(|| invalid("call target no longer active"))?
            .clone();
        control.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &call::signing_bytes(&control)?,
            account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        );
        let bytes = call::bytes(&control)?;
        let id = crate::new_surface_message_id()?;
        let message = GatewayDirectMessage {
            conversation_id: plan.original.row.conversation_id.clone(),
            message_id: id.clone(),
            envelope_id: id,
            source_principal_id: plan.config.principal_id.clone(),
            sender_id: plan.config.device_id.clone(),
            recipient_device_id: Some(target.device.clone()),
            recipient_principal_commitment: Some(target.identity.root_commitment().into()),
            target_delivery_id: target.delivery.clone(),
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 3600,
        };
        let request = account.client.routed_send_material_request(&plan.config, &message)?;
        controls.push(Control { plan: plan.clone(), target, message, bytes, request });
    }
    Ok(Some(controls))
}
fn seal_control(
    account: &LocalBusAccountState,
    mut control: Control,
    material: SendMaterial,
) -> Result<Option<ramflux_protocol::Envelope>, SdkError> {
    if !current(account, &control.plan)? {
        return Ok(None);
    }
    account.client.require_native_operation(
        &account.client.owned_device_identity()?,
        NativeOperation::Call,
    )?;
    task_transport::direct_target_input(account, &control.plan.thread)?;
    let sealed = account.client.seal_routed_prepared(
        &control.plan.config,
        &control.message,
        &control.bytes,
        crate::client::routed::Route::control(),
        material,
    )?;
    control.message.encrypted_body = serde_json::to_vec(&sealed)?;
    crate::dm::gateway_direct_message_envelope(&control.plan.config, &control.message, None)
        .map(Some)
}
async fn release(context: &SessionContext, writer: &Writer, id: &str) -> Result<(), SdkError> {
    let owned_id = id.to_owned();
    let Some(prepared) = writer.apply(move |account| prepare(account, &owned_id)).await? else {
        return Ok(());
    };
    let plan = prepared.plan;
    let now = now_unix_timestamp();
    if plan.original.release_until <= now.unsigned_abs() || plan.original.next_lease_refresh > now {
        return Ok(());
    }
    let request = VoiceLeaseRequest::Release { scope: scope(&plan.original) };
    let result = context
        .call(
            move |engine| Box::pin(async move { engine.voice_lease(request).await }),
            context.call_deadline(),
        )
        .await;
    writer
        .apply(move |account| {
            if !current(account, &plan)? {
                return Ok(());
            }
            let mut next = plan.original;
            if result.is_ok() {
                next.release_until = 0;
            } else {
                next.next_lease_refresh = now_unix_timestamp().saturating_add(5);
            }
            install(account, next)
        })
        .await
}
