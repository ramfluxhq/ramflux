// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent call signaling and lease exchanges with whole-call snapshot fences.

use super::{invalid, recover, scope};
use crate::bus::dispatch::task_transport::{self, DirectTargetInput, Target};
use crate::bus::{
    connection_manager::SessionContext,
    couriers::{federation, writer::Writer},
};
use crate::client::identity_authority::HeadUse;
use crate::client::{
    call::{self, state::LiveCall},
    identity_authority::NativeOperation,
    routed::{SendMaterial, SendMaterialRequest},
};
use crate::prelude::*;
use ramflux_protocol::{
    VoiceCallFailureReason, VoiceLeaseConsent, VoiceLeaseRequest, VoiceLeaseResponse,
};

/// Typed refusal from `GatewaySessionEngine` when the established session carries no call
/// resolution generation (the node has no call authority configured).
const CALL_RESOLUTION_NOT_NEGOTIATED: &str = "call_resolution_not_negotiated";
/// Gateway NACK when the attached call intent does not verify. The envelope was not posted.
const CALL_INTENT_REJECTED: &str = "call intent rejected";

#[derive(Clone)]
struct Plan {
    original: LiveCall,
    thread: serde_json::Value,
    config: crate::SealingConfig,
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
    extras: crate::gateway::engine::CallSubmitExtras,
    deadline: tokio::time::Instant,
}
struct SignedControl {
    id: String,
    extras: crate::gateway::engine::CallSubmitExtras,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    intent_created_at: Option<i64>,
}
struct ControlOutcome {
    success: bool,
    /// The session's gateway granted no call-resolution generation: no control can be submitted.
    not_negotiated: bool,
    sent: bool,
    acknowledged: Option<String>,
    resolutions: Vec<crate::gateway::call_resolution::CallSubmitOutcome>,
    #[cfg(feature = "test-support")]
    error: Option<String>,
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
        let promote_id = id.clone();
        writer.apply(move |account| promote_requested_answer(account, &promote_id)).await?;
        let owned_id = id.clone();
        let prepared = writer.apply(move |account| prepare(account, &owned_id)).await?;
        let Some(prepared) = prepared else { continue };
        let lease_due = !prepared.plan.original.media_lost()
            && !prepared.plan.original.media_held
            && prepared.plan.original.next_lease_refresh <= now_unix_timestamp()
            && matches!(prepared.plan.original.row.state.as_str(), "connecting" | "active");
        let manifest = if lease_due {
            match prepared.input {
                Ok(input) => {
                    federation::manifest_for_route(
                        &context,
                        &writer,
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
        let sent = Box::pin(send_controls(&context, &writer, &id)).await;
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
        plan: Plan { original: call.clone(), thread, config: account.sealing_config()? },
        input,
    }))
}
fn current(account: &LocalBusAccountState, plan: &Plan) -> Result<bool, SdkError> {
    Ok(account
        .client
        .voice_calls
        .get(&plan.original.row.call_id)
        .is_some_and(|live| live.same_signaling(&plan.original))
        && account
            .client
            .account_db()?
            .client_record("conversation", &plan.original.row.conversation_id)?
            .as_ref()
            == Some(&plan.thread))
}
fn promote_requested_answer(account: &mut LocalBusAccountState, id: &str) -> Result<(), SdkError> {
    let Some(call) = account.client.voice_calls.get(id) else { return Ok(()) };
    if call.held_answer != call::state::HeldAnswer::Requested
        || call.media_held
        || call.row.state != "incoming_ringing"
    {
        return Ok(());
    }
    let mut next = call.clone();
    next.queue_requested_answer(now_unix_timestamp())?;
    if next.row.state == "incoming_ringing" {
        return Ok(());
    }
    install(account, next)
}
fn install(account: &mut LocalBusAccountState, mut next: LiveCall) -> Result<(), SdkError> {
    if next.row.state == "incoming_ringing"
        && account
            .client
            .voice_calls
            .get(&next.row.call_id)
            .is_some_and(|old| old.held_answer == call::state::HeldAnswer::Requested)
    {
        next.held_answer = call::state::HeldAnswer::Requested;
    }
    if account.client.voice_calls.get(&next.row.call_id).is_none_or(|old| old.row != next.row) {
        account
            .client
            .account_db()?
            .write_transaction(|| account.client.persist_live_call(&next))?;
    }
    account.client.voice_calls.insert(next.row.call_id.clone(), next);
    crate::bus::media::reconcile(account);
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
        || next.media_held
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
    let record =
        match account.client.call_device_identity(peer).and_then(|identity| {
            account.client.trusted_device(HeadUse::NewAuthorization, &identity)
        }) {
            Ok(record) => record,
            Err(error) if crate::error_policy::approval_retryable(&error) => return Err(error),
            Err(_) => {
                next.fail(VoiceCallFailureReason::AuthorityRefused, now)?;
                install(account, next)?;
                return Ok(None);
            }
        };
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
    let request = lease.request;
    let result = context
        .priority_call(
            move |engine| Box::pin(async move { engine.voice_lease(request).await }),
            context.call_deadline().saturating_duration_since(tokio::time::Instant::now()),
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
            super::lease_outcome::apply_result(&mut next, result, lease.consent, now)?;
            install(account, next)?;
            Ok(true)
        })
        .await?;

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
    let result = Box::pin(async {
        if plan.original.pending.is_empty() {
            return Ok((false, None, Vec::new()));
        }
        let input = prepared.input?;
        let manifest = federation::manifest_for_route(
            context,
            writer,
            &plan.config,
            &input.root,
            input.federation.as_ref(),
        )
        .await?;
        let captured = plan.clone();
        let controls =
            writer.apply(move |account| prepare_controls(account, &captured, manifest)).await?;
        let Some(controls) = controls else { return Ok((false, None, Vec::new())) };
        let mut acknowledged = None;
        let mut resolutions = Vec::new();
        for control in controls {
            let call_ref = control.extras.call_ref.clone();
            let delivered =
                Box::pin(deliver_control(context, writer, &input.root, control)).await?;
            let Delivered::Posted(resolved) = delivered else {
                return Ok((false, None, Vec::new()));
            };
            if let Some(resolved) = resolved {
                resolutions.push(*resolved);
            }
            if acknowledged.is_none() {
                acknowledged = call_ref;
            }
        }
        Ok((true, acknowledged, resolutions))
    })
    .await;
    let outcome = ControlOutcome {
        #[cfg(feature = "test-support")]
        error: result.as_ref().err().map(ToString::to_string),
        success: result.is_ok(),
        not_negotiated: matches!(
            &result,
            Err(SdkError::GatewaySessionRejected(reason))
                if reason == CALL_RESOLUTION_NOT_NEGOTIATED
        ),
        sent: result.as_ref().is_ok_and(|(sent, _, _)| *sent),
        acknowledged: result.as_ref().ok().and_then(|(_, call_ref, _)| call_ref.clone()),
        resolutions: result
            .as_ref()
            .map(|(_, _, resolutions)| resolutions.clone())
            .unwrap_or_default(),
    };
    writer.apply(move |account| note_control_result(account, &plan, &outcome)).await?;
    result.map(|(sent, _, _)| sent)
}

enum Delivered {
    Unsealed,
    Posted(Option<Box<crate::gateway::call_resolution::CallSubmitOutcome>>),
}

async fn deliver_control(
    context: &SessionContext,
    writer: &Writer,
    input_root: &str,
    mut control: Control,
) -> Result<Delivered, SdkError> {
    let request =
        std::mem::replace(&mut control.request, SendMaterialRequest { root: None, prekey: None });
    let material = federation::material_for_route(
        context,
        &control.plan.config,
        request,
        crate::bus::connection_manager::CallClass::Priority,
        federation::HomeLookup {
            writer,
            commitment: input_root,
            route: control.target.federation.as_ref(),
        },
    )
    .await?;
    let route = control.target.federation.clone();
    let extras = std::mem::replace(
        &mut control.extras,
        crate::gateway::engine::CallSubmitExtras::from_intent(None),
    );
    let deadline = control.deadline;
    let envelope = writer.apply(move |account| seal_control(account, control, material)).await?;
    let Some(envelope) = envelope else {
        return Ok(Delivered::Unsealed);
    };
    if route.is_some() {
        let route = federation::pinned_submit_route(writer, input_root, route).await?;
        federation::submit_until(context, envelope, route, context.call_deadline(), true).await?;
        return Ok(Delivered::Posted(None));
    }
    submit_home_control(context, envelope, deadline, extras).await
}

/// One home submit. A rejected intent is retried once without it: that NACK is before post.
async fn submit_home_control(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
    deadline: tokio::time::Instant,
    extras: crate::gateway::engine::CallSubmitExtras,
) -> Result<Delivered, SdkError> {
    let bare = extras.call_intent.is_some().then(|| {
        let mut bare = extras.clone();
        bare.call_intent = None;
        bare
    });
    let retry = bare.as_ref().map(|_| envelope.clone());
    let until = context.call_deadline().min(deadline);
    match federation::submit_local_call(context, envelope, until, extras).await {
        Ok(resolved) => Ok(Delivered::Posted(Some(Box::new(resolved)))),
        Err(SdkError::GatewaySessionRejected(reason)) if reason == CALL_INTENT_REJECTED => {
            let (Some(bare), Some(envelope)) = (bare, retry) else {
                return Err(SdkError::GatewaySessionRejected(reason));
            };
            let resolved = federation::submit_local_call(context, envelope, until, bare).await?;
            Ok(Delivered::Posted(Some(Box::new(resolved))))
        }
        Err(error) => Err(error),
    }
}

fn note_control_result(
    account: &mut LocalBusAccountState,
    plan: &Plan,
    outcome: &ControlOutcome,
) -> Result<(), SdkError> {
    if !current_control_result(account, plan, outcome)? {
        return Ok(());
    }
    let now = now_unix_timestamp();
    let expected_actions = plan
        .original
        .pending
        .iter()
        .map(crate::gateway::call_resolution::CallOperationAction::from_control)
        .collect::<std::collections::BTreeSet<_>>();
    let mut next = account
        .client
        .voice_calls
        .get(&plan.original.row.call_id)
        .cloned()
        .ok_or_else(|| invalid("call completion lost its live owner"))?;
    #[cfg(feature = "test-support")]
    {
        next.last_control_error.clone_from(&outcome.error);
    }
    if outcome.success && outcome.sent {
        // Receiving Ringing or Answer may advance the caller while this submit
        // completes. Keep that state and any controls queued after this batch.
        next.pending.retain(|control| !plan.original.pending.contains(control));
        next.retry_attempts = 0;
        next.retry_at = 0;
        if outcome.acknowledged.is_some() {
            apply_sent_resolutions(account, &mut next, &expected_actions, outcome, now)?;
        }
    } else if outcome.success {
        // The control was not posted. Keep it pending so a hangup is retried.
    } else if outcome.not_negotiated && next.row.state != "ended" {
        // Retrying cannot help within a ring window; report the real cause, not a timeout.
        tracing::warn!("call failed: the home node did not negotiate call resolution");
        next.fail(VoiceCallFailureReason::SignalingUnavailable, now)?;
    } else {
        next.retry_attempts = next.retry_attempts.saturating_add(1);
        next.retry_at = now.saturating_add(1_i64 << next.retry_attempts.saturating_sub(1).min(4));
        if next.row.state == "ended" && now.saturating_sub(next.row.ended_at.unwrap_or(now)) >= 60 {
            next.pending.clear();
        }
    }
    next.queue_requested_answer(now)?;
    install(account, next)
}

fn current_control_result(
    account: &LocalBusAccountState,
    plan: &Plan,
    outcome: &ControlOutcome,
) -> Result<bool, SdkError> {
    if current(account, plan)? {
        return Ok(true);
    }
    let Some(live) = account.client.voice_calls.get(&plan.original.row.call_id) else {
        return Ok(false);
    };
    // Only a delivered caller batch can merge across received peer controls.
    // A changed authority generation, terminal call, invitation roster, local
    // media loss, conversation or pending batch still invalidates completion.
    let applies = outcome.success
        && outcome.sent
        && plan.original.local == plan.original.caller
        && plan.original.row.state != "ended"
        && live.row.state != "ended"
        && live.local_generation == plan.original.local_generation
        && live.gateway_generation == plan.original.gateway_generation
        && live.invited == plan.original.invited
        && live.media_lost() == plan.original.media_lost()
        && plan.original.pending.iter().all(|control| live.pending.contains(control))
        && account
            .client
            .account_db()?
            .client_record("conversation", &plan.original.row.conversation_id)?
            .as_ref()
            == Some(&plan.thread);
    if applies {
        tracing::debug!("call completion retained received peer controls");
    }
    Ok(applies)
}

struct BoundStart {
    peer: ramflux_protocol::CallEndpoint,
    digest: String,
    start: ramflux_protocol::SignedCallIntentV1,
}

fn apply_sent_resolutions(
    account: &LocalBusAccountState,
    next: &mut LiveCall,
    expected_actions: &std::collections::BTreeSet<
        crate::gateway::call_resolution::CallOperationAction,
    >,
    outcome: &ControlOutcome,
    now: i64,
) -> Result<(), SdkError> {
    let peers =
        if next.local == next.caller { next.invited.clone() } else { vec![next.caller.clone()] };
    let mut bindings = Vec::new();
    for peer in peers {
        let Some(start) = call::intent::start_for_control(account, next, &peer.device_id)? else {
            continue;
        };
        let origin_identity = account.client.call_device_identity(&next.caller)?;
        let destination = if next.local == next.caller { &peer } else { &next.local };
        let target_identity = account.client.call_device_identity(destination)?;
        if start.body.sender_device == origin_identity.storage_key()
            && start.body.target_device == target_identity.storage_key()
        {
            bindings.push(BoundStart {
                peer,
                digest: ramflux_protocol::call_intent_digest(&start)?,
                start,
            });
        }
    }
    for resolved in &outcome.resolutions {
        apply_one_resolution(account, next, expected_actions, resolved, &bindings, now)?;
    }
    Ok(())
}

fn apply_one_resolution(
    account: &LocalBusAccountState,
    next: &mut LiveCall,
    expected_actions: &std::collections::BTreeSet<
        crate::gateway::call_resolution::CallOperationAction,
    >,
    resolved: &crate::gateway::call_resolution::CallSubmitOutcome,
    bindings: &[BoundStart],
    now: i64,
) -> Result<(), SdkError> {
    let Some(bound) = bindings.iter().find(|bound| {
        resolved.context.start_digest == bound.digest
            && resolved.context.call_ref == bound.start.body.call_ref
    }) else {
        return Ok(());
    };
    if !live_resolution(account, resolved)
        || !expected_actions.contains(&resolved.action)
        || next.expired(now)
        || next.row.state == "ended"
    {
        return Ok(());
    }
    if matches!(
        resolved.decision.state,
        ramflux_protocol::CallResolutionState::Ended
            | ramflux_protocol::CallResolutionState::Cancelled
    ) {
        let reason = if next.row.answered_at.is_some() {
            "completed"
        } else if next.local == next.caller {
            "cancelled"
        } else {
            "missed"
        };
        return next.finish(reason, now);
    }
    // New calls are created after the connection is installed. Bind only the
    // authenticated, current operation's generation before releasing media.
    next.bind_gateway_generation(Some(&resolved.context.session_generation))?;
    let allowed = resolved.permits_media();
    next.apply_media_for(
        bound.peer.clone(),
        &bound.start,
        allowed,
        allowed && resolved.decision.state == ramflux_protocol::CallResolutionState::Answered,
    )
}

fn live_resolution(
    account: &LocalBusAccountState,
    resolved: &crate::gateway::call_resolution::CallSubmitOutcome,
) -> bool {
    account.connection.as_ref().is_some_and(|handle| {
        let snapshot = handle.snapshot();
        handle.metadata().is_some_and(|metadata| {
            snapshot.state == crate::bus::connection_manager::NetworkingState::Live
                && metadata.generation == snapshot.generation
                && metadata.session.session_id == resolved.context.session_id
                && metadata.session.call_session_generation.as_ref()
                    == Some(&resolved.context.session_generation)
        })
    })
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
    let device_epochs = manifest
        .devices
        .iter()
        .map(|device| (device.device_id.clone(), device.device_epoch))
        .collect::<Vec<_>>();
    let targets = addressable_targets(account, plan, manifest)?;
    let now = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let mut controls = Vec::new();
    for control in plan.original.pending.clone() {
        controls.push(bind_pending_control(account, plan, &targets, &device_epochs, control, now)?);
    }
    Ok(Some(controls))
}

fn addressable_targets(
    account: &LocalBusAccountState,
    plan: &Plan,
    manifest: crate::SdkDeviceManifestResponse,
) -> Result<Vec<Target>, SdkError> {
    account.client.persist_fetched_identity_directory(&manifest)?;
    match task_transport::direct_targets_from_manifest(account, &plan.thread, manifest) {
        Ok(targets) => Ok(targets),
        Err(SdkError::TaskRefused { message, .. }) if message == "task peer root changed" => {
            Ok(Vec::new())
        }
        Err(error) => Err(error),
    }
}

fn bind_pending_control(
    account: &LocalBusAccountState,
    plan: &Plan,
    targets: &[Target],
    device_epochs: &[(String, u64)],
    mut control: ramflux_protocol::CallControl,
    now: u64,
) -> Result<Control, SdkError> {
    let (target, pinned_epoch) = recipient_target(account, plan, targets, &control)?;
    let epoch = pinned_epoch.or_else(|| {
        device_epochs.iter().find(|(id, _)| id == &target.device).map(|(_, epoch)| *epoch)
    });
    let prepared = if target.federation.is_none()
        && let Some(epoch) = epoch
    {
        call::intent::bind_call_intent(
            account,
            &control,
            &call::intent::IntentTarget {
                device_id: target.device.clone(),
                qualified_device: target.identity.storage_key().to_owned(),
                epoch,
                delivery_id: target.delivery.clone(),
            },
            now,
        )?
    } else {
        None
    };
    if let Some(prepared) = prepared.as_ref() {
        control.call_ref = Some(prepared.signed.body.call_ref.clone());
        if matches!(control.body, ramflux_protocol::CallAction::Invite { .. }) {
            control.call_start = Some(prepared.signed.clone());
        }
    }
    let stored_start = call::intent::start_for_control(account, &plan.original, &target.device)?;
    let bound_start = control.call_start.as_ref().or(stored_start.as_ref());
    let start_digest = bound_start.map(ramflux_protocol::call_intent_digest).transpose()?;
    let mut deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    if !plan.original.gateway_answered
        && let Some(start) = bound_start
    {
        deadline = deadline.min(
            tokio::time::Instant::now()
                + std::time::Duration::from_secs(start.body.expires_at.saturating_sub(now)),
        );
    }
    // Fan-out controls bind their actual recipient, including a losing sibling.
    control.call_ref = bound_start.map(|start| start.body.call_ref.clone());
    let signed = sign_control(account, &mut control, prepared, start_digest)?;
    let message = GatewayDirectMessage {
        conversation_id: plan.original.row.conversation_id.clone(),
        message_id: signed.id.clone(),
        envelope_id: signed.id,
        source_principal_id: plan.config.config().principal_id.clone(),
        sender_id: plan.config.config().device_id.clone(),
        recipient_device_id: Some(target.device.clone()),
        recipient_principal_commitment: Some(target.identity.root_commitment().into()),
        target_delivery_id: target.delivery.clone(),
        encrypted_body: Vec::new(),
        created_at: signed.intent_created_at.unwrap_or_else(now_unix_timestamp),
        ttl: crate::offline_retention::CALL_SIGNAL_TTL_SECS,
    };
    let request = account.client.routed_send_material_request(&plan.config, &message)?;
    Ok(Control {
        plan: plan.clone(),
        target,
        message,
        bytes: signed.bytes,
        request,
        extras: signed.extras,
        deadline,
    })
}

fn recipient_target(
    account: &LocalBusAccountState,
    plan: &Plan,
    targets: &[Target],
    control: &ramflux_protocol::CallControl,
) -> Result<(Target, Option<u64>), SdkError> {
    let endpoint = if control.sender == control.caller { &control.callee } else { &control.caller };
    if let Some(target) = targets.iter().find(|target| target.device == endpoint.device_id) {
        return Ok((target.clone(), None));
    }
    let federation = task_transport::direct_target_input(account, &plan.thread)
        .ok()
        .and_then(|input| input.federation);
    pinned_device(account, endpoint, federation)?
        .ok_or_else(|| invalid("call target no longer active"))
}

fn pinned_device(
    account: &LocalBusAccountState,
    endpoint: &ramflux_protocol::CallEndpoint,
    federation: Option<crate::bus::protocol::LocalBusFederationRoute>,
) -> Result<Option<(Target, Option<u64>)>, SdkError> {
    let root = crate::identity_root_public_key_commitment(&endpoint.root_public_key)?;
    let stored =
        account.client.account_db()?.load_actor_state::<crate::SdkDeviceManifestResponse>(
            &format!("identity/manifest-root/{root}"),
        )?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let Some(device) =
        stored.devices.into_iter().find(|device| device.device_id == endpoint.device_id)
    else {
        return Ok(None);
    };
    let epoch = device.device_epoch;
    let identity =
        account.client.device_identity_for_root(&device.principal_commitment, &device.device_id)?;
    Ok(Some((
        Target {
            device: device.device_id,
            identity,
            delivery: device.target_delivery_id,
            federation,
            own: false,
        },
        Some(epoch),
    )))
}
fn sign_control(
    account: &LocalBusAccountState,
    control: &mut ramflux_protocol::CallControl,
    prepared: Option<call::intent::BoundCallIntent>,
    start_digest: Option<String>,
) -> Result<SignedControl, SdkError> {
    control.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &call::signing_bytes(control)?,
        account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
    );
    let bytes = call::bytes(control)?;
    let intent_created_at =
        prepared.as_ref().and_then(|bound| i64::try_from(bound.signed.body.created_at).ok());
    let (id, call_intent) = match prepared {
        Some(prepared) => (prepared.envelope_id, Some(prepared.signed)),
        None => (crate::new_surface_message_id()?, None),
    };
    let extras = crate::gateway::engine::CallSubmitExtras {
        action: Some(crate::gateway::call_resolution::CallOperationAction::from_control(control)),
        start_digest,
        call_intent,
        wake_id: None,
        call_ref: control.call_ref.clone(),
        call_terminal: call::resolution_terminal(control),
        target_node: None,
    };
    Ok(SignedControl { id, extras, bytes, intent_created_at })
}

fn seal_control(
    account: &LocalBusAccountState,
    mut control: Control,
    material: SendMaterial,
) -> Result<Option<ramflux_protocol::Envelope>, SdkError> {
    use prost::Message as _;
    use ramflux_protocol::message as g;
    if !current(account, &control.plan)? {
        return Ok(None);
    }
    account.client.require_native_operation(
        &account.client.owned_device_identity()?,
        NativeOperation::Call,
    )?;
    task_transport::direct_target_input(account, &control.plan.thread)?;

    let call =
        g::Call::decode(control.bytes.as_slice()).map_err(|_| invalid("invalid typed Call"))?;
    let prepared = account.client.prepare_authored_content(
        &mut control.message,
        None,
        &g::Content { value: Some(g::content::Value::Call(call)) },
    )?;
    let sealed = account.client.seal_routed_prepared(
        &control.plan.config,
        &control.message,
        &prepared.wire,
        crate::client::routed::Route::control(),
        material,
    )?;
    crate::dm::gateway_generated_envelope_from_sealed(
        &control.plan.config,
        &mut control.message,
        sealed,
    )
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
        .priority_call(
            move |engine| Box::pin(async move { engine.voice_lease(request).await }),
            context.call_deadline().saturating_duration_since(tokio::time::Instant::now()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transient_manifest_fetch_preserves_call_lease_and_contact_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, mut state, id) =
            crate::bus::dispatch::call::tests::fixture("call-directory-retry")?;
        let account = state.accounts.get_mut("alice").ok_or("account")?;
        account.client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &serde_json::json!({"id":"thread"}),
        )?;
        let call = account.client.voice_calls.get_mut(&id).ok_or("call")?;
        call.next_lease_refresh = 0;
        let original = call.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);
        let certified = rcgen::generate_simple_self_signed(vec!["retry.test".into()])?;
        let ca = root.join("retry-ca.pem");
        std::fs::write(&ca, certified.cert.pem())?;
        let mut config = account.sealing_config()?.config().clone();
        config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
        config.gateway_addr = address;
        config.tcp_gateway_addr = Some(address);
        config.server_name = "retry.test".into();
        config.ca_cert = ca;
        let (handle, _io) = crate::bus::connection_manager::tests::fixture().await?;
        let outcome =
            federation::manifest(&handle.test_context(), &config, "peer-root", None).await;
        let error = outcome.as_ref().err().ok_or("fetch must fail")?;
        assert!(
            crate::error_policy::approval_retryable(error),
            "shared manifest fetch must preserve transient classification: {error:?}"
        );
        let thread = account
            .client
            .account_db()?
            .client_record("conversation", "thread")?
            .ok_or("thread")?;
        assert!(
            prepare_lease(
                account,
                Plan {
                    original: original.clone(),
                    thread,
                    config: crate::bus::connection_manager::SessionMetadata::sealing_config_for(
                        &config,
                    )?,
                },
                outcome
            )?
            .is_none()
        );
        let next = account.client.voice_calls.get(&id).ok_or("call")?;
        assert_eq!(next.row.state, "active", "directory outage must not end an active call");
        assert!(next.next_lease_refresh >= now_unix_timestamp() + 4);
        let contact = crate::client::contact::fetch_verified_device_manifest(&config, "own-root")
            .await
            .err()
            .ok_or("fetch must fail")?;
        assert!(matches!(
            crate::client::contact_resolution::manifest_failure(contact),
            SdkError::ContactUnavailable(_)
        ));
        handle.stop().await;
        drop(state);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
