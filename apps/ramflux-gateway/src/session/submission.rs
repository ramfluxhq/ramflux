// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated session submission, own-device fanout and delivery wake dispatch.

use super::{
    Arc, GatewayForwardDeliverRequest, GatewayForwardDeliverResponse, GatewayPeerDirectory,
    GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime, Instant, SystemTime, UNIX_EPOCH,
    capture_itest_gateway_json, durable_rejection_reason, notify_offline_wake, post_signed_wake,
    router_post_json_async, router_session_async, validate_gateway_session_signed_request,
    write_gateway_handle,
};

/// Non-durable dispatch: `Ephemeral` on a session that negotiated it goes to the ephemeral
/// handler; everything else (not negotiated, unknown string, non-string) gets P03's live refusal.
async fn route_non_durable_submit(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> anyhow::Result<()> {
    use ramflux_protocol::ephemeral::{DeliveryMode, classify_delivery_mode};
    if classify_delivery_mode(&submit.envelope) == DeliveryMode::Ephemeral
        && crate::ephemeral::negotiated(runtime)
    {
        return crate::ephemeral::handle_submit(send, context, runtime, submit).await;
    }
    write_gateway_handle(send, &crate::durable_mode::nack_frame()).await?;
    Ok(())
}

async fn validate_durable_submit(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> anyhow::Result<ramflux_protocol::Envelope> {
    let owned_runtime = runtime.clone();
    let owned_submit = submit.clone();
    crate::durable_work::run(context, Some(&runtime.source_identity), move |context| {
        let envelope = crate::submit_source::bind_source(&owned_runtime, &owned_submit.envelope)?;
        let body = crate::call_intent::authenticated_submit_body(&owned_runtime, &owned_submit)?;
        validate_gateway_session_signed_request(
            context,
            &owned_runtime,
            &owned_submit.signed_request,
            "POST",
            "/gateway/session/submit",
            &body,
        )?;
        Ok(envelope)
    })
    .await
}

pub(crate) async fn handle_gateway_submit(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> anyhow::Result<()> {
    if ramflux_protocol::ephemeral::require_durable(&submit.envelope).is_err() {
        return route_non_durable_submit(send, context, runtime, submit).await;
    }
    let validated = validate_durable_submit(context, runtime, submit).await;
    let mut envelope = match validated {
        Ok(envelope) => envelope,
        Err(error) => {
            write_gateway_handle(
                send,
                &ramflux_node_core::GatewayServerFrame::Nack {
                    reason: durable_rejection_reason("submit source rejected", &error),
                },
            )
            .await?;
            return Ok(());
        }
    };
    if !enforce_call_resolution(send, context, runtime, submit).await? {
        return Ok(());
    }
    let verified_intent =
        match check_submit_intent(send, context, runtime, submit, &envelope).await? {
            CheckedSubmitIntent::Answered => return Ok(()),
            CheckedSubmitIntent::Continue(verified) => verified,
        };
    let accepted_at_unix_ms = now_unix_millis();
    if let Err(error) = attach_franking_node_tag(
        &mut envelope,
        &context.node_id,
        &context.notify.signer,
        accepted_at_unix_ms,
    ) {
        tracing::warn!(%error, envelope_id = %envelope.envelope_id, "gateway franking tag not attached");
    }
    capture_itest_gateway_json(
        "submit",
        &serde_json::json!({
            "path": "/gateway/session/submit",
            "envelope": &envelope,
        }),
    );
    let decision = crate::submit_target::route_frame(&context.node_id, submit);
    if let crate::submit_target::Route::Refused(reason) = decision {
        write_gateway_handle(
            send,
            &ramflux_node_core::GatewayServerFrame::Nack { reason: reason.to_owned() },
        )
        .await?;
        return Ok(());
    }
    let mesh: serde_json::Value =
        crate::submit_target::post(&context.router, decision, &envelope).await?;
    let response: ramflux_node_core::EnvelopeSubmitResponse = serde_json::from_value(mesh.clone())?;
    if !admit_or_defer_call_intent(
        send,
        context,
        runtime,
        submit,
        verified_intent.as_ref(),
        response.outcome.as_str(),
    )
    .await?
    {
        return Ok(());
    }
    let metadata = crate::session_push::metadata(
        &mesh,
        runtime.session_push.is_some()
            && matches!(response.outcome.as_str(), "online" | "offline_queued"),
    )?;
    if response.outcome == "incarnation_mismatch"
        && let Some(id) = runtime.session_push.as_deref()
    {
        context.hub.retire_incarnation(&runtime.target_delivery_id, id, send).await;
        return Err(crate::session_push::Retired.into());
    }
    finish_accepted_submit(
        send,
        context,
        runtime,
        AcceptedSubmit { submit, response: &response, envelope, metadata: metadata.as_ref() },
    )
    .await
}

struct AcceptedSubmit<'a> {
    submit: &'a ramflux_node_core::GatewaySubmitFrame,
    response: &'a ramflux_node_core::EnvelopeSubmitResponse,
    envelope: ramflux_protocol::Envelope,
    metadata: Option<&'a (String, i64)>,
}

async fn finish_accepted_submit(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    accepted: AcceptedSubmit<'_>,
) -> anyhow::Result<()> {
    if nack_refused_submit(send, &accepted.response.outcome).await? {
        return Ok(());
    }
    if crate::submit_target::ack_home_forward(send, runtime, accepted.response, &accepted.envelope)
        .await?
    {
        return Ok(());
    }
    if reply_if_home_migrated(send, runtime, accepted.response, &accepted.envelope).await? {
        return Ok(());
    }
    if !commit_owner_resolution(
        send,
        context,
        runtime,
        accepted.submit,
        accepted.response.outcome.as_str(),
    )
    .await?
    {
        return Ok(());
    }
    // The router response confirms the durable submit. A recipient can ACK and remove its
    // pending entry before this task resumes, so the inbox is not a submit receipt store.
    let entry = committed_submit_entry(accepted.response, accepted.envelope)?;
    let frame = ramflux_node_core::GatewayServerFrame::Deliver { entry };
    capture_itest_gateway_json(
        "deliver",
        &serde_json::json!({
            "path": "/gateway/session/deliver",
            "frame": &frame,
        }),
    );
    reply_and_deliver_submitted(
        send,
        context,
        runtime,
        accepted.response,
        &frame,
        accepted.metadata,
    )
    .await
}

enum CheckedSubmitIntent {
    Answered,
    Continue(Option<crate::call_intent::VerifiedIntent>),
}

/// `true` when the submit may continue. A refusal is already written to `send`.
///
/// Caller-signed intents keep the existing admission path. A callee submit that names a
/// wake id, call reference, or terminal action must resolve as the authenticated device.
pub(crate) async fn enforce_call_resolution(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
) -> anyhow::Result<bool> {
    if submit.call_intent.is_some()
        || (submit.wake_id.is_none() && submit.call_ref.is_none() && submit.call_terminal.is_none())
    {
        return Ok(true);
    }
    let now = ramflux_node_core::now_unix_seconds();
    let owner_device = runtime.source_identity.storage_key();
    let lookup = ramflux_node_core::WakeOwnerLookup {
        owner_device,
        owner_epoch: runtime.device_epoch,
        wake_id: submit.wake_id.as_deref(),
        call_ref: submit.call_ref.as_deref(),
        now,
    };
    let Some(call_context) = submit.call_context.as_ref() else {
        nack_call_resolution(send).await?;
        return Ok(false);
    };
    if context
        .store
        .resolve_call_context(call_context, owner_device, runtime.device_epoch, now)
        .is_err()
    {
        nack_call_resolution(send).await?;
        return Ok(false);
    }
    if context.store.validate_call_owner_context(&lookup, call_context).is_err() {
        nack_call_resolution(send).await?;
        return Ok(false);
    }
    match context.store.owner_terminal_permitted(&lookup, submit.call_terminal.as_deref()) {
        Ok(Some(())) => Ok(true),
        Ok(None) => {
            nack_call_resolution(send).await?;
            Ok(false)
        }
        Err(ramflux_node_core::NodeCoreError::InvalidConfiguration(reason))
            if reason == "call resolution refused" =>
        {
            nack_call_resolution(send).await?;
            Ok(false)
        }
        Err(error) => Err(anyhow::anyhow!(error)),
    }
}

pub(crate) async fn commit_owner_resolution(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
    outcome: &str,
) -> anyhow::Result<bool> {
    if submit.call_context.is_none() {
        return Ok(true);
    }
    if !matches!(outcome, "online" | "offline_queued") {
        return Ok(true);
    }
    let (owned_runtime, owned_submit) = (runtime.clone(), submit.clone());
    let completion =
        crate::durable_work::run(context, Some(&runtime.source_identity), move |context| {
            crate::call_intent::complete_resolution(context, &owned_runtime, &owned_submit)
                .map_err(anyhow::Error::from)
        })
        .await;
    let completion = match completion {
        Ok(completion) => completion,
        Err(error) => {
            tracing::warn!(%error,"call resolution remains held");
            nack_call_resolution(send).await?;
            return Ok(false);
        }
    };
    let decision = completion.decision;
    write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::CallResolved {
            context: decision.context,
            state: decision.state,
            media_allowed: decision.media_allowed,
            wake_resolved: decision.wake_resolved,
        },
    )
    .await?;
    if let Some((start, digest, wake_id)) = completion.cancellation {
        dispatch_cancel_wake(context, &start, &digest, &wake_id, start.body.target_epoch).await;
    }
    Ok(true)
}

async fn nack_call_resolution(send: &GatewaySendHandle) -> anyhow::Result<()> {
    write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Nack {
            reason: "call resolution refused".to_owned(),
        },
    )
    .await
}

async fn check_submit_intent(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<CheckedSubmitIntent> {
    let Some(intent) = submit.call_intent.as_deref() else {
        return Ok(CheckedSubmitIntent::Continue(None));
    };
    let Some(owner) =
        crate::lookup_target_owner_epoch(&context.router, &envelope.target_delivery_id).await
    else {
        nack_call_intent(send).await?;
        return Ok(CheckedSubmitIntent::Answered);
    };
    match crate::call_intent::verify_submission(
        runtime,
        envelope,
        intent,
        owner.device_epoch,
        &owner.owner_device,
        ramflux_node_core::now_unix_seconds(),
    ) {
        Ok(verified) => Ok(CheckedSubmitIntent::Continue(Some(verified))),
        Err(_error) => {
            nack_call_intent(send).await?;
            Ok(CheckedSubmitIntent::Answered)
        }
    }
}

async fn nack_refused_submit(send: &GatewaySendHandle, outcome: &str) -> anyhow::Result<bool> {
    if !crate::session_push::submit_refused(outcome) {
        return Ok(false);
    }
    write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Nack { reason: outcome.to_owned() },
    )
    .await?;
    Ok(true)
}

async fn nack_call_intent(send: &GatewaySendHandle) -> anyhow::Result<()> {
    write_gateway_handle(
        send,
        &ramflux_node_core::GatewayServerFrame::Nack { reason: "call intent rejected".to_owned() },
    )
    .await
}

async fn admit_or_defer_call_intent(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
    verified: Option<&crate::call_intent::VerifiedIntent>,
    outcome: &str,
) -> anyhow::Result<bool> {
    if let Err(error) = persist_accepted_intent(
        context,
        runtime,
        submit,
        &submit.envelope.envelope_id,
        verified,
        outcome,
    )
    .await
    {
        if schedule_call_wake_after_delay(context, runtime, submit, verified, &error, outcome) {
            return Ok(true);
        }
        tracing::warn!(%error, "call intent admission failed");
        nack_call_intent(send).await?;
        return Ok(false);
    }
    Ok(true)
}

async fn persist_accepted_intent(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
    envelope_id: &str,
    verified: Option<&crate::call_intent::VerifiedIntent>,
    outcome: &str,
) -> anyhow::Result<()> {
    if !matches!(outcome, "online" | "offline_queued") {
        return Ok(());
    }
    let (Some(intent), Some(verified)) = (submit.call_intent.as_deref(), verified) else {
        return Ok(());
    };
    let request_expires_at = u64::try_from(submit.signed_request.expires_at)
        .map_err(|_| anyhow::anyhow!("call request expiry rejected"))?;
    match admit_signed_call(CallIntentRetry {
        context,
        runtime,
        intent,
        start_digest: &verified.start_digest,
        envelope_id,
        encrypted_payload: &submit.envelope.encrypted_payload,
        request_expires_at,
    })
    .await?
    {
        ramflux_node_core::CallIntentEffect::Cancelled { wake_id: Some(wake_id) } => {
            dispatch_cancel_wake(
                context,
                intent,
                &verified.start_digest,
                &wake_id,
                intent.body.target_epoch,
            )
            .await;
            Ok(())
        }
        ramflux_node_core::CallIntentEffect::Authorized
        | ramflux_node_core::CallIntentEffect::Cancelled { wake_id: None } => Ok(()),
    }
}

struct CallIntentRetry<'a> {
    context: &'a GatewayQuicContext,
    runtime: &'a GatewaySessionRuntime,
    intent: &'a ramflux_protocol::SignedCallIntentV1,
    start_digest: &'a str,
    envelope_id: &'a str,
    encrypted_payload: &'a str,
    request_expires_at: u64,
}

async fn admit_signed_call(
    retry: CallIntentRetry<'_>,
) -> anyhow::Result<ramflux_node_core::CallIntentEffect> {
    let (owned_intent, owned_digest, owned_envelope, source, epoch, ciphertext) = (
        retry.intent.clone(),
        retry.start_digest.to_owned(),
        retry.envelope_id.to_owned(),
        retry.runtime.source_identity.clone(),
        retry.runtime.device_epoch,
        retry.encrypted_payload.as_bytes().to_vec(),
    );
    let request_expires_at = retry.request_expires_at;
    crate::durable_work::run(retry.context, Some(&retry.runtime.source_identity), move |context| {
        Ok(context.store.admit_verified_call_intent_with_expiry(
            &ramflux_node_core::CallIntentAdmission {
                signed: &owned_intent,
                start_digest: &owned_digest,
                envelope_id: &owned_envelope,
                source_identity: source.storage_key(),
                source_epoch: epoch,
                encrypted_invite: &ciphertext,
            },
            request_expires_at,
        )?)
    })
    .await
}

fn call_authority_slow(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text.contains("mesh request deadline exceeded")
        || text.contains("send_authority_closed")
        || text.contains("call_authority_busy")
}

fn schedule_call_wake_after_delay(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    submit: &ramflux_node_core::GatewaySubmitFrame,
    verified: Option<&crate::call_intent::VerifiedIntent>,
    error: &anyhow::Error,
    outcome: &str,
) -> bool {
    if !call_authority_slow(error) {
        return false;
    }
    let (Some(intent), Some(verified)) = (submit.call_intent.as_deref(), verified) else {
        return false;
    };
    let Ok(request_expires_at) = u64::try_from(submit.signed_request.expires_at) else {
        return false;
    };
    let delayed = DelayedCallWake {
        context: context.clone(),
        runtime: runtime.clone(),
        intent: intent.clone(),
        start_digest: verified.start_digest.clone(),
        envelope: submit.envelope.clone(),
        request_expires_at,
        outcome: outcome.to_owned(),
    };
    let _join = tokio::spawn(async move {
        finish_delayed_call_wake(delayed).await;
    });
    true
}

struct DelayedCallWake {
    context: GatewayQuicContext,
    runtime: GatewaySessionRuntime,
    intent: ramflux_protocol::SignedCallIntentV1,
    start_digest: String,
    envelope: ramflux_protocol::Envelope,
    request_expires_at: u64,
    outcome: String,
}

async fn dispatch_delayed_offline_wake(delayed: &DelayedCallWake) {
    if let Err(error) = dispatch_authenticated_offline_wake(
        &delayed.context,
        &delayed.runtime,
        &delayed.envelope.target_delivery_id,
        &delayed.envelope,
    )
    .await
    {
        tracing::warn!(%error, "delayed call wake dispatch failed");
    }
}

async fn finish_delayed_call_wake(delayed: DelayedCallWake) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
    loop {
        let admitted = admit_signed_call(CallIntentRetry {
            context: &delayed.context,
            runtime: &delayed.runtime,
            intent: &delayed.intent,
            start_digest: &delayed.start_digest,
            envelope_id: &delayed.envelope.envelope_id,
            encrypted_payload: &delayed.envelope.encrypted_payload,
            request_expires_at: delayed.request_expires_at,
        })
        .await;
        match admitted {
            Ok(ramflux_node_core::CallIntentEffect::Cancelled { wake_id: Some(wake_id) }) => {
                dispatch_cancel_wake(
                    &delayed.context,
                    &delayed.intent,
                    &delayed.start_digest,
                    &wake_id,
                    delayed.intent.body.target_epoch,
                )
                .await;
                return;
            }
            Ok(_) => {
                if delayed.outcome == "offline_queued" {
                    dispatch_delayed_offline_wake(&delayed).await;
                }
                return;
            }
            Err(error) if call_authority_slow(&error) && std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(error) => {
                tracing::warn!(%error, "call intent admission failed");
                return;
            }
        }
    }
}

async fn reply_if_home_migrated(
    send: &GatewaySendHandle,
    runtime: &GatewaySessionRuntime,
    response: &ramflux_node_core::EnvelopeSubmitResponse,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<bool> {
    if response.outcome != ramflux_protocol::GATEWAY_FORWARDED_HOME_NODE_MIGRATED_REASON {
        return Ok(false);
    }
    anyhow::ensure!(
        response.target_delivery_id == envelope.target_delivery_id,
        "forward acknowledgement target does not match submitted envelope"
    );
    let frame = if runtime.supports_forward_ack {
        ramflux_node_core::GatewayServerFrame::ForwardAck {
            ack: ramflux_node_core::GatewayForwardAck {
                envelope_id: envelope.envelope_id.clone(),
                target_delivery_id: response.target_delivery_id.clone(),
                inbox_seq: response.inbox_seq,
            },
        }
    } else {
        ramflux_node_core::GatewayServerFrame::Nack { reason: response.outcome.clone() }
    };
    write_gateway_handle(send, &frame).await?;
    Ok(true)
}

pub(super) async fn reply_and_deliver_submitted(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    response: &ramflux_node_core::EnvelopeSubmitResponse,
    frame: &ramflux_node_core::GatewayServerFrame,
    metadata: Option<&(String, i64)>,
) -> anyhow::Result<()> {
    let ramflux_node_core::GatewayServerFrame::Deliver { entry } = frame else {
        anyhow::bail!("submit reply requires accepted entry");
    };
    let envelope = &entry.envelope;
    if response.target_delivery_id == runtime.target_delivery_id
        && let (Some(expected), Some((observed, _))) = (runtime.session_push.as_deref(), metadata)
        && observed != expected
    {
        context.hub.retire_incarnation(&runtime.target_delivery_id, expected, send).await;
        return Err(crate::session_push::Retired.into());
    }
    crate::session_push::submit_reply(send, runtime, response, envelope, frame, metadata).await?;
    // After this reply, peer forwarding and notification cannot send a second response.
    if let Err(error) =
        deliver_submitted_to_peer(context, runtime, response, frame, envelope, metadata).await
    {
        tracing::warn!(%error, target_delivery_id = %response.target_delivery_id, "post-submit delivery deferred to durable inbox");
    }
    Ok(())
}

pub(super) async fn deliver_submitted_to_peer(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    response: &ramflux_node_core::EnvelopeSubmitResponse,
    frame: &ramflux_node_core::GatewayServerFrame,
    envelope: &ramflux_protocol::Envelope,
    metadata: Option<&(String, i64)>,
) -> anyhow::Result<()> {
    if response.outcome == "offline_queued" {
        dispatch_authenticated_offline_wake(
            context,
            runtime,
            &response.target_delivery_id,
            envelope,
        )
        .await?;
    } else if response.outcome == "online"
        && (response.target_delivery_id != runtime.target_delivery_id
            || runtime.session_push.is_some())
    {
        let delivered = context
            .hub
            .send_delivery(
                &response.target_delivery_id,
                frame,
                metadata.map(|(id, deadline)| (id.as_str(), *deadline)),
            )
            .await;
        if !delivered
            && !forward_deliver_on_local_miss(
                context,
                &response.target_delivery_id,
                frame,
                metadata,
            )
            .await?
        {
            dispatch_authenticated_offline_wake(
                context,
                runtime,
                &response.target_delivery_id,
                envelope,
            )
            .await?;
        }
    }
    Ok(())
}

pub(super) fn committed_submit_entry(
    response: &ramflux_node_core::EnvelopeSubmitResponse,
    envelope: ramflux_protocol::Envelope,
) -> anyhow::Result<ramflux_node_core::InboxEntry> {
    anyhow::ensure!(
        matches!(response.outcome.as_str(), "online" | "offline_queued")
            && response.nack.is_none()
            && response.target_delivery_id == envelope.target_delivery_id,
        "router submit response does not confirm this target"
    );
    let inbox_seq = response.inbox_seq.filter(|seq| *seq > 0).ok_or_else(|| {
        anyhow::anyhow!("router submit response is missing its committed sequence")
    })?;
    Ok(ramflux_node_core::InboxEntry {
        inbox_seq,
        target_delivery_id: response.target_delivery_id.clone(),
        envelope,
    })
}

fn fanout_replay_rejection(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    fanout: &ramflux_node_core::GatewayOwnDeviceFanoutFrame,
) -> anyhow::Result<Option<String>> {
    let writer = context.store.write_guard()?;
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    match writer.save_auth_replay(&runtime.source_identity, &fanout.signed_request, now) {
        Ok(()) => Ok(None),
        Err(
            error @ (ramflux_node_core::NodeCoreError::ReplayGuard(_)
            | ramflux_node_core::NodeCoreError::GatewayReplayCapacity),
        ) => Ok(Some(format!("fanout replay rejected: {error}"))),
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn handle_gateway_own_device_fanout(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    fanout: &ramflux_node_core::GatewayOwnDeviceFanoutFrame,
) -> anyhow::Result<()> {
    if ramflux_protocol::ephemeral::require_durable(&fanout.envelope).is_err() {
        write_gateway_handle(send, &crate::durable_mode::nack_frame()).await?;
        return Ok(());
    }
    if let Some(reason) = own_device_fanout_session_rejection(runtime, fanout) {
        write_gateway_handle(
            send,
            &ramflux_node_core::GatewayServerFrame::Nack { reason: reason.to_owned() },
        )
        .await?;
        return Ok(());
    }
    let owned_runtime = runtime.clone();
    let owned_fanout = fanout.clone();
    let replay_rejection =
        crate::durable_work::run(context, Some(&runtime.source_identity), move |context| {
            fanout_replay_rejection(context, &owned_runtime, &owned_fanout)
        })
        .await?;
    if let Some(reason) = replay_rejection {
        write_gateway_handle(send, &ramflux_node_core::GatewayServerFrame::Nack { reason }).await?;
        return Ok(());
    }

    let request = ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
        principal_id: fanout.principal_id.clone(),
        source_device_id: fanout.source_device_id.clone(),
        envelope: fanout.envelope.clone(),
    };
    capture_itest_gateway_json(
        "own_device_fanout",
        &serde_json::json!({
            "path": "/gateway/session/own-device-fanout",
            "principal_id": &request.principal_id,
            "source_device_id": &request.source_device_id,
            "envelope": &request.envelope,
        }),
    );
    let mesh: serde_json::Value = match router_post_json_async(
        &context.router,
        "/mvp10/own-devices/fanout",
        &request,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            write_gateway_handle(
                send,
                &ramflux_node_core::GatewayServerFrame::Nack {
                    reason: format!("own-device fanout rejected: {error}"),
                },
            )
            .await?;
            return Ok(());
        }
    };
    let shim_response: ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse =
        serde_json::from_value(mesh.clone())?;
    let response = ramflux_node_core::GatewayOwnDeviceFanoutResponse::from(shim_response);
    let rows = mesh["delivered"].as_array().ok_or(crate::session_push::Retired)?;
    anyhow::ensure!(rows.len() == response.delivered.len(), crate::session_push::Retired);
    for (delivery, row) in response.delivered.iter().zip(rows) {
        let metadata = crate::session_push::metadata(
            row,
            runtime.session_push.is_some() && delivery.inbox_seq.is_some(),
        )?;
        if delivery.target_delivery_id == runtime.target_delivery_id
            && runtime.session_push.is_some()
        {
            anyhow::ensure!(
                metadata.as_ref().map(|m| m.0.as_str()) == runtime.session_push.as_deref(),
                crate::session_push::Retired
            );
        }
        if let Err(error) = deliver_own_device_fanout_entry(
            context,
            runtime,
            delivery,
            &request.envelope,
            metadata.as_ref(),
        )
        .await
        {
            tracing::warn!(%error, target_delivery_id = %delivery.target_delivery_id, "fanout peer delivery deferred to durable inbox");
        }
    }
    write_gateway_handle(send, &ramflux_node_core::GatewayServerFrame::OwnDeviceFanout { response })
        .await
}

pub(super) async fn deliver_own_device_fanout_entry(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    delivery: &ramflux_node_core::GatewayOwnDeviceFanoutDelivery,
    envelope: &ramflux_protocol::Envelope,
    metadata: Option<&(String, i64)>,
) -> anyhow::Result<()> {
    let Some(entry) = committed_fanout_entry(delivery, envelope)? else { return Ok(()) };
    let frame = ramflux_node_core::GatewayServerFrame::Deliver { entry: entry.clone() };
    match delivery.outcome.as_str() {
        "online"
            if delivery.target_delivery_id != runtime.target_delivery_id
                || runtime.session_push.is_some() =>
        {
            let local_delivered = context
                .hub
                .send_delivery(
                    &delivery.target_delivery_id,
                    &frame,
                    metadata.map(|(id, deadline)| (id.as_str(), *deadline)),
                )
                .await;
            if !local_delivered
                && !forward_deliver_on_local_miss(
                    context,
                    &delivery.target_delivery_id,
                    &frame,
                    metadata,
                )
                .await?
            {
                dispatch_authenticated_offline_wake(
                    context,
                    runtime,
                    &delivery.target_delivery_id,
                    &entry.envelope,
                )
                .await?;
            }
        }
        "offline_queued" => {
            dispatch_authenticated_offline_wake(
                context,
                runtime,
                &delivery.target_delivery_id,
                &entry.envelope,
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn committed_fanout_entry(
    delivery: &ramflux_node_core::GatewayOwnDeviceFanoutDelivery,
    submitted: &ramflux_protocol::Envelope,
) -> anyhow::Result<Option<ramflux_node_core::InboxEntry>> {
    if delivery.inbox_seq.is_none()
        && !matches!(delivery.outcome.as_str(), "online" | "offline_queued")
    {
        return Ok(None);
    }
    ramflux_protocol::validate_device_name(&delivery.device_id)?;
    let mut envelope = submitted.clone();
    envelope.target_delivery_id.clone_from(&delivery.target_delivery_id);
    envelope.envelope_id =
        ramflux_node_core::mvp10_fanout_envelope_id(&submitted.envelope_id, &delivery.device_id);
    let committed = ramflux_node_core::EnvelopeSubmitResponse {
        migration_refusal: None,
        outcome: delivery.outcome.clone(),
        target_delivery_id: delivery.target_delivery_id.clone(),
        inbox_seq: delivery.inbox_seq,
        cursor: None,
        nack: None,
    };
    committed_submit_entry(&committed, envelope).map(Some)
}

pub(super) fn own_device_fanout_session_rejection(
    runtime: &GatewaySessionRuntime,
    fanout: &ramflux_node_core::GatewayOwnDeviceFanoutFrame,
) -> Option<&'static str> {
    if fanout.source_device_id != runtime.device_id {
        return Some("own-device fanout source device does not match authenticated session");
    }
    if fanout.principal_id != runtime.principal_id {
        return Some("own-device fanout principal does not match authenticated session");
    }
    None
}

pub(super) fn attach_franking_node_tag(
    envelope: &mut ramflux_protocol::Envelope,
    node_id: &str,
    signer: &ramflux_node_core::NodeServiceSigningKey,
    accepted_at_unix_ms: u64,
) -> anyhow::Result<bool> {
    let Some(franking) = envelope.ext.ext.get_mut("franking") else {
        return Ok(false);
    };
    let Some(franking) = franking.as_object_mut() else {
        anyhow::bail!("envelope franking ext must be a JSON object");
    };
    let sender_device_id_hash = required_franking_string(franking, "sender_device_id_hash")
        .and_then(|value| {
            let decoded = ramflux_protocol::decode_base64url(&value)?;
            if decoded.len() != 32 {
                anyhow::bail!("franking sender_device_id_hash must be 32 bytes");
            }
            Ok(decoded)
        })?;
    let message_event_id = required_franking_string(franking, "message_event_id")?;
    let commitment = required_franking_string(franking, "commitment")?;
    let ciphertext_hash = required_franking_string(franking, "ciphertext_hash")?;
    let franking_tag = signer.sign_franking_node_tag(ramflux_node_core::NodeFrankingTagInput {
        node_id,
        envelope_id: &envelope.envelope_id,
        message_event_id: &message_event_id,
        sender_device_id_hash: &sender_device_id_hash,
        commitment: &commitment,
        ciphertext_hash: &ciphertext_hash,
        accepted_at_unix_ms,
    });
    franking.insert("franking_tag".to_owned(), serde_json::Value::String(franking_tag));
    franking.insert("node_id".to_owned(), serde_json::Value::String(node_id.to_owned()));
    franking.insert(
        "accepted_at".to_owned(),
        serde_json::Value::Number(serde_json::Number::from(accepted_at_unix_ms)),
    );
    Ok(true)
}

fn required_franking_string(
    franking: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> anyhow::Result<String> {
    franking
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("franking metadata missing string field {field}"))
}

fn now_unix_millis() -> u64 {
    let millis =
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_millis());
    u64::try_from(millis).unwrap_or(u64::MAX)
}

pub(super) fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

async fn dispatch_cancel_wake(
    context: &GatewayQuicContext,
    intent: &ramflux_protocol::SignedCallIntentV1,
    start_digest: &str,
    wake_id: &str,
    target_owner_epoch: u64,
) {
    let notify = context.notify.clone();
    let intent = intent.clone();
    let start_digest = start_digest.to_owned();
    let wake_id = wake_id.to_owned();
    let now = ramflux_node_core::now_unix_seconds();
    let posted = tokio::task::spawn_blocking(move || {
        let Some(signed_wake) = crate::notify_wake::signed_cancel_wake(
            &notify.signer,
            &intent,
            &start_digest,
            &wake_id,
            target_owner_epoch,
            now,
        ) else {
            return Ok(());
        };
        post_signed_wake(&notify, &intent.body.target_delivery_id, signed_wake, now)
    })
    .await;
    match posted {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(%error, "call cancel wake dispatch failed"),
        Err(error) => tracing::warn!(%error, "call cancel wake task failed"),
    }
}

async fn dispatch_authenticated_offline_wake(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    target_delivery_id: &str,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<()> {
    let Some(owner) = crate::lookup_target_owner_epoch(&context.router, target_delivery_id).await
    else {
        tracing::warn!("offline wake skipped because the target owner epoch is unavailable");
        return Ok(());
    };
    dispatch_offline_wake(
        context,
        runtime.source_identity.storage_key(),
        runtime.device_epoch,
        owner.device_epoch,
        target_delivery_id,
        envelope,
    )
    .await
}

pub(crate) async fn dispatch_offline_wake(
    context: &GatewayQuicContext,
    source_identity: &str,
    source_epoch: u64,
    target_owner_epoch: u64,
    target_delivery_id: &str,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<()> {
    let notify = context.notify.clone();
    let store = Arc::clone(&context.store);
    let source_identity = source_identity.to_owned();
    let target_delivery_id_owned = target_delivery_id.to_owned();
    let envelope = envelope.clone();
    let now = ramflux_node_core::now_unix_seconds();
    match tokio::task::spawn_blocking(move || {
        notify_offline_wake(
            &notify,
            &store,
            &crate::notify_wake::OfflineWakeInput {
                source_identity: &source_identity,
                source_epoch,
                target_owner_epoch,
                target_delivery_id: &target_delivery_id_owned,
                envelope: &envelope,
                now,
            },
        )
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(%error, "offline notify wake dispatch failed");
        }
        Err(error) => {
            tracing::warn!(%error, "offline notify wake task failed");
        }
    }
    Ok(())
}

async fn forward_deliver_on_local_miss(
    context: &GatewayQuicContext,
    target_delivery_id: &str,
    frame: &ramflux_node_core::GatewayServerFrame,
    metadata: Option<&(String, i64)>,
) -> anyhow::Result<bool> {
    if context.peers.is_empty() {
        return Ok(false);
    }
    let session = match router_session_async(&context.router, target_delivery_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return Ok(false),
        Err(error) => {
            tracing::warn!(%error, target_delivery_id, "gateway forward presence lookup failed");
            return Ok(false);
        }
    };
    if session.gateway_id == context.gateway_id {
        return Ok(false);
    }
    let Some(peer) = context.peers.peer(&session.gateway_id).cloned() else {
        return Ok(false);
    };
    let request = GatewayForwardDeliverRequest {
        source_gateway_id: context.gateway_id.clone(),
        target_delivery_id: target_delivery_id.to_owned(),
        forwarded: true,
        incarnation_id: metadata.map(|m| m.0.clone()),
        retain_until: metadata.map(|m| m.1),
        frame: frame.clone(),
    };
    let tls = context.peers.tls().clone();
    let peer_ca_pems = context.peers.peer_ca_pems().to_vec();
    let forward_path = GatewayPeerDirectory::forward_path();
    let expected_instance = session.gateway_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        ramflux_transport::mesh_quic_post_json_with_peer_ca_pems_and_instance::<
            _,
            GatewayForwardDeliverResponse,
        >(
            &peer.endpoint,
            forward_path,
            &tls,
            &peer.server_name,
            &peer_ca_pems,
            &expected_instance,
            &request,
        )
    })
    .await;
    match result {
        Ok(Ok(response)) => crate::mesh_delivery::handled(&response),
        Ok(Err(error)) => {
            tracing::warn!(
                %error,
                target_delivery_id,
                peer_gateway_id = %session.gateway_id,
                "gateway forward deliver failed"
            );
            Ok(false)
        }
        Err(error) => {
            tracing::warn!(%error, target_delivery_id, "gateway forward deliver task failed");
            Ok(false)
        }
    }
}
