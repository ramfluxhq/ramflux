// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::time::Instant;

#[cfg(test)]
thread_local! {
    static SUBMISSION_TIME: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
struct TestClock(Option<u64>);
#[cfg(test)]
impl Drop for TestClock {
    fn drop(&mut self) {
        SUBMISSION_TIME.set(self.0);
    }
}
fn submission_now() -> u64 {
    #[cfg(test)]
    if let Some(now) = SUBMISSION_TIME.get() {
        return now;
    }
    ramflux_node_core::now_unix_seconds()
}

#[derive(Clone, Copy)]
pub(crate) struct AsyncForwardContext<'a> {
    pub(crate) client: Option<&'a crate::router_runtime::LocalFederationForwardClient>,
    pub(crate) semaphore: &'a std::sync::Arc<tokio::sync::Semaphore>,
    pub(crate) timeout: std::time::Duration,
}

#[cfg(any(test, feature = "itest-http"))]
pub(crate) fn submit_envelope(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    forward: AsyncForwardContext<'_>,
    envelope: ramflux_protocol::Envelope,
    total_started: Instant,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security(&envelope));
    }
    submit_envelope_mesh(state, store, forward, envelope, total_started, origin)
        .map(|response| response.delivery)
}
pub(crate) fn submit_envelope_mesh(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    forward: AsyncForwardContext<'_>,
    envelope: ramflux_protocol::Envelope,
    total_started: Instant,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
    if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security_mesh(&envelope));
    }
    ramflux_node_core::publication::capture(|| {
        submit_envelope_mesh_inner(state, store, forward, envelope, total_started, origin)
    })?
    .published_blocking()?
}

pub(crate) fn submit_envelope_mesh_inner(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    forward: AsyncForwardContext<'_>,
    envelope: ramflux_protocol::Envelope,
    total_started: Instant,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
    if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security_mesh(&envelope));
    }
    let target = envelope.target_delivery_id.clone();
    let result =
        (|| match prepare_submission(state, store, forward, envelope, total_started, origin)? {
            PreparedSubmit::Complete(response) => Ok(*response),
            PreparedSubmit::Waiting(waiter) => {
                let runtime = tokio::runtime::Builder::new_current_thread().build()?;
                let assignment = runtime.block_on(waiter.resolved())?;
                let assignment = ramflux_node_core::publication::await_sender_retry(
                    &store.publication_core()?,
                    assignment,
                )?;
                Ok(sender_retry_mesh_response(&assignment))
            }
        })();
    typed_sender_mesh_result(result, &target)
}

fn complete_response(response: ramflux_node_core::EnvelopeSubmitResponse) -> PreparedSubmit {
    complete_mesh_response(response, (None, None))
}

fn complete_mesh_response(
    delivery: ramflux_node_core::EnvelopeSubmitResponse,
    (incarnation_id, retain_until): (Option<String>, Option<i64>),
) -> PreparedSubmit {
    PreparedSubmit::Complete(Box::new(ramflux_node_core::SessionPushSubmitResponse {
        delivery,
        incarnation_id,
        retain_until,
    }))
}
fn sender_retry_mesh_response(
    assignment: &ramflux_node_core::sender_retry::SenderAssignment,
) -> ramflux_node_core::SessionPushSubmitResponse {
    ramflux_node_core::SessionPushSubmitResponse {
        delivery: sender_retry_response(assignment),
        incarnation_id: Some(assignment.inbox_incarnation_id.clone()),
        retain_until: Some(assignment.retain_until),
    }
}
fn typed_sender_mesh_result(
    result: anyhow::Result<ramflux_node_core::SessionPushSubmitResponse>,
    target: &str,
) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
    match result {
        Ok(response) => Ok(response),
        Err(error) => typed_sender_result(Err(error), target).map(|delivery| {
            ramflux_node_core::SessionPushSubmitResponse {
                delivery,
                incarnation_id: None,
                retain_until: None,
            }
        }),
    }
}

enum PreparedSubmit {
    Complete(Box<ramflux_node_core::SessionPushSubmitResponse>),
    Waiting(ramflux_node_core::sender_retry::RetryWaiter),
}

fn prepare_submission(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    forward: AsyncForwardContext<'_>,
    mut envelope: ramflux_protocol::Envelope,
    total_started: Instant,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<PreparedSubmit> {
    if matches!(
        ramflux_node_core::check_entry_bound(&envelope),
        Err(ramflux_node_core::NodeCoreError::DeliveryModeRefused)
    ) {
        return Ok(complete_response(crate::durable_mode::rejected_security(&envelope)));
    }
    record_decoded(&envelope);
    let (source, mut source_lease) = match authenticate_submission(state, store, &envelope, origin)?
    {
        SourceAdmission::Admitted(source, lease) => (source, lease),
        SourceAdmission::Refused(response) => return Ok(complete_response(*response)),
    };
    let submission = match store.acquire_submission(&envelope.target_delivery_id) {
        Ok(mut lease) => {
            if let Some(source) = source_lease.take() {
                lease.retain_home_operation(source);
            }
            lease
        }
        Err(ramflux_node_core::NodeCoreError::HomeMigration(
            ramflux_protocol::home_migration::Refusal::HomeMigrated,
        )) if forward.client.is_some() => {
            let preparation =
                committed_preparation(state, store, &source, envelope, forward.timeout);
            return Ok(complete_response(submit_response_from_outcome(
                state,
                complete_sync_forward(state, forward, preparation)?,
            )));
        }
        Err(error) => {
            return submission_refusal(state, store, &envelope, error).map(complete_response);
        }
    };
    let retry_owner = match prepare_sender_retry(store, &source, &envelope)? {
        RetryPreparation::Owner(owner) => owner,
        RetryPreparation::Return(response) => return Ok(response),
    };
    retry_owner.bind(&envelope.target_delivery_id)?;
    if let Err(error) = state.prepare_publication_target(store, &envelope.target_delivery_id) {
        return submission_refusal(state, store, &envelope, error).map(complete_response);
    }
    state.refresh_registered_envelope_authority(&mut envelope)?;
    let replay_key = ramflux_node_core::envelope_replay_tuple_key(&source, &envelope);
    let sender_root_commitment = source.root_commitment().to_owned();
    let replay_expires_at = envelope
        .created_at
        .checked_add(i64::from(envelope.ttl))
        .ok_or_else(|| anyhow::anyhow!("envelope ttl overflows replay expiry"))?;
    ramflux_node_core::record_router_submit_lock_wait_us(0);
    let dispatch_started = Instant::now();
    let now_unix_seconds = i64::try_from(submission_now()).unwrap_or(i64::MAX);
    if let Some(response) = persistent_local_replay_response(PersistentReplayQuery {
        store,
        origin,
        sender_root_commitment: source.root_commitment(),
        envelope: &envelope,
        replay_key: &replay_key,
        now_unix_seconds,
    })? {
        return Ok(complete_response(response));
    }
    let outcome = if forward.client.is_some() {
        let preparation = state.prepare_envelope_with_home_node_forward_at(
            &source,
            envelope,
            now_unix_seconds,
            origin,
            forward.timeout.as_secs().max(1),
        );
        complete_sync_forward(state, forward, preparation)?
    } else {
        state.submit_envelope_at(&source, envelope, now_unix_seconds)
    };
    ramflux_node_core::record_router_submit_dispatch_us(elapsed_us(dispatch_started));
    let save_started = Instant::now();
    let persistent_entry = persistent_entry_from_outcome(&outcome);
    let metadata = persistent_entry.as_ref().map_or((None, None), |entry| {
        state.session_delivery_metadata(&entry.target_delivery_id, entry.inbox_seq)
    });
    persist_submission_outcome(
        store,
        &replay_key,
        replay_expires_at,
        &sender_root_commitment,
        submission,
        (&outcome, persistent_entry.as_ref()),
    )?;
    finish_retry_owner(
        retry_owner,
        store,
        &sender_root_commitment,
        persistent_entry.as_ref(),
        &outcome,
        now_unix_seconds,
    );
    ramflux_node_core::record_router_submit_completed();
    ramflux_node_core::record_router_submit_save_us(elapsed_us(save_started));
    let response = submission_response(state, outcome, total_started);
    Ok(complete_mesh_response(response, metadata))
}

enum SourceAdmission {
    Admitted(ramflux_crypto::RootQualifiedDeviceRef, Option<ramflux_node_core::SubmissionLease>),
    Refused(Box<ramflux_node_core::EnvelopeSubmitResponse>),
}

fn authenticate_submission(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    envelope: &ramflux_protocol::Envelope,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<SourceAdmission> {
    let source = match state.authenticated_envelope_source_from(envelope, Some(store), origin) {
        Ok(source) => source,
        Err(ramflux_node_core::NodeCoreError::Capacity { .. }) => {
            return Ok(SourceAdmission::Refused(Box::new(
                ramflux_node_core::EnvelopeSubmitResponse {
                    migration_refusal: None,
                    outcome: "rejected_capacity".into(),
                    target_delivery_id: envelope.target_delivery_id.clone(),
                    inbox_seq: None,
                    cursor: None,
                    nack: None,
                },
            )));
        }
        Err(error) => return Err(error.into()),
    };
    // Hold local source admission through durable acceptance and any outbound call.
    // Federation retries already accepted elsewhere do not reacquire client admission.
    let source_lease = if origin == ramflux_node_core::RouterEnvelopeOrigin::Gateway {
        match store.acquire_home_operation(source.root_commitment()) {
            Ok(lease) => Some(lease),
            Err(ramflux_node_core::NodeCoreError::HomeMigration(reason)) => {
                return Ok(SourceAdmission::Refused(Box::new(
                    state.migration_source_submission_refusal(
                        store,
                        envelope,
                        source.root_commitment(),
                        reason,
                        submission_now(),
                    )?,
                )));
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };
    Ok(SourceAdmission::Admitted(source, source_lease))
}

fn complete_sync_forward(
    state: &ramflux_node_core::RouterCore,
    forward: AsyncForwardContext<'_>,
    preparation: ramflux_node_core::RouterForwardPreparation,
) -> anyhow::Result<ramflux_node_core::RouterSubmitOutcome> {
    Ok(match preparation {
        ramflux_node_core::RouterForwardPreparation::Complete(outcome) => *outcome,
        ramflux_node_core::RouterForwardPreparation::Forward(reservation) => {
            match std::sync::Arc::clone(forward.semaphore).try_acquire_owned() {
                Ok(_permit) => {
                    let client =
                        forward.client.ok_or_else(|| anyhow::anyhow!("missing forward client"))?;
                    let plan = reservation
                        .plan()
                        .ok_or_else(|| anyhow::anyhow!("missing forward plan"))?;
                    let peer_permit = if plan.migration_evidence.is_some() {
                        match crate::migration_forward_limits::acquire(&plan.new_home_node) {
                            Ok(permit) => Some(permit),
                            Err(_) => {
                                return Ok(
                                    ramflux_node_core::RouterSubmitOutcome::ForwardInProgress {
                                        target_delivery_id: reservation.target_delivery_id().into(),
                                    },
                                );
                            }
                        }
                    } else {
                        None
                    };
                    let _peer_permit = peer_permit;
                    let plan = plan.clone();
                    complete_forward_attempt(state, reservation, || {
                        client.forward(&plan, forward.timeout)
                    })
                }
                Err(_full) => {
                    let target_delivery_id = reservation.target_delivery_id().to_owned();
                    drop(reservation);
                    ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { target_delivery_id }
                }
            }
        }
    })
}

#[cfg(test)]
pub(crate) async fn submit_envelope_async(
    state: &std::sync::Arc<ramflux_node_core::RouterCore>,
    store: &std::sync::Arc<ramflux_node_core::RouterRedbStore>,
    forward: AsyncForwardContext<'_>,
    envelope: ramflux_protocol::Envelope,
    total_started: Instant,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security(&envelope));
    }
    submit_envelope_mesh_async(state, store, forward, envelope, total_started, origin)
        .await
        .map(|response| response.delivery)
}
pub(crate) async fn submit_envelope_mesh_async(
    state: &std::sync::Arc<ramflux_node_core::RouterCore>,
    store: &std::sync::Arc<ramflux_node_core::RouterRedbStore>,
    forward: AsyncForwardContext<'_>,
    envelope: ramflux_protocol::Envelope,
    total_started: Instant,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::SessionPushSubmitResponse> {
    if ramflux_protocol::ephemeral::require_durable(&envelope).is_err() {
        return Ok(crate::durable_mode::rejected_security_mesh(&envelope));
    }
    let target = envelope.target_delivery_id.clone();
    let publication = store.publication_core()?;
    let state = std::sync::Arc::clone(state);
    let store = std::sync::Arc::clone(store);
    let client = forward.client.cloned();
    let semaphore = std::sync::Arc::clone(forward.semaphore);
    let timeout = forward.timeout;
    #[cfg(test)]
    let fixture_clock = SUBMISSION_TIME.get();
    let prepared = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        let _clock = TestClock(SUBMISSION_TIME.replace(fixture_clock));
        ramflux_node_core::publication::capture(|| {
            prepare_submission(
                &state,
                &store,
                AsyncForwardContext { client: client.as_ref(), semaphore: &semaphore, timeout },
                envelope,
                total_started,
                origin,
            )
        })
    })
    .await??;
    let result = async {
        match prepared.published().await? {
            PreparedSubmit::Complete(response) => Ok(*response),
            PreparedSubmit::Waiting(waiter) => {
                let assignment = waiter.resolved().await?;
                publication.wait_sender_assignment(&assignment).await;
                Ok(sender_retry_mesh_response(&assignment))
            }
        }
    }
    .await;
    typed_sender_mesh_result(result, &target)
}

fn record_decoded(envelope: &ramflux_protocol::Envelope) {
    ramflux_node_core::record_router_submit_started();
    tracing::info!(
        envelope_id = %envelope.envelope_id,
        target_delivery_id = %envelope.target_delivery_id,
        source_device_id = %envelope.source_device_id,
        "router decoded mvp0 envelope"
    );
}

fn committed_preparation(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: ramflux_protocol::Envelope,
    timeout: std::time::Duration,
) -> ramflux_node_core::RouterForwardPreparation {
    let target_delivery_id = envelope.target_delivery_id.clone();
    state
        .prepare_committed_home_forward(
            store,
            source,
            envelope,
            submission_now(),
            timeout.as_secs().max(1),
        )
        .unwrap_or_else(|error| {
            tracing::warn!(%error, %target_delivery_id, "committed forward preparation refused");
            ramflux_node_core::RouterForwardPreparation::Complete(Box::new(
                committed_forward_error_outcome(&error, target_delivery_id),
            ))
        })
}

/// Map committed-home-forward refusals the same way `router.rs` maps `check_entry_bound`.
/// Home-migration retryables stay in progress; leftover bound errors are security refusals.
fn committed_forward_error_outcome(
    error: &ramflux_node_core::NodeCoreError,
    target_delivery_id: String,
) -> ramflux_node_core::RouterSubmitOutcome {
    match error {
        ramflux_node_core::NodeCoreError::HomeMigration(reason)
            if !matches!(
                reason,
                ramflux_protocol::home_migration::Refusal::StorageUnavailable
                    | ramflux_protocol::home_migration::Refusal::EvidenceRequired
                    | ramflux_protocol::home_migration::Refusal::PeeringUnavailable
                    | ramflux_protocol::home_migration::Refusal::MigrationInProgress
            ) =>
        {
            ramflux_node_core::RouterSubmitOutcome::RejectedSecurity {
                target_delivery_id,
                reason: format!("committed_forward:{reason:?}"),
            }
        }
        ramflux_node_core::NodeCoreError::Unauthorized(reason) => {
            ramflux_node_core::RouterSubmitOutcome::RejectedSecurity {
                target_delivery_id,
                reason: reason.clone(),
            }
        }
        ramflux_node_core::NodeCoreError::DeliveryModeRefused
        | ramflux_node_core::NodeCoreError::PayloadTooLarge
        | ramflux_node_core::NodeCoreError::InvalidConfiguration(_) => {
            ramflux_node_core::RouterSubmitOutcome::RejectedSecurity {
                target_delivery_id,
                reason: error.to_string(),
            }
        }
        _ => ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { target_delivery_id },
    }
}

fn submission_refusal(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    envelope: &ramflux_protocol::Envelope,
    error: ramflux_node_core::NodeCoreError,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    match error {
        ramflux_node_core::NodeCoreError::Publication(reason) => {
            let text = reason.to_string();
            let Some(outcome) = publication_reason(&text) else {
                return Err(reason.into());
            };
            Ok(ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: outcome.into(),
                target_delivery_id: envelope.target_delivery_id.clone(),
                inbox_seq: None,
                cursor: None,
                nack: None,
            })
        }
        ramflux_node_core::NodeCoreError::HomeMigration(mut reason) => {
            if reason == ramflux_protocol::home_migration::Refusal::HomeMigrated
                && store
                    .migration_forward_window(&envelope.target_delivery_id, submission_now())
                    .is_err()
            {
                reason = ramflux_protocol::home_migration::Refusal::StorageUnavailable;
            }
            Ok(state.migration_submission_refusal(store, envelope, reason, submission_now())?)
        }
        error => Err(error.into()),
    }
}

// Both ingress adapters complete typed forwarding failures through the same
// reservation owner, releasing permits before the next retry.
pub(crate) fn complete_forward_attempt(
    state: &ramflux_node_core::RouterCore,
    reservation: Box<ramflux_node_core::RouterForwardReservation>,
    work: impl FnOnce() -> Result<
        ramflux_node_core::FederatedEnvelopeForwardResponse,
        ramflux_node_core::NodeCoreError,
    >,
) -> ramflux_node_core::RouterSubmitOutcome {
    state.complete_home_node_forward(reservation, work())
}

#[cfg(feature = "itest-http")]
pub(crate) fn apply_ack(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    ack: &ramflux_protocol::Ack,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let target = state
        .target_for_envelope_id(&ack.envelope_id)
        .ok_or_else(|| anyhow::anyhow!("ACK envelope unavailable"))?;
    let cursor = state
        .apply_ack_batch(store, &target, std::slice::from_ref(ack))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing ACK result"))??;
    Ok(ramflux_node_core::InboxCursorResponse::from(&cursor))
}

pub(crate) fn apply_bound_ack(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::TargetAckRequest,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let cursor = state
        .apply_ack_batch(store, &request.target_delivery_id, std::slice::from_ref(&request.ack))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing ACK result"))??;
    Ok(ramflux_node_core::InboxCursorResponse::from(&cursor))
}

#[cfg(feature = "itest-http")]
pub(crate) fn apply_nack(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    nack: &ramflux_protocol::Nack,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let target = state
        .target_for_envelope_id(&nack.envelope_id)
        .ok_or_else(|| anyhow::anyhow!("NACK envelope unavailable"))?;
    let lease = store.acquire_acknowledgement(&target)?;
    let cursor = state.apply_nack(nack)?;
    store.record_leased_nack(&cursor, lease)?;
    Ok(ramflux_node_core::InboxCursorResponse::from(&cursor))
}

pub(crate) fn apply_bound_nack(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::TargetNackRequest,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let lease = store.acquire_acknowledgement(&request.target_delivery_id)?;
    let cursor = state.apply_nack_for_target(&request.target_delivery_id, &request.nack)?;
    store.record_leased_nack(&cursor, lease)?;
    Ok(ramflux_node_core::InboxCursorResponse::from(&cursor))
}

#[cfg(any(test, feature = "itest-http"))]
pub(crate) fn own_device_fanout(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
    if ramflux_protocol::ephemeral::require_durable(&request.envelope).is_err() {
        anyhow::bail!(crate::durable_mode::DeliveryModeRefused::from_envelope(&request.envelope));
    }
    Ok(ramflux_node_core::publication::capture(|| own_device_fanout_inner(state, store, request))?
        .published_blocking()??
        .resolved_blocking()?)
}

pub(crate) fn own_device_fanout_inner(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
) -> anyhow::Result<ramflux_node_core::PreparedFanout> {
    if ramflux_protocol::ephemeral::require_durable(&request.envelope).is_err() {
        anyhow::bail!(crate::durable_mode::DeliveryModeRefused::from_envelope(&request.envelope));
    }
    Ok(state.prepare_sender_fanout(
        store,
        request,
        i64::try_from(submission_now()).unwrap_or(i64::MAX),
    )?)
}

pub(crate) fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy)]
struct PersistentReplayQuery<'a> {
    store: &'a ramflux_node_core::RouterRedbStore,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
    sender_root_commitment: &'a str,
    envelope: &'a ramflux_protocol::Envelope,
    replay_key: &'a str,
    now_unix_seconds: i64,
}

fn persistent_local_replay_response(
    query: PersistentReplayQuery<'_>,
) -> anyhow::Result<Option<ramflux_node_core::EnvelopeSubmitResponse>> {
    if !query.store.has_local_delivery_envelope(
        query.sender_root_commitment,
        &query.envelope.envelope_id,
        &query.envelope.target_delivery_id,
        query.now_unix_seconds,
    )? {
        return Ok(None);
    }
    let outcome = match query.origin {
        ramflux_node_core::RouterEnvelopeOrigin::Federation => {
            "duplicate_federated_forward".to_owned()
        }
        ramflux_node_core::RouterEnvelopeOrigin::Gateway => format!(
            "rejected_security:{}",
            ramflux_node_core::NodeCoreError::ReplayGuard(format!("replay: {}", query.replay_key))
        ),
    };
    Ok(Some(ramflux_node_core::EnvelopeSubmitResponse {
        migration_refusal: None,
        outcome,
        target_delivery_id: query.envelope.target_delivery_id.clone(),
        inbox_seq: None,
        cursor: None,
        nack: None,
    }))
}

pub(crate) fn persistent_entry_from_outcome(
    outcome: &ramflux_node_core::RouterSubmitOutcome,
) -> Option<ramflux_node_core::InboxEntry> {
    match outcome {
        ramflux_node_core::RouterSubmitOutcome::Online(delivery) => {
            Some(ramflux_node_core::InboxEntry {
                inbox_seq: delivery.inbox_seq,
                target_delivery_id: delivery.target_delivery_id.clone(),
                envelope: delivery.envelope.clone(),
            })
        }
        ramflux_node_core::RouterSubmitOutcome::OfflineQueued(queued) => Some(queued.entry.clone()),
        ramflux_node_core::RouterSubmitOutcome::ForwardedHomeNodeMigrated(_)
        | ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { .. }
        | ramflux_node_core::RouterSubmitOutcome::DuplicateFederatedForward { .. }
        | ramflux_node_core::RouterSubmitOutcome::RejectedDeactivated { .. }
        | ramflux_node_core::RouterSubmitOutcome::RejectedDeleted { .. }
        | ramflux_node_core::RouterSubmitOutcome::RejectedHomeNodeMigrated(_)
        | ramflux_node_core::RouterSubmitOutcome::RejectedSecurity { .. } => None,
    }
}

fn should_persist_submission(outcome: &ramflux_node_core::RouterSubmitOutcome) -> bool {
    match outcome {
        ramflux_node_core::RouterSubmitOutcome::RejectedSecurity { .. }
        | ramflux_node_core::RouterSubmitOutcome::RejectedHomeNodeMigrated(_)
        | ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { .. }
        | ramflux_node_core::RouterSubmitOutcome::DuplicateFederatedForward { .. } => false,
        ramflux_node_core::RouterSubmitOutcome::ForwardedHomeNodeMigrated(delivery) => {
            !delivery.replayed
        }
        _ => true,
    }
}

pub(crate) fn submit_response_from_outcome(
    state: &ramflux_node_core::RouterCore,
    outcome: ramflux_node_core::RouterSubmitOutcome,
) -> ramflux_node_core::EnvelopeSubmitResponse {
    match outcome {
        ramflux_node_core::RouterSubmitOutcome::Online(delivery) => {
            ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "online".to_owned(),
                target_delivery_id: delivery.target_delivery_id,
                inbox_seq: Some(delivery.inbox_seq),
                cursor: None,
                nack: None,
            }
        }
        ramflux_node_core::RouterSubmitOutcome::OfflineQueued(queued) => {
            let target_delivery_id = queued.entry.target_delivery_id;
            ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "offline_queued".to_owned(),
                target_delivery_id: target_delivery_id.clone(),
                inbox_seq: Some(queued.entry.inbox_seq),
                cursor: state
                    .cursor_state(&target_delivery_id)
                    .as_ref()
                    .map(ramflux_node_core::InboxCursorResponse::from),
                nack: None,
            }
        }
        ramflux_node_core::RouterSubmitOutcome::ForwardedHomeNodeMigrated(delivery) => {
            ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "forwarded_home_node_migrated".to_owned(),
                target_delivery_id: delivery.target_delivery_id,
                inbox_seq: delivery.delivery.inbox_seq,
                cursor: delivery.delivery.cursor,
                nack: None,
            }
        }
        ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { target_delivery_id } => {
            ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "forward_in_progress".to_owned(),
                target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: None,
            }
        }
        ramflux_node_core::RouterSubmitOutcome::DuplicateFederatedForward {
            target_delivery_id,
        } => ramflux_node_core::EnvelopeSubmitResponse {
            migration_refusal: None,
            outcome: "duplicate_federated_forward".to_owned(),
            target_delivery_id,
            inbox_seq: None,
            cursor: None,
            nack: None,
        },
        ramflux_node_core::RouterSubmitOutcome::RejectedHomeNodeMigrated(delivery) => {
            ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "rejected_home_node_migrated".to_owned(),
                target_delivery_id: delivery.target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: Some(delivery.nack),
            }
        }
        ramflux_node_core::RouterSubmitOutcome::RejectedDeactivated { target_delivery_id } => {
            ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "rejected_deactivated".to_owned(),
                target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: None,
            }
        }
        ramflux_node_core::RouterSubmitOutcome::RejectedDeleted { target_delivery_id } => {
            ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: "rejected_deleted".to_owned(),
                target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: None,
            }
        }
        ramflux_node_core::RouterSubmitOutcome::RejectedSecurity { target_delivery_id, reason } => {
            ramflux_node_core::EnvelopeSubmitResponse {
                migration_refusal: None,
                outcome: publication_reason(&reason)
                    .map_or_else(|| format!("rejected_security:{reason}"), str::to_owned),
                target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::should_persist_submission;

    #[test]
    fn publication_refusals_preserve_typed_outcomes() -> anyhow::Result<()> {
        let root =
            super::migration_tests::directory().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let store = ramflux_node_core::RouterRedbStore::open(root.0.join("refusals.db"))?;
        let state = ramflux_node_core::RouterCore::new();
        let envelope = super::migration_tests::envelope("target", "refusal")
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        for (reason, code) in [
            (
                ramflux_node_core::publication::PublicationRefusal::CapacityRetryAfter {
                    retry_after_ms: 1000,
                },
                "capacity_retry_after",
            ),
            (
                ramflux_node_core::publication::PublicationRefusal::IncarnationMismatch,
                "incarnation_mismatch",
            ),
            (ramflux_node_core::publication::PublicationRefusal::SequenceExhausted, "invalid_seq"),
        ] {
            let response = super::submission_refusal(&state, &store, &envelope, reason.into())?;
            assert_eq!(response.outcome, code);
            let response = super::submit_response_from_outcome(
                &state,
                ramflux_node_core::RouterSubmitOutcome::RejectedSecurity {
                    target_delivery_id: envelope.target_delivery_id.clone(),
                    reason: reason.to_string(),
                },
            );
            assert_eq!(response.outcome, code);
        }
        assert!(
            super::submission_refusal(
                &state,
                &store,
                &envelope,
                ramflux_node_core::publication::PublicationRefusal::FatalUncertain.into()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn invalid_configuration_committed_forward_is_rejected_security() {
        let outcome = super::committed_forward_error_outcome(
            &ramflux_node_core::NodeCoreError::InvalidConfiguration("bad report commitment".into()),
            "target".into(),
        );
        assert!(
            matches!(
                outcome,
                ramflux_node_core::RouterSubmitOutcome::RejectedSecurity { ref reason, .. }
                    if reason.contains("invalid configuration")
            ),
            "exact RejectedSecurity, got {outcome:?}"
        );
        let retryable = super::committed_forward_error_outcome(
            &ramflux_node_core::NodeCoreError::HomeMigration(
                ramflux_protocol::home_migration::Refusal::StorageUnavailable,
            ),
            "target".into(),
        );
        assert!(
            matches!(retryable, ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { .. }),
            "home-migration retryables stay in progress, got {retryable:?}"
        );
    }

    #[test]
    fn replayed_forward_ack_does_not_rewrite_the_router_wal() {
        let outcome = ramflux_node_core::RouterSubmitOutcome::ForwardedHomeNodeMigrated(Box::new(
            ramflux_node_core::HomeNodeMigrationForwardDelivery {
                target_delivery_id: "target".into(),
                proof_hash: "proof".into(),
                new_home_node_hint: "node-new".into(),
                route: ramflux_node_core::HomeNodeRouteRecord {
                    identity_commitment: "identity".into(),
                    home_node: "node-new".into(),
                    home_node_key_hash: "key-hash".into(),
                    node_public_key: "node-key".into(),
                    node_endpoint: "node-new.example:7443".into(),
                    route_record_hash: "route-hash".into(),
                    migration_proof_hash: "proof".into(),
                    route_update_proof_hash: "route-update".into(),
                    updated_at: 1,
                    expires_at: 2,
                },
                delivery: ramflux_node_core::EnvelopeSubmitResponse {
                    migration_refusal: None,
                    outcome: "duplicate_federated_forward".into(),
                    target_delivery_id: "target".into(),
                    inbox_seq: None,
                    cursor: None,
                    nack: None,
                },
                replayed: true,
            },
        ));
        assert!(!should_persist_submission(&outcome));
    }
}

#[cfg(test)]
#[path = "router_engine_migration_tests.rs"]
mod migration_tests;

#[cfg(test)]
#[path = "router_engine_window_tests.rs"]
pub(crate) mod window_tests;

#[cfg(test)]
#[path = "router_engine_concurrency_tests.rs"]
mod concurrency_tests;

#[cfg(test)]
#[path = "router_engine_drain_tests.rs"]
mod drain_tests;

#[cfg(test)]
#[path = "router_engine_drain_recovery_tests.rs"]
mod drain_recovery_tests;

pub(crate) fn publication_reason(reason: &str) -> Option<&'static str> {
    if reason == "payload_too_large" {
        Some("payload_too_large")
    } else if reason == "aborted_retry_safe" {
        Some("aborted_retry_safe")
    } else if reason == "idempotency_conflict" {
        Some("idempotency_conflict")
    } else if reason.starts_with("capacity_retry_after") {
        Some("capacity_retry_after")
    } else if reason == "incarnation_mismatch" {
        Some("incarnation_mismatch")
    } else if reason == "inbox sequence exhausted" {
        Some("invalid_seq")
    } else {
        None
    }
}

fn sender_retry_response(
    assignment: &ramflux_node_core::sender_retry::SenderAssignment,
) -> ramflux_node_core::EnvelopeSubmitResponse {
    ramflux_node_core::EnvelopeSubmitResponse {
        migration_refusal: None,
        outcome: "offline_queued".into(),
        target_delivery_id: assignment.target_delivery_id.clone(),
        inbox_seq: Some(assignment.inbox_seq),
        cursor: None,
        nack: None,
    }
}

fn persist_submission_outcome(
    store: &ramflux_node_core::RouterRedbStore,
    replay_key: &str,
    replay_expires_at: i64,
    root: &str,
    lease: ramflux_node_core::SubmissionLease,
    (outcome, entry): (
        &ramflux_node_core::RouterSubmitOutcome,
        Option<&ramflux_node_core::InboxEntry>,
    ),
) -> anyhow::Result<()> {
    if should_persist_submission(outcome)
        && let Err(error) = store.record_leased_submission(
            replay_key,
            replay_expires_at,
            entry,
            Some(root),
            Some(lease),
        )
    {
        if ramflux_node_core::publication::proved_non_write() {
            return Err(ramflux_node_core::NodeCoreError::SenderRetry(
                ramflux_node_core::sender_retry::SenderRetryRefusal::AbortedRetrySafe,
            )
            .into());
        }
        tracing::error!(error = %error, "router submit persistence failed after writer hand-off");
        std::process::abort();
    }
    Ok(())
}

enum RetryPreparation {
    Owner(ramflux_node_core::sender_retry::RetryOwner),
    Return(PreparedSubmit),
}
fn prepare_sender_retry(
    store: &ramflux_node_core::RouterRedbStore,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<RetryPreparation> {
    Ok(
        match store.admit_sender_retry(
            source,
            envelope,
            i64::try_from(submission_now()).unwrap_or(i64::MAX),
        )? {
            ramflux_node_core::sender_retry::RetryAdmission::Owner(owner) => {
                RetryPreparation::Owner(owner)
            }
            ramflux_node_core::sender_retry::RetryAdmission::Waiting(waiter) => {
                RetryPreparation::Return(PreparedSubmit::Waiting(waiter))
            }
            ramflux_node_core::sender_retry::RetryAdmission::Accepted(assignment) => {
                let assignment = ramflux_node_core::publication::await_sender_retry(
                    &store.publication_core()?,
                    assignment,
                )?;
                RetryPreparation::Return(PreparedSubmit::Complete(Box::new(
                    sender_retry_mesh_response(&assignment),
                )))
            }
        },
    )
}

fn typed_sender_result(
    result: anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse>,
    target: &str,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    match result {
        Ok(response) => Ok(response),
        Err(error) => {
            let code = error.downcast_ref::<ramflux_node_core::NodeCoreError>().and_then(|error| {
                match error {
                    ramflux_node_core::NodeCoreError::SenderRetry(reason) => {
                        Some(reason.to_string())
                    }
                    ramflux_node_core::NodeCoreError::Publication(reason) => {
                        publication_reason(&reason.to_string()).map(str::to_owned)
                    }
                    _ => None,
                }
            });
            match code {
                Some(outcome) => Ok(ramflux_node_core::EnvelopeSubmitResponse {
                    migration_refusal: None,
                    outcome,
                    target_delivery_id: target.into(),
                    inbox_seq: None,
                    cursor: None,
                    nack: None,
                }),
                None => Err(error),
            }
        }
    }
}

fn finish_retry_owner(
    owner: ramflux_node_core::sender_retry::RetryOwner,
    store: &ramflux_node_core::RouterRedbStore,
    root: &str,
    entry: Option<&ramflux_node_core::InboxEntry>,
    outcome: &ramflux_node_core::RouterSubmitOutcome,
    now: i64,
) {
    if let Some(entry) = entry {
        owner.accepted_entry(store, root, entry, now);
    } else if matches!(
        outcome,
        ramflux_node_core::RouterSubmitOutcome::ForwardedHomeNodeMigrated(_)
            | ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { .. }
    ) {
        owner.forwarded();
    }
}

fn submission_response(
    state: &ramflux_node_core::RouterCore,
    outcome: ramflux_node_core::RouterSubmitOutcome,
    total_started: Instant,
) -> ramflux_node_core::EnvelopeSubmitResponse {
    let response_started = Instant::now();
    let response = submit_response_from_outcome(state, outcome);
    tracing::info!(
        target_delivery_id = %response.target_delivery_id,
        outcome = %response.outcome,
        inbox_seq = ?response.inbox_seq,
        "router mvp0 envelope outcome"
    );
    ramflux_node_core::record_router_submit_response_us(elapsed_us(response_started));
    ramflux_node_core::record_router_submit_total_us(elapsed_us(total_started));
    response
}
