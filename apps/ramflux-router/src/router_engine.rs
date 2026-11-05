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

pub(crate) fn submit_envelope(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    forward: AsyncForwardContext<'_>,
    envelope: ramflux_protocol::Envelope,
    total_started: Instant,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    ramflux_node_core::publication::capture(|| {
        submit_envelope_inner(state, store, forward, envelope, total_started, origin)
    })?
    .published_blocking()?
}

pub(crate) fn submit_envelope_inner(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    forward: AsyncForwardContext<'_>,
    mut envelope: ramflux_protocol::Envelope,
    total_started: Instant,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    record_decoded(&envelope);
    let (source, mut source_lease) = match authenticate_submission(state, store, &envelope, origin)?
    {
        SourceAdmission::Admitted(source, lease) => (source, lease),
        SourceAdmission::Refused(response) => return Ok(*response),
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
            return Ok(submit_response_from_outcome(
                state,
                complete_sync_forward(state, forward, preparation)?,
            ));
        }
        Err(error) => return submission_refusal(state, store, &envelope, error),
    };
    if let Err(error) = state.prepare_publication_target(store, &envelope.target_delivery_id) {
        return submission_refusal(state, store, &envelope, error);
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
        return Ok(response);
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
    if should_persist_submission(&outcome)
        && let Err(error) = store.record_leased_submission(
            &replay_key,
            replay_expires_at,
            persistent_entry.as_ref(),
            Some(&sender_root_commitment),
            Some(submission),
        )
    {
        tracing::error!(
            error = %error,
            replay_key = %replay_key,
            "router submit persistence failed after in-memory accept; aborting to avoid state fork"
        );
        std::process::abort();
    }
    ramflux_node_core::record_router_submit_completed();
    ramflux_node_core::record_router_submit_save_us(elapsed_us(save_started));
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
    Ok(response)
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

pub(crate) async fn submit_envelope_async(
    state: &std::sync::Arc<ramflux_node_core::RouterCore>,
    store: &std::sync::Arc<ramflux_node_core::RouterRedbStore>,
    forward: AsyncForwardContext<'_>,
    envelope: ramflux_protocol::Envelope,
    total_started: Instant,
    origin: ramflux_node_core::RouterEnvelopeOrigin,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
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
            submit_envelope_inner(
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
    prepared.published().await
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
            let outcome = match error {
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
                        reason,
                    }
                }
                _ => {
                    ramflux_node_core::RouterSubmitOutcome::ForwardInProgress { target_delivery_id }
                }
            };
            ramflux_node_core::RouterForwardPreparation::Complete(Box::new(outcome))
        })
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

// Both ingress adapters use this completion path; a client panic releases the
// reservation and owned permits without turning a retryable forward into HTTP failure.
pub(crate) fn complete_forward_attempt(
    state: &ramflux_node_core::RouterCore,
    reservation: Box<ramflux_node_core::RouterForwardReservation>,
    work: impl FnOnce() -> Result<
        ramflux_node_core::FederatedEnvelopeForwardResponse,
        ramflux_node_core::NodeCoreError,
    >,
) -> ramflux_node_core::RouterSubmitOutcome {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
        Ok(response) => state.complete_home_node_forward(reservation, response),
        Err(_) => ramflux_node_core::RouterSubmitOutcome::ForwardInProgress {
            target_delivery_id: reservation.target_delivery_id().to_owned(),
        },
    }
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
    let lease = store.acquire_acknowledgement(&target)?;
    let cursor = state.apply_ack(ack)?;
    store.record_leased_ack(&cursor, &ack.envelope_id, lease)?;
    Ok(ramflux_node_core::InboxCursorResponse::from(&cursor))
}

pub(crate) fn apply_bound_ack(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::TargetAckRequest,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let lease = store.acquire_acknowledgement(&request.target_delivery_id)?;
    let cursor = state.apply_ack_for_target(&request.target_delivery_id, &request.ack)?;
    store.record_leased_ack(&cursor, &request.ack.envelope_id, lease)?;
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

pub(crate) fn own_device_fanout(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
    ramflux_node_core::publication::capture(|| own_device_fanout_inner(state, store, request))?
        .published_blocking()?
}

pub(crate) fn own_device_fanout_inner(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
    let now = i64::try_from(submission_now()).unwrap_or(i64::MAX);
    let (plan, leases) = state.accept_leased_fanout(request.clone(), store, now)?;
    let response = ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse {
        principal_id: plan.principal_id,
        source_device_id: plan.source_device_id,
        delivered: plan
            .deliveries
            .into_iter()
            .map(|delivery| state.submit_replay_accepted_fanout_delivery(delivery, now).0)
            .collect(),
    };
    let entries = response
        .delivered
        .iter()
        .filter_map(|delivery| {
            delivery.inbox_seq.map(|inbox_seq| {
                let mut envelope = request.envelope.clone();
                envelope.target_delivery_id.clone_from(&delivery.target_delivery_id);
                envelope.envelope_id = ramflux_node_core::mvp10_fanout_envelope_id(
                    &request.envelope.envelope_id,
                    &delivery.device_id,
                );
                ramflux_node_core::InboxEntry {
                    inbox_seq,
                    target_delivery_id: delivery.target_delivery_id.clone(),
                    envelope,
                }
            })
        })
        .collect::<Vec<_>>();
    let replay_expires_at = request
        .envelope
        .created_at
        .checked_add(i64::from(request.envelope.ttl))
        .ok_or_else(|| anyhow::anyhow!("fan-out envelope ttl overflows replay expiry"))?;
    let source = state.authenticated_envelope_source_durable(&request.envelope, store)?;
    store.record_leased_fanout(
        &ramflux_node_core::envelope_replay_tuple_key(&source, &request.envelope),
        replay_expires_at,
        source.root_commitment(),
        &entries,
        leases,
    )?;
    Ok(response)
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

fn publication_reason(reason: &str) -> Option<&'static str> {
    if reason.starts_with("capacity_retry_after") {
        Some("capacity_retry_after")
    } else if reason == "incarnation_mismatch" {
        Some("incarnation_mismatch")
    } else if reason == "inbox sequence exhausted" {
        Some("invalid_seq")
    } else {
        None
    }
}
