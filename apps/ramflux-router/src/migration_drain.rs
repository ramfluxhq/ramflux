// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Supervised bounded backlog retries; only durable destination ACKs settle an obligation.
use crate::router_runtime::LocalFederationForwardClient;
use ramflux_node_core::{
    MigrationDrainEntry, MigrationDrainOutcome, MigrationDrainState, NodeCoreError, RouterCore,
    RouterEnvelopeOrigin, RouterForwardPreparation, RouterRedbStore,
};
use std::{
    sync::{Arc, Condvar, Mutex, Weak},
    thread::JoinHandle,
    time::Duration,
};

pub(crate) struct MigrationDrain {
    stopped: Arc<(Mutex<bool>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}
impl Drop for MigrationDrain {
    fn drop(&mut self) {
        let (stopped, changed) = &*self.stopped;
        *stopped.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        changed.notify_all();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl MigrationDrain {
    pub(crate) fn start(
        state: Weak<RouterCore>,
        store: Weak<RouterRedbStore>,
        client: LocalFederationForwardClient,
        semaphore: Arc<tokio::sync::Semaphore>,
        timeout: Duration,
    ) -> std::io::Result<Self> {
        let stopped = Arc::new((Mutex::new(false), Condvar::new()));
        let control = stopped.clone();
        let worker =
            std::thread::Builder::new().name("home-migration-drain".into()).spawn(move || {
                let mut position = String::new();
                loop {
                    let (stopped, changed) = &*control;
                    if *stopped.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
                        break;
                    }
                    let (Some(state), Some(store)) = (state.upgrade(), store.upgrade()) else {
                        break;
                    };
                    let result = tick(
                        &state,
                        &store,
                        &mut position,
                        ramflux_node_core::now_unix_seconds(),
                        |row, now| {
                            if *stopped.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
                                return Err(NodeCoreError::Redb("migration drain stopping".into()));
                            }
                            forward(
                                &state,
                                &store,
                                crate::router_engine::AsyncForwardContext {
                                    client: Some(&client),
                                    semaphore: &semaphore,
                                    timeout,
                                },
                                row,
                                now,
                            )
                        },
                    );
                    if let Err(error) = result {
                        tracing::warn!(%error, "home migration drain tick stopped");
                    }
                    drop((state, store));
                    let guard = stopped.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if *guard {
                        break;
                    }
                    drop(
                        changed
                            .wait_timeout(guard, Duration::from_millis(250))
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    );
                }
            })?;
        Ok(Self { stopped, worker: Some(worker) })
    }
}

/// Two pages per tick bound both decoded rows and state transitions, including poison rows.
pub(crate) fn tick(
    state: &RouterCore,
    store: &RouterRedbStore,
    position: &mut String,
    now: u64,
    mut send: impl FnMut(&MigrationDrainEntry, u64) -> Result<MigrationDrainOutcome, NodeCoreError>,
) -> Result<usize, NodeCoreError> {
    let now = store.migration_clock_floor(now)?;
    let mut transitions = 0;
    for _ in 0..2 {
        let page = store.migration_drain_work_page(position)?;
        if page.is_empty() {
            position.clear();
            break;
        }
        for (key, row) in page {
            let Some(row) = row else {
                *position = key;
                continue;
            };
            let expired = i64::try_from(now).unwrap_or(i64::MAX) >= row.retain_until;
            if !expired && (row.state == MigrationDrainState::Rejected || row.next_attempt > now) {
                *position = key;
                continue;
            }
            // Only due rows make a decision requiring the durable window latch.
            let open = match store.migration_forward_window(&row.entry.target_delivery_id, now) {
                Ok(window) => window.is_some(),
                Err(error @ NodeCoreError::Redb(_)) => return Err(error),
                Err(_) => false,
            };
            if expired || row.state != MigrationDrainState::Rejected && row.next_attempt <= now {
                let outcome = if expired {
                    MigrationDrainOutcome::Expired
                } else if !open {
                    MigrationDrainOutcome::Held
                } else {
                    match send(&row, now) {
                        Ok(outcome) => outcome,
                        Err(error @ NodeCoreError::Redb(_)) => return Err(error),
                        Err(_) => MigrationDrainOutcome::Held,
                    }
                };
                match store.settle_migration_drain(state, &row, outcome, now) {
                    Ok(()) => {}
                    Err(NodeCoreError::MigrationDrainCorrupt(error)) => {
                        tracing::warn!(%error, %key, "corrupt drain obligation retained");
                        *position = key;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                transitions += 1;
                if matches!(outcome, MigrationDrainOutcome::BAck | MigrationDrainOutcome::Expired)
                    && store
                        .migration_backlog_progress(
                            &row.account_anchor,
                            &row.migration_id,
                            ramflux_node_core::MigrationRole::Source,
                        )?
                        .remaining
                        == 0
                {
                    store.finish_home_migration_backlog(
                        &row.account_anchor,
                        &row.migration_id,
                        now,
                    )?;
                }
            }
            // Advance only after the decision and its storage writes succeed.
            *position = key;
        }
    }
    Ok(transitions)
}

pub(crate) fn forward(
    state: &RouterCore,
    store: &RouterRedbStore,
    context: crate::router_engine::AsyncForwardContext<'_>,
    row: &MigrationDrainEntry,
    now: u64,
) -> Result<MigrationDrainOutcome, NodeCoreError> {
    let Some(client) = context.client else {
        return Ok(MigrationDrainOutcome::Held);
    };
    let semaphore = context.semaphore;
    let timeout = context.timeout;
    // Authority is unsigned transport evidence; refresh a copy without rewriting the obligation.
    let mut envelope = row.entry.envelope.clone();
    match state.refresh_registered_envelope_authority(&mut envelope) {
        Ok(()) => {}
        Err(error @ NodeCoreError::Redb(_)) => return Err(error),
        Err(_) => return Ok(MigrationDrainOutcome::Held),
    }
    let envelope = &envelope;
    let native = envelope
        .ext
        .ext
        .get("source_device_authority")
        .and_then(|a| a.get("custody_authority"))
        .is_some_and(|a| !a.is_null());
    let source = if native {
        state.authenticated_native_forwarded_source_with_floors(
            envelope,
            &[],
            store,
            RouterEnvelopeOrigin::Federation,
        )
    } else {
        state.authenticated_envelope_source_from(
            envelope,
            Some(store),
            RouterEnvelopeOrigin::Federation,
        )
    };
    let source = match source {
        Ok(source) => source,
        Err(error @ NodeCoreError::Redb(_)) => return Err(error),
        Err(_) => return Ok(MigrationDrainOutcome::Held),
    };
    let preparation = state.prepare_committed_home_forward(
        store,
        &source,
        envelope.clone(),
        now,
        timeout.as_secs().max(1),
    )?;
    let RouterForwardPreparation::Forward(reservation) = preparation else {
        return Ok(MigrationDrainOutcome::Held);
    };
    let Some(mut plan) = reservation.plan().cloned() else {
        return Ok(MigrationDrainOutcome::Held);
    };
    let Ok(_global) = semaphore.clone().try_acquire_owned() else {
        return Ok(MigrationDrainOutcome::Held);
    };
    let Ok(_peer) = crate::migration_forward_limits::acquire(&plan.new_home_node) else {
        return Ok(MigrationDrainOutcome::Held);
    };
    if let Some(evidence) = &mut plan.migration_evidence {
        evidence.retain_until = row.retain_until;
    }
    let response = client.forward(&plan, timeout);
    // Keep the reservation and both permits through the full blocking IO, even after lease expiry.
    let ack = response.as_ref().is_ok_and(|r| {
        r.accepted
            && matches!(
                r.delivery.outcome.as_str(),
                "online" | "offline_queued" | "duplicate_federated_forward"
            )
    });
    drop(reservation);
    Ok(if ack {
        MigrationDrainOutcome::BAck
    } else if response.as_ref().is_ok_and(|reply| signed_permanent_refusal(&plan, reply)) {
        MigrationDrainOutcome::Rejected
    } else {
        MigrationDrainOutcome::Held
    })
}

/// Only a destination-signed permanent refusal can stop retries; unsigned failures stay held.
pub(super) fn signed_permanent_refusal(
    plan: &ramflux_node_core::HomeNodeMigrationForwardPlan,
    reply: &ramflux_node_core::FederatedEnvelopeForwardResponse,
) -> bool {
    let Some(nack) = &reply.delivery.nack else { return false };
    !reply.accepted
        && reply.target_node_id == plan.new_home_node
        && reply.delivery.target_delivery_id == plan.target_delivery_id
        && reply.delivery.outcome.starts_with("rejected_")
        && nack.envelope_id == plan.envelope.envelope_id
        && nack.receiver_device_id == plan.target_delivery_id
        && nack.retry_after.is_none()
        && matches!(
            nack.reason,
            ramflux_protocol::NackReason::InvalidSignature
                | ramflux_protocol::NackReason::UnknownDevice
                | ramflux_protocol::NackReason::RevokedCapability
                | ramflux_protocol::NackReason::PayloadTooLarge
                | ramflux_protocol::NackReason::UnsupportedSchema
        )
        && ramflux_protocol::signed_bytes(nack).is_ok_and(|bytes| {
            ramflux_crypto::verify_canonical_signature(
                &bytes,
                &nack.signed.signature,
                &plan.route.node_public_key,
            )
            .is_ok()
        })
}
