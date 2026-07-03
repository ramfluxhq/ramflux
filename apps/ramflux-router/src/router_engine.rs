// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::time::Instant;

pub(crate) fn submit_envelope(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    home_node_forward: Option<&crate::router_runtime::LocalFederationForwardClient>,
    envelope: ramflux_protocol::Envelope,
    total_started: Instant,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    tracing::info!(
        envelope_id = %envelope.envelope_id,
        target_delivery_id = %envelope.target_delivery_id,
        source_device_id = %envelope.source_device_id,
        "router decoded mvp0 envelope"
    );
    let replay_key = ramflux_node_core::envelope_replay_tuple_key(&envelope);
    let replay_expires_at = envelope
        .created_at
        .checked_add(i64::from(envelope.ttl))
        .ok_or_else(|| anyhow::anyhow!("envelope ttl overflows replay expiry"))?;
    ramflux_node_core::record_router_submit_lock_wait_us(0);
    let dispatch_started = Instant::now();
    let now_unix_seconds = i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX);
    let outcome = match home_node_forward {
        Some(client) => {
            state.submit_envelope_with_home_node_forward_at(envelope, now_unix_seconds, |plan| {
                client.forward(plan)
            })
        }
        None => state.submit_envelope_at(envelope, now_unix_seconds),
    };
    ramflux_node_core::record_router_submit_dispatch_us(elapsed_us(dispatch_started));
    let save_started = Instant::now();
    let persistent_entry = persistent_entry_from_outcome(&outcome);
    if !matches!(
        outcome,
        ramflux_node_core::RouterSubmitOutcome::RejectedSecurity { .. }
            | ramflux_node_core::RouterSubmitOutcome::RejectedHomeNodeMigrated(_)
    ) && let Err(error) =
        store.record_submission_increment(&replay_key, replay_expires_at, persistent_entry.as_ref())
    {
        tracing::error!(
            error = %error,
            replay_key = %replay_key,
            "router submit persistence failed after in-memory accept; aborting to avoid state fork"
        );
        std::process::abort();
    }
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

pub(crate) async fn submit_envelope_async(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    home_node_forward: Option<&crate::router_runtime::LocalFederationForwardClient>,
    envelope: ramflux_protocol::Envelope,
    total_started: Instant,
) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
    tracing::info!(
        envelope_id = %envelope.envelope_id,
        target_delivery_id = %envelope.target_delivery_id,
        source_device_id = %envelope.source_device_id,
        "router decoded mvp0 envelope"
    );
    let replay_key = ramflux_node_core::envelope_replay_tuple_key(&envelope);
    let replay_expires_at = envelope
        .created_at
        .checked_add(i64::from(envelope.ttl))
        .ok_or_else(|| anyhow::anyhow!("envelope ttl overflows replay expiry"))?;
    ramflux_node_core::record_router_submit_lock_wait_us(0);
    let dispatch_started = Instant::now();
    let now_unix_seconds = i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX);
    let outcome = match home_node_forward {
        Some(client) => {
            state.submit_envelope_with_home_node_forward_at(envelope, now_unix_seconds, |plan| {
                client.forward(plan)
            })
        }
        None => state.submit_envelope_at(envelope, now_unix_seconds),
    };
    ramflux_node_core::record_router_submit_dispatch_us(elapsed_us(dispatch_started));
    let save_started = Instant::now();
    let persistent_entry = persistent_entry_from_outcome(&outcome);
    if !matches!(
        outcome,
        ramflux_node_core::RouterSubmitOutcome::RejectedSecurity { .. }
            | ramflux_node_core::RouterSubmitOutcome::RejectedHomeNodeMigrated(_)
    ) && let Err(error) = store
        .record_submission_increment_async(
            &replay_key,
            replay_expires_at,
            persistent_entry.as_ref(),
        )
        .await
    {
        tracing::error!(
            error = %error,
            replay_key = %replay_key,
            "router submit persistence failed after in-memory accept; aborting to avoid state fork"
        );
        std::process::abort();
    }
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

#[cfg(feature = "itest-http")]
pub(crate) fn apply_ack(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    ack: &ramflux_protocol::Ack,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let cursor = state.apply_ack(ack)?;
    store.record_ack_increment(&cursor, &ack.envelope_id)?;
    Ok(ramflux_node_core::InboxCursorResponse::from(&cursor))
}

pub(crate) fn apply_bound_ack(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::TargetAckRequest,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let cursor = state.apply_ack_for_target(&request.target_delivery_id, &request.ack)?;
    store.record_ack_increment(&cursor, &request.ack.envelope_id)?;
    Ok(ramflux_node_core::InboxCursorResponse::from(&cursor))
}

#[cfg(feature = "itest-http")]
pub(crate) fn apply_nack(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    nack: &ramflux_protocol::Nack,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let cursor = state.apply_nack(nack)?;
    store.record_nack_increment(&cursor)?;
    Ok(ramflux_node_core::InboxCursorResponse::from(&cursor))
}

pub(crate) fn apply_bound_nack(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::TargetNackRequest,
) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
    let cursor = state.apply_nack_for_target(&request.target_delivery_id, &request.nack)?;
    store.record_nack_increment(&cursor)?;
    Ok(ramflux_node_core::InboxCursorResponse::from(&cursor))
}

pub(crate) fn own_device_fanout(
    state: &ramflux_node_core::RouterCore,
    store: &ramflux_node_core::RouterRedbStore,
    request: &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
    let response = state.mvp10_own_device_fanout(request.clone())?;
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
    store.record_fanout_increment(
        &ramflux_node_core::envelope_replay_tuple_key(&request.envelope),
        replay_expires_at,
        &entries,
    )?;
    Ok(response)
}

pub(crate) fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
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
        | ramflux_node_core::RouterSubmitOutcome::RejectedDeactivated { .. }
        | ramflux_node_core::RouterSubmitOutcome::RejectedDeleted { .. }
        | ramflux_node_core::RouterSubmitOutcome::RejectedHomeNodeMigrated(_)
        | ramflux_node_core::RouterSubmitOutcome::RejectedSecurity { .. } => None,
    }
}

pub(crate) fn submit_response_from_outcome(
    state: &ramflux_node_core::RouterCore,
    outcome: ramflux_node_core::RouterSubmitOutcome,
) -> ramflux_node_core::EnvelopeSubmitResponse {
    match outcome {
        ramflux_node_core::RouterSubmitOutcome::Online(delivery) => {
            ramflux_node_core::EnvelopeSubmitResponse {
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
                outcome: "forwarded_home_node_migrated".to_owned(),
                target_delivery_id: delivery.target_delivery_id,
                inbox_seq: delivery.delivery.inbox_seq,
                cursor: delivery.delivery.cursor,
                nack: None,
            }
        }
        ramflux_node_core::RouterSubmitOutcome::RejectedHomeNodeMigrated(delivery) => {
            ramflux_node_core::EnvelopeSubmitResponse {
                outcome: "rejected_home_node_migrated".to_owned(),
                target_delivery_id: delivery.target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: Some(delivery.nack),
            }
        }
        ramflux_node_core::RouterSubmitOutcome::RejectedDeactivated { target_delivery_id } => {
            ramflux_node_core::EnvelopeSubmitResponse {
                outcome: "rejected_deactivated".to_owned(),
                target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: None,
            }
        }
        ramflux_node_core::RouterSubmitOutcome::RejectedDeleted { target_delivery_id } => {
            ramflux_node_core::EnvelopeSubmitResponse {
                outcome: "rejected_deleted".to_owned(),
                target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: None,
            }
        }
        ramflux_node_core::RouterSubmitOutcome::RejectedSecurity { target_delivery_id, reason } => {
            ramflux_node_core::EnvelopeSubmitResponse {
                outcome: format!("rejected_security:{reason}"),
                target_delivery_id,
                inbox_seq: None,
                cursor: None,
                nack: None,
            }
        }
    }
}
