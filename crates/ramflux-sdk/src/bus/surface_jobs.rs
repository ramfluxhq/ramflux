// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded surface outbox with latest-snapshot group coalescing and retained ciphertext retries.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
const PREFIX: &str = "surface/transport/";
const MAX_JOBS: usize = 64;
const MAX_BYTES: usize = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
pub(super) struct Delivery {
    pub envelope: ramflux_protocol::Envelope,
    pub federation: Option<FederatedTarget>,
    pub ack_key: Option<String>,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub next_at: i64,
}
#[derive(Serialize, Deserialize)]
pub(super) struct FederatedTarget {
    pub conversation_id: String,
    pub message_id: String,
    pub recipient_device_id: Option<String>,
    pub route: LocalBusFederationRoute,
}
#[derive(Serialize, Deserialize)]
struct Job {
    #[serde(default)]
    group: Option<super::dispatch::surface_group::QueuedGroup>,
    sequence: u64,
    #[serde(default)]
    envelope: Option<ramflux_protocol::Envelope>,
    #[serde(default)]
    deliveries: Vec<Delivery>,
    attempts: u32,
    next_at: i64,
}
pub(super) fn admit(
    account: &LocalBusAccountState,
    additional: usize,
    bytes: usize,
) -> Result<(), SdkError> {
    let rows = account.client.account_db()?.surface_history_page::<Job>(PREFIX, PREFIX, 65)?;
    let size = rows
        .iter()
        .try_fold(bytes, |sum, row| serde_json::to_vec(row).map(|b| sum.saturating_add(b.len())))?;
    if rows.len().saturating_add(additional) > MAX_JOBS || size > MAX_BYTES {
        return Err(SdkError::InboundPending("surface transport outbox is full".into()));
    }
    Ok(())
}
pub(super) fn enqueue(
    account: &LocalBusAccountState,
    envelopes: Vec<ramflux_protocol::Envelope>,
) -> Result<(), SdkError> {
    let bytes = envelopes.iter().try_fold(0usize, |sum, env| {
        serde_json::to_vec(env).map(|b| sum.saturating_add(b.len() + 128))
    })?;
    admit(account, envelopes.len(), bytes)?;
    let db = account.client.account_db()?;
    let mut sequence = db.load_actor_state::<u64>("surface/transport_sequence")?.unwrap_or(0);
    for envelope in envelopes {
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| SdkError::LocalBus("surface transport sequence exhausted".into()))?;
        db.persist_actor_state(
            &format!("{PREFIX}{sequence:020}"),
            &Job {
                sequence,
                group: None,
                envelope: Some(envelope),
                deliveries: Vec::new(),
                attempts: 0,
                next_at: 0,
            },
        )?;
    }
    db.persist_actor_state("surface/transport_sequence", &sequence)?;
    Ok(())
}
#[cfg(test)]
pub(super) fn enqueue_group(
    account: &LocalBusAccountState,
    deliveries: Vec<Delivery>,
) -> Result<(), SdkError> {
    if deliveries.is_empty() {
        return Ok(());
    }
    admit(account, 1, serde_json::to_vec(&deliveries)?.len().saturating_add(512))?;
    let db = account.client.account_db()?;
    let sequence = db
        .load_actor_state::<u64>("surface/transport_sequence")?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| SdkError::LocalBus("surface transport sequence exhausted".into()))?;
    db.persist_actor_state(
        &format!("{PREFIX}{sequence:020}"),
        &Job { sequence, group: None, envelope: None, deliveries, attempts: 0, next_at: 0 },
    )?;
    db.persist_actor_state("surface/transport_sequence", &sequence)?;
    Ok(())
}
fn group_key(carrier: &crate::client::surface::Carrier) -> Result<String, SdkError> {
    Ok(format!(
        "{PREFIX}group-{}",
        ramflux_protocol::hash_base64url(
            "ramflux.surface.queued_group.v1",
            carrier.surface_reference()?.as_bytes()
        )
    ))
}
pub(super) fn admit_group(
    account: &LocalBusAccountState,
    carrier: &crate::client::surface::Carrier,
    bytes: usize,
) -> Result<(), SdkError> {
    let key = group_key(carrier)?;
    let rows = account.client.account_db()?.surface_record_page::<Job>(PREFIX, PREFIX, 65)?;
    let others = rows.iter().filter(|(k, _)| k != &key).collect::<Vec<_>>();
    let total = others.iter().try_fold(bytes, |sum, (_, j)| {
        serde_json::to_vec(j).map(|b| sum.saturating_add(b.len()))
    })?;
    if others.len() >= MAX_JOBS || total > MAX_BYTES {
        return Err(SdkError::InboundPending("surface transport outbox is full".into()));
    }
    Ok(())
}
pub(super) fn enqueue_latest_group(
    account: &LocalBusAccountState,
    carrier: &crate::client::surface::Carrier,
    plan: super::dispatch::surface_group::Plan,
) -> Result<(), SdkError> {
    if carrier.snapshot.is_none() {
        return Err(SdkError::LocalBus(
            "coalesced group publication requires signed full-state proof".into(),
        ));
    }
    admit_group(account, carrier, plan.bytes)?;
    account.client.account_db()?.persist_actor_state(
        &group_key(carrier)?,
        &Job {
            sequence: 0,
            group: Some(super::dispatch::surface_group::QueuedGroup::new(carrier.clone(), plan)),
            envelope: None,
            deliveries: Vec::new(),
            attempts: 0,
            next_at: 0,
        },
    )?;
    Ok(())
}
fn refresh_job(
    account: &LocalBusAccountState,
    key: &str,
    job: &mut Job,
    now: i64,
) -> Result<(), SdkError> {
    if let Some(envelope) = job.envelope.take() {
        job.deliveries.insert(
            0,
            Delivery {
                envelope,
                federation: None,
                ack_key: None,
                attempts: job.attempts,
                next_at: job.next_at,
            },
        );
    }
    if let Some(group) = &mut job.group {
        if group.enqueued_at.saturating_add(600) <= now
            || job.deliveries.iter().any(|d| d.attempts >= 8)
        {
            // Keep the signed full state and restart with current membership and fresh packet TTLs.
            // This never drops the final publication solely because its old ciphertext expired.
            group.restart(account)?;
            job.deliveries.clear();
            job.next_at = 0;
            account.client.account_db()?.append_journal(
                &format!("surface-snapshot-retry:{key}:{now}"),
                "surface.full_snapshot_retry",
                &json!({"surface_ref":group.carrier.surface_reference()?}),
                now,
                None,
            )?;
        }
    } else {
        job.deliveries.retain(|d| {
            d.envelope.created_at.saturating_add(i64::from(d.envelope.ttl)) > now && d.attempts < 8
        });
    }
    Ok(())
}
pub(super) async fn run(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let now = now_unix_timestamp();
    let jobs = account.client.account_db()?.surface_record_page::<Job>(PREFIX, PREFIX, 65)?;
    let deadline = std::time::Instant::now() + Duration::from_millis(200);
    let mut bytes = 0usize;
    let mut sent = 0;
    for (key, mut job) in jobs {
        if std::time::Instant::now() >= deadline || bytes >= 4 * 1024 * 1024 {
            break;
        }
        refresh_job(account, &key, &mut job, now)?;
        loop {
            if std::time::Instant::now() >= deadline
                || bytes >= 4 * 1024 * 1024
                || job.next_at > now
            {
                break;
            }
            let mut seen = BTreeSet::new();
            let mut index = job.deliveries.iter().position(|d| {
                seen.insert(d.envelope.target_delivery_id.clone()) && d.next_at <= now
            });
            if index.is_none() {
                let Some(group) = &mut job.group else {
                    break;
                };
                if group.finished() {
                    break;
                }
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if let Ok(deliveries) =
                    super::dispatch::surface_group::prepare_next(account, group, remaining).await
                {
                    index = Some(job.deliveries.len());
                    job.deliveries.extend(deliveries);
                    job.attempts = 0;
                } else {
                    job.attempts = job.attempts.saturating_add(1);
                    job.next_at = now.saturating_add(2_i64.pow(job.attempts.min(6)));
                    break;
                }
                account.client.account_db()?.persist_actor_state(&key, &job)?;
            }
            let Some(index) = index else {
                break;
            };
            let Some(delivery) = job.deliveries.get(index) else {
                break;
            };
            let size = serde_json::to_vec(delivery)?.len();
            if bytes.saturating_add(size) > 4 * 1024 * 1024 {
                break;
            }
            bytes = bytes.saturating_add(size);
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let result = submit(account, delivery, remaining).await;
            if result.is_ok() {
                if let Some(ack) = &delivery.ack_key {
                    account.client.account_db()?.persist_actor_state(ack, &true)?;
                }
                job.deliveries.remove(index);
                sent += 1;
            } else {
                let delivery = &mut job.deliveries[index];
                delivery.attempts = delivery.attempts.saturating_add(1);
                delivery.next_at = now.saturating_add(2_i64.pow(delivery.attempts.min(6)));
            }
            account.client.account_db()?.persist_actor_state(&key, &job)?;
        }
        if job.deliveries.is_empty()
            && job.group.as_ref().is_none_or(super::dispatch::surface_group::QueuedGroup::finished)
        {
            account.client.account_db()?.delete_surface_state(&key)?;
        } else {
            account.client.account_db()?.persist_actor_state(&key, &job)?;
        }
    }
    Ok(sent)
}

async fn submit(
    account: &mut LocalBusAccountState,
    delivery: &Delivery,
    budget: Duration,
) -> Result<(), SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = async {
        if let Some(target) = &delivery.federation {
            let message = GatewayDirectMessage {
                conversation_id: target.conversation_id.clone(),
                message_id: target.message_id.clone(),
                envelope_id: delivery.envelope.envelope_id.clone(),
                source_principal_id: delivery.envelope.source_principal_id.clone(),
                sender_id: delivery.envelope.source_device_id.clone(),
                recipient_device_id: target.recipient_device_id.clone(),
                target_delivery_id: delivery.envelope.target_delivery_id.clone(),
                encrypted_body: ramflux_protocol::decode_base64url(
                    &delivery.envelope.encrypted_payload,
                )
                .map_err(|_| SdkError::LocalBus("invalid retained group ciphertext".into()))?,
                created_at: delivery.envelope.created_at,
                ttl: delivery.envelope.ttl,
            };
            account
                .client
                .forward_federated_gateway_message(&engine, &message, &target.route)
                .map(|_| ())
        } else {
            match tokio::time::timeout(
                budget.min(Duration::from_secs(2)),
                engine.submit_envelope(delivery.envelope.clone()),
            )
            .await
            {
                Ok(result) => result.map(|_| ()),
                Err(_) => Err(SdkError::InboundPending("surface submit timed out".into())),
            }
        }
    }
    .await;
    account.put_engine(engine);
    result
}
