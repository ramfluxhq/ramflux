// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable already-encrypted surface delivery; retries never re-seal or reuse a ratchet key.
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
        &Job { sequence, envelope: None, deliveries, attempts: 0, next_at: 0 },
    )?;
    db.persist_actor_state("surface/transport_sequence", &sequence)?;
    Ok(())
}
pub(super) async fn run(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let now = now_unix_timestamp();
    let jobs = account.client.account_db()?.surface_history_page::<Job>(PREFIX, PREFIX, 65)?;
    let mut blocked = BTreeSet::new();
    let mut sent = 0;
    let mut attempted = 0;
    for mut job in jobs {
        let key = format!("{PREFIX}{:020}", job.sequence);
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
        let failed = job
            .deliveries
            .iter()
            .filter(|d| {
                d.envelope.created_at.saturating_add(i64::from(d.envelope.ttl)) <= now
                    || d.attempts >= 8
            })
            .map(|d| d.envelope.target_delivery_id.clone())
            .collect::<BTreeSet<_>>();
        if !failed.is_empty() {
            account.client.account_db()?.append_journal(
                &format!("surface-transport-expired:{}:{}", job.sequence, job.deliveries.len()),
                "surface.delivery_failed",
                &json!({"sequence":job.sequence,"target_delivery_ids":failed}),
                now,
                None,
            )?;
            job.deliveries.retain(|d| !failed.contains(&d.envelope.target_delivery_id));
            account.client.account_db()?.persist_actor_state(&key, &job)?;
        }
        if job.deliveries.is_empty() {
            account.client.account_db()?.delete_surface_state(&key)?;
            continue;
        }
        // Skip a backed-off recipient while preserving its distribution-before-message order.
        let index = job.deliveries.iter().position(|d| {
            blocked.insert(d.envelope.target_delivery_id.clone()) && d.next_at <= now
        });
        let Some(index) = index else {
            continue;
        };
        let delivery = &job.deliveries[index];
        if attempted >= 2 {
            break;
        }
        attempted += 1;
        let result = submit(account, delivery).await;
        let ack_key = delivery.ack_key.clone();
        if result.is_ok() {
            account.client.account_db()?.surface_transaction(|| {
                if let Some(ack) = &ack_key {
                    account.client.account_db()?.persist_actor_state(ack, &true)?;
                }
                job.deliveries.remove(index);
                job.attempts = 0;
                job.next_at = 0;
                if job.deliveries.is_empty() {
                    account.client.account_db()?.delete_surface_state(&key)?;
                } else {
                    account.client.account_db()?.persist_actor_state(&key, &job)?;
                }
                Ok::<_, SdkError>(())
            })?;
            sent += 1;
        } else {
            let delivery = &mut job.deliveries[index];
            delivery.attempts += 1;
            delivery.next_at = now.saturating_add(2_i64.pow(delivery.attempts.min(6)));
            account.client.account_db()?.persist_actor_state(&key, &job)?;
        }
    }
    Ok(sent)
}

async fn submit(account: &mut LocalBusAccountState, delivery: &Delivery) -> Result<(), SdkError> {
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
                Duration::from_secs(2),
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
