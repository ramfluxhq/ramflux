// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sealed task fan-out jobs; recipient FIFO, bounded work and durable per-recipient retries.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
const PREFIX: &str = "task/transport/";
const MAX_JOBS: u64 = 64;
const MAX_BYTES: u64 = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
pub(super) struct Destination {
    pub route: LocalBusFederationRoute,
    pub conversation_id: String,
    pub message_id: String,
    pub device_id: String,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Delivery {
    pub envelope: ramflux_protocol::Envelope,
    pub federation: Option<Destination>,
    pub attempts: u32,
    pub next_at: i64,
}
#[derive(Serialize, Deserialize)]
struct Job {
    sequence: u64,
    conversation_id: String,
    task_id: String,
    deliveries: Vec<Delivery>,
}
pub(super) fn admit(
    account: &LocalBusAccountState,
    additional: usize,
    bytes: usize,
) -> Result<(), SdkError> {
    let (count, size) = account.client.account_db()?.task_state_usage(PREFIX)?;
    if count.saturating_add(u64::try_from(additional).unwrap_or(u64::MAX)) > MAX_JOBS
        || size.saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX)) > MAX_BYTES
    {
        return Err(SdkError::InboundPending("task transport outbox capacity reached".into()));
    }
    Ok(())
}
pub(super) fn enqueue(
    account: &LocalBusAccountState,
    conversation: &str,
    task: &str,
    deliveries: Vec<Delivery>,
) -> Result<(), SdkError> {
    if deliveries.is_empty() {
        return Ok(());
    }
    admit(account, 1, serde_json::to_vec(&deliveries)?.len().saturating_add(1024))?;
    let db = account.client.account_db()?;
    let sequence = db
        .load_actor_state::<u64>("task/transport_sequence")?
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| SdkError::LocalBus("task transport sequence exhausted".into()))?;
    db.persist_actor_state(
        &format!("{PREFIX}{sequence:020}"),
        &Job { sequence, conversation_id: conversation.into(), task_id: task.into(), deliveries },
    )?;
    db.persist_actor_state("task/transport_sequence", &sequence)?;
    Ok(())
}
pub(super) async fn run(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let now = now_unix_timestamp();
    let mut jobs = account.client.account_db()?.task_record_page::<Job>(PREFIX, PREFIX, 65)?;
    let mut blocked = BTreeSet::new();
    let mut completed = 0;
    let mut attempted = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    for (key, job) in &mut jobs {
        let mut index = 0;
        let mut changed = false;
        while index < job.deliveries.len() {
            let delivery = &job.deliveries[index];
            let target = delivery.envelope.target_delivery_id.clone();
            if now >= delivery.envelope.created_at.saturating_add(i64::from(delivery.envelope.ttl))
                || delivery.attempts >= 8
            {
                account.client.account_db()?.append_journal(&format!("task-delivery-expired:{}:{}",job.sequence,delivery.envelope.envelope_id),"task.changed",&json!({"task_id":job.task_id,"conversation_id":job.conversation_id,"target_delivery_id":target,"envelope_id":delivery.envelope.envelope_id,"delivery_state":"failed","delivery_error":"task_delivery_retry_exhausted"}),now,None)?;
                account.client.set_task_delivery_state(
                    &job.conversation_id,
                    &job.task_id,
                    "failed",
                    Some("task_delivery_retry_exhausted"),
                )?;
                job.deliveries.remove(index);
                changed = true;
                continue;
            }
            if !blocked.insert(target) || delivery.next_at > now {
                index += 1;
                continue;
            }
            if attempted >= 8 || tokio::time::Instant::now() >= deadline {
                break;
            }
            attempted += 1;
            let result = submit(account, delivery, deadline).await;
            changed = true;
            if result.is_ok() {
                job.deliveries.remove(index);
                completed += 1;
            } else {
                let d = &mut job.deliveries[index];
                d.attempts += 1;
                d.next_at = now.saturating_add(2_i64.pow(d.attempts.min(6)));
                index += 1;
            }
        }
        if changed {
            account.client.account_db()?.write_transaction(|| {
                if job.deliveries.is_empty() {
                    account.client.account_db()?.delete_task_state(key)?;
                } else {
                    account.client.account_db()?.persist_actor_state(key, job)?;
                }
                Ok::<_, SdkError>(())
            })?;
        }
        if attempted >= 8 || tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    Ok(completed)
}
async fn submit(
    account: &mut LocalBusAccountState,
    delivery: &Delivery,
    deadline: tokio::time::Instant,
) -> Result<(), SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = if let Some(destination) = &delivery.federation {
        let envelope = &delivery.envelope;
        let body = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
            .map_err(|_| SdkError::LocalBus("invalid retained task ciphertext".into()));
        match body {
            Ok(encrypted_body) => account
                .client
                .forward_federated_gateway_message(
                    &engine,
                    &GatewayDirectMessage {
                        conversation_id: destination.conversation_id.clone(),
                        message_id: destination.message_id.clone(),
                        envelope_id: envelope.envelope_id.clone(),
                        source_principal_id: envelope.source_principal_id.clone(),
                        sender_id: envelope.source_device_id.clone(),
                        recipient_device_id: Some(destination.device_id.clone()),
                        target_delivery_id: envelope.target_delivery_id.clone(),
                        encrypted_body,
                        created_at: envelope.created_at,
                        ttl: envelope.ttl,
                    },
                    &destination.route,
                )
                .map(|_| ()),
            Err(error) => Err(error),
        }
    } else {
        match tokio::time::timeout_at(deadline, engine.submit_envelope(delivery.envelope.clone()))
            .await
        {
            Ok(result) => result.map(|_| ()),
            Err(_) => Err(SdkError::InboundPending("task delivery tick budget exhausted".into())),
        }
    };
    account.put_engine(engine);
    result
}
