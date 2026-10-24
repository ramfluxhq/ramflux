// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable already-encrypted task delivery; retries never re-seal or reuse a ratchet key.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
const PREFIX: &str = "task/transport/";
const MAX_JOBS: usize = 64;
const MAX_BYTES: usize = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
struct Job {
    sequence: u64,
    envelope: ramflux_protocol::Envelope,
    attempts: u32,
    next_at: i64,
}
pub(super) fn admit(
    account: &LocalBusAccountState,
    additional: usize,
    bytes: usize,
) -> Result<(), SdkError> {
    let rows = account.client.account_db()?.task_record_page::<Job>(PREFIX, PREFIX, 65)?;
    let size = rows.iter().try_fold(bytes, |sum, row| {
        serde_json::to_vec(&row.1).map(|b| sum.saturating_add(b.len()))
    })?;
    if rows.len().saturating_add(additional) > MAX_JOBS || size > MAX_BYTES {
        return Err(SdkError::InboundPending("task transport outbox is full".into()));
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
    let mut sequence = db.load_actor_state::<u64>("task/transport_sequence")?.unwrap_or(0);
    for envelope in envelopes {
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| SdkError::LocalBus("task transport sequence exhausted".into()))?;
        db.persist_actor_state(
            &format!("{PREFIX}{sequence:020}"),
            &Job { sequence, envelope, attempts: 0, next_at: 0 },
        )?;
    }
    db.persist_actor_state("task/transport_sequence", &sequence)?;
    Ok(())
}
pub(super) async fn run(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let now = now_unix_timestamp();
    let jobs = account.client.account_db()?.task_record_page::<Job>(PREFIX, PREFIX, 65)?;
    let mut blocked = BTreeSet::new();
    let mut sent = 0;
    for (_, mut job) in jobs {
        let key = format!("{PREFIX}{:020}", job.sequence);
        if job.envelope.created_at.saturating_add(i64::from(job.envelope.ttl)) <= now
            || job.attempts >= 8
        {
            account.client.account_db()?.append_journal(&format!("task-transport-expired:{}",job.sequence),"task.delivery_failed",&json!({"device_id":job.envelope.source_device_id,"envelope_id":job.envelope.envelope_id}),now,None)?;
            account.client.account_db()?.delete_task_state(&key)?;
            continue;
        }
        // Preserve each recipient's order, without letting one unavailable terminal block others.
        if !blocked.insert(job.envelope.target_delivery_id.clone()) || job.next_at > now {
            continue;
        }
        if sent >= 8 {
            break;
        }
        let mut engine = account.take_live_engine().await?;
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            engine.submit_envelope(job.envelope.clone()),
        )
        .await;
        account.put_engine(engine);
        if matches!(result, Ok(Ok(_))) {
            account.client.account_db()?.delete_task_state(&key)?;
            sent += 1;
        } else {
            job.attempts += 1;
            job.next_at = now.saturating_add(2_i64.pow(job.attempts.min(6)));
            account.client.account_db()?.persist_actor_state(&key, &job)?;
        }
    }
    Ok(sent)
}
