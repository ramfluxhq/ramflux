// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actor-owned, failure-isolated submission and durable per-item retry bookkeeping.

use super::dispatch::task_approval;
use super::task_courier::{Failure, Item};
use super::task_courier::{Preparation, manifest_request_keys};
use super::task_courier_queue::stop_class;
use super::task_courier_queue::{self as queue, JobRow};
use crate::prelude::*;
use serde_json::json;

/// The per-item diagnostic both `charge` and `conflict_terminal` write, pruned to 128.
fn diagnose(
    db: &AccountDb,
    item: &Item,
    reason: Failure,
    attempts: u32,
    now: i64,
) -> Result<(), SdkError> {
    let id =
        ramflux_protocol::hash_base64url("ramflux.task.courier.failure.v1", item.key.as_bytes());
    db.persist_actor_state(
        &format!("task/courier_failure/{id}"),
        &json!({"id":item.key,"reason":reason,"attempts":attempts,"start":now}),
    )?;
    db.prune_task_diagnostics("task/courier_failure/", 128)?;
    Ok(())
}

/// A gateway idempotency conflict on a sent envelope: the item takes its terminal transition
/// at once and is never resubmitted. Ack, Forward and Approval Request rows go to the existing
/// quarantine. An Approval Decision keeps its signed packet under the same key, made
/// ineligible (`attempts = 8`, the existing exhaustion), and its receipt becomes
/// `failed / submit_conflict`, so an explicit `grant.approve` can still re-enqueue it once.
fn conflict_terminal(account: &LocalBusAccountState, item: &Item) -> Result<(), SdkError> {
    use crate::client::task::approval::Payload;
    use crate::client::task::approval_retention::{DeliveryReason, DeliveryState};
    let Some((mut job, revision)) = queue::load(account, &item.key)? else {
        return Ok(());
    };
    if revision != item.revision {
        return Ok(());
    }
    match &mut job {
        JobRow::Approval(job) if matches!(job.packet.payload, Payload::Decision { .. }) => {
            let now = now_unix_timestamp();
            let db = account.client.account_db()?;
            db.write_transaction(|| {
                job.attempts = 8;
                db.persist_actor_state(&item.key, &**job)?;
                account.client.record_task_approval_delivery(
                    &job.packet,
                    DeliveryState::Failed,
                    Some(DeliveryReason::SubmitConflict),
                )?;
                diagnose(db, item, Failure::SubmitConflict, 8, now)
            })?;
            tracing::warn!(item_id = item.key, "task courier decision retired on conflict");
            Ok(())
        }
        _ => queue::quarantine(account, &item.key, Failure::SubmitConflict),
    }
}

fn charge(account: &LocalBusAccountState, item: &Item, reason: Failure) -> Result<(), SdkError> {
    let Some((mut job, revision)) = queue::load(account, &item.key)? else {
        return Ok(());
    };
    if revision != item.revision {
        return Ok(());
    }
    let now = now_unix_timestamp();
    let attempts = job.attempts().saturating_add(1);
    let next_at = now.saturating_add(2_i64.pow(attempts.min(6)));
    let db = account.client.account_db()?;
    db.write_transaction(|| {
        match &mut job {
            JobRow::Approval(job) => {
                task_approval::record_delivery(account, &item.key, job, false, now)?;
            }
            JobRow::Ack(job) => {
                job.attempts = attempts;
                job.next_at = next_at;
                db.persist_actor_state(&item.key, job)?;
            }
            JobRow::Forward(job) => {
                job.attempts = attempts;
                job.next_at = next_at;
                db.persist_actor_state(&item.key, job)?;
            }
        }
        diagnose(db, item, reason, attempts, now)?;
        Ok::<_, SdkError>(())
    })?;
    tracing::warn!(item_id = item.key, "task courier item charged");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::task::control::ForwardJob;
    use std::sync::{Arc, atomic::AtomicBool};

    #[tokio::test]
    async fn post_seal_worker_capacity_refusal_records_a_bounded_application_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::bus::runtime_tests::root("post-seal-capacity-retry");
        let account = crate::bus::runtime_tests::account(
            &root,
            "sender",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let db = account.client.account_db()?;
        let key = "task/forward/capacity";
        let now = now_unix_timestamp();
        db.persist_actor_state(
            key,
            &ForwardJob {
                conversation_id: "thread".into(),
                task_id: "task".into(),
                attempts: 0,
                next_at: 0,
                created_at: now,
            },
        )?;
        let (_, revision) = queue::load(&account, key)?.ok_or("job")?;
        let item = Item { key: key.into(), revision, requests: Vec::new(), failure: None };
        assert!(!apply_result(&account, &item, Err(SdkError::TaskForwardWorkerCapacity))?);
        tokio::task::yield_now().await;
        let saved = db.load_actor_state::<ForwardJob>(key)?.ok_or("saved job")?;
        assert_eq!(
            saved.attempts, 1,
            "post-seal refusal must not enable an unbounded free resealing loop"
        );
        assert!(saved.next_at >= now + 2);
        let failure = db
            .actor_state_key_page("task/courier_failure/", 1)?
            .into_iter()
            .next()
            .ok_or("failure record")?;
        let record =
            db.load_actor_state::<serde_json::Value>(&failure)?.ok_or("failure metadata")?;
        assert_eq!(record["reason"], "application");
        assert_eq!(record["attempts"], 1);
        Ok(())
    }
}
fn apply_result(
    account: &LocalBusAccountState,
    item: &Item,
    result: Result<bool, SdkError>,
) -> Result<bool, SdkError> {
    match result {
        Ok(sent) => Ok(sent),
        Err(error) if stop_class(&error) => Err(error),
        Err(_) => {
            tracing::warn!(item_id = item.key, "task courier item application failed");
            match charge(account, item, Failure::Application) {
                Err(error) if stop_class(&error) => Err(error),
                _ => Ok(false),
            }
        }
    }
}

pub(crate) mod background;
