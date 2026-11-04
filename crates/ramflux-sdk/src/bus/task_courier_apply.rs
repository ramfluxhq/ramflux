// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actor-owned, failure-isolated submission and durable per-item retry bookkeeping.

use super::dispatch::{task_approval, task_approval_transport, task_transport};
use super::task_courier::{Failure, Item, Preparation, manifest_request_keys};
use super::task_courier_queue::{self as queue, JobRow, stop_class};
use crate::prelude::*;
use serde_json::json;

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
        let id = ramflux_protocol::hash_base64url(
            "ramflux.task.courier.failure.v1",
            item.key.as_bytes(),
        );
        db.persist_actor_state(
            &format!("task/courier_failure/{id}"),
            &json!({"id":item.key,"reason":reason,"attempts":attempts,"start":now}),
        )?;
        db.prune_task_diagnostics("task/courier_failure/", 128)?;
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
/// Only stop-class errors escape. Every other error charges this item and permits the next result.
pub(super) async fn apply(
    account: &mut LocalBusAccountState,
    item: Item,
    preparation: Preparation,
) -> Result<bool, SdkError> {
    let result = apply_item(account, &item, preparation).await;
    account.task_prepared_manifests.clear();
    account.task_prepared_only = false;
    apply_result(account, &item, result)
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

async fn apply_item(
    account: &mut LocalBusAccountState,
    item: &Item,
    preparation: Preparation,
) -> Result<bool, SdkError> {
    let Some(live) = queue::item(account, &item.key, now_unix_timestamp())? else {
        return Ok(false);
    };
    // Check the individual row and routing authority, rather than rejecting unrelated ready items.
    if live.revision != item.revision
        || manifest_request_keys(&live.requests) != manifest_request_keys(&item.requests)
    {
        account.signal_task_courier();
        return Ok(false);
    }
    let (manifests, fetched_after) = match preparation {
        Preparation::Deferred => return Ok(false),
        Preparation::Charged(reason) => {
            charge(account, item, reason)?;
            return Ok(false);
        }
        Preparation::Ready { manifests, fetched_after } => (manifests, fetched_after),
    };
    account.task_prepared_only = true;
    for manifest in manifests {
        // Preserve the actual preparation age, rather than granting a fresh clock after queueing.
        account.client.persist_fetched_identity_directory_at(&manifest, fetched_after)?;
        account.task_prepared_manifests.insert(manifest.principal_commitment.clone(), manifest);
    }
    let Some((mut job, _)) = queue::load(account, &item.key)? else {
        return Ok(false);
    };
    let now = now_unix_timestamp();
    let result = match &job {
        JobRow::Approval(job) => {
            task_approval_transport::send(
                account,
                &job.packet.request().binding.conversation_id,
                job.packet.recipient(),
                &job.packet.bytes()?,
            )
            .await
        }
        JobRow::Ack(job) => {
            let carrier = job.ack.original()?;
            task_transport::send_control(account, &carrier, task_transport::Mode::Ack(&job.ack))
                .await
        }
        JobRow::Forward(job) => {
            let history = account.client.task_history(&job.conversation_id, &job.task_id)?;
            let Some(last) = history.events.last() else {
                account.client.account_db()?.delete_task_state(&item.key)?;
                return Ok(false);
            };
            task_transport::send_control(account, &last.carrier, task_transport::Mode::Own).await
        }
    }?;
    if matches!(result, task_transport::Preparation::Deferred) {
        return Ok(false);
    }
    let db = account.client.account_db()?;
    match &mut job {
        JobRow::Approval(job) => {
            task_approval::record_delivery(account, &item.key, job, true, now)?;
        }
        JobRow::Ack(job) => {
            let hash = crate::client::task::certificate::carrier_hash(&job.ack.original()?)?;
            db.write_transaction(|| {
                db.persist_actor_state(
                    &crate::client::task::key("ack_sent", &hash),
                    &json!({"start":now}),
                )?;
                db.prune_task_diagnostics("task/ack_sent/", 1024)?;
                db.delete_task_state(&item.key)?;
                Ok::<_, SdkError>(())
            })?;
        }
        JobRow::Forward(_) => db.delete_task_state(&item.key)?,
    }
    Ok(true)
}

pub(crate) mod background;
