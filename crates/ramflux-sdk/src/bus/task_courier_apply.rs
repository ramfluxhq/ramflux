// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actor-owned, failure-isolated submission and durable per-item retry bookkeeping.

use super::dispatch::{task_approval, task_approval_transport, task_transport};
use super::task_courier::{Failure, Item, Preparation, manifest_request_keys};
use super::task_courier_queue::{self as queue, JobRow, stop_class};
use crate::prelude::*;
use serde_json::json;

/// Only stop-class errors escape. Every other error charges this item and permits the next result.
pub(super) async fn apply(
    account: &mut LocalBusAccountState,
    item: Item,
    preparation: Preparation,
) -> Result<bool, SdkError> {
    let result = apply_item(account, &item, preparation).await;
    account.task_prepared_manifests.clear();
    account.task_prepared_only = false;
    match result {
        Ok(sent) => Ok(sent),
        Err(error) if stop_class(&error) => Err(error),
        Err(_) => {
            tracing::warn!(item_id = item.key, "task courier item application failed");
            match charge(account, &item, Failure::Application) {
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
    let manifests = match preparation {
        Preparation::Deferred => return Ok(false),
        Preparation::Charged(reason) => {
            charge(account, item, reason)?;
            return Ok(false);
        }
        Preparation::Ready(manifests) => manifests,
    };
    account.task_prepared_only = true;
    for manifest in manifests {
        account.client.persist_identity_directory(&manifest)?;
        for device in &manifest.devices {
            account.client.account_db()?.upsert_device_directory_entry(
                &device.device_id,
                &manifest.principal_commitment,
                "task_courier",
                now_unix_timestamp(),
            )?;
        }
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
