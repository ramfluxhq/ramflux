// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lenient courier queue admission, per-item routing snapshots and payload-free dead rows.

use super::task_courier::{Failure, Item, ManifestRequest, ManifestSource};
use crate::client::task::{
    approval::Job,
    control::{AckJob, ForwardJob},
};
use crate::prelude::*;
use serde_json::{Value, json};

pub(super) enum JobRow {
    Approval(Box<Job>),
    Ack(Box<AckJob>),
    Forward(ForwardJob),
}

impl JobRow {
    pub(super) fn attempts(&self) -> u32 {
        match self {
            Self::Approval(job) => job.attempts,
            Self::Ack(job) => job.attempts,
            Self::Forward(job) => job.attempts,
        }
    }

    fn eligible(&self, now: i64) -> bool {
        match self {
            Self::Approval(job) => {
                job.next_at <= now && job.packet.deadline() > now && job.attempts < 8
            }
            Self::Ack(job) => job.next_at <= now,
            Self::Forward(job) => job.next_at <= now,
        }
    }
}

pub(super) fn load(
    account: &LocalBusAccountState,
    key: &str,
) -> Result<Option<(JobRow, String)>, SdkError> {
    let db = account.client.account_db()?;
    let row = match db.load_actor_state::<Value>(key) {
        Ok(Some(row)) => row,
        Ok(None) => return Ok(None),
        Err(StorageError::Serde(_)) => {
            quarantine(account, key, Failure::UndecodableRow)?;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let revision = ramflux_protocol::hash_base64url(
        "ramflux.task.courier.row.v1",
        &ramflux_protocol::canonical_json_bytes(&row)?,
    );
    let decoded = if key.starts_with("task/ack/") {
        serde_json::from_value(row).map(|job| JobRow::Ack(Box::new(job)))
    } else if key.starts_with("task/forward/") {
        serde_json::from_value(row).map(JobRow::Forward)
    } else {
        serde_json::from_value(row).map(|job| JobRow::Approval(Box::new(job)))
    };
    if let Ok(job) = decoded {
        Ok(Some((job, revision)))
    } else {
        quarantine(account, key, Failure::UndecodableRow)?;
        Ok(None)
    }
}

pub(super) fn quarantine(
    account: &LocalBusAccountState,
    key: &str,
    reason: Failure,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let id = ramflux_protocol::hash_base64url("ramflux.task.courier.dead.v1", key.as_bytes());
    db.write_transaction(|| {
        let count = db.load_actor_state::<u64>("task/courier_dead_count")?.unwrap_or(0);
        db.persist_actor_state(
            &format!("task/courier_dead/{id}"),
            &json!({"id":key,"reason":reason}),
        )?;
        db.delete_task_state(key)?;
        db.persist_actor_state("task/courier_dead_count", &count.saturating_add(1))?;
        db.prune_task_diagnostics("task/courier_dead/", 128)?;
        Ok::<_, SdkError>(())
    })?;
    tracing::warn!(item_id = key, "task courier row quarantined");
    Ok(())
}

pub(super) fn manifest_requests(account: &mut LocalBusAccountState) -> Result<Vec<Item>, SdkError> {
    let now = now_unix_timestamp();
    let mut items = Vec::new();
    for (prefixes, cursor) in [
        (&["task/approval_decision_out/", "task/approval_out/"][..], account.task_approval_cursor),
        (&["task/ack/"][..], account.task_ack_cursor),
        (&["task/forward/"][..], account.task_forward_cursor),
    ] {
        // Keys are read independently of values so even invalid JSON cannot abort a page.
        let mut keys = Vec::new();
        for prefix in prefixes {
            match account.client.account_db()?.actor_state_key_page(prefix, 65) {
                Ok(page) => keys.extend(page),
                Err(error) => {
                    let error = SdkError::from(error);
                    if stop_class(&error) {
                        return Err(error);
                    }
                    tracing::warn!(item_id = prefix, "task courier queue read deferred");
                }
            }
        }
        keys.sort();
        if !keys.is_empty() {
            let offset = cursor % keys.len();
            keys.rotate_left(offset);
        }
        // Cursor advancement belongs to admission, not to completion order.
        match prefixes[0] {
            "task/ack/" => account.task_ack_cursor = cursor.wrapping_add(2),
            "task/forward/" => account.task_forward_cursor = cursor.wrapping_add(2),
            _ => account.task_approval_cursor = cursor.wrapping_add(2),
        }
        let mut selected = 0;
        for key in keys {
            let result = item(account, &key, now);
            match result {
                Ok(Some(item)) => {
                    items.push(item);
                    selected += 1;
                    if selected == 2 {
                        break;
                    }
                }
                Ok(None) => {}
                Err(error) if stop_class(&error) => return Err(error),
                Err(_) => tracing::warn!(item_id = key, "task courier item read deferred"),
            }
        }
    }
    Ok(items)
}

pub(super) fn item(
    account: &LocalBusAccountState,
    key: &str,
    now: i64,
) -> Result<Option<Item>, SdkError> {
    let Some((job, revision)) = load(account, key)? else {
        return Ok(None);
    };
    let expired = match &job {
        JobRow::Ack(job) => job.attempts >= 8 || now.saturating_sub(job.created_at) > 600,
        JobRow::Forward(job) => job.attempts >= 8 || now.saturating_sub(job.created_at) > 600,
        JobRow::Approval(_) => false,
    };
    if expired {
        account.client.account_db()?.delete_task_state(key)?;
        return Ok(None);
    }
    if !job.eligible(now) {
        return Ok(None);
    }
    let conversation = match &job {
        JobRow::Approval(job) => job.packet.request().binding.conversation_id.clone(),
        JobRow::Ack(job) => {
            if let Ok(carrier) = job.ack.original() {
                carrier.conversation_id
            } else {
                quarantine(account, key, Failure::UndecodableCarrier)?;
                return Ok(None);
            }
        }
        JobRow::Forward(job) => job.conversation_id.clone(),
    };
    let requests = requests_for(account, &conversation, matches!(job, JobRow::Forward(_)));
    let (requests, failure) = match requests {
        Ok(requests) => (requests, None),
        Err(error) if stop_class(&error) => return Err(error),
        Err(_) => (Vec::new(), Some(Failure::Preparation)),
    };
    Ok(Some(Item { key: key.into(), revision, requests, failure }))
}

fn requests_for(
    account: &LocalBusAccountState,
    conversation: &str,
    own_only: bool,
) -> Result<Vec<ManifestRequest>, SdkError> {
    let db = account.client.account_db()?;
    let mut requests = vec![ManifestRequest {
        source: ManifestSource::Gateway(Box::new(account.gateway_config.clone())),
        commitment: account.principal_commitment.clone(),
    }];
    if own_only {
        return Ok(requests);
    }
    let thread = db
        .client_record("conversation", conversation)?
        .ok_or_else(|| SdkError::InboundRejected("task conversation missing".into()))?;
    if let Some(group) = thread["group_id"].as_str() {
        for route in super::group_delivery::directory(&account.client, group)? {
            if let Some(commitment) = route["member_principal_commitment"].as_str()
                && commitment != account.principal_commitment
            {
                requests.push(request(
                    account,
                    &route["federation"]["recipient_prekey_url"],
                    commitment,
                ));
            }
        }
    } else if let Some(participants) = thread["participants"].as_array() {
        let local = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        for principal in
            participants.iter().filter_map(Value::as_str).filter(|id| *id != local.principal_id)
        {
            if let Some(identity) = db.client_record("identity", principal)?
                && let Some(commitment) = identity["contact_identity_commitment"].as_str()
            {
                requests.push(request(
                    account,
                    &thread["direct_route"]["federation"]["recipient_prekey_url"],
                    commitment,
                ));
            }
        }
    }
    Ok(requests)
}

fn request(account: &LocalBusAccountState, url: &Value, commitment: &str) -> ManifestRequest {
    ManifestRequest {
        source: url.as_str().map_or_else(
            || ManifestSource::Gateway(Box::new(account.gateway_config.clone())),
            |url| ManifestSource::Federation(url.into()),
        ),
        commitment: commitment.into(),
    }
}

/// Explicit account-stop allowlist. Row decode, network, quota, busy and I/O failures stay local.
pub(super) fn stop_class(error: &SdkError) -> bool {
    match error {
        SdkError::AccountDbNotUnlocked
        | SdkError::AccountNotOpen(_)
        | SdkError::IdentityRootMissing
        | SdkError::CustodyVaultUnavailable => true,
        SdkError::Storage(error) => error.is_account_unusable(),
        _ => false,
    }
}
