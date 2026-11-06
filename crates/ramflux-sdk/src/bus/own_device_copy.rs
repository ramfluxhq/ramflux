// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded durable per-message `OwnDeviceFanout` retries, independent of peer delivery status.
use crate::client::own_device_copy::OwnMessageInput;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
mod targets;
use targets::Target;
const PREFIX: &str = "own-device/send/";
const MAX_PENDING: u32 = 256;
const MAX_PENDING_BYTES: u64 = 8 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
struct Intent {
    copy_id: String,
    #[serde(default)]
    sequence: u64,
    id: String,
    conversation: String,
    group: Option<String>,
    body: String,
    created_at: i64,
    #[serde(default)]
    expires_at: Option<i64>,
    owner_record: Option<(String, String)>,
}
impl Intent {
    fn expiry(&self) -> i64 {
        // Pre-parameter queued work retains its original ten-minute lifetime.
        self.expires_at.unwrap_or(self.created_at.saturating_add(600))
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Work {
    intent: Intent,
    packet: Option<serde_json::Value>,
    attempts: u32,
    next_at: i64,
    #[serde(default)]
    held: bool,
    #[serde(default)]
    local_manifest: bool,
    #[serde(default)]
    targets: Vec<Target>,
    #[serde(default)]
    context_delivery: Option<crate::client::surface::OwnContextDelivery>,
}
pub(crate) fn copy_id(client: &RamfluxClient, id: &str) -> Result<String, SdkError> {
    let source = client.read_device_identity()?.ok_or(SdkError::IdentityRootMissing)?;
    crate::client::own_device_copy::copy_id(
        &client.surface_local_root_commitment()?,
        source.device_id(),
        id,
    )
}
pub(crate) fn status(client: &RamfluxClient, id: &str) -> Result<String, SdkError> {
    Ok(client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&format!(
            "own-device/status/{}",
            copy_id(client, id)?
        ))?
        .and_then(|value| value["state"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into()))
}
pub(crate) fn stage(
    client: &RamfluxClient,
    input: OwnMessageInput<'_>,
    owner_record: Option<(&str, &str)>,
) -> Result<(), SdkError> {
    stage_inner(client, input, owner_record, false)
}
pub(crate) fn stage_held(
    client: &RamfluxClient,
    input: OwnMessageInput<'_>,
    message: &str,
) -> Result<(), SdkError> {
    stage_inner(client, input, Some(("message", message)), true)
}
fn stage_inner(
    client: &RamfluxClient,
    input: OwnMessageInput<'_>,
    owner_record: Option<(&str, &str)>,
    held: bool,
) -> Result<(), SdkError> {
    let id = copy_id(client, input.id)?;
    let key = format!("{PREFIX}{id}");
    let db = client.account_db()?;
    if db.actor_state_exists(&key)?
        || matches!(status(client, input.id)?.as_str(), "submitted" | "failed" | "not_needed")
    {
        return Ok(());
    }
    let mut work = Work {
        intent: Intent {
            copy_id: id.clone(),
            sequence: 0,
            id: input.id.into(),
            conversation: input.conversation.into(),
            group: input.group.map(str::to_owned),
            body: ramflux_protocol::encode_base64url(input.body),
            created_at: input.created_at,
            expires_at: Some(input.created_at.saturating_add(i64::from(client.content_ttl()?))),
            owner_record: owner_record.map(|(directory, id)| (directory.into(), id.into())),
        },
        packet: None,
        attempts: 0,
        next_at: input.created_at,
        held,
        local_manifest: held,
        targets: Vec::new(),
        context_delivery: None,
    };
    db.write_transaction(|| {
        let (rows, bytes) = db.own_copy_actor_usage(PREFIX)?;
        if input.body.len() > crate::client::own_device_copy::MAX_PACKET_BYTES
            || rows >= u64::from(MAX_PENDING)
            || bytes.saturating_add(work_bytes(&work)?) > MAX_PENDING_BYTES
        {
            return Err(SdkError::LocalBus("own-device retry capacity exceeded".into()));
        }
        let sequence = db
            .load_actor_state::<u64>("own-device/sequence")?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| SdkError::LocalBus("own-device queue sequence exhausted".into()))?;
        work.intent.sequence = sequence;
        db.persist_actor_state("own-device/sequence", &sequence)?;
        if let Some(message) = message_owner(&work) {
            db.persist_message_actor_state(message, &key, &work)?;
        } else {
            db.persist_actor_state(&key, &work)?;
        }
        state(client, &work, "pending", true)
    })
}
fn pending_ordered(client: &RamfluxClient, now: i64) -> Result<Vec<(String, Work)>, SdkError> {
    let keys = client.account_db()?.due_own_copy_keys(now, MAX_PENDING)?;
    let mut ordered = Vec::new();
    for id in keys {
        if let Some(work) = client.account_db()?.load_actor_state::<Work>(&id)? {
            ordered.push((id, work));
        }
    }
    ordered.sort_by(|a, b| {
        (a.1.intent.sequence, a.1.intent.created_at, &a.0).cmp(&(
            b.1.intent.sequence,
            b.1.intent.created_at,
            &b.0,
        ))
    });
    Ok(ordered)
}
fn persist_work(client: &RamfluxClient, key: &str, work: &Work) -> Result<bool, SdkError> {
    let db = client.account_db()?;
    db.write_transaction(|| {
        let Some(old) = db.load_actor_state::<serde_json::Value>(key)? else { return Ok(false) };
        let old_bytes = u64::try_from(serde_json::to_vec(&old)?.len())
            .map_err(|_| SdkError::LocalBus("own-device record size overflow".into()))?;
        let (_, bytes) = db.own_copy_actor_usage(PREFIX)?;
        if bytes.saturating_sub(old_bytes).saturating_add(work_bytes(work)?) > MAX_PENDING_BYTES {
            return Ok(false);
        }
        db.persist_actor_state(key, work)?;
        Ok(true)
    })
}

fn finish_attempt(
    client: &RamfluxClient,
    id: &str,
    work: &mut Work,
    delivered: Option<&[String]>,
    now: i64,
) -> Result<bool, SdkError> {
    for target in &mut work.targets {
        if let Some(delivered) = delivered {
            target.confirm(delivered);
        }
        target.park_after_attempt(now);
    }
    let completed = work.targets.iter().all(Target::acknowledged);
    client.account_db()?.write_transaction(|| {
        let value = if completed {
            client.account_db()?.remove_actor_state(id)?;
            "submitted"
        } else if persist_work(client, id, work)? {
            "pending"
        } else {
            client.account_db()?.remove_actor_state(id)?;
            "failed"
        };
        state(client, work, value, false)
    })?;
    Ok(completed)
}

#[cfg(test)]
pub(crate) async fn flush(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let keys = pending_ordered(&account.client, now_unix_timestamp())?;
    let mut sent = 0;
    for (key, work) in keys {
        if !account.client.account_db()?.actor_state_exists(&key)? {
            continue;
        }
        let _ = background::drive_once(account).await;
        sent += usize::from(status(&account.client, &work.intent.id)? == "submitted");
    }
    Ok(sent)
}
fn state(client: &RamfluxClient, work: &Work, value: &str, latest: bool) -> Result<(), SdkError> {
    let id = &work.intent.copy_id;
    let db = client.account_db()?;
    if let Some(context) = &work.context_delivery {
        client.finish_own_surface_context(context, value == "submitted")?;
    }
    let key = format!("own-device/status/{id}");
    let status = json!({"state":value,"acknowledged":value == "submitted","completed":value != "pending","conversation_id":work.intent.conversation,"message_id":message_owner(work).unwrap_or(&work.intent.id),"expires_at":work.intent.expiry().saturating_add(300)});
    if let Some(message) = message_owner(work) {
        db.persist_message_actor_state(message, &key, &status)?;
    } else {
        db.persist_actor_state(&key, &status)?;
    }
    db.maintain_own_copy_delivery(
        now_unix_timestamp(),
        crate::client::own_device_copy::MAX_DELIVERY_ROWS,
    )?;
    if let Some((directory, record)) = &work.intent.owner_record
        && matches!(directory.as_str(), "surface" | "message")
        && let Some(mut row) = db.client_record(directory, record)?.or_else(|| {
            (directory == "message")
                .then(|| json!({"id":record,"conversation_id":work.intent.conversation}))
        })
        && (latest || row["own_copy_message_id"].as_str() == Some(id.as_str()))
    {
        row["own_copy_message_id"] = json!(id);
        row["own_device_copy_state"] = json!(value);
        db.persist_client_record(directory, record, &row)?;
    }
    Ok(())
}

fn message_owner(work: &Work) -> Option<&str> {
    work.intent
        .owner_record
        .as_ref()
        .and_then(|(directory, message)| (directory == "message").then_some(message.as_str()))
}

fn work_bytes(work: &Work) -> Result<u64, SdkError> {
    u64::try_from(serde_json::to_vec(work)?.len())
        .map_err(|_| SdkError::LocalBus("own-device record size overflow".into()))
}

/// Release only a held plain-message copy; legacy/surface retries keep their existing lifecycle.
pub(crate) fn finish_held(
    client: &RamfluxClient,
    envelope: &str,
    confirmed: bool,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let key = format!("{PREFIX}{}", copy_id(client, envelope)?);
    db.write_transaction(|| {
        let Some(mut work) = db.load_actor_state::<Work>(&key)? else { return Ok(()) };
        if !work.held {
            return Ok(());
        }
        if confirmed {
            work.held = false;
            db.persist_actor_state(&key, &work)?;
            state(client, &work, "pending", false)?;
        } else {
            db.remove_actor_state(&key)?;
            state(client, &work, "failed", false)?;
        }
        Ok(())
    })
}

mod background;
pub(crate) use background::{OwnCopyWork, apply as apply_background, run as run_background};

#[cfg(test)]
pub(crate) use background::drive_once;
