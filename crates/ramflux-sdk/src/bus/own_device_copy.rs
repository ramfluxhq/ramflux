// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded durable per-message `OwnDeviceFanout` retries, independent of peer delivery status.
#[cfg(test)]
use crate::client::own_device_copy::OwnDeviceMessage;
use crate::client::own_device_copy::OwnMessageInput;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(test)]
use zeroize::Zeroize;
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
    owner_record: Option<(String, String)>,
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

async fn prepare_work(
    account: &mut LocalBusAccountState,
    id: &str,
    work: &mut Work,
    now: i64,
) -> Result<bool, SdkError> {
    if work.next_at > now {
        return Ok(false);
    }
    work.attempts += 1;
    work.next_at = now.saturating_add((1_i64 << work.attempts.min(6)).min(60));
    if !persist_work(&account.client, id, work)? {
        account.client.account_db()?.remove_actor_state(id)?;
        state(&account.client, work, "failed", false)?;
        return Ok(false);
    }
    match prepare(account, &work.intent, work.local_manifest).await {
        Ok(Some(packet)) => {
            work.context_delivery.clone_from(&packet.context_delivery);
            work.targets = packet
                .slots
                .iter()
                .map(|slot| Target::new(slot.recipient_device_id.clone(), 0, now))
                .collect();
            work.packet = Some(serde_json::to_value(packet)?);
            work.intent.body.zeroize();
            let admitted = persist_work(&account.client, id, work)?;
            if !admitted {
                account.client.account_db()?.remove_actor_state(id)?;
                state(&account.client, work, "failed", false)?;
                return Ok(false);
            }
        }
        Ok(None) => {
            account.client.account_db()?.remove_actor_state(id)?;
            state(&account.client, work, "not_needed", false)?;
            return Ok(false);
        }
        Err(SdkError::InboundRejected(reason))
            if reason == crate::client::own_device_copy::TOO_LARGE =>
        {
            account.client.account_db()?.remove_actor_state(id)?;
            state(&account.client, work, "failed", false)?;
            return Ok(false);
        }
        Err(error) => {
            tracing::warn!(%error,"own-device message preparation deferred");
            return Ok(false);
        }
    }
    Ok(true)
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
    let now = now_unix_timestamp();
    let started = std::time::Instant::now();
    let ordered = pending_ordered(&account.client, now)?;
    let mut sent = 0;
    for (id, mut work) in ordered {
        if started.elapsed() >= Duration::from_millis(250) {
            break;
        }
        // Pre-confirmation plain intents from older versions have no submit receipt. Do not
        // infer success on upgrade; surfaces and other legacy controls keep their lifecycle.
        if !work.local_manifest
            && work.intent.owner_record.as_ref().is_some_and(|(kind, _)| kind == "message")
        {
            account.client.account_db()?.remove_actor_state(&id)?;
            state(&account.client, &work, "failed", false)?;
            continue;
        }
        if work.intent.created_at.saturating_add(600) <= now
            || (work.packet.is_none() && work.attempts >= 10)
            || copy_id(&account.client, &work.intent.id)? != work.intent.copy_id
        {
            account.client.account_db()?.remove_actor_state(&id)?;
            state(&account.client, &work, "failed", false)?;
            continue;
        }
        if work.held {
            continue;
        }
        if work.packet.is_none() && !prepare_work(account, &id, &mut work, now).await? {
            continue;
        }
        let packet = work
            .packet
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("own-device message absent".into()))?;
        let Ok(packet) = serde_json::from_value::<OwnDeviceMessage>(packet.clone()) else {
            account.client.account_db()?.remove_actor_state(&id)?;
            state(&account.client, &work, "failed", false)?;
            continue;
        };
        if work.targets.is_empty() {
            // Upgrade prepared rows without granting an extra retry budget.
            work.targets = packet
                .slots
                .iter()
                .map(|slot| {
                    Target::new(slot.recipient_device_id.clone(), work.attempts, work.next_at)
                })
                .collect();
        }
        if work.targets.iter().all(Target::finished) {
            let completed = work.targets.iter().all(Target::acknowledged);
            account.client.account_db()?.write_transaction(|| {
                account.client.account_db()?.remove_actor_state(&id)?;
                state(&account.client, &work, if completed { "submitted" } else { "failed" }, false)
            })?;
            continue;
        }
        if !work.targets.iter().any(|target| target.due(now)) {
            // A parked target never holds the account-wide queue head.
            continue;
        }
        for target in &mut work.targets {
            target.charge(now);
        }
        if !persist_work(&account.client, &id, &work)? {
            account.client.account_db()?.remove_actor_state(&id)?;
            state(&account.client, &work, "failed", false)?;
            continue;
        }
        match send(account, &packet).await {
            Ok(delivered) => {
                sent += usize::from(finish_attempt(
                    &account.client,
                    &id,
                    &mut work,
                    Some(&delivered),
                    now_unix_timestamp(),
                )?);
            }
            Err(error) => {
                finish_attempt(&account.client, &id, &mut work, None, now_unix_timestamp())?;
                tracing::warn!(%error,"own-device message copy deferred");
            }
        }
    }
    Ok(sent)
}
#[cfg(test)]
async fn prepare(
    account: &mut LocalBusAccountState,
    intent: &Intent,
    local_manifest: bool,
) -> Result<Option<OwnDeviceMessage>, SdkError> {
    let body = zeroize::Zeroizing::new(
        ramflux_protocol::decode_base64url(&intent.body)
            .map_err(|_| SdkError::LocalBus("own-device intent encoding".into()))?,
    );
    let mut engine = account.session_client().await?;
    let prepared = account
        .client
        .prepare_own_device_message_with_source(
            &mut engine,
            OwnMessageInput {
                id: &intent.id,
                created_at: intent.created_at,
                conversation: &intent.conversation,
                group: intent.group.as_deref(),
                body: &body,
            },
            local_manifest,
        )
        .await;
    account.apply_session_metadata(engine);
    prepared
}
#[cfg(test)]
async fn send(
    account: &mut LocalBusAccountState,
    packet: &OwnDeviceMessage,
) -> Result<Vec<String>, SdkError> {
    let mut engine = account.session_client().await?;
    let result = async {
        // Fresh outer ids allow lost-ACK retries through the router's replay guard.
        // The immutable logical packet and sibling receipts prevent duplicate projection.
        let message = GatewayDirectMessage {
            conversation_id: packet.id.clone(),
            message_id: packet.id.clone(),
            envelope_id: crate::new_surface_message_id()?,
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: engine.config.device_id.clone(),
            recipient_device_id: None,
            recipient_principal_commitment: None,
            target_delivery_id: engine.config.target_delivery_id.clone(),
            encrypted_body: packet.bytes()?,
            created_at: now_unix_timestamp(),
            ttl: 600,
        };
        let mut envelope = gateway_direct_message_envelope(&engine.config, &message, None)?;
        envelope.delivery_class = ramflux_protocol::DeliveryClass::SelfDeviceControl;
        envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &envelope,
        )?;
        let response = engine
            .own_device_fanout(
                engine.config.principal_id.clone(),
                engine.config.device_id.clone(),
                envelope,
            )
            .await?;
        if response.principal_id != engine.config.principal_id
            || response.source_device_id != engine.config.device_id
        {
            return Err(SdkError::LocalBus("own-device fanout acknowledgement mismatch".into()));
        }
        Ok(response
            .delivered
            .into_iter()
            .filter(|delivery| {
                packet.slots.iter().any(|slot| slot.recipient_device_id == delivery.device_id)
                    && matches!(delivery.outcome.as_str(), "online" | "offline_queued")
            })
            .map(|delivery| delivery.device_id)
            .collect())
    }
    .await;
    account.apply_session_metadata(engine);
    result
}
fn state(client: &RamfluxClient, work: &Work, value: &str, latest: bool) -> Result<(), SdkError> {
    let id = &work.intent.copy_id;
    let db = client.account_db()?;
    if let Some(context) = &work.context_delivery {
        client.finish_own_surface_context(context, value == "submitted")?;
    }
    let key = format!("own-device/status/{id}");
    let status = json!({"state":value,"acknowledged":value == "submitted","completed":value != "pending","conversation_id":work.intent.conversation,"message_id":message_owner(work).unwrap_or(&work.intent.id),"expires_at":work.intent.created_at.saturating_add(900)});
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
