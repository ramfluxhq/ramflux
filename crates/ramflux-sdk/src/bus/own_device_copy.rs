// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded durable per-message `OwnDeviceFanout` retries, independent of peer delivery status.
use crate::client::own_device_copy::{OwnDeviceMessage, OwnMessageInput};
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
const PREFIX: &str = "own-device/send/";
const MAX_PENDING: u32 = 256;
const MAX_PENDING_BYTES: u64 = 8 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
struct Intent {
    copy_id: String,
    id: String,
    conversation: String,
    group: Option<String>,
    body: String,
    created_at: i64,
    owner_record: Option<(String, String)>,
}
#[derive(Serialize, Deserialize)]
struct Work {
    intent: Intent,
    packet: Option<OwnDeviceMessage>,
    attempts: u32,
    next_at: i64,
}
pub(crate) fn copy_id(client: &RamfluxClient, id: &str) -> Result<String, SdkError> {
    let source = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.sdk.own_device_message.v1",
        &ramflux_protocol::canonical_json_bytes(&(
            &client.surface_local_root_commitment()?,
            &source.device_id,
            id,
        ))?,
    ))
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
    let id = copy_id(client, input.id)?;
    let key = format!("{PREFIX}{id}");
    let db = client.account_db()?;
    if db.actor_state_exists(&key)?
        || matches!(status(client, input.id)?.as_str(), "submitted" | "failed" | "not_needed")
    {
        return Ok(());
    }
    let work = Work {
        intent: Intent {
            copy_id: id.clone(),
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
    };
    db.write_transaction(|| {
        let (rows, bytes) = db.actor_state_usage(PREFIX)?;
        if input.body.len() > crate::client::own_device_copy::MAX_PACKET_BYTES
            || rows >= u64::from(MAX_PENDING)
            || bytes.saturating_add(work_bytes(&work)?) > MAX_PENDING_BYTES
        {
            return Err(SdkError::LocalBus("own-device retry capacity exceeded".into()));
        }
        db.persist_actor_state(&key, &work)?;
        Ok::<_, SdkError>(())
    })?;
    state(client, &work, "pending", true)
}
pub(crate) async fn flush(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let now = now_unix_timestamp();
    let started = std::time::Instant::now();
    let keys = account.client.account_db()?.actor_state_key_page(PREFIX, MAX_PENDING)?;
    let mut sent = 0;
    for id in keys {
        if started.elapsed() >= Duration::from_millis(250) {
            break;
        }
        let Some(mut work) = account.client.account_db()?.load_actor_state::<Work>(&id)? else {
            continue;
        };
        if work.intent.created_at.saturating_add(600) <= now
            || work.attempts >= 10
            || copy_id(&account.client, &work.intent.id)? != work.intent.copy_id
        {
            account.client.account_db()?.remove_actor_state(&id)?;
            state(&account.client, &work, "failed", false)?;
            continue;
        }
        if work.next_at > now {
            continue;
        }
        work.attempts += 1;
        work.next_at = now.saturating_add((1_i64 << work.attempts.min(6)).min(60));
        account.client.account_db()?.persist_actor_state(&id, &work)?;
        if work.packet.is_none() {
            match prepare(account, &work.intent).await {
                Ok(Some(packet)) => {
                    let old_bytes = work_bytes(&work)?;
                    work.packet = Some(packet);
                    work.intent.body.clear();
                    let db = account.client.account_db()?;
                    let admitted = db.write_transaction(|| {
                        let (_, bytes) = db.actor_state_usage(PREFIX)?;
                        if bytes.saturating_sub(old_bytes).saturating_add(work_bytes(&work)?)
                            > MAX_PENDING_BYTES
                        {
                            return Ok::<_, SdkError>(false);
                        }
                        db.persist_actor_state(&id, &work)?;
                        Ok(true)
                    })?;
                    if !admitted {
                        continue;
                    }
                }
                Ok(None) => {
                    account.client.account_db()?.remove_actor_state(&id)?;
                    state(&account.client, &work, "not_needed", false)?;
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error,"own-device message preparation deferred");
                    break;
                }
            }
        }
        let packet = work
            .packet
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("own-device message absent".into()))?;
        match send(account, packet).await {
            Ok(()) => {
                account.client.account_db()?.remove_actor_state(&id)?;
                state(&account.client, &work, "submitted", false)?;
                sent += 1;
            }
            Err(error) => {
                state(&account.client, &work, "pending", false)?;
                tracing::warn!(%error,"own-device message copy deferred");
                break;
            }
        }
    }
    Ok(sent)
}
async fn prepare(
    account: &mut LocalBusAccountState,
    intent: &Intent,
) -> Result<Option<OwnDeviceMessage>, SdkError> {
    let body = ramflux_protocol::decode_base64url(&intent.body)
        .map_err(|_| SdkError::LocalBus("own-device intent encoding".into()))?;
    let mut engine = account.take_live_engine().await?;
    let prepared = account
        .client
        .prepare_own_device_message(
            &mut engine,
            OwnMessageInput {
                id: &intent.id,
                created_at: intent.created_at,
                conversation: &intent.conversation,
                group: intent.group.as_deref(),
                body: &body,
            },
        )
        .await;
    account.put_engine(engine);
    prepared
}
async fn send(
    account: &mut LocalBusAccountState,
    packet: &OwnDeviceMessage,
) -> Result<(), SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = async {
        // Fresh outer ids allow lost-ACK retries through the router's replay guard.
        // The immutable logical packet and sibling receipts prevent duplicate projection.
        let message = GatewayDirectMessage {
            conversation_id: packet.conversation.clone(),
            message_id: packet.id.clone(),
            envelope_id: crate::new_surface_message_id()?,
            source_principal_id: packet.principal.clone(),
            sender_id: packet.source.clone(),
            recipient_device_id: None,
            target_delivery_id: engine.config.target_delivery_id.clone(),
            encrypted_body: packet.bytes()?,
            created_at: packet.created_at,
            ttl: 600,
        };
        let mut envelope = gateway_direct_message_envelope(&engine.config, &message, None)?;
        envelope.delivery_class = ramflux_protocol::DeliveryClass::SelfDeviceControl;
        envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &envelope,
        )?;
        let response =
            engine.own_device_fanout(&packet.principal, &packet.source, envelope).await?;
        if response.principal_id != packet.principal
            || response.source_device_id != packet.source
            || packet.slots.iter().any(|slot| {
                !response.delivered.iter().any(|delivery| {
                    delivery.device_id == slot.recipient_device_id
                        && matches!(delivery.outcome.as_str(), "online" | "offline_queued")
                })
            })
        {
            return Err(SdkError::LocalBus("own-device fanout acknowledgement mismatch".into()));
        }
        Ok(())
    }
    .await;
    account.put_engine(engine);
    result
}
fn state(client: &RamfluxClient, work: &Work, value: &str, latest: bool) -> Result<(), SdkError> {
    let id = &work.intent.copy_id;
    let db = client.account_db()?;
    db.persist_actor_state(&format!("own-device/status/{id}"),&json!({"state":value,"conversation_id":work.intent.conversation,"message_id":work.intent.id}))?;
    if let Some((directory, record)) = &work.intent.owner_record
        && matches!(directory.as_str(), "surface" | "message")
        && let Some(mut row) = db.client_record(directory, record)?
        && (latest || row["own_copy_message_id"].as_str() == Some(id.as_str()))
    {
        row["own_copy_message_id"] = json!(id);
        row["own_device_copy_state"] = json!(value);
        db.persist_client_record(directory, record, &row)?;
    }
    Ok(())
}

fn work_bytes(work: &Work) -> Result<u64, SdkError> {
    u64::try_from(serde_json::to_vec(work)?.len())
        .map_err(|_| SdkError::LocalBus("own-device record size overflow".into()))
}
