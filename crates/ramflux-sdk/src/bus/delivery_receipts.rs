// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned bounded receipt courier; retries reuse the committed ciphertext.
use crate::client::delivery_receipts::{PREFIX, Work};
use crate::prelude::*;
use serde_json::json;
const SCAN: u32 = 256;
const SCAN_CURSOR: &str = "delivery-receipt/scan-cursor";
const ATTEMPTS: u32 = 8;
const LIFETIME: i64 = 600;
const GATEWAY_RETRY_AT: &str = "delivery-receipt/gateway-retry-at";
pub(crate) async fn flush(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let now = now_unix_timestamp();
    let db = account.client.account_db()?;
    if let Some(at) = db.load_actor_state::<i64>(GATEWAY_RETRY_AT)? {
        // A persisted cooldown must never extend beyond its thirty-second duration,
        // including after a backwards wall-clock correction or a restored database.
        if now < at && at <= now.saturating_add(30) {
            return Ok(0);
        }
        db.remove_actor_state(GATEWAY_RETRY_AT)?;
    }
    let after = db.load_actor_state::<String>(SCAN_CURSOR)?.unwrap_or_default();
    let mut keys = db.actor_state_key_page_after(PREFIX, &after, SCAN)?;
    if keys.is_empty() && !after.is_empty() {
        keys = db.actor_state_key_page_after(PREFIX, "", SCAN)?;
    }
    if let Some(last) = keys.last() {
        db.persist_actor_state(SCAN_CURSOR, last)?;
    }
    let mut due = Vec::new();
    for key in keys {
        if let Some(work) = db.load_actor_state::<Work>(&key)?
            && (work.next_at <= now
                || work.at.saturating_add(LIFETIME) <= now
                || work.attempts >= ATTEMPTS)
        {
            due.push((key, work));
        }
    }
    due.sort_by_key(|(_, work)| work.at);
    let mut sent = 0;
    let started = std::time::Instant::now();
    for (index, (key, mut work)) in due.into_iter().take(16).enumerate() {
        if index > 0 && started.elapsed() >= Duration::from_millis(250) {
            break;
        }
        if account.client.account_db()?.message_is_deleted(&work.message)? {
            discard(&account.client, &key, &work)?;
            continue;
        }
        let attempt_at = now_unix_timestamp();
        if work.at.saturating_add(LIFETIME) <= attempt_at || work.attempts >= ATTEMPTS {
            finish(&account.client, &key, &work, "failed")?;
            continue;
        }
        work.attempts += 1;
        let backoff = (1_i64 << work.attempts.min(6)).min(60);
        // A crash during connection/send must not create a hot retry loop.
        work.next_at = attempt_at.saturating_add(30).saturating_add(backoff);
        account.client.account_db()?.persist_actor_state(&key, &work)?;
        // Ownership stays outside the cancellable send future. A deadline cannot silently
        // drop a borrowed live engine and reconnect for every remaining queue entry.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let result = match tokio::time::timeout_at(deadline, account.take_live_engine()).await {
            Ok(Ok(mut engine)) => {
                let outcome =
                    tokio::time::timeout_at(deadline, send(account, &mut engine, &key, &mut work))
                        .await;
                account.put_engine(engine);
                outcome
            }
            Ok(Err(error)) => Ok(Err(error)),
            Err(elapsed) => Err(elapsed),
        };
        match result {
            Ok(Ok(())) => {
                finish(&account.client, &key, &work, "sent")?;
                sent += 1;
            }
            Ok(Err(SdkError::InboundRejected(_))) => {
                finish(&account.client, &key, &work, "failed")?;
            }
            Ok(Err(error)) => {
                tracing::warn!(%error,"delivery receipt deferred");
                postpone(&account.client, &key, &mut work, backoff)?;
            }
            Err(_) => {
                tracing::warn!("delivery receipt deadline exceeded");
                // The stream may have an outstanding request. Retire it explicitly and
                // bound receipt-driven reconnects across all queue entries and sync passes.
                account.persist_push_route_seq();
                account.engine = None;
                account.client.account_db()?.persist_actor_state(
                    GATEWAY_RETRY_AT,
                    &now_unix_timestamp().saturating_add(30),
                )?;
                postpone(&account.client, &key, &mut work, backoff)?;
                break;
            }
        }
    }
    Ok(sent)
}
fn discard(client: &RamfluxClient, key: &str, work: &Work) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.write_transaction(|| {
        db.remove_actor_state(key)?;
        let id = if work.status_id.is_empty() {
            key.strip_prefix(PREFIX)
                .ok_or_else(|| SdkError::InboundRejected("invalid receipt work key".into()))?
        } else {
            work.status_id.as_str()
        };
        db.remove_actor_state(&format!("delivery-receipt/status/{id}"))?;
        Ok(())
    })
}
fn postpone(
    client: &RamfluxClient,
    key: &str,
    work: &mut Work,
    backoff: i64,
) -> Result<(), SdkError> {
    work.next_at = now_unix_timestamp().saturating_add(backoff);
    Ok(client.account_db()?.persist_actor_state(key, work)?)
}

async fn send(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    key: &str,
    work: &mut Work,
) -> Result<(), SdkError> {
    let source = account.client.device_identity(&work.sender)?;
    let receiver = account.client.owned_device_identity()?;
    if work.receiver != receiver.storage_key() || receiver.device_id() != engine.config.device_id {
        return Err(SdkError::InboundRejected("receipt receiving device changed".into()));
    }
    let device = account.client.trusted_device(&source)?;
    if work.root.as_deref() != Some(source.root_commitment())
        || device["principal_commitment"].as_str() != Some(source.root_commitment())
    {
        return Err(SdkError::InboundRejected("receipt sender root changed".into()));
    }
    if work.packet.is_none() {
        let target = device["target_delivery_id"]
            .as_str()
            .ok_or_else(|| SdkError::InboundPending("receipt sender route missing".into()))?;
        let receipt =
            crate::client::delivery_receipts::id(&work.conversation, &work.message, &receiver)?;
        let event = SdkReceiptEventEnvelope {
            schema: "ramflux.sdk.receipt_event.v1".into(),
            version: 1,
            receipt_id: receipt.clone(),
            event_seq: u64::try_from(work.at).unwrap_or(0),
            nonce: receipt.clone(),
            reader_device_id: receiver.device_id().into(),
            event: SdkReceiptEventBody::Delivered {
                conversation_id: work.conversation.clone(),
                message_id: work.wire_message.as_ref().unwrap_or(&work.message).clone(),
                delivered_at: work.at,
                receiver_device_id: receiver.device_id().into(),
                scope: "e2ee_private".into(),
                ttl_seconds: 300,
            },
        };
        let mut message = GatewayDirectMessage {
            conversation_id: work.conversation.clone(),
            message_id: receipt.clone(),
            envelope_id: format!("receipt_evt_{receipt}"),
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: receiver.device_id().into(),
            recipient_device_id: Some(source.device_id().into()),
            recipient_principal_commitment: Some(source.root_commitment().into()),
            target_delivery_id: target.into(),
            encrypted_body: Vec::new(),
            created_at: work.at,
            ttl: u32::try_from(LIFETIME).unwrap_or(600),
        };
        let sealed = account
            .client
            .seal_routed_as(
                engine,
                &message,
                &serde_json::to_vec(&event)?,
                crate::client::routed::Route::receipt(),
            )
            .await?;
        message.encrypted_body = serde_json::to_vec(&sealed)?;
        work.packet = Some(gateway_direct_message_envelope(&engine.config, &message, None)?);
        account.client.account_db()?.persist_actor_state(key, work)?;
    }
    let packet =
        work.packet.as_ref().ok_or_else(|| SdkError::LocalBus("receipt packet absent".into()))?;
    engine.submit_envelope(packet.clone()).await?;
    Ok(())
}
fn finish(client: &RamfluxClient, key: &str, work: &Work, state: &str) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.write_transaction(|| {
        let id = if work.status_id.is_empty() {
            key.strip_prefix(PREFIX)
                .ok_or_else(|| SdkError::InboundRejected("invalid receipt work key".into()))?
        } else {
            work.status_id.as_str()
        };
        db.persist_receipt_state(
            &format!("delivery-receipt/status/{id}"),
            &json!({
                "state": state, "delivered_at": work.at, "attempts": work.attempts,
                "retry_work": if state == "failed" { Some(work) } else { None },
            }),
            now_unix_timestamp(),
        )?;
        db.remove_actor_state(key)?;
        if state == "failed" {
            db.append_journal(
                &format!("receipt-failed:{id}"),
                "message.delivery_receipt.failed",
                &json!({
                    "conversation_id": work.conversation, "message_id": work.message,
                    "receiver_device_id": work.receiver,
                }),
                now_unix_timestamp(),
                None,
            )?;
        }
        Ok(())
    })
}

#[cfg(test)]
#[path = "receipt_tests/mod.rs"]
mod tests;
