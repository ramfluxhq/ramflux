// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned receive, durable quarantine, and commit-before-ACK synchronization.
use crate::prelude::*;
use serde_json::json;

pub(super) struct Schedule {
    pub min: Duration,
    pub max: Duration,
    pub interval: Duration,
}
impl Schedule {
    pub fn new() -> Result<Self, SdkError> {
        fn milliseconds(key: &str, default: u64) -> Result<Duration, SdkError> {
            let value = std::env::var(key).map_or(Ok(default), |v| {
                v.parse::<u64>().map_err(|_| SdkError::LocalBus(format!("invalid {key}")))
            })?;
            Ok(Duration::from_millis(value.clamp(50, 60_000)))
        }
        let min = milliseconds("RAMFLUX_SYNC_MIN_MS", 250)?;
        let max = milliseconds("RAMFLUX_SYNC_MAX_MS", 5000)?;
        if max < min {
            return Err(SdkError::LocalBus("sync maximum must be >= minimum".to_owned()));
        }
        Ok(Self { min, max, interval: min })
    }
    pub fn completed(&mut self, active: bool) {
        self.interval =
            if active { self.min } else { self.interval.saturating_mul(2).min(self.max) };
    }
}

pub(crate) async fn run(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = receive(account, &mut engine).await;
    account.put_engine(engine);
    result
}

async fn receive(
    account: &mut LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
) -> Result<usize, SdkError> {
    let now = now_unix_timestamp();
    account.client.account_db()?.expire_inbox_holds(now)?;
    let pool = account.relay_quic_pool()?;
    let cursor = account.client.gateway_receive_cursor(engine.target_delivery_id())?;
    let mut entries = engine.resume_after(cursor, 64).await?;
    for bytes in account
        .client
        .account_db()?
        .unrouted_entries()?
        .into_iter()
        .chain(account.client.account_db()?.due_inbox_retries(now)?)
    {
        let entry: GatewayInboxEntry = serde_json::from_slice(&bytes)?;
        if !entries.iter().any(|item| {
            item.envelope.source_device_id == entry.envelope.source_device_id
                && item.envelope.envelope_id == entry.envelope.envelope_id
        }) {
            entries.push(entry);
        }
    }
    entries.sort_by_key(|entry| entry.inbox_seq);
    let mut applied = 0;
    for entry in entries {
        let key = crate::client::routed::committed_key(&entry)?;
        if !account.client.account_db()?.inbox_retry_ready(&key, now)? {
            account
                .client
                .persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
            continue;
        }
        let outcome = process(account, engine, &pool, &entry).await;
        let accepted = match outcome {
            Ok(false) => {
                account
                    .client
                    .persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
                continue;
            }
            Ok(true) => true,
            Err(error) => {
                let bytes = serde_json::to_vec(&entry)?;
                let code = if let Some(code) = deterministic(&error) {
                    code
                } else if bytes.len() > 1024 * 1024 {
                    "oversized_retry"
                } else if account.client.account_db()?.defer_inbox_entry(&key, &bytes, now)? <= 6 {
                    account.client.persist_gateway_receive_cursor(
                        engine.target_delivery_id(),
                        entry.inbox_seq,
                    )?;
                    continue;
                } else {
                    "retry_exhausted"
                };
                account.client.account_db()?.dead_letter_inbox(&key,&bytes,&json!({"envelope_id":entry.envelope.envelope_id,"claimed_source_device_id":entry.envelope.source_device_id,"error_code":code}),now)?;
                false
            }
        };
        let device = engine.config.device_id.clone();
        if account
            .client
            .ack_gateway_delivery(engine, &entry.envelope.envelope_id, &device, now)
            .await
            .is_err()
        {
            let bytes = serde_json::to_vec(&entry)?;
            if bytes.len() <= 1024 * 1024 {
                account.client.account_db()?.defer_inbox_entry(&key, &bytes, now)?;
            }
            account
                .client
                .persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
            continue;
        }
        let db = account.client.account_db()?;
        db.remove_inbox_retry(&key)?;
        db.remove_unrouted(&key)?;
        db.remove_unrouted(&entry.envelope.envelope_id)?;
        account
            .client
            .persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
        if accepted {
            if !account.pending_deliveries.iter().any(|item| {
                item.envelope.source_device_id == entry.envelope.source_device_id
                    && item.envelope.envelope_id == entry.envelope.envelope_id
            }) {
                account.pending_deliveries.push(entry);
                if account.pending_deliveries.len() > 64 {
                    account.pending_deliveries.remove(0);
                }
            }
            applied += 1;
        }
    }
    Ok(applied)
}

async fn process(
    account: &mut LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    entry: &GatewayInboxEntry,
) -> Result<bool, SdkError> {
    if crate::client::routed::decode(&entry.envelope).is_ok() {
        account.client.apply_routed_entry(engine, pool, entry, false).await?;
        return Ok(true);
    }
    let bytes = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|_| SdkError::InboundRejected("invalid payload encoding".to_owned()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if !matches!(
        value["schema"].as_str(),
        Some("ramflux.sdk.dm_x3dh_envelope.v1" | "ramflux.sdk.group_sender_key.message.v1")
    ) || value["version"] != 1
    {
        return Err(SdkError::InboundRejected("unsupported envelope schema or version".to_owned()));
    }
    if account.client.v2_blocks_legacy(&entry.envelope.source_device_id)? {
        return Err(SdkError::InboundRejected("legacy downgrade rejected".to_owned()));
    }
    if let Some(conversation) =
        account.client.legacy_routing_binding(&engine.config.device_id, entry)?
    {
        account
            .client
            .receive_legacy_entry(
                engine,
                pool,
                entry.clone(),
                crate::client::dm::LegacyReceive {
                    conversation_id: &conversation,
                    auto_fetch_attachments: false,
                    relay_service_key_base64: None,
                },
            )
            .await?;
        return Ok(true);
    }
    let db = account.client.account_db()?;
    let key = crate::client::routed::committed_key(entry)?;
    db.hold_unrouted(&key, entry.inbox_seq, &serde_json::to_vec(entry)?, now_unix_timestamp())?;
    db.append_journal(&format!("unrouted:{key}"),"message.unrouted",&json!({"envelope_id":entry.envelope.envelope_id,"claimed_source_device_id":entry.envelope.source_device_id,"inbox_seq":entry.inbox_seq}),now_unix_timestamp(),None)?;
    Ok(false)
}

fn deterministic(error: &SdkError) -> Option<&'static str> {
    match error {
        SdkError::Crypto(_) => Some("authentication_failed"),
        SdkError::Json(_) | SdkError::Protocol(_) => Some("schema_invalid"),
        SdkError::InboundRejected(_) => Some("routing_rejected"),
        SdkError::LocalBus(_) => Some("inbound_state_invalid"),
        SdkError::Storage(StorageError::Sqlite(_) | StorageError::Io(_)) => None,
        SdkError::Storage(_) => Some("storage_policy_rejected"),
        _ => None,
    }
}
