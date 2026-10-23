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

pub(super) async fn run(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let mut engine = account.take_live_engine().await?;
    let result = receive(account, &mut engine).await;
    account.put_engine(engine);
    result
}

async fn receive(
    account: &mut LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
) -> Result<usize, SdkError> {
    let pool = account.relay_quic_pool()?;
    let cursor = account.client.gateway_receive_cursor(engine.target_delivery_id())?;
    let mut entries = engine.resume_after(cursor, 64).await?;
    // Quarantine is retried only if an explicit legacy binding exists. It is never acknowledged by scanning.
    for bytes in account.client.account_db()?.unrouted_entries()? {
        let entry: GatewayInboxEntry = serde_json::from_slice(&bytes)?;
        if !entries.iter().any(|e| e.envelope.envelope_id == entry.envelope.envelope_id) {
            entries.push(entry);
        }
    }
    entries.sort_by_key(|e| e.inbox_seq);
    let mut applied = 0;
    for entry in entries {
        if crate::client::routed::decode(&entry.envelope).is_ok() {
            account.client.apply_routed_entry(engine, &pool, &entry, true).await?;
        } else if let Some(conversation) =
            account.client.legacy_routing_binding(&engine.config.device_id, &entry)?
        {
            account
                .client
                .receive_legacy_entry(
                    engine,
                    &pool,
                    entry.clone(),
                    crate::client::dm::LegacyReceive {
                        conversation_id: &conversation,
                        auto_fetch_attachments: true,
                        relay_service_key_base64: None,
                    },
                )
                .await?;
        } else {
            let db = account.client.account_db()?;
            db.hold_unrouted(
                &entry.envelope.envelope_id,
                entry.inbox_seq,
                &serde_json::to_vec(&entry)?,
                now_unix_timestamp(),
            )?;
            db.append_journal(&format!("unrouted:{}",entry.envelope.envelope_id),"message.unrouted",&json!({"envelope_id":entry.envelope.envelope_id,"source_device_id":entry.envelope.source_device_id,"inbox_seq":entry.inbox_seq}),now_unix_timestamp(),None)?;
            account
                .client
                .persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
            continue;
        }
        // FULL transaction(s) above durably commit ratchet, content, and outbox before network ACK.
        account
            .client
            .ack_gateway_delivery(
                engine,
                &entry.envelope.envelope_id,
                &engine.config.device_id.clone(),
                now_unix_timestamp(),
            )
            .await?;
        account.client.account_db()?.remove_unrouted(&entry.envelope.envelope_id)?;
        account
            .client
            .persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
        // Bounded compatibility window for clients still using receive/ack RPCs.
        if !account
            .pending_deliveries
            .iter()
            .any(|e| e.envelope.envelope_id == entry.envelope.envelope_id)
        {
            account.pending_deliveries.push(entry);
            if account.pending_deliveries.len() > 64 {
                account.pending_deliveries.remove(0);
            }
        }
        applied += 1;
    }
    Ok(applied)
}
