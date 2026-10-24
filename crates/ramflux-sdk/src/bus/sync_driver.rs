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
    let (received, replies) = result?;
    for reply in replies {
        if let Err(error) =
            super::dispatch::surface_transport::send_resync_reply(account, &reply).await
        {
            tracing::warn!(%error,"surface resync reply failed; requester may retry next window");
        }
    }
    if let Err(error) = super::own_device_copy::flush(account).await {
        tracing::warn!(%error, "own-device message copy deferred");
    }
    let approvals = match super::dispatch::task_approval::drive(account).await {
        Ok(n) => n,
        Err(error) => {
            tracing::warn!(%error,"task approval delivery deferred");
            0
        }
    };
    let tasks_applied = account.client.retry_pending_tasks(now_unix_timestamp())?;
    let task_sent = match super::dispatch::task_transport::drain_confirmations(account).await {
        Ok(n) => n,
        Err(error) => {
            tracing::warn!(%error,"task confirmation deferred");
            0
        }
    };
    Ok(received + tasks_applied + task_sent + approvals)
}

async fn receive(
    account: &mut LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
) -> Result<(usize, Vec<crate::client::surface::ResyncReply>), SdkError> {
    let now = now_unix_timestamp();
    account.client.prune_surface_resync_state()?;
    account.client.account_db()?.expire_inbox_holds(now)?;
    redrive_if_state_changed(&account.client)?;
    let pool = account.relay_quic_pool()?;
    let cursor = account.client.gateway_receive_cursor(engine.target_delivery_id())?;
    let mut entries = engine.resume_after(cursor, 64).await?;
    append_pending_entries(account, &mut entries, now)?;
    entries.sort_by_key(|entry| entry.inbox_seq);
    let mut applied = 0;
    let mut replies = Vec::new();
    for entry in entries {
        let key = crate::client::routed::committed_key(&entry)?;
        if !account.client.account_db()?.inbox_retry_ready(&key, now)? {
            account
                .client
                .persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
            continue;
        }
        let expires = entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl));
        let outcome = if now >= expires && account.client.account_db()?.has_inbox_retry(&key)? {
            Err(SdkError::InboundRejected("gateway TTL expired".to_owned()))
        } else {
            process(account, engine, &pool, &entry).await
        };
        let accepted = match outcome {
            Ok((false, _)) => {
                account
                    .client
                    .persist_gateway_receive_cursor(engine.target_delivery_id(), entry.inbox_seq)?;
                continue;
            }
            Ok((true, reply)) => {
                replies.extend(reply);
                true
            }
            Err(error) => {
                if !quarantine_failure(
                    &account.client,
                    &engine.config.device_id,
                    &entry,
                    &key,
                    &error,
                    now,
                )? {
                    account.client.persist_gateway_receive_cursor(
                        engine.target_delivery_id(),
                        entry.inbox_seq,
                    )?;
                    continue;
                }

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
    account.client.retry_pair_resets(engine, now).await?;
    Ok((applied, replies))
}

async fn process(
    account: &mut LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    entry: &GatewayInboxEntry,
) -> Result<(bool, Option<crate::client::surface::ResyncReply>), SdkError> {
    if account.client.receive_own_device_message(&engine.config, entry).await? {
        return Ok((true, None));
    }
    if crate::client::routed::decode(&entry.envelope).is_ok() {
        account.client.apply_routed_entry(engine, pool, entry, false).await?;
        let reply = account.client.take_surface_resync_answer(entry)?;
        return Ok((true, reply));
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
    if value["schema"] == "ramflux.sdk.group_sender_key.message.v1" {
        account.client.retain_legacy_group_entry(entry)?;
        return Ok((false, None));
    }
    if account.client.v2_blocks_legacy(&entry.envelope.source_device_id)? {
        let db = account.client.account_db()?;
        db.hold_unrouted(
            &crate::client::routed::committed_key(entry)?,
            entry.inbox_seq,
            &serde_json::to_vec(entry)?,
            now_unix_timestamp(),
        )?;
        return Ok((false, None));
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
        return Ok((true, None));
    }
    let db = account.client.account_db()?;
    let key = crate::client::routed::committed_key(entry)?;
    db.hold_unrouted(&key, entry.inbox_seq, &serde_json::to_vec(entry)?, now_unix_timestamp())?;
    db.append_journal(&format!("unrouted:{key}"),"message.unrouted",&json!({"envelope_id":entry.envelope.envelope_id,"claimed_source_device_id":entry.envelope.source_device_id,"inbox_seq":entry.inbox_seq}),now_unix_timestamp(),None)?;
    Ok((false, None))
}

fn quarantine_failure(
    client: &RamfluxClient,
    device: &str,
    entry: &GatewayInboxEntry,
    key: &str,
    error: &SdkError,
    now: i64,
) -> Result<bool, SdkError> {
    let bytes = serde_json::to_vec(entry)?;
    let code = if let Some(code) = crate::client::inbox_failure::deterministic(error) {
        code
    } else if bytes.len() > 1024 * 1024 {
        "oversized_retry"
    } else {
        if crate::client::inbox_failure::defer_entry(client, device, entry, key, &bytes, now)? {
            return Ok(false);
        }
        "retry_exhausted"
    };
    client.account_db()?.dead_letter_inbox(key,&bytes,&json!({"envelope_id":entry.envelope.envelope_id,"claimed_source_device_id":entry.envelope.source_device_id,"error_code":code}),now)?;
    Ok(true)
}

fn redrive_if_state_changed(client: &RamfluxClient) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let revision = db.inbox_recovery_revision()?;
    let key = "inbox/recovery-revision";
    let previous = db.load_actor_state::<u64>(key)?.unwrap_or(0);
    db.redrive_inbox_changes(now_unix_timestamp())?;
    if previous != revision {
        db.persist_actor_state(key, &revision)?;
    }
    Ok(())
}

fn append_pending_entries(
    account: &LocalBusAccountState,
    entries: &mut Vec<GatewayInboxEntry>,
    now: i64,
) -> Result<(), SdkError> {
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
    Ok(())
}
