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
    run_with_receive_clock(account, now_unix_timestamp).await
}

// Exercise the complete driver with a stable receive clock for retry-boundary assertions.
#[cfg(test)]
pub(crate) async fn run_at(
    account: &mut LocalBusAccountState,
    now: i64,
) -> Result<usize, SdkError> {
    run_with_receive_clock(account, || now).await
}

async fn run_with_receive_clock(
    account: &mut LocalBusAccountState,
    receive_now: impl FnOnce() -> i64,
) -> Result<usize, SdkError> {
    account.client.account_db()?.expire_backup_pairs(now_unix_timestamp())?;
    if let Err(error) = account.client.account_db().and_then(|db| {
        db.retain_delivery_receipts(now_unix_timestamp(), 128).map_err(SdkError::from)
    }) {
        tracing::warn!(%error, "receipt retention failed; continuing sync");
    }
    account.client.finish_pair_retirement()?;
    super::dispatch::call::expire_due(account)?;
    let mut engine = account.take_live_engine().await?;
    let result = receive(account, &mut engine, receive_now()).await;
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
    let contacts = match Box::pin(crate::client::contact_requests::flush(account)).await {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(%error,"contact control delivery deferred");
            0
        }
    };
    let group_staged = match super::shared_group_sync::stage(account) {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(%error, "group state recovery staging deferred");
            0
        }
    };
    let group_controls = match Box::pin(super::shared_group_sync::flush_requests(account)).await {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(%error,"group request courier deferred");
            0
        }
    };
    let group_sent = match Box::pin(super::shared_group_sync::flush(account)).await {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(%error, "group state delivery deferred");
            0
        }
    };
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
    let receipts = match super::delivery_receipts::flush(account).await {
        Ok(n) => n,
        Err(error) => {
            tracing::warn!(%error,"delivery receipt courier deferred");
            0
        }
    };
    let voice = match super::dispatch::call::drive(account).await {
        Ok(n) => n,
        Err(error) => {
            tracing::warn!(%error,"call signaling deferred");
            0
        }
    };
    Ok(received
        + tasks_applied
        + task_sent
        + approvals
        + receipts
        + voice
        + contacts
        + group_staged
        + group_sent
        + group_controls)
}

/// Projection is best-effort; the durable message remains available when its claim cannot be written.
pub(crate) fn project_committed_message(
    account: &mut LocalBusAccountState,
    entry: &GatewayInboxEntry,
) -> Result<(), SdkError> {
    match account.client.claim_inbox_projection(entry) {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(error) => {
            tracing::warn!(%error, envelope_id = %entry.envelope.envelope_id,
                "inbox projection claim failed; message remains durable");
            return Ok(());
        }
    }
    let pending_keys = account
        .pending_deliveries
        .iter()
        .map(|item| account.client.inbox_admission_key(item))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if !pending_keys.contains(&account.client.inbox_admission_key(entry)?) {
        account.pending_deliveries.push(entry.clone());
        if account.pending_deliveries.len() > 64 {
            account.pending_deliveries.remove(0);
        }
    }
    Ok(())
}

async fn receive(
    account: &mut LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    now: i64,
) -> Result<(usize, Vec<crate::client::surface::ResyncReply>), SdkError> {
    account.client.prune_surface_resync_state()?;
    account.client.account_db()?.expire_inbox_holds(now)?;
    redrive_if_state_changed(&account.client)?;
    let pool = account.relay_quic_pool()?;
    let cursor = account.client.gateway_receive_cursor(engine.target_delivery_id())?;
    let mut entries = engine.resume_after(cursor, 64).await?;
    append_pending_entries(account, &mut entries, now)?;
    entries.sort_by_key(|entry| entry.inbox_seq);
    let mut backpressure = super::contact_backpressure::Backpressure::load(&account.client, now)?;
    let (mut applied, mut replies) = receive_page(
        account,
        engine,
        &pool,
        entries,
        &mut backpressure,
        PageContext { replay: false, now },
    )
    .await?;
    let walk = account.client.gateway_receive_cursor(engine.target_delivery_id())?;
    if let Some((cursor, until)) = backpressure.scan_cursor(&account.client, walk, now)? {
        let mut page = engine.resume_after(cursor, 64).await?;
        let count = page.len();
        page.retain(|entry| entry.inbox_seq <= until);
        let last = page.iter().map(|entry| entry.inbox_seq).max();
        let (more, reply) = receive_page(
            account,
            engine,
            &pool,
            page,
            &mut backpressure,
            PageContext { replay: true, now },
        )
        .await?;
        applied += more;
        replies.extend(reply);
        backpressure.scanned(&account.client, last, count, now)?;
    }
    account.client.retry_pair_resets(engine, now).await?;
    Ok((applied, replies))
}
fn advance_cursor(client: &RamfluxClient, target: &str, sequence: u64) -> Result<(), SdkError> {
    client.persist_gateway_receive_cursor(
        target,
        client.gateway_receive_cursor(target)?.max(sequence),
    )
}
struct PageContext {
    replay: bool,
    now: i64,
}
async fn receive_page(
    account: &mut LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    entries: Vec<GatewayInboxEntry>,
    backpressure: &mut super::contact_backpressure::Backpressure,
    context: PageContext,
) -> Result<(usize, Vec<crate::client::surface::ResyncReply>), SdkError> {
    let PageContext { replay, now } = context;
    let mut applied = 0;
    let mut replies = Vec::new();
    for entry in entries {
        let key = account.client.inbox_admission_key(&entry)?;
        if !account.client.account_db()?.inbox_retry_ready(&key, now)? {
            advance_cursor(&account.client, engine.target_delivery_id(), entry.inbox_seq)?;
            continue;
        }
        if replay && backpressure.saturated(&account.client, &entry, now)? {
            continue;
        }
        let expires = entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl));
        let outcome = if backpressure.duplicate(&entry) {
            Err(SdkError::InboundRejected(
                "another contact envelope for this root is already deferred".into(),
            ))
        } else if now >= expires && account.client.account_db()?.has_inbox_retry(&key)? {
            Err(SdkError::InboundRejected("gateway TTL expired".to_owned()))
        } else {
            Box::pin(process(account, engine, pool, &entry)).await
        };
        let mut project_message = false;
        let mut strip_call_ciphertext = false;
        let accepted = match outcome {
            Ok(Processed { consumed: false, .. }) => {
                advance_cursor(&account.client, engine.target_delivery_id(), entry.inbox_seq)?;
                continue;
            }
            Ok(Processed { reply, publish, call_control, .. }) => {
                replies.extend(reply);
                project_message = publish;
                strip_call_ciphertext = call_control;
                true
            }
            Err(mut error) => {
                if super::contact_backpressure::deferred(&entry, &error)
                    && backpressure.record(&account.client, &entry, now)?
                {
                    if !replay {
                        advance_cursor(
                            &account.client,
                            engine.target_delivery_id(),
                            entry.inbox_seq,
                        )?;
                    }
                    continue;
                }
                if matches!(error, SdkError::ContactRequestCapacity(_)) {
                    error = SdkError::InboundRejected(
                        "deferred contact root capacity exhausted".into(),
                    );
                }
                if !quarantine_failure(
                    &account.client,
                    &engine.config.device_id,
                    &entry,
                    &key,
                    &error,
                    now,
                )? {
                    advance_cursor(&account.client, engine.target_delivery_id(), entry.inbox_seq)?;
                    continue;
                }

                false
            }
        };
        // Keep committed messages visible while acknowledgement retries remain pending.
        if project_message {
            project_committed_message(account, &entry)?;
        }
        if account.client.ack_gateway_entry(engine, &entry, now).await.is_err() {
            let retained = retained_inbox_entry(&entry, strip_call_ciphertext);
            let bytes = serde_json::to_vec(&retained)?;
            if bytes.len() <= 1024 * 1024 {
                account.client.account_db()?.defer_inbox_entry(&key, &bytes, now)?;
            }
            advance_cursor(&account.client, engine.target_delivery_id(), entry.inbox_seq)?;
            continue;
        }
        let db = account.client.account_db()?;
        backpressure.completed(&account.client, &entry)?;
        db.remove_inbox_retry(&key)?;
        db.remove_unrouted(&key)?;
        db.remove_unrouted(&entry.envelope.envelope_id)?;
        advance_cursor(&account.client, engine.target_delivery_id(), entry.inbox_seq)?;
        if accepted {
            applied += 1;
        }
    }
    Ok((applied, replies))
}

struct Processed {
    consumed: bool,
    publish: bool,
    reply: Option<crate::client::surface::ResyncReply>,
    call_control: bool,
}
impl Processed {
    fn message(reply: Option<crate::client::surface::ResyncReply>) -> Self {
        Self { consumed: true, publish: true, reply, call_control: false }
    }
    fn control() -> Self {
        Self { consumed: true, publish: false, reply: None, call_control: false }
    }
    fn held() -> Self {
        Self { consumed: false, publish: false, reply: None, call_control: false }
    }
}

async fn process(
    account: &mut LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    entry: &GatewayInboxEntry,
) -> Result<Processed, SdkError> {
    if account.client.receive_own_device_message(&engine.config, entry).await? {
        return Ok(Processed::control());
    }
    if crate::client::routed::decode(&entry.envelope).is_ok() {
        let delivery = account.client.apply_routed_entry(engine, pool, entry, false).await?;
        let reply = account.client.take_surface_resync_answer(entry)?;
        let mut processed = Processed::message(reply);
        processed.call_control = delivery.call_control;
        return Ok(processed);
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
        return Ok(Processed::held());
    }
    if account.client.v2_blocks_legacy(&account.client.inbound_device_reference(entry)?)? {
        let db = account.client.account_db()?;
        db.hold_unrouted(
            &account.client.inbox_admission_key(entry)?,
            entry.inbox_seq,
            &serde_json::to_vec(entry)?,
            now_unix_timestamp(),
        )?;
        return Ok(Processed::held());
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
        return Ok(Processed::message(None));
    }
    let db = account.client.account_db()?;
    let key = account.client.inbox_admission_key(entry)?;
    db.hold_unrouted(&key, entry.inbox_seq, &serde_json::to_vec(entry)?, now_unix_timestamp())?;
    db.append_journal(&format!("unrouted:{key}"),"message.unrouted",&json!({"envelope_id":entry.envelope.envelope_id,"claimed_source_device_id":entry.envelope.source_device_id,"inbox_seq":entry.inbox_seq}),now_unix_timestamp(),None)?;
    Ok(Processed::held())
}

pub(super) fn quarantine_failure(
    client: &RamfluxClient,
    device: &str,
    entry: &GatewayInboxEntry,
    key: &str,
    error: &SdkError,
    now: i64,
) -> Result<bool, SdkError> {
    tracing::debug!(%error, error_code = local_bus_error_code(error),
        envelope_id = %entry.envelope.envelope_id, source_device_id = %entry.envelope.source_device_id,
        target_delivery_id = %entry.target_delivery_id, inbox_seq = entry.inbox_seq,
        "gateway receive entry handling failed");
    let retry_bytes = serde_json::to_vec(entry)?;
    let code = if let Some(code) = crate::client::inbox_failure::deterministic(error) {
        code
    } else if retry_bytes.len() > 1024 * 1024 {
        "oversized_retry"
    } else {
        if crate::client::inbox_failure::defer_entry(client, device, entry, key, &retry_bytes, now)?
        {
            return Ok(false);
        }
        "retry_exhausted"
    };
    let call_control = client.is_call_control_entry(entry, device).unwrap_or(false);
    let retained = retained_inbox_entry(entry, call_control);
    let bytes = serde_json::to_vec(&retained)?;
    client.account_db()?.dead_letter_inbox(key,&bytes,&json!({"envelope_id":entry.envelope.envelope_id,"claimed_source_device_id":entry.envelope.source_device_id,"error_code":code}),now)?;
    Ok(true)
}

pub(crate) fn retained_inbox_entry(
    entry: &GatewayInboxEntry,
    strip_call_ciphertext: bool,
) -> GatewayInboxEntry {
    let mut retained = entry.clone();
    if strip_call_ciphertext {
        retained.envelope.encrypted_payload.clear();
    }
    retained
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
    let mut seen = entries
        .iter()
        .map(|entry| account.client.inbox_admission_key(entry))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for bytes in account
        .client
        .account_db()?
        .unrouted_entries()?
        .into_iter()
        .chain(account.client.account_db()?.due_inbox_retries(now)?)
    {
        let entry: GatewayInboxEntry = serde_json::from_slice(&bytes)?;
        if seen.insert(account.client.inbox_admission_key(&entry)?) {
            entries.push(entry);
        }
    }
    Ok(())
}
