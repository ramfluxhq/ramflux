// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned receive, durable quarantine, and commit-before-ACK synchronization.
use crate::prelude::*;
use serde_json::json;

pub(crate) mod source;
use super::couriers::head_refresh::inbound as head_inbound;

type PendingEntryId = (String, u64, String);

pub(super) struct Schedule {
    pub min: Duration,
    pub max: Duration,
    pub interval: Duration,
}
impl Schedule {
    /// Live 250 ms–5 s tick. Candidate replacement is
    /// [`crate::bus::push_receiver::sweep::SweepSetting`] (`RAMFLUX_SESSION_SAFETY_SWEEP_SECS`).
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

/// P23 replacement for [`Schedule::new`]. Live receive still constructs [`Schedule`].
#[allow(dead_code, reason = "P24 activation reads this in place of Schedule::new")]
pub(crate) fn session_safety_sweep() -> crate::bus::push_receiver::sweep::SweepSetting {
    crate::bus::push_receiver::sweep::SweepSetting::from_process()
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
    let tasks_applied = maintain_local(account)?;
    let mut engine = account.session_client().await?;
    let result = receive(account, &mut engine, receive_now()).await;
    account.apply_session_metadata(engine);
    let (received, _replies) = result?;
    #[cfg(test)]
    if let Err(error) = super::own_device_copy::flush(account).await {
        tracing::warn!(%error, "own-device message copy deferred");
    }
    #[cfg(test)]
    let contacts = match Box::pin(crate::client::contact_requests::flush(account)).await {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(%error,"contact control delivery deferred");
            0
        }
    };
    #[cfg(not(test))]
    let contacts = 0;
    #[cfg(test)]
    let group_staged = match super::shared_group_sync::stage(account) {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(%error, "group state recovery staging deferred");
            0
        }
    };
    #[cfg(not(test))]
    let group_staged = 0;
    #[cfg(test)]
    let group_controls = match Box::pin(super::shared_group_sync::flush_requests(account)).await {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(%error,"group request courier deferred");
            0
        }
    };
    #[cfg(not(test))]
    let group_controls = 0;
    #[cfg(test)]
    let group_sent = match Box::pin(super::shared_group_sync::flush(account)).await {
        Ok(count) => count,
        Err(error) => {
            tracing::warn!(%error, "group state delivery deferred");
            0
        }
    };
    #[cfg(not(test))]
    let group_sent = 0;
    account.signal_task_courier();
    #[cfg(test)]
    let voice = match super::dispatch::call::drive(account).await {
        Ok(n) => n,
        Err(error) => {
            tracing::warn!(%error,"call signaling deferred");
            0
        }
    };
    #[cfg(not(test))]
    let voice = 0;
    Ok(received + tasks_applied + voice + contacts + group_staged + group_sent + group_controls)
}

pub(crate) async fn apply_prepared_receive(
    account: &mut LocalBusAccountState,
    prepared: super::connection_manager::ReceiveEntry,
    prepared_source: source::PreparedSource,
    mut backpressure: Box<super::contact_backpressure::Backpressure>,
) -> Result<super::connection_manager::ReceiveApplied, SdkError> {
    let mut engine = account.live_session_client()?;
    let now = now_unix_timestamp();
    let mut retry_keys = BTreeMap::new();
    if let Some(key) = prepared.retry_key {
        retry_keys.insert(pending_entry_id(&prepared.entry), key);
    }
    let pool = account.relay_quic_pool()?;
    let prepared = Box::pin(prepare_entry(
        account,
        &mut engine,
        &pool,
        EntryInput { entry: prepared.entry, source: prepared_source },
        &mut backpressure,
        PageContext { replay: prepared.replay, defer_controls: true, now, retry_keys: &retry_keys },
    ))
    .await?;
    let acknowledgement = prepared
        .map(|prepared| {
            debug_assert!(prepared.replies.is_empty());
            let mut ack = ack::stage(account, prepared.state)?;
            ack.pair_reply = prepared.pair_reply;
            Ok::<_, SdkError>(ack)
        })
        .transpose()?;
    account.apply_session_metadata(engine);
    Ok((acknowledgement, backpressure))
}

/// Shared hold expiry for push and compat receive. Activated accounts expire ledger holds
/// under the captured turn and still run every non-ledger part of `expire_inbox_holds`.
fn expire_receive_holds(
    db: &ramflux_storage::AccountDb,
    target: &str,
    generation: u64,
    now: i64,
) -> Result<Option<super::connection_manager::ReceiveTurn>, SdkError> {
    if !super::push_receiver::apply_w1::is_active(db, target)? {
        db.expire_inbox_holds(now)?;
        return Ok(None);
    }
    let turn = super::push_receiver::apply_w1::capture_turn(db, generation, target)?;
    source::failure::SourceFailure { expected: turn.expected(), generation }
        .expire_holds(db, now)?;
    db.expire_inbox_holds_non_ledger(now)?;
    Ok(Some(turn))
}

pub(crate) fn prepare_receive(
    account: &LocalBusAccountState,
    generation: u64,
) -> Result<super::connection_manager::ReceivePlan, SdkError> {
    account.client.prune_surface_resync_state()?;
    let db = account.client.account_db()?;
    let target = account.target_delivery_id.as_str();
    let now = now_unix_timestamp();
    let turn = expire_receive_holds(db, target, generation, now)?;
    redrive_if_state_changed(&account.client)?;
    let cursor = account.client.gateway_receive_cursor(&account.target_delivery_id)?;
    let mut entries = Vec::new();
    let mut keys = append_pending_entries(account, &mut entries, now)?;
    let retries = entries
        .into_iter()
        .map(|entry| {
            let retry_key = keys.remove(&pending_entry_id(&entry));
            super::connection_manager::ReceiveEntry { entry, retry_key, replay: false, turn: None }
        })
        .collect();
    let backpressure =
        Box::new(super::contact_backpressure::Backpressure::load(&account.client, now)?);
    Ok(super::connection_manager::ReceivePlan { cursor, limit: 64, retries, backpressure, turn })
}

/// Projection is best-effort; the durable message remains available when its claim cannot be written.
pub(crate) fn project_committed_message(
    account: &mut LocalBusAccountState,
    entry: &GatewayInboxEntry,
) {
    #[cfg(test)]
    let started = std::time::Instant::now();
    match account.client.claim_inbox_projection(entry) {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            tracing::warn!(%error, envelope_id = %entry.envelope.envelope_id,
                "inbox projection claim failed; message remains durable");
            return;
        }
    }
    // The durable authenticated claim above owns authorization and exactly-once projection.
    // RAM cache membership compares immutable wire bytes; reauthenticating every cached
    // envelope here makes draining a page quadratic in signatures and payload size.
    crate::client::application_outbox::publish_application_entry(
        &mut account.pending_deliveries,
        entry,
    );
    #[cfg(test)]
    if let Some(handle) = &account.connection {
        handle.test_record_receive("projection", started.elapsed());
    }
}

pub(crate) async fn receive(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    now: i64,
) -> Result<(usize, Vec<crate::client::surface::ResyncReply>), SdkError> {
    account.client.account_db()?.refuse_legacy_receive()?;
    account.client.prune_surface_resync_state()?;
    expire_receive_holds(
        account.client.account_db()?,
        account.target_delivery_id.as_str(),
        1,
        now,
    )?;
    redrive_if_state_changed(&account.client)?;
    let pool = account.relay_quic_pool()?;
    let cursor = account.client.gateway_receive_cursor(engine.target_delivery_id())?;
    let mut entries = engine.resume_after(cursor, 64).await?;
    let retry_keys = append_pending_entries(account, &mut entries, now)?;
    entries.sort_by_key(|entry| entry.inbox_seq);
    let mut backpressure = super::contact_backpressure::Backpressure::load(&account.client, now)?;
    let (mut applied, mut replies) = receive_page(
        account,
        engine,
        &pool,
        entries,
        &mut backpressure,
        PageContext { replay: false, defer_controls: true, now, retry_keys: &retry_keys },
    )
    .await?;
    let walk = account.client.gateway_receive_cursor(engine.target_delivery_id())?;
    if let Some((cursor, until)) = backpressure.scan_cursor(&account.client, walk, now)? {
        let mut page = engine.resume_after(cursor, 64).await?;
        let count = page.len();
        page.retain(|entry| entry.inbox_seq <= until);
        let last = page.iter().map(|entry| entry.inbox_seq).max();
        let retry_keys = BTreeMap::new();
        let (more, reply) = receive_page(
            account,
            engine,
            &pool,
            page,
            &mut backpressure,
            PageContext { replay: true, defer_controls: true, now, retry_keys: &retry_keys },
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
#[derive(Clone, Copy)]
struct PageContext<'a> {
    replay: bool,
    defer_controls: bool,
    now: i64,
    retry_keys: &'a BTreeMap<PendingEntryId, String>,
}
fn retry_context(
    client: &RamfluxClient,
    entry: &GatewayInboxEntry,
    retry_keys: &BTreeMap<PendingEntryId, String>,
) -> Result<(String, Result<bool, SdkError>), SdkError> {
    let retry_key = retry_keys.get(&pending_entry_id(entry));
    let key = retry_key.cloned().map_or_else(|| client.inbox_admission_key(entry), Ok)?;
    let committed = if entry.envelope.encrypted_payload.is_empty()
        && let Some(stored_key) = retry_key
    {
        client.retained_committed_receipt_key(entry).and_then(|receipt_key| match receipt_key {
            Some(receipt_key) if receipt_key == *stored_key => Ok(true),
            Some(_) => Err(SdkError::InboundRejected(
                "retained receipt key does not match retry admission".to_owned(),
            )),
            None => Ok(false),
        })
    } else {
        Ok(false)
    };
    Ok((key, committed))
}
async fn receive_page(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    entries: Vec<GatewayInboxEntry>,
    backpressure: &mut super::contact_backpressure::Backpressure,
    context: PageContext<'_>,
) -> Result<(usize, Vec<crate::client::surface::ResyncReply>), SdkError> {
    let mut applied = 0;
    let mut replies = Vec::new();
    for entry in entries {
        let Some(prepared) = Box::pin(prepare_entry(
            account,
            engine,
            pool,
            EntryInput { entry, source: None },
            backpressure,
            context,
        ))
        .await?
        else {
            continue;
        };
        replies.extend(prepared.replies);
        let AckState { entry, key, already_seen, strip_call_ciphertext, accepted, received_at } =
            prepared.state;
        if account.client.ack_gateway_entry(engine, &entry, received_at).await.is_err() {
            if already_seen && !account.client.account_db()?.has_inbox_retry(&key)? {
                break;
            }
            retain_ack_retry(&account.client, &entry, strip_call_ciphertext, &key, received_at)?;
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

struct EntryInput {
    entry: GatewayInboxEntry,
    source: source::PreparedSource,
}

async fn prepare_entry(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    input: EntryInput,
    backpressure: &mut super::contact_backpressure::Backpressure,
    context: PageContext<'_>,
) -> Result<Option<PreparedEntry>, SdkError> {
    let EntryInput { entry, source: prepared_source } = input;
    let PageContext { replay, defer_controls, now, retry_keys } = context;
    let mut replies = Vec::new();
    let already_seen = account.client.routed_seen_marker(&entry)?.is_some();
    let (key, committed_retry) = retry_context(&account.client, &entry, retry_keys)?;
    if !head_inbound::eligible(account, &key)
        && !account.client.account_db()?.inbox_retry_ready(&key, now)?
    {
        advance_cursor(&account.client, engine.target_delivery_id(), entry.inbox_seq)?;
        return Ok(None);
    }
    if replay && backpressure.saturated(&account.client, &entry, now)? {
        return Ok(None);
    }
    head_inbound::consume(account, &key);
    let expires = entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl));
    let outcome = match committed_retry {
        Err(error) => Err(error),
        Ok(true) => Ok(Processed::control()),
        Ok(false) => {
            if backpressure.duplicate(&entry) {
                Err(SdkError::InboundRejected(
                    "another contact envelope for this root is already deferred".into(),
                ))
            } else if now >= expires && account.client.account_db()?.has_inbox_retry(&key)? {
                Err(SdkError::InboundRejected("gateway TTL expired".to_owned()))
            } else {
                Box::pin(process_with_prepared_source(
                    account,
                    engine,
                    pool,
                    &entry,
                    defer_controls,
                    prepared_source,
                ))
                .await
            }
        }
    };
    let mut project_message = false;
    let mut strip_call_ciphertext = false;
    let mut pair_reply = None;
    let accepted = match outcome {
        Ok(Processed { consumed: false, .. }) => {
            advance_cursor(&account.client, engine.target_delivery_id(), entry.inbox_seq)?;
            return Ok(None);
        }
        Ok(Processed { reply, publish, call_control, pair_reply: reset_reply, .. }) => {
            replies.extend(reply);
            project_message = publish;
            strip_call_ciphertext = call_control;
            pair_reply = reset_reply;
            true
        }
        Err(mut error) => {
            if super::contact_backpressure::deferred(&entry, &error)
                && backpressure.record(&account.client, &entry, now)?
            {
                if !replay {
                    advance_cursor(&account.client, engine.target_delivery_id(), entry.inbox_seq)?;
                }
                return Ok(None);
            }
            if matches!(error, SdkError::ContactRequestCapacity(_)) {
                error =
                    SdkError::InboundRejected("deferred contact root capacity exhausted".into());
            }
            if !quarantine_failure(
                &account.client,
                &engine.config().device_id,
                &entry,
                &key,
                &error,
                now,
            )? {
                head_inbound::retain(account, &entry, &key, &error)?;
                advance_cursor(&account.client, engine.target_delivery_id(), entry.inbox_seq)?;
                return Ok(None);
            }

            false
        }
    };
    // Keep committed messages visible while acknowledgement retries remain pending.
    if project_message {
        project_committed_message(account, &entry);
    }
    Ok(Some(PreparedEntry {
        state: AckState {
            entry,
            key,
            already_seen,
            strip_call_ciphertext,
            accepted,
            received_at: now,
        },
        replies,
        pair_reply,
    }))
}
struct PreparedEntry {
    state: AckState,
    replies: Vec<crate::client::surface::ResyncReply>,
    pair_reply: Option<ramflux_protocol::Envelope>,
}

fn retain_ack_retry(
    client: &RamfluxClient,
    entry: &GatewayInboxEntry,
    strip: bool,
    key: &str,
    now: i64,
) -> Result<(), SdkError> {
    let retained = retained_inbox_entry(entry, strip);
    let bytes = serde_json::to_vec(&retained)?;
    if bytes.len() <= 1024 * 1024 {
        client.account_db()?.defer_inbox_entry(key, &bytes, now)?;
    }
    Ok(())
}

pub(super) struct Processed {
    consumed: bool,
    publish: bool,
    reply: Option<crate::client::surface::ResyncReply>,
    call_control: bool,
    pair_reply: Option<ramflux_protocol::Envelope>,
}
impl Processed {
    fn message(reply: Option<crate::client::surface::ResyncReply>) -> Self {
        Self { consumed: true, publish: true, reply, call_control: false, pair_reply: None }
    }
    fn control() -> Self {
        Self { consumed: true, publish: false, reply: None, call_control: false, pair_reply: None }
    }
    fn held() -> Self {
        Self { consumed: false, publish: false, reply: None, call_control: false, pair_reply: None }
    }
}

#[cfg(test)]
pub(super) async fn process_with_mode(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    entry: &GatewayInboxEntry,
    defer_controls: bool,
) -> Result<Processed, SdkError> {
    process_with_prepared_source(account, engine, pool, entry, defer_controls, None).await
}

async fn process_with_prepared_source(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    entry: &GatewayInboxEntry,
    defer_controls: bool,
    prepared_source: source::PreparedSource,
) -> Result<Processed, SdkError> {
    if account.client.routed_seen_marker(entry)?.is_some() {
        return Ok(Processed::control());
    }
    let mut prepared_source = prepared_source.map(|prepared| *prepared).transpose()?;
    if let Some(manifest) =
        prepared_source.as_mut().and_then(|prepared| prepared.own_copy_manifest.take())
    {
        if account.client.receive_prepared_own_device_message(entry, manifest)? {
            return Ok(Processed::control());
        }
    } else if account.client.receive_own_device_message(engine.config(), entry).await? {
        return Ok(Processed::control());
    }
    if crate::client::routed::decode(&entry.envelope).is_ok() {
        let delivery = if let Some(prepared) = prepared_source {
            account.client.apply_routed_prepared_entry(engine, pool, entry, Ok(prepared)).await?
        } else {
            account.client.apply_routed_entry(engine, pool, entry, false).await?
        };
        let reply =
            if defer_controls { None } else { account.client.take_surface_resync_answer(entry)? };
        let mut processed = Processed::message(reply);
        processed.call_control = delivery.call_control;
        processed.pair_reply = delivery.pair_reply;
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
        log_unrouted_hold(entry, "legacy group entry awaits compatibility receive");
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
        log_unrouted_hold(entry, "legacy traffic blocked by v2 binding");
        return Ok(Processed::held());
    }
    if let Some(conversation) =
        account.client.legacy_routing_binding(&engine.config().device_id, entry)?
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
    db.append_journal(&format!("unrouted:{key}"),"message.unrouted",&json!({"envelope_id":entry.envelope.envelope_id,"claimed_source_device_id":entry.envelope.source_device_id,"payload_hash":entry.envelope.payload_hash,"inbox_seq":entry.inbox_seq}),now_unix_timestamp(),None)?;
    log_unrouted_hold(entry, "no authenticated conversation binding");
    Ok(Processed::held())
}

fn log_unrouted_hold(entry: &GatewayInboxEntry, reason: &str) {
    tracing::info!(inbox_seq = entry.inbox_seq, kind = "unrouted",
        envelope_id = %entry.envelope.envelope_id,
        source_device_id = %entry.envelope.source_device_id,
        target_delivery_id = %entry.target_delivery_id,
        reason, "gateway inbound entry held");
}

pub(super) fn quarantine_failure(
    client: &RamfluxClient,
    device: &str,
    entry: &GatewayInboxEntry,
    key: &str,
    error: &SdkError,
    now: i64,
) -> Result<bool, SdkError> {
    if client.routed_seen_marker(entry)?.is_some() {
        return Ok(true);
    }
    // Immutable malformed signature bytes cannot become valid after a directory refresh.
    let wire_error = crate::client::inbox_failure::wire_signature_error(entry);
    let error = wire_error.as_ref().unwrap_or(error);
    let kind = inbound_failure_kind(error);
    let retry_bytes = serde_json::to_vec(entry)?;
    let code = if let Some(code) = crate::client::inbox_failure::deterministic(error) {
        code
    } else if retry_bytes.len() > 1024 * 1024 {
        "oversized_retry"
    } else {
        if crate::client::inbox_failure::defer_entry(client, device, entry, key, &retry_bytes, now)?
        {
            tracing::info!(inbox_seq = entry.inbox_seq, kind,
                envelope_id = %entry.envelope.envelope_id,
                source_device_id = %entry.envelope.source_device_id,
                target_delivery_id = %entry.target_delivery_id,
                reason = %error, "gateway inbound entry held");
            return Ok(false);
        }
        "retry_exhausted"
    };
    let db = client.account_db()?;
    db.remove_inbox_retry(key)?;
    db.remove_unrouted(key)?;
    if matches!(error, SdkError::ReplayMismatch)
        || db.message_is_deleted(&entry.envelope.envelope_id)?
    {
        db.dead_letter_routed(
            &ramflux_protocol::canonical_json_bytes(&entry.envelope)?,
            code,
            now,
        )?;
    } else {
        db.dead_letter_inbox(
            key,
            &serde_json::to_vec(entry)?,
            &json!({
                "envelope_id": entry.envelope.envelope_id,
                "claimed_source_device_id": entry.envelope.source_device_id,
                "error_code": code,
            }),
            now,
        )?;
    }
    tracing::warn!(inbox_seq = entry.inbox_seq, kind,
        envelope_id = %entry.envelope.envelope_id,
        source_device_id = %entry.envelope.source_device_id,
        target_delivery_id = %entry.target_delivery_id,
        reason = %error, outcome = code, "gateway inbound entry dead-lettered");
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

fn pending_entry_id(entry: &GatewayInboxEntry) -> PendingEntryId {
    (entry.target_delivery_id.clone(), entry.inbox_seq, entry.envelope.envelope_id.clone())
}

fn append_pending_entries(
    account: &LocalBusAccountState,
    entries: &mut Vec<GatewayInboxEntry>,
    now: i64,
) -> Result<BTreeMap<PendingEntryId, String>, SdkError> {
    let mut seen = entries
        .iter()
        .map(|entry| account.client.inbox_admission_key(entry))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for bytes in account.client.account_db()?.unrouted_entries()? {
        let entry: GatewayInboxEntry = serde_json::from_slice(&bytes)?;
        if seen.insert(account.client.inbox_admission_key(&entry)?) {
            entries.push(entry);
        }
    }
    let mut retry_keys = BTreeMap::new();
    for (key, entry) in head_inbound::entries(account) {
        if account.client.account_db()?.has_inbox_retry(key)? {
            retry_keys.insert(pending_entry_id(entry), key.clone());
            if seen.insert(key.clone()) {
                entries.push(entry.clone());
            }
        }
    }
    for (key, bytes) in account.client.account_db()?.due_inbox_retry_rows(now)? {
        let entry: GatewayInboxEntry = serde_json::from_slice(&bytes)?;
        retry_keys.insert(pending_entry_id(&entry), key.clone());
        if seen.insert(key) {
            entries.push(entry);
        }
    }
    Ok(retry_keys)
}

/// Bounded local housekeeping is available even while admission is pending.
pub(crate) fn maintain_local(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    account.client.account_db()?.expire_backup_pairs(now_unix_timestamp())?;
    if let Err(error) = account.client.account_db().and_then(|db| {
        db.retain_delivery_receipts(now_unix_timestamp(), 128).map_err(SdkError::from)
    }) {
        tracing::warn!(%error, "receipt retention failed; continuing sync");
    }
    account.client.finish_pair_retirement()?;
    super::dispatch::call::expire_due(account)?;
    account.client.retry_pending_tasks(now_unix_timestamp())
}

#[cfg(test)]
pub(super) async fn process(
    account: &mut LocalBusAccountState,
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    entry: &GatewayInboxEntry,
) -> Result<Processed, SdkError> {
    process_with_mode(account, engine, pool, entry, false).await
}

mod ack;
#[cfg(test)]
mod ack_tests;
pub(crate) use ack::{AckState, PreparedAck, finish as finish_prepared_ack};

pub(crate) fn inbound_failure_kind(error: &SdkError) -> &'static str {
    match error.directory_source() {
        SdkError::InboundPending(_)
        | SdkError::SenderManifestRequired { .. }
        | SdkError::FreshHeadRequired { .. } => "InboundPending",
        SdkError::InboundRejected(_) => "InboundRejected",
        source => local_bus_error_code(source),
    }
}
