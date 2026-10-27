// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete verified task fan-out, sealed once and submitted through the ordinary gateway delivery paths.
use crate::bus::task_delivery::{Delivery as SealedDelivery, Destination};
use crate::client::task::{Delivery, carrier::Carrier, invalid};
use crate::prelude::*;
use serde_json::{Value, json};
use std::future::Future;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

// Preparation refreshes verified own and peer directories before sealing. Keep
// task couriers bounded while allowing normal latency on CPU-constrained hosts.
const TASK_PREPARATION_TIMEOUT: Duration = Duration::from_secs(5);
const TASK_COURIER_PREPARATION_BUDGET: Duration = Duration::from_secs(12);
const TASK_APPROVAL_PREPARATION_BUDGET: Duration = Duration::from_secs(6);

pub(crate) struct PreparationBudget {
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
}

impl PreparationBudget {
    pub(crate) fn for_sync_cycle() -> Self {
        Self::new(TASK_COURIER_PREPARATION_BUDGET)
    }

    pub(super) fn new(duration: Duration) -> Self {
        let started = tokio::time::Instant::now();
        Self { started, deadline: started + duration }
    }

    pub(super) fn approval_share(&self) -> Self {
        Self {
            started: self.started,
            deadline: self.deadline.min(self.started + TASK_APPROVAL_PREPARATION_BUDGET),
        }
    }

    pub(super) fn can_start_item(&self) -> bool {
        let remaining = self.deadline.saturating_duration_since(tokio::time::Instant::now());
        remaining >= TASK_PREPARATION_TIMEOUT
    }

    fn next_timeout(&self) -> Option<Duration> {
        self.can_start_item().then_some(TASK_PREPARATION_TIMEOUT)
    }
}

pub(super) fn rotate_to_cursor<T>(rows: &mut [(String, T)], cursor: usize) {
    if !rows.is_empty() {
        let offset = cursor % rows.len();
        rows.rotate_left(offset);
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Preparation<T> {
    Ready(T),
    Deferred,
}

pub(super) async fn await_preparation<T>(
    future: impl Future<Output = Result<T, SdkError>>,
    budget: &PreparationBudget,
    deferred: &'static str,
) -> Result<Preparation<T>, SdkError> {
    let Some(timeout) = budget.next_timeout() else {
        return Ok(Preparation::Deferred);
    };
    match tokio::time::timeout(timeout, future).await {
        Ok(Ok(value)) => Ok(Preparation::Ready(value)),
        Ok(Err(SdkError::TaskManifestWorkerCapacity)) => {
            tracing::debug!(deferred, "task courier preparation deferred without retry charge");
            Ok(Preparation::Deferred)
        }
        Ok(Err(error)) => Err(error),
        Err(_) => Err(SdkError::InboundPending(deferred.to_owned())),
    }
}

#[derive(Clone)]
pub(super) struct Target {
    pub device: String,
    pub identity: ramflux_crypto::RootQualifiedDeviceRef,
    pub delivery: String,
    pub federation: Option<LocalBusFederationRoute>,
    pub own: bool,
}
pub(crate) async fn send(
    account: &mut LocalBusAccountState,
    c: &Carrier,
) -> Result<Value, SdkError> {
    crate::client::task::check_delivery_size(c.bytes()?.len())?;
    if let Some(outcome) = account.client.task_delivery_receipt(c)?
        && !outcome.accepted
    {
        return Err(crate::task_refusal::refused(
            outcome.reason_code.unwrap_or(crate::TaskRefusalCode::InvalidEvent),
            outcome.reject.unwrap_or_else(|| "task rejected".into()),
        ));
    }
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &c.conversation_id)?
        .ok_or_else(|| invalid("task conversation missing"))?;
    let mut engine = account.take_live_engine().await?;
    let result = prepare(account, &mut engine, c, &thread, Mode::Event).await;
    account.put_engine(engine);
    let deliveries = result?;
    let response = account.client.account_db()?.write_transaction(|| {
        let timeline = crate::client::task::timeline_id(c)?;
        let outcome = account.client.project_task_message(&Delivery {
            conversation: &c.conversation_id,
            message: &timeline,
            principal: &c.principal_id,
            device: &c.device_id,
            at: now_unix_timestamp(),
        }, &c.bytes()?)?.ok_or_else(|| invalid("task projection absent"))?;
        if !outcome.accepted && !outcome.pending {
            return Err(crate::task_refusal::refused(outcome.reason_code.unwrap_or(crate::TaskRefusalCode::InvalidEvent),outcome.reject.unwrap_or_else(|| "task rejected".into())));
        }
        if account.client.direct_message_by_id(&timeline)?.is_none() {
            account.client.send_direct_message(&c.conversation_id,&timeline,&c.device_id,&[])?;
        }
        account.client.account_db()?.replace_surface_message_content(&c.conversation_id,&timeline,outcome.fallback_text.as_bytes())?;
        account.client.set_task_delivery_state(&c.conversation_id,c.event()?.event().task_id(),"sending",None)?;
        Ok(json!({"accepted":outcome.accepted,"pending":outcome.pending,"task_id":c.event()?.event().task_id(),"message_id":c.message_id,"delivery_state":"submitted","actor_kind":crate::client::task::carrier_actor_kind(&account.client, c),"actor_kind_verified":crate::client::task::carrier_kind_verified(&account.client, c)}))
    })?;
    if let Err(error) = super::super::task_delivery::submit_all(account, deliveries).await {
        account.client.set_task_delivery_state(
            &c.conversation_id,
            c.event()?.event().task_id(),
            "failed",
            Some("task_transport_error"),
        )?;
        return Err(error);
    }
    account.client.set_task_delivery_state(
        &c.conversation_id,
        c.event()?.event().task_id(),
        "submitted",
        None,
    )?;
    Ok(response)
}
pub(super) enum Mode<'a> {
    Event,
    Ack(&'a crate::client::task::control::Ack),
    Own,
}

#[cfg(test)]
async fn test_preparation_override(
    thread: &Value,
) -> Option<Result<Vec<SealedDelivery>, SdkError>> {
    if let Some(delay) = thread["test_preparation_delay_ms"].as_u64() {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    (thread["test_preparation_ready"] == true).then(|| Ok(Vec::new()))
}

pub(super) async fn prepare(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    c: &Carrier,
    thread: &Value,
    mode: Mode<'_>,
) -> Result<Vec<SealedDelivery>, SdkError> {
    #[cfg(test)]
    if let Some(result) = test_preparation_override(thread).await {
        return result;
    }
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let mut own_targets = own_targets(account, &engine.config).await?;
    let mut group_plan = None;
    let mut peers = Vec::new();
    if !matches!(mode, Mode::Own) {
        if let Some(group) = thread["group_id"].as_str() {
            group_plan = Some(
                super::task_group::plan(
                    account,
                    &c.conversation_id,
                    &c.message_id,
                    group,
                    &engine.config,
                )
                .await?,
            );
        } else {
            peers = task_direct_targets(account, &engine.config, thread).await?;
        }
    }
    let intent = matches!(mode, Mode::Event)
        && matches!(c.event()?.event(), ramflux_protocol::TaskEventBody::Resolve(_));
    if intent {
        own_targets.clear();
    }
    let task_body = match &mode {
        Mode::Ack(ack) => {
            crate::client::task::control::Control::Ack(Box::new((*ack).clone())).bytes()?
        }
        Mode::Event if intent => crate::client::task::control::Control::Intent {
            carrier_base64: ramflux_protocol::encode_base64url(c.bytes()?),
        }
        .bytes()?,
        _ => c.bytes()?,
    };
    let control = intent || matches!(mode, Mode::Ack(_));
    if control {
        if let Some(plan) = group_plan.take() {
            peers.extend(plan.targets);
        }
        if intent {
            let state =
                client.task_history(&c.conversation_id, c.event()?.event().task_id())?.state()?;
            let task = state.task().ok_or_else(|| invalid("task not found"))?;
            let ramflux_protocol::TaskEventBody::Resolve(resolution) = c.event()?.event().clone()
            else {
                return Err(invalid("task resolve expected"));
            };
            let (executor, _) = client
                .task_history(&c.conversation_id, &task.task_id)?
                .intervention_source(&resolution.step_id, &resolution.target)?;
            peers.retain(|target| target.device == executor);
            if peers.is_empty() && executor != local.device_id {
                return Err(invalid("task executor has no active delivery route"));
            }
        }
    }
    let (own_packet, original_own_event) = if own_targets.is_empty() {
        (None, false)
    } else {
        let (pages, original) = own_payloads(client, c, &task_body, &mode)?;
        (Some(pages), original)
    };
    crate::client::task::check_delivery_size(task_body.len())?;
    check_preparation_budget(
        own_packet.as_deref(),
        own_targets.len(),
        group_plan.as_ref().map_or(0, |p| p.targets.len().saturating_mul(2)),
        peers.len(),
        task_body.len(),
    )?;
    let mut deliveries = Vec::new();
    if let Some(plan) = group_plan {
        deliveries.extend(super::task_group::prepare(account, engine, c, plan).await?);
    }
    own_targets.append(&mut peers);
    for target in own_targets {
        let route =
            delivery_route(&target, control, original_own_event, thread["group_id"].as_str());
        if target.own {
            for page in own_packet.as_ref().ok_or_else(|| invalid("own task pages missing"))? {
                deliveries.push(
                    seal(account, engine, &target, &c.conversation_id, page, route.clone()).await?,
                );
            }
        } else {
            deliveries
                .push(seal(account, engine, &target, &c.conversation_id, &task_body, route).await?);
        }
    }
    Ok(deliveries)
}
fn check_preparation_budget(
    own: Option<&[Vec<u8>]>,
    own_targets: usize,
    group_targets: usize,
    peers: usize,
    body: usize,
) -> Result<(), SdkError> {
    let own_bytes = own.map_or(0, |pages| pages.iter().map(Vec::len).sum::<usize>());
    let budget = own_bytes
        .saturating_mul(own_targets)
        .saturating_add(
            body.saturating_add(4096).saturating_mul(peers.saturating_add(group_targets)),
        )
        .saturating_mul(32);
    if budget > 32 * 1024 * 1024 {
        return Err(invalid("task fanout preparation byte budget exceeded"));
    }
    Ok(())
}
fn delivery_route(
    target: &Target,
    control: bool,
    original: bool,
    group: Option<&str>,
) -> crate::client::routed::Route {
    if (target.own && original) || (!target.own && !control) {
        return crate::client::routed::Route::direct();
    }
    crate::client::routed::Route {
        kind: crate::client::routed::Kind::Control,
        group_id: group.map(str::to_owned),
        attachments: false,
    }
}
// A compacted local checkpoint is never sent as signed history. An original local
// event still travels to existing siblings through ordinary authenticated ingress.
fn own_payloads(
    client: &RamfluxClient,
    c: &Carrier,
    body: &[u8],
    mode: &Mode<'_>,
) -> Result<(Vec<Vec<u8>>, bool), SdkError> {
    let pages = client.task_own_packets(c)?;
    if !pages.is_empty() || matches!(mode, Mode::Own) {
        return Ok((pages, false));
    }
    let original = matches!(mode, Mode::Event);
    if original
        && client
            .device_branch
            .as_ref()
            .is_none_or(|d| d.principal_id != c.principal_id || d.device_id != c.device_id)
    {
        return Err(invalid("compacted original task sender differs from local device"));
    }
    Ok((vec![body.to_vec()], original))
}
pub(super) async fn seal(
    account: &LocalBusAccountState,
    engine: &mut GatewaySessionEngine,
    target: &Target,
    conversation: &str,
    body: &[u8],
    kind: crate::client::routed::Route,
) -> Result<SealedDelivery, SdkError> {
    let id = crate::new_surface_message_id()?;
    let mut message = GatewayDirectMessage {
        conversation_id: conversation.into(),
        message_id: id.clone(),
        envelope_id: id,
        source_principal_id: account
            .client
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .principal_id
            .clone(),
        sender_id: account
            .client
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .device_id
            .clone(),
        recipient_device_id: Some(target.device.clone()),
        recipient_principal_commitment: Some(target.identity.root_commitment().into()),
        target_delivery_id: target.delivery.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let sealed = if let Some(federation) = &target.federation {
        account.client.seal_routed_federated_as(
            engine,
            &message,
            body,
            federation.recipient_prekey_url.as_deref(),
            kind,
        )?
    } else {
        account.client.seal_routed_as(engine, &message, body, kind).await?
    };
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    let envelope = crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?;
    Ok(SealedDelivery {
        envelope,
        federation: target.federation.clone().map(|route| Destination {
            recipient_root: target.identity.root_commitment().into(),
            route,
            conversation_id: conversation.into(),
            message_id: message.message_id,
            device_id: target.device.clone(),
        }),
    })
}

/// Confirmation and same-root forwarding are bounded independently of inbound processing.
pub(crate) async fn drain_confirmations(
    account: &mut LocalBusAccountState,
    budget: &PreparationBudget,
) -> Result<usize, SdkError> {
    let forward_first = account.task_forward_first;
    account.task_forward_first = !forward_first;
    if forward_first {
        let forwards = drain_forwards(account, budget).await?;
        let acknowledgements = drain_acknowledgements(account, budget).await?;
        Ok(forwards + acknowledgements)
    } else {
        let acknowledgements = drain_acknowledgements(account, budget).await?;
        let forwards = drain_forwards(account, budget).await?;
        Ok(acknowledgements + forwards)
    }
}

async fn drain_acknowledgements(
    account: &mut LocalBusAccountState,
    budget: &PreparationBudget,
) -> Result<usize, SdkError> {
    use crate::client::task::control::AckJob;
    let now = now_unix_timestamp();
    let mut sent = 0;
    let mut jobs =
        account.client.account_db()?.task_record_page::<AckJob>("task/ack/", "task/ack/", 65)?;
    jobs.sort_by(|left, right| left.0.cmp(&right.0));
    rotate_to_cursor(&mut jobs, account.task_ack_cursor);
    for (key, mut job) in jobs.into_iter().filter(|(_, j)| j.next_at <= now).take(2) {
        if job.attempts >= 8 || now.saturating_sub(job.created_at) > 600 {
            account.client.account_db()?.delete_task_state(&key)?;
            continue;
        }
        if !budget.can_start_item() {
            break;
        }
        let c = job.ack.original()?;
        let result = send_control(account, &c, Mode::Ack(&job.ack), budget).await;
        account.task_ack_cursor = account.task_ack_cursor.wrapping_add(1);
        if matches!(&result, Ok(Preparation::Ready(()))) {
            let original = job.ack.original()?;
            let hash = crate::client::task::certificate::carrier_hash(&original)?;
            account.client.account_db()?.persist_actor_state(
                &crate::client::task::key("ack_sent", &hash),
                &json!({"start":now}),
            )?;
            account.client.account_db()?.prune_task_diagnostics("task/ack_sent/", 1024)?;
            account.client.account_db()?.delete_task_state(&key)?;
            sent += 1;
        } else if matches!(&result, Ok(Preparation::Deferred)) {
            if !budget.can_start_item() {
                break;
            }
        } else {
            job.attempts += 1;
            job.next_at = now.saturating_add(2_i64.pow(job.attempts.min(6)));
            account.client.account_db()?.persist_actor_state(&key, &job)?;
        }
    }
    Ok(sent)
}

async fn drain_forwards(
    account: &mut LocalBusAccountState,
    budget: &PreparationBudget,
) -> Result<usize, SdkError> {
    use crate::client::task::control::ForwardJob;
    let now = now_unix_timestamp();
    let mut sent = 0;
    let mut jobs = account.client.account_db()?.task_record_page::<ForwardJob>(
        "task/forward/",
        "task/forward/",
        65,
    )?;
    jobs.sort_by(|left, right| left.0.cmp(&right.0));
    rotate_to_cursor(&mut jobs, account.task_forward_cursor);
    for (key, mut job) in jobs.into_iter().filter(|(_, j)| j.next_at <= now).take(2) {
        if job.attempts >= 8 || now.saturating_sub(job.created_at) > 600 {
            account.client.account_db()?.delete_task_state(&key)?;
            continue;
        }
        if !budget.can_start_item() {
            break;
        }
        let history = account.client.task_history(&job.conversation_id, &job.task_id)?;
        if let Some(last) = history.events.last() {
            let result = send_control(account, &last.carrier, Mode::Own, budget).await;
            account.task_forward_cursor = account.task_forward_cursor.wrapping_add(1);
            if matches!(&result, Ok(Preparation::Ready(()))) {
                account.client.account_db()?.delete_task_state(&key)?;
                sent += 1;
            } else if matches!(&result, Ok(Preparation::Deferred)) {
                if !budget.can_start_item() {
                    break;
                }
            } else {
                job.attempts += 1;
                job.next_at = now.saturating_add(2_i64.pow(job.attempts.min(6)));
                account.client.account_db()?.persist_actor_state(&key, &job)?;
            }
        } else {
            account.client.account_db()?.delete_task_state(&key)?;
        }
    }
    Ok(sent)
}
pub(super) async fn send_control(
    account: &mut LocalBusAccountState,
    c: &Carrier,
    mode: Mode<'_>,
    budget: &PreparationBudget,
) -> Result<Preparation<()>, SdkError> {
    let thread = account
        .client
        .account_db()?
        .client_record("conversation", &c.conversation_id)?
        .ok_or_else(|| invalid("task conversation missing"))?;
    let mut engine = account.take_live_engine().await?;
    let result = await_preparation(
        prepare(account, &mut engine, c, &thread, mode),
        budget,
        "task confirmation preparation deferred",
    )
    .await;
    account.put_engine(engine);
    let Preparation::Ready(deliveries) = result? else {
        return Ok(Preparation::Deferred);
    };
    super::super::task_delivery::submit_until(
        account,
        deliveries,
        tokio::time::Instant::now() + Duration::from_secs(1),
    )
    .await?;
    Ok(Preparation::Ready(()))
}

pub(super) async fn direct_targets(
    account: &LocalBusAccountState,
    gateway: &GatewaySessionConfig,
    thread: &Value,
) -> Result<Vec<Target>, SdkError> {
    direct_targets_with_policy(account, gateway, thread, false).await
}

pub(super) async fn task_direct_targets(
    account: &LocalBusAccountState,
    gateway: &GatewaySessionConfig,
    thread: &Value,
) -> Result<Vec<Target>, SdkError> {
    direct_targets_with_policy(account, gateway, thread, true).await
}

async fn direct_targets_with_policy(
    account: &LocalBusAccountState,
    gateway: &GatewaySessionConfig,
    thread: &Value,
    bounded_manifest_worker: bool,
) -> Result<Vec<Target>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let ids = thread["participants"]
        .as_array()
        .ok_or_else(|| invalid("task direct participants missing"))?;
    let peers_ids = ids
        .iter()
        .filter_map(Value::as_str)
        .filter(|p| *p != local.principal_id)
        .collect::<Vec<_>>();
    if thread["kind"] != "direct"
        || peers_ids.len() != 1
        || !ids.iter().any(|p| p == &local.principal_id)
    {
        return Err(invalid("task direct conversation membership mismatch"));
    }
    let identity = client
        .account_db()?
        .client_record("identity", peers_ids[0])?
        .ok_or_else(|| invalid("task peer identity unavailable"))?;
    let commitment = identity["contact_identity_commitment"]
        .as_str()
        .ok_or_else(|| invalid("task peer root unavailable"))?;
    client.require_accepted_friend_link_for_dm_send(
        &local.principal_id,
        &account.principal_commitment,
        Some(peers_ids[0]),
        commitment,
    )?;
    let federation: Option<LocalBusFederationRoute> = thread["direct_route"]["federation"]
        .as_object()
        .map(|_| serde_json::from_value(thread["direct_route"]["federation"].clone()))
        .transpose()?;
    let manifest = if let Some(route) = &federation {
        let url = route
            .recipient_prekey_url
            .as_deref()
            .ok_or_else(|| invalid("task federated peer prekey URL missing"))?;
        let manifest = if bounded_manifest_worker {
            fetch_federated_manifest(url, commitment).await?
        } else {
            crate::client::contact::fetch_verified_device_manifest_from_url(url, commitment)?
        };
        client.persist_identity_directory(&manifest)?;
        manifest
    } else {
        client.cache_verified_device_manifest(gateway, commitment, "task_peer").await?
    };
    if manifest.principal_id != peers_ids[0] {
        return Err(invalid("task peer principal changed"));
    }
    manifest
        .devices
        .into_iter()
        .map(|d| {
            Ok(Target {
                identity: client.device_identity_for_root(&d.principal_commitment, &d.device_id)?,
                device: d.device_id,
                delivery: d.target_delivery_id,
                federation: federation.clone(),
                own: false,
            })
        })
        .collect::<Result<_, SdkError>>()
}

async fn fetch_federated_manifest(
    url: &str,
    commitment: &str,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    let url = url.to_owned();
    let commitment = commitment.to_owned();
    let flight_key = format!("{}/mvp1/device-manifest/{commitment}", url.trim_end_matches('/'));
    let guard = loop {
        match reserve_manifest_flight(&flight_key)? {
            ManifestReservation::Wait(flight) => {
                let notified = flight.complete.notified();
                if !flight.finished.load(Ordering::Acquire) {
                    notified.await;
                }
            }
            ManifestReservation::Start(guard) => break guard,
        }
    };
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        crate::client::contact::fetch_verified_device_manifest_from_url_bounded(
            &url,
            &commitment,
            TASK_PREPARATION_TIMEOUT,
        )
    })
    .await
    .map_err(|error| SdkError::LocalBus(format!("federated manifest worker failed: {error}")))?
}

const MAX_MANIFEST_WORKERS: usize = 4;

struct ManifestFlight {
    complete: tokio::sync::Notify,
    finished: std::sync::atomic::AtomicBool,
}

enum ManifestReservation {
    Start(ManifestFlightGuard),
    Wait(Arc<ManifestFlight>),
}

struct ManifestFlightGuard {
    key: String,
    flight: Arc<ManifestFlight>,
}

impl Drop for ManifestFlightGuard {
    fn drop(&mut self) {
        finish_manifest_flight(&self.key, &self.flight);
    }
}

fn manifest_flights() -> &'static Mutex<std::collections::HashMap<String, Arc<ManifestFlight>>> {
    static FLIGHTS: OnceLock<Mutex<std::collections::HashMap<String, Arc<ManifestFlight>>>> =
        OnceLock::new();
    FLIGHTS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

fn manifest_worker_count() -> &'static AtomicUsize {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    &COUNT
}

fn reserve_manifest_flight(url: &str) -> Result<ManifestReservation, SdkError> {
    let mut flights = manifest_flights().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(flight) = flights.get(url) {
        return Ok(ManifestReservation::Wait(Arc::clone(flight)));
    }
    manifest_worker_count()
        .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_MANIFEST_WORKERS).then_some(count + 1)
        })
        .map_err(|_| SdkError::TaskManifestWorkerCapacity)?;
    let flight = Arc::new(ManifestFlight {
        complete: tokio::sync::Notify::new(),
        finished: std::sync::atomic::AtomicBool::new(false),
    });
    flights.insert(url.to_owned(), Arc::clone(&flight));
    Ok(ManifestReservation::Start(ManifestFlightGuard { key: url.to_owned(), flight }))
}

fn finish_manifest_flight(url: &str, flight: &Arc<ManifestFlight>) {
    let mut flights = manifest_flights().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if flights.get(url).is_some_and(|current| Arc::ptr_eq(current, flight)) {
        flights.remove(url);
        manifest_worker_count().fetch_sub(1, Ordering::AcqRel);
    }
    flight.finished.store(true, Ordering::Release);
    flight.complete.notify_waiters();
}

pub(super) async fn own_targets(
    account: &LocalBusAccountState,
    gateway: &GatewaySessionConfig,
) -> Result<Vec<Target>, SdkError> {
    let client = &account.client;
    let local = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let own = client
        .cache_verified_device_manifest(gateway, &account.principal_commitment, "task_own")
        .await?;
    if !own.devices.iter().any(|d| d.device_id == local.device_id) {
        return Err(invalid("task source device is not in the active manifest"));
    }
    own.devices
        .into_iter()
        .filter(|d| d.device_id != local.device_id)
        .map(|d| {
            Ok(Target {
                identity: client.device_identity_for_root(&d.principal_commitment, &d.device_id)?,
                device: d.device_id,
                delivery: d.target_delivery_id,
                federation: None,
                own: true,
            })
        })
        .collect::<Result<_, SdkError>>()
}

#[cfg(test)]
#[path = "task_transport_tests.rs"]
mod tests;
