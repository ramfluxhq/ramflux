// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded native attempt and one resident session per account generation.

use super::ConnectionPhase;
use super::{
    Call, Child, ConnectionEvent, ConnectionHandle, DisconnectReason, NetworkingSnapshot,
    NetworkingState, RuntimeTimeouts, SessionConnector, SessionContext, SessionHub,
    SessionMetadata, new_generation,
};
use crate::custody::retry::AdmissionRetry;
use crate::gateway::host_frames::HostFrames;
use crate::{GatewaySessionConfig, GatewaySessionEngine, GatewaySessionState, SdkError};
use std::{collections::BTreeMap, sync::Arc};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time::{Instant, timeout_at},
};

#[derive(Default)]
pub(super) struct Children {
    factories: BTreeMap<&'static str, super::ChildFactory>,
    running: BTreeMap<&'static str, JoinHandle<()>>,
    cancel: Option<watch::Sender<bool>>,
}

impl Children {
    pub(super) async fn register(
        &mut self,
        child: Child,
        handle: &ConnectionHandle,
        session: &GatewaySessionState,
    ) {
        if let Some(running) = self.running.remove(child.name) {
            running.abort();
            let _ = running.await;
        }
        self.factories.insert(child.name, Arc::clone(&child.factory));
        self.spawn(child.name, &child.factory, handle, session);
    }
    fn spawn(
        &mut self,
        name: &'static str,
        factory: &super::ChildFactory,
        handle: &ConnectionHandle,
        session: &GatewaySessionState,
    ) {
        let cancel = self.cancel.get_or_insert_with(|| watch::channel(false).0).subscribe();
        let context = SessionContext {
            session_id: session.session_id.clone(),
            generation: handle.generation(),
            cancel,
            connection: handle.clone(),
        };
        self.running.insert(name, tokio::spawn(factory(context)));
    }
    fn start(&mut self, handle: &ConnectionHandle, session: &GatewaySessionState) {
        let factories = self
            .factories
            .iter()
            .map(|(name, factory)| (*name, Arc::clone(factory)))
            .collect::<Vec<_>>();
        for (name, factory) in factories {
            self.spawn(name, &factory, handle, session);
        }
    }
    async fn stop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.send_replace(true);
        }
        let running = std::mem::take(&mut self.running);
        for task in running.values() {
            task.abort();
        }
        for (_, task) in running {
            let _ = task.await;
        }
    }
}

pub(super) struct Bootstrap {
    pub handle: ConnectionHandle,
    pub config: GatewaySessionConfig,
    pub engine: Option<GatewaySessionEngine>,
    pub connector: Arc<dyn SessionConnector>,
    pub timeouts: RuntimeTimeouts,
    pub calls: mpsc::Receiver<Call>,
    pub registrations: mpsc::Receiver<Child>,
    pub stopping: watch::Receiver<bool>,
}

pub(super) async fn run(bootstrap: Bootstrap) {
    let Bootstrap {
        handle,
        mut config,
        mut engine,
        connector,
        timeouts,
        mut calls,
        mut registrations,
        mut stopping,
    } = bootstrap;
    let mut retry = AdmissionRetry::default();
    let mut children = Children::default();
    run_account(
        &handle,
        AccountLoop {
            config: &mut config,
            engine: &mut engine,
            connector: &connector,
            retry: &mut retry,
            children: &mut children,
        },
        &timeouts,
        &mut calls,
        &mut registrations,
        &mut stopping,
    )
    .await;
    children.stop().await;
    handle
        .shared
        .ephemeral_inbox
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .disconnect(true);
    while let Ok(call) = calls.try_recv() {
        let _ = call.reply.send(Err(handle.pending()));
    }
    // Retired-session configuration remains available for checkpointing while retrying,
    // but a stopped account must retain no established-session capability metadata.
    *handle.shared.metadata.write().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    settle_stopped(&handle, &config);
}

/// A stopped worker keeps today's pending observation. A revoked branch does not:
/// pending and a retry schedule are what status was copying over `suspended`.
fn settle_stopped(handle: &ConnectionHandle, config: &GatewaySessionConfig) {
    let revoked = super::super::host_branch::marked_on(config);
    update(handle, |snapshot| {
        snapshot.active_transport_kind = None;
        snapshot.session_id = None;
        snapshot.generation = new_generation();
        snapshot.phase = ConnectionPhase::Stopped;
        if !revoked {
            snapshot.state = NetworkingState::NetworkingPending;
            return;
        }
        snapshot.state = NetworkingState::Suspended;
        snapshot.cause = None;
        snapshot.retry_after_ms = None;
        snapshot.next_retry_at_ms = None;
        snapshot.last_reason = Some("branch_revoked".into());
    });
}

struct AccountLoop<'a> {
    config: &'a mut GatewaySessionConfig,
    engine: &'a mut Option<GatewaySessionEngine>,
    connector: &'a Arc<dyn SessionConnector>,
    retry: &'a mut AdmissionRetry,
    children: &'a mut Children,
}

async fn run_account(
    handle: &ConnectionHandle,
    state: AccountLoop<'_>,
    timeouts: &RuntimeTimeouts,
    calls: &mut mpsc::Receiver<Call>,
    registrations: &mut mpsc::Receiver<Child>,
    stopping: &mut watch::Receiver<bool>,
) {
    let AccountLoop { config, engine, connector, retry, children } = state;
    let mut networks = config.network_monitor.subscribe();
    'account: loop {
        if *stopping.borrow() {
            break;
        }
        if stop_marked_host(config, handle) {
            break;
        }
        if !wait_for_network(&mut networks, stopping).await {
            break;
        }
        if engine.is_none() {
            while let Some(not_before) = retry.not_before().filter(|until| *until > Instant::now())
            {
                tokio::select! {
                    biased;
                    _=stopping.changed()=>break,
                    _=networks.changed()=>continue 'account,
                    ()=tokio::time::sleep_until(not_before)=>{},
                    call=calls.recv()=>{if let Some(call)=call {let _=call.reply.send(Err(handle.pending()));}}
                    child=registrations.recv()=>{if let Some(child)=child {children.factories.insert(child.name,child.factory);}}
                }
                if *stopping.borrow() {
                    break;
                }
            }
            if *stopping.borrow() {
                break;
            }
            let result = tokio::select! {
                biased;
                _ = networks.changed() => continue,
                result = connect_attempt(handle, config, connector, timeouts, stopping, retry) => result,
            };
            let Some(result) = result else {
                break;
            };
            match result {
                Ok(connected) => *engine = Some(connected),
                Err(error) => {
                    retry.record(&error, Instant::now());
                    // Every failed admission needs a future retry boundary, including
                    // frame/transport errors without a server-provided cooldown.
                    if retry.not_before().is_none_or(|at| at <= Instant::now()) {
                        retry.record(
                            &SdkError::NodeTimeout {
                                retry_after_ms: crate::node::NODE_RETRY_AFTER_MS,
                            },
                            Instant::now(),
                        );
                    }
                    failed(handle, retry, &error);
                    if let Some(work) = &handle.shared.account_work {
                        let failed =
                            super::AccountWork::Failed { generation: handle.generation(), error };
                        tokio::select! {biased;_=stopping.changed()=>break,_=work.send(failed)=>{}}
                    }
                    continue;
                }
            }
        }
        let Some(mut resident) = engine.take() else {
            continue;
        };
        let generation = handle.generation();
        let session = announce_live(handle, &mut resident, config.previous_session_id.is_some());
        children.start(handle, &session);
        let (exit, network_changed) = session_or_network(
            handle,
            &mut resident,
            super::session_host::HostIo { calls, registrations, children, stopping },
            timeouts,
            &mut networks,
        )
        .await;
        children.stop().await;
        *config = resident.config.clone();
        publish_metadata(handle, &resident);
        let reason = match exit {
            super::session_host::HostExit::Stop => handle
                .shared
                .stop_reason
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .unwrap_or(DisconnectReason::Stop),
            super::session_host::HostExit::Retired(reason) => reason,
        };
        retire_resident(handle, &resident, reason, generation);
        let why = resident.terminal_why.clone();
        resident.shutdown_transport().await;
        if matches!(reason, DisconnectReason::Stop | DisconnectReason::Lock) {
            break;
        }
        if network_changed {
            // A new path should dial immediately; server-directed admission cooldowns are
            // still enforced inside connect_attempt by the existing retry owner.
            continue;
        }
        reconnect_after_retirement(handle, retry, reason, why.as_deref(), generation);
    }
}

fn stop_marked_host(config: &GatewaySessionConfig, handle: &ConnectionHandle) -> bool {
    if !super::super::host_branch::marked_on(config) {
        return false;
    }
    super::super::host_branch::suspend_marked(config);
    handle.signal_stop();
    true
}

/// A retired resident session waits out the reconnect cooldown. The snapshot names
/// grant expiry, renewal refusal, or that cooldown. A real dial timeout stays elsewhere.
fn reconnect_after_retirement(
    handle: &ConnectionHandle,
    retry: &mut AdmissionRetry,
    reason: DisconnectReason,
    why: Option<&str>,
    generation: u64,
) {
    let error = SdkError::NodeTimeout { retry_after_ms: crate::node::NODE_RETRY_AFTER_MS };
    retry.record(&error, Instant::now());
    let delay = backoff(handle, retry, &error);
    let named = retirement_status(why);
    update(handle, |snapshot| {
        snapshot.last_reason = Some(named.to_owned());
        // NodeTimeout is the reconnect delay. It is not why a revoked grant closed.
        if named == "renewal_refused" {
            snapshot.cause = None;
        }
    });
    tracing::warn!(
        ?reason,
        why = why.unwrap_or(""),
        status = named,
        generation,
        retry_after_ms = ?delay,
        "resident account session retired; reconnecting"
    );
}

fn retirement_status(why: Option<&str>) -> &'static str {
    let why = why.unwrap_or("");
    if why.contains("renewal_refused") {
        "renewal_refused"
    } else if why.contains("grant_expired") {
        "grant_expired"
    } else {
        "cooldown"
    }
}

async fn wait_for_network(
    networks: &mut watch::Receiver<crate::NetworkSnapshot>,
    stopping: &mut watch::Receiver<bool>,
) -> bool {
    while matches!(networks.borrow_and_update().kind, crate::NetworkChangeKind::Lost) {
        tokio::select! {
            biased;
            _ = stopping.changed() => return false,
            changed = networks.changed() => if changed.is_err() { return false; },
        }
    }
    true
}

async fn session_or_network(
    handle: &ConnectionHandle,
    resident: &mut GatewaySessionEngine,
    io: super::session_host::HostIo<'_>,
    timeouts: &RuntimeTimeouts,
    networks: &mut watch::Receiver<crate::NetworkSnapshot>,
) -> (super::session_host::HostExit, bool) {
    tokio::select! {
        biased;
        _ = networks.changed() => (super::session_host::HostExit::Retired(DisconnectReason::Transport), true),
        exit = super::session_host::run(handle, resident, io, timeouts) => (exit, false),
    }
}

fn retire_resident(
    handle: &ConnectionHandle,
    resident: &GatewaySessionEngine,
    reason: DisconnectReason,
    generation: u64,
) {
    retire_inbox(handle, reason);
    if let Some(host) = &resident.host {
        host.hub.disconnect(reason);
    }
    disconnected(handle, reason, resident.terminal_why.as_deref(), generation);
}

fn retire_inbox(handle: &ConnectionHandle, reason: DisconnectReason) {
    let mut inbox =
        handle.shared.ephemeral_inbox.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    inbox.disconnect(matches!(
        reason,
        DisconnectReason::Stop | DisconnectReason::Lock | DisconnectReason::Restart
    ));
    if reason == DisconnectReason::Restart {
        *inbox = crate::ephemeral::session::SessionInbox::new();
    }
}

fn disconnected(
    handle: &ConnectionHandle,
    reason: DisconnectReason,
    why: Option<&str>,
    generation: u64,
) {
    update(handle, |snapshot| {
        snapshot.state = NetworkingState::NetworkingPending;
        snapshot.phase = if matches!(reason, DisconnectReason::Stop | DisconnectReason::Lock) {
            ConnectionPhase::Stopped
        } else {
            ConnectionPhase::Backoff
        };
        snapshot.active_transport_kind = None;
        snapshot.session_id = None;
        snapshot.last_reason = Some(match why {
            Some(why) => format!("{reason:?}: {why}"),
            None => format!("{reason:?}"),
        });
        snapshot.retry_after_ms = None;
        snapshot.next_retry_at_ms = None;
    });
    crate::diag::events::conn_disconnect(&format!("{reason:?}"), generation);
    let _ = handle.shared.events.send(ConnectionEvent::Disconnected { reason, generation });
}

fn update(handle: &ConnectionHandle, change: impl FnOnce(&mut NetworkingSnapshot)) {
    let generation = {
        let mut snapshot =
            handle.shared.snapshot.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        change(&mut snapshot);
        snapshot.generation
    };
    handle.shared.changed.send_replace(generation);
}
pub(super) fn publish_metadata(handle: &ConnectionHandle, engine: &GatewaySessionEngine) {
    *handle.shared.metadata.write().unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(SessionMetadata {
            ephemeral_negotiated: engine.ephemeral_negotiated,
            config: engine.config.clone(),
            session: engine.session().clone(),
            mode: engine.mode.clone(),
            generation: handle.generation(),
        });
}
fn failed(handle: &ConnectionHandle, retry: &AdmissionRetry, error: &SdkError) {
    let delay = backoff(handle, retry, error);
    tracing::warn!(
        %error,
        error_code = crate::bus::io::local_bus_error_code(error),
        retry_after_ms = ?delay,
        "account connection attempt deferred"
    );
}

/// Publishes the retry boundary after a failed attempt or a retired session.
fn backoff(handle: &ConnectionHandle, retry: &AdmissionRetry, error: &SdkError) -> Option<u64> {
    let delay = retry.not_before().map(|until| {
        u64::try_from(until.saturating_duration_since(Instant::now()).as_millis())
            .unwrap_or(u64::MAX)
    });
    crate::diag::events::conn_backoff(error, delay.unwrap_or(0));
    update(handle, |snapshot| {
        snapshot.phase = ConnectionPhase::Backoff;
        snapshot.gateway_writer_busy = error.gateway_writer_busy();
        snapshot.cause = super::super::native_account::networking_reason(error);
        let mapped = if matches!(error, SdkError::NodeTimeout { .. }) {
            "AttemptTimeout".to_owned()
        } else {
            error.to_string()
        };
        snapshot.last_reason = Some({
            #[cfg(test)]
            {
                match snapshot.last_reason.take() {
                    Some(previous) if previous != mapped => format!("{mapped} after {previous}"),
                    _ => mapped,
                }
            }
            #[cfg(not(test))]
            {
                mapped
            }
        });
        snapshot.retry_after_ms = delay;
        snapshot.next_retry_at_ms = delay.map(|delay| wall_ms().saturating_add(delay));
    });
    let _ = handle.shared.events.send(ConnectionEvent::AttemptFailed {
        reason: error.to_string(),
        retry_after_ms: delay,
        generation: handle.generation(),
    });
    delay
}
fn wall_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

async fn prepare(
    handle: &ConnectionHandle,
    config: GatewaySessionConfig,
    deadline: Instant,
) -> Result<GatewaySessionConfig, SdkError> {
    let Some(work) = &handle.shared.account_work else {
        return Ok(config);
    };
    let (reply, response) = tokio::sync::oneshot::channel();
    work.send(super::AccountWork::Prepare { generation: handle.generation(), deadline, reply })
        .await
        .map_err(|_| handle.pending())?;
    response.await.map_err(|_| handle.pending())?
}
async fn install(handle: &ConnectionHandle, metadata: SessionMetadata) -> Result<(), SdkError> {
    let Some(work) = &handle.shared.account_work else {
        return Ok(());
    };
    let (reply, response) = tokio::sync::oneshot::channel();
    work.send(super::AccountWork::Connected { metadata: Box::new(metadata), reply })
        .await
        .map_err(|_| handle.pending())?;
    response.await.map_err(|_| handle.pending())?
}

async fn connect_attempt(
    handle: &ConnectionHandle,
    config: &GatewaySessionConfig,
    connector: &Arc<dyn SessionConnector>,
    timeouts: &RuntimeTimeouts,
    stopping: &mut watch::Receiver<bool>,
    retry: &mut AdmissionRetry,
) -> Option<Result<GatewaySessionEngine, SdkError>> {
    let now = Instant::now();
    let generation = new_generation();
    update(handle, |snapshot| {
        snapshot.generation = generation;
        snapshot.attempt += 1;
        snapshot.attempt_started = Some(now);
        snapshot.attempt_started_at_ms = Some(wall_ms());
        snapshot.next_retry_at_ms = None;
        snapshot.retry_after_ms = None;
        snapshot.last_reason = Some("Connecting".into());
        snapshot.phase = ConnectionPhase::Connecting;
    });
    // This adapter is replaced by S1's policy at integration. Keep one policy
    // across attempts, and do not let readers advance its not_before value.
    let mut budget = retry.begin_attempt().await;
    let prepared = budget.attempt(async { Ok(()) }).await;
    let deadline = now + timeouts.attempt;
    let result = tokio::select! {
        biased;
        _=stopping.changed()=>return None,
        result=timeout_at(deadline,async {
            prepared?;
            let prepared_config=prepare(handle,config.clone(),deadline).await?;
            let mut connected=connector.connect(prepared_config,deadline).await?;
            reconcile_receive_epoch(handle, &mut connected).await?;
            install(handle,SessionMetadata {ephemeral_negotiated:connected.ephemeral_negotiated,config:connected.config.clone(),session:connected.session().clone(),mode:connected.mode.clone(),generation:handle.generation()}).await?;
            Ok(connected)
        })=>match result {
            Ok(result)=>result,
            Err(_)=>Err(SdkError::NodeTimeout {retry_after_ms:crate::node::NODE_RETRY_AFTER_MS}),
        },
    };
    Some(result)
}

fn announce_live(
    handle: &ConnectionHandle,
    resident: &mut GatewaySessionEngine,
    resumed: bool,
) -> GatewaySessionState {
    let generation = handle.generation();
    let hub = Arc::new(SessionHub::new(generation));
    *handle.shared.hub.write().unwrap_or_else(std::sync::PoisonError::into_inner) =
        Arc::clone(&hub);
    handle.shared.read_clock.reset_to_now();
    handle.set_session_mode(resident.mode.clone());
    resident.ephemeral_owner.take();
    resident.ephemeral_inbox = handle
        .shared
        .ephemeral_inbox
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    resident.ephemeral_inbox.reconnect();
    resident.host = Some(HostFrames {
        hub,
        resync_needed: Arc::clone(&handle.shared.resync_needed),
        clock: Arc::clone(&handle.shared.read_clock),
        #[cfg(test)]
        buffer_stats: Arc::clone(&handle.shared.buffer_stats),
        #[cfg(test)]
        dispatch_count: Arc::default(),
    });
    publish_metadata(handle, resident);
    // Counted before Live is published so a reader never sees the Connected pass first.
    handle.receive_observations().session_live();
    update(handle, |snapshot| {
        snapshot.state = NetworkingState::Live;
        snapshot.phase = ConnectionPhase::Live;
        snapshot.gateway_writer_busy = false;
        snapshot.last_reason = None;
        snapshot.cause = None;
        snapshot.retry_after_ms = None;
        snapshot.next_retry_at_ms = None;
        snapshot.active_transport_kind = Some(resident.active_transport_kind());
        snapshot.session_id = Some(resident.session().session_id.clone());
    });
    let session = resident.session().clone();
    crate::diag::events::conn_connect(resumed, generation);
    let _ = handle.shared.events.send(ConnectionEvent::Connected {
        session_id: session.session_id.clone(),
        resumed,
        generation,
    });
    handle.shared.receive_wake.notify_one();
    session
}

// Before announcing Live, reconcile the durable epoch through the actor. The worker
// owns wire I/O; only the account actor reads and resets the account DB.
async fn reconcile_receive_epoch(
    handle: &ConnectionHandle,
    engine: &mut GatewaySessionEngine,
) -> Result<(), SdkError> {
    let Some(incarnation) = engine.mode.push_incarnation().map(str::to_owned) else {
        return Ok(());
    };
    let Some(work) = &handle.shared.account_work else {
        return Ok(());
    };
    let generation = handle.generation();
    let (reply, response) = tokio::sync::oneshot::channel();
    work.send(super::AccountWork::PrepareReceiveEpoch {
        generation,
        incarnation: incarnation.clone(),
        reply,
    })
    .await
    .map_err(|_| handle.pending())?;
    let Some(turn) = response.await.map_err(|_| handle.pending())?? else {
        return Ok(());
    };
    let page = match engine.resume_page(0, 64).await? {
        crate::gateway::push_resume::PageReply::Page(page) => page,
        crate::gateway::push_resume::PageReply::Refused(reason) => {
            return Err(SdkError::GatewaySessionRejected(reason.as_str().into()));
        }
    };
    let (reply, response) = tokio::sync::oneshot::channel();
    work.send(super::AccountWork::ResetReceiveEpoch {
        generation,
        turn: Box::new(turn),
        incarnation,
        page,
        reply,
    })
    .await
    .map_err(|_| handle.pending())?;
    response.await.map_err(|_| handle.pending())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnect_event_exposes_terminal_or_retry_phase()
    -> Result<(), Box<dyn std::error::Error>> {
        let (handle, _io) = super::super::tests::fixture().await?;
        handle.stop().await;
        let mut events = handle.events();
        for reason in [DisconnectReason::Stop, DisconnectReason::Lock, DisconnectReason::Drain] {
            update(&handle, |snapshot| {
                snapshot.state = NetworkingState::Live;
                snapshot.phase = ConnectionPhase::Live;
                snapshot.gateway_writer_busy = false;
                snapshot.session_id = Some("retiring".into());
                snapshot.retry_after_ms = Some(1000);
                snapshot.next_retry_at_ms = Some(4242);
            });
            let generation = handle.generation();
            disconnected(&handle, reason, None, generation);
            assert!(
                matches!(events.recv().await?, ConnectionEvent::Disconnected { reason: r, generation: g } if r == reason && g == generation)
            );
            let snapshot = handle.snapshot();
            let expected = if reason == DisconnectReason::Drain {
                ConnectionPhase::Backoff
            } else {
                ConnectionPhase::Stopped
            };
            assert_eq!(snapshot.phase, expected);
            assert_eq!(snapshot.state, NetworkingState::NetworkingPending);
            assert!(snapshot.session_id.is_none());
            assert!(snapshot.active_transport_kind.is_none());
            assert!(snapshot.retry_after_ms.is_none());
            assert!(snapshot.next_retry_at_ms.is_none());
        }
        Ok(())
    }
}
