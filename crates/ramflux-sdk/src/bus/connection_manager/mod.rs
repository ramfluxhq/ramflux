// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resident account connection authority, bounded calls, observations, and session children.

mod model;
pub(crate) mod receive;
pub(crate) mod resync;
pub(crate) use receive::{ReceiveApplied, ReceiveEntry, ReceivePlan, ReceiveTrigger};
mod account_work;
mod background_children;
mod metadata_child;
#[cfg_attr(
    not(test),
    allow(unused_imports, reason = "W0 on main and bus tests import this path")
)]
pub(crate) use account_work::ReceiveTurn;
pub(crate) use account_work::{AccountWork, AckFlushReply, AckFlushResults};
mod client;
pub(crate) use client::SessionClient;
pub(crate) mod session_host;
pub(crate) mod subscriptions;
mod worker;

use super::runtime_limits::{CALL_QUEUE, RuntimeTimeouts};
use crate::gateway::frame_dispatch::FrameKind;
use crate::{GatewaySessionConfig, GatewaySessionEngine, GatewaySessionState, SdkError};
pub(crate) use model::{
    ConnectionEvent, ConnectionPhase, DisconnectReason, NetworkingSnapshot, NetworkingState,
};
use std::{
    any::Any,
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};
pub(crate) use subscriptions::{SessionHub, SessionSubscription};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot, watch},
    time::{Instant, timeout_at},
};

pub(crate) type SessionFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SdkError>> + Send + 'a>>;
type Erased = Box<dyn Any + Send>;
type Operation =
    Box<dyn for<'a> FnOnce(&'a mut GatewaySessionEngine) -> SessionFuture<'a, Erased> + Send>;
type ChildFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type ChildFactory = Arc<dyn Fn(SessionContext) -> ChildFuture + Send + Sync>;

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
fn new_generation() -> u64 {
    NEXT_GENERATION.fetch_add(1, Ordering::Relaxed)
}

pub(crate) trait SessionConnector: Send + Sync {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        deadline: Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine>;
}

pub(crate) struct GatewayConnector {
    pub timeouts: RuntimeTimeouts,
}
impl SessionConnector for GatewayConnector {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        deadline: Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        let native_deadline = config.custody.as_ref().map(|_| deadline);
        Box::pin(GatewaySessionEngine::connect_with_opener(
            config,
            native_deadline,
            self.timeouts.clone(),
            Arc::new(crate::gateway::transport_opener::ConfiguredTransport),
        ))
    }
}

#[derive(Clone)]
pub(crate) struct SessionMetadata {
    pub config: GatewaySessionConfig,
    pub session: GatewaySessionState,
    pub generation: u64,
}

struct Shared {
    timeouts: RuntimeTimeouts,
    session_push_advertise: bool,
    snapshot: RwLock<NetworkingSnapshot>,
    metadata: RwLock<Option<SessionMetadata>>,
    hub: RwLock<Arc<SessionHub>>,
    changed: watch::Sender<u64>,
    events: broadcast::Sender<ConnectionEvent>,
    resync_needed: Arc<resync::ResyncState>,
    receive_wake: Arc<Notify>,
    courier_wakes: std::collections::BTreeMap<&'static str, Arc<Notify>>,
    account_work: Option<mpsc::Sender<AccountWork>>,
    call_changed: Arc<Notify>,
    stop_reason: std::sync::Mutex<Option<DisconnectReason>>,
    #[cfg(test)]
    removals: std::sync::Mutex<Vec<CallRemoval>>,
    #[cfg(test)]
    receive_trace: std::sync::Mutex<Vec<(ReceiveTrigger, bool)>>,
    #[cfg(test)]
    receive_last_error: std::sync::Mutex<Option<String>>,
    #[cfg(test)]
    receive_completed: Arc<Notify>,
    #[cfg(test)]
    receive_profile: std::sync::Mutex<resync::ReceiveProfile>,
    #[cfg(test)]
    buffer_stats: Arc<std::sync::Mutex<crate::gateway::host_frames::BufferStats>>,
    retirement: std::sync::Mutex<Option<(u64, DisconnectReason)>>,
    retirement_changed: Notify,
    read_clock: Arc<crate::gateway::host_frames::ReadClock>,
    reorder: std::sync::Mutex<crate::bus::push_receiver::reorder::ReorderBuffer>,
    receive_origin: Instant,
    #[cfg(test)]
    live_waiters: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    keepalive_running: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    catch_up_yields: std::sync::atomic::AtomicU32,
    #[cfg(test)]
    catch_up_yield_progress: std::sync::atomic::AtomicU32,
    #[cfg(test)]
    yield_witness_at: std::sync::atomic::AtomicU32,
    #[cfg(test)]
    in_flight: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
thread_local! {
    static YIELD_WITNESS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn new_shared(
    config: &GatewaySessionConfig,
    timeouts: &RuntimeTimeouts,
    generation: u64,
    account_work: Option<mpsc::Sender<AccountWork>>,
) -> Arc<Shared> {
    let (changed, _) = watch::channel(generation);
    let (events, _) = broadcast::channel(64);
    Arc::new(Shared {
        timeouts: timeouts.clone(),
        session_push_advertise: config.session_push_advertise,
        snapshot: RwLock::new(NetworkingSnapshot::pending(generation)),
        metadata: RwLock::new(None),
        hub: RwLock::new(Arc::new(SessionHub::new(generation))),
        changed,
        events,
        resync_needed: Arc::new(resync::ResyncState::default()),
        receive_wake: Arc::new(Notify::new()),
        courier_wakes: [
            "delivery-receipts",
            "own-device-copy",
            "contact-control",
            "surface-resync",
            "pair-reset",
            "group-stage",
            "group-requests",
            "group-delivery",
            "call-signaling",
            "own-contact-backfill",
        ]
        .into_iter()
        .map(|name| (name, Arc::new(Notify::new())))
        .collect(),
        account_work,
        call_changed: Arc::new(Notify::new()),
        #[cfg(test)]
        live_waiters: std::sync::atomic::AtomicUsize::new(0),
        #[cfg(test)]
        keepalive_running: std::sync::atomic::AtomicBool::new(false),
        #[cfg(test)]
        catch_up_yields: std::sync::atomic::AtomicU32::new(0),
        #[cfg(test)]
        catch_up_yield_progress: std::sync::atomic::AtomicU32::new(0),
        #[cfg(test)]
        yield_witness_at: std::sync::atomic::AtomicU32::new(0),
        #[cfg(test)]
        in_flight: std::sync::atomic::AtomicUsize::new(0),
        stop_reason: std::sync::Mutex::new(None),
        #[cfg(test)]
        removals: std::sync::Mutex::new(Vec::new()),
        #[cfg(test)]
        receive_trace: std::sync::Mutex::new(Vec::new()),
        #[cfg(test)]
        receive_last_error: std::sync::Mutex::new(None),
        #[cfg(test)]
        receive_completed: Arc::default(),
        #[cfg(test)]
        receive_profile: std::sync::Mutex::new(resync::ReceiveProfile::default()),
        #[cfg(test)]
        buffer_stats: Arc::new(std::sync::Mutex::new(
            crate::gateway::host_frames::BufferStats::default(),
        )),
        retirement: std::sync::Mutex::new(None),
        retirement_changed: Notify::new(),
        read_clock: crate::gateway::host_frames::ReadClock::new(),
        reorder: std::sync::Mutex::new(crate::bus::push_receiver::reorder::ReorderBuffer::new(0)),
        receive_origin: Instant::now(),
    })
}

#[derive(Clone)]
pub(crate) struct ConnectionHandle {
    shared: Arc<Shared>,
    calls: mpsc::Sender<Call>,
    places: Arc<Semaphore>,
    priority_places: Arc<Semaphore>,
    children: mpsc::Sender<Child>,
    safety_refresh: mpsc::Sender<String>,
    task_delivery: crate::bus::task_courier_apply::background::Queue,
    stop: watch::Sender<bool>,
    finished: watch::Receiver<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallClass {
    Priority,
    Bulk,
}

struct Call {
    class: CallClass,
    exchange_timeout: Option<std::time::Duration>,
    operation: Operation,
    deadline: Instant,
    generation: u64,
    reply: oneshot::Sender<Result<(Erased, u64), SdkError>>,
    cancelled: watch::Receiver<bool>,
    place: OwnedSemaphorePermit,
    #[cfg(test)]
    _in_flight: InFlight,
}

#[cfg(test)]
struct InFlight(Arc<Shared>);

#[cfg(test)]
impl InFlight {
    fn new(shared: &Arc<Shared>) -> Self {
        shared.in_flight.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(Arc::clone(shared))
    }
}

#[cfg(test)]
impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

struct Child {
    name: &'static str,
    factory: ChildFactory,
}

#[derive(Clone)]
pub(crate) struct SessionContext {
    pub session_id: String,
    pub generation: u64,
    pub cancel: watch::Receiver<bool>,
    connection: ConnectionHandle,
}

impl SessionContext {
    pub(crate) async fn courier_wake(&self, name: &'static str) {
        if let Some(wake) = self.connection.shared.courier_wakes.get(name) {
            wake.notified().await;
        } else {
            std::future::pending::<()>().await;
        }
    }

    pub(crate) fn call_deadline(&self) -> Instant {
        Instant::now() + self.connection.shared.timeouts.call
    }
    pub(crate) fn receipt_deadline(&self) -> Instant {
        Instant::now() + self.receipt_timeout()
    }
    pub(crate) fn receipt_timeout(&self) -> std::time::Duration {
        self.connection.shared.timeouts.receipt
    }
    pub(crate) fn network_wait(&self) -> std::time::Duration {
        self.connection.shared.timeouts.network_wait
    }
    pub(crate) fn task_deadline(&self, approval: bool) -> Instant {
        Instant::now()
            + if approval {
                self.connection.shared.timeouts.task_approval
            } else {
                self.connection.shared.timeouts.task_submit
            }
    }
    pub(crate) fn subscribe(
        &self,
        kinds: impl IntoIterator<Item = FrameKind>,
    ) -> SessionSubscription {
        self.connection.subscribe(kinds)
    }
    pub(crate) async fn priority_call<T, F>(
        &self,
        operation: F,
        exchange_timeout: std::time::Duration,
    ) -> Result<T, SdkError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut GatewaySessionEngine) -> SessionFuture<'a, T> + Send + 'static,
    {
        self.connection
            .call_class_generation(
                operation,
                self.call_deadline() + exchange_timeout,
                self.generation,
                CallClass::Priority,
                Some(exchange_timeout),
            )
            .await
    }
    pub(crate) async fn call<T, F>(&self, operation: F, deadline: Instant) -> Result<T, SdkError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut GatewaySessionEngine) -> SessionFuture<'a, T> + Send + 'static,
    {
        self.connection.call_generation(operation, deadline, self.generation).await
    }

    #[must_use]
    pub(crate) fn last_read_at(&self) -> Instant {
        self.connection.last_read_at()
    }

    #[cfg(test)]
    pub(crate) fn set_keepalive_running(&self, running: bool) {
        self.connection.set_keepalive_running(running);
    }

    #[must_use]
    pub(crate) fn connection_generation(&self) -> u64 {
        self.connection.generation()
    }

    #[must_use]
    pub(crate) fn keepalive_idle(&self) -> std::time::Duration {
        self.connection.shared.timeouts.keepalive_idle
    }

    pub(crate) async fn keepalive_heartbeat(&self) -> Result<(), SdkError> {
        let timeout = self.connection.shared.timeouts.keepalive_call;
        let idle = self.keepalive_idle();
        let handle = self.connection.clone();
        self.connection
            .call_class_generation(
                move |engine| {
                    Box::pin(async move {
                        if Instant::now() < handle.last_read_at() + idle {
                            return Ok(());
                        }
                        engine.heartbeat().await
                    })
                },
                Instant::now() + timeout,
                self.generation,
                CallClass::Bulk,
                Some(timeout),
            )
            .await
    }
}

impl ConnectionHandle {
    pub(in crate::bus) fn enqueue_task_delivery(
        &self,
        item: crate::bus::task_courier::Item,
        preparation: crate::bus::task_courier::Preparation,
    ) {
        self.task_delivery.enqueue(item, preparation, self.generation());
    }

    #[cfg(test)]
    pub(crate) fn test_context(&self) -> SessionContext {
        SessionContext {
            session_id: self.metadata().map_or_else(String::new, |m| m.session.session_id),
            generation: self.generation(),
            cancel: self.stop.subscribe(),
            connection: self.clone(),
        }
    }

    #[must_use]
    pub(crate) fn last_read_at(&self) -> Instant {
        self.shared.read_clock.last_read_at()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn test_read_count(&self) -> u64 {
        self.shared.read_clock.read_count()
    }

    #[cfg(test)]
    pub(crate) fn set_keepalive_running(&self, running: bool) {
        self.shared.keepalive_running.store(running, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn test_keepalive_running(&self) -> bool {
        self.shared.keepalive_running.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn start_with(
        config: GatewaySessionConfig,
        engine: Option<GatewaySessionEngine>,
        timeouts: RuntimeTimeouts,
        connector: Arc<dyn SessionConnector>,
        account_work: Option<mpsc::Sender<AccountWork>>,
    ) -> Self {
        let generation = new_generation();
        let shared = new_shared(&config, &timeouts, generation, account_work);
        let (calls, receive) = mpsc::channel(2 * CALL_QUEUE);
        let (children, registrations) = mpsc::channel(32);
        let (stop, stopping) = watch::channel(false);
        let (complete, finished) = watch::channel(false);
        let (safety_refresh, safety_requests) = mpsc::channel(32);
        let (task_delivery, task_requests) =
            crate::bus::task_courier_apply::background::Queue::new();
        let handle = Self {
            task_delivery,
            safety_refresh,
            shared,
            calls,
            places: Arc::new(Semaphore::new(CALL_QUEUE)),
            priority_places: Arc::new(Semaphore::new(CALL_QUEUE)),
            children,
            stop,
            finished,
        };
        let auxiliary = background_children::start(
            &handle,
            &timeouts,
            safety_requests,
            task_requests,
            &stopping,
        );
        let task_handle = handle.clone();
        tokio::spawn(async move {
            Box::pin(worker::run(worker::Bootstrap {
                handle: task_handle,
                config,
                engine,
                connector,
                timeouts,
                calls: receive,
                registrations,
                stopping,
            }))
            .await;
            for task in &auxiliary {
                task.abort();
            }
            for task in auxiliary {
                let _ = task.await;
            }
            complete.send_replace(true);
        });
        handle
    }

    fn record_removal(&self, cause: &'static str, deadline: Instant) {
        tracing::trace!(
            cause,
            ?deadline,
            generation = self.generation(),
            "queued session call removed"
        );
        #[cfg(test)]
        self.shared
            .removals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(CallRemoval { cause, deadline });
    }
    #[cfg(test)]
    pub(crate) fn queued_calls(&self) -> usize {
        2 * CALL_QUEUE - self.places.available_permits() - self.priority_places.available_permits()
    }
    #[cfg(test)]
    pub(crate) fn removals(&self) -> Vec<CallRemoval> {
        self.shared.removals.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
    pub(crate) fn wake_couriers(&self) {
        for wake in self.shared.courier_wakes.values() {
            wake.notify_one();
        }
    }
    pub(crate) fn refresh_contact_safety(&self, root: &str) {
        let _ = self.safety_refresh.try_send(root.to_owned());
    }
    pub(crate) fn snapshot(&self) -> NetworkingSnapshot {
        self.shared.snapshot.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
    pub(crate) fn snapshot_watch(&self) -> watch::Receiver<u64> {
        self.shared.changed.subscribe()
    }
    pub(crate) fn metadata(&self) -> Option<SessionMetadata> {
        self.shared.metadata.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
    pub(crate) fn events(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.shared.events.subscribe()
    }
    pub(crate) fn generation(&self) -> u64 {
        self.snapshot().generation
    }
    pub(crate) fn note_catch_up_yield(&self) {
        #[cfg(not(test))]
        let _ = self;
        #[cfg(test)]
        {
            self.shared.yield_witness_at.store(
                YIELD_WITNESS.with(std::cell::Cell::get),
                std::sync::atomic::Ordering::Relaxed,
            );
            self.shared.catch_up_yields.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    pub(crate) fn note_catch_up_yield_resumed(&self) {
        #[cfg(not(test))]
        let _ = self;
        #[cfg(test)]
        {
            let before = self.shared.yield_witness_at.load(std::sync::atomic::Ordering::Relaxed);
            let after = YIELD_WITNESS.with(std::cell::Cell::get);
            self.shared
                .catch_up_yield_progress
                .store(after.saturating_sub(before), std::sync::atomic::Ordering::Relaxed);
        }
    }
    #[cfg(test)]
    #[must_use]
    pub(crate) fn test_catch_up_yields(&self) -> u32 {
        self.shared.catch_up_yields.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    #[must_use]
    pub(crate) fn test_catch_up_yield_progress(&self) -> u32 {
        self.shared.catch_up_yield_progress.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    #[must_use]
    pub(crate) fn in_flight_calls(&self) -> usize {
        self.shared.in_flight.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    pub(crate) fn bump_yield_witness() {
        YIELD_WITNESS.with(|cell| cell.set(cell.get().saturating_add(1)));
    }
    /// Wake the receive loop without requesting resync (tests drive the paused clock).
    #[cfg(test)]
    pub(crate) fn notify_receive_wake(&self) {
        self.wake_receive();
    }

    pub(crate) fn wake_receive(&self) {
        self.shared.receive_wake.notify_one();
    }

    pub(crate) fn stopping(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    pub(crate) fn call_timeout(&self) -> std::time::Duration {
        self.shared.timeouts.call
    }

    pub(crate) fn receive_origin(&self) -> Instant {
        self.shared.receive_origin
    }

    #[must_use]
    pub(crate) fn receive_now_ms(&self) -> u64 {
        u64::try_from(self.shared.receive_origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub(crate) fn reorder(
        &self,
    ) -> std::sync::MutexGuard<'_, crate::bus::push_receiver::reorder::ReorderBuffer> {
        self.shared.reorder.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn publish_capable(&self, event: crate::gateway::session_push::CapableEvent) {
        self.shared
            .hub
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .publish_capable(event);
    }
    pub(crate) fn pending(&self) -> SdkError {
        let snapshot = self.snapshot();
        SdkError::NetworkingPendingContext {
            retry_after_ms: snapshot.retry_after_ms,
            networking: Box::new(serde_json::json!(snapshot)),
        }
    }
    pub(crate) async fn require_live(&self, wait: std::time::Duration) -> Result<(), SdkError> {
        self.require_live_since(Instant::now(), wait).await
    }
    pub(crate) async fn require_live_since(
        &self,
        admitted_at: Instant,
        wait: std::time::Duration,
    ) -> Result<(), SdkError> {
        #[cfg(test)]
        let _waiter = LiveWaiter::new(&self.shared.live_waiters);
        let mut changed = self.shared.changed.subscribe();
        let snapshot = self.snapshot();
        let origin = snapshot.attempt_started.map_or(admitted_at, |start| start.min(admitted_at));
        let deadline = origin + wait;
        loop {
            if self.snapshot().state == NetworkingState::Live {
                return Ok(());
            }
            if timeout_at(deadline, changed.changed()).await.is_err() {
                return Err(self.pending());
            }
            if changed.has_changed().is_err() || *self.stop.borrow() {
                return Err(self.pending());
            }
        }
    }
    pub(crate) async fn call<T, F>(&self, operation: F, deadline: Instant) -> Result<T, SdkError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut GatewaySessionEngine) -> SessionFuture<'a, T> + Send + 'static,
    {
        self.call_generation(operation, deadline, self.generation()).await
    }
    pub(crate) async fn call_generation<T, F>(
        &self,
        operation: F,
        deadline: Instant,
        generation: u64,
    ) -> Result<T, SdkError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut GatewaySessionEngine) -> SessionFuture<'a, T> + Send + 'static,
    {
        self.call_class_generation(operation, deadline, generation, CallClass::Bulk, None).await
    }
    async fn call_class_generation<T, F>(
        &self,
        operation: F,
        deadline: Instant,
        generation: u64,
        class: CallClass,
        exchange_timeout: Option<std::time::Duration>,
    ) -> Result<T, SdkError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut GatewaySessionEngine) -> SessionFuture<'a, T> + Send + 'static,
    {
        if self.snapshot().state != NetworkingState::Live
            || generation != self.generation()
            || self.retirement_requested()
        {
            return Err(self.pending());
        }
        let places = match class {
            CallClass::Priority => &self.priority_places,
            CallClass::Bulk => &self.places,
        };
        let place = Arc::clone(places).try_acquire_owned().map_err(|_| full())?;
        let (reply, response) = oneshot::channel();
        let (cancel, cancelled) = watch::channel(false);
        let _cancel = CancelOnDrop { cancel, changed: Arc::clone(&self.shared.call_changed) };
        self.calls
            .try_send(Call {
                class,
                exchange_timeout,
                operation: Box::new(move |engine| {
                    Box::pin(async move {
                        operation(engine).await.map(|result| Box::new(result) as Erased)
                    })
                }),
                deadline,
                generation,
                reply,
                cancelled,
                place,
                #[cfg(test)]
                _in_flight: InFlight::new(&self.shared),
            })
            .map_err(|_| full())?;
        let (result, stamped) = response.await.map_err(|_| self.pending())??;
        if stamped != generation || stamped != self.generation() {
            return Err(self.pending());
        }
        result.downcast::<T>().map(|value| *value).map_err(|_| {
            SdkError::GatewaySessionRejected("session call result type mismatch".into())
        })
    }
    pub(crate) fn subscribe(
        &self,
        kinds: impl IntoIterator<Item = FrameKind>,
    ) -> SessionSubscription {
        self.shared.hub.read().unwrap_or_else(std::sync::PoisonError::into_inner).subscribe(kinds)
    }
    pub(crate) fn spawn_session_child(
        &self,
        name: &'static str,
        factory: impl Fn(SessionContext) -> ChildFuture + Send + Sync + 'static,
    ) -> Result<(), SdkError> {
        self.children.try_send(Child { name, factory: Arc::new(factory) }).map_err(|_| full())
    }
    pub(crate) fn request_retirement(&self, generation: u64, reason: DisconnectReason) {
        if generation != self.generation() {
            return;
        }
        *self.shared.retirement.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((generation, reason));
        self.shared.retirement_changed.notify_one();
    }
    pub(crate) fn retirement_requested(&self) -> bool {
        self.shared
            .retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|(generation, _)| generation == self.generation())
    }
    fn take_retirement(&self) -> Option<DisconnectReason> {
        self.shared
            .retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .filter(|(generation, _)| *generation == self.generation())
            .map(|(_, reason)| reason)
    }
    pub(crate) fn redrive_receive(&self) {
        self.shared.resync_needed.request();
        self.shared.receive_wake.notify_one();
    }
    pub(crate) fn resync_needed(&self) -> bool {
        self.shared.resync_needed.needed()
    }
    pub(crate) fn resync_epoch(&self) -> u64 {
        self.shared.resync_needed.epoch()
    }
    pub(crate) fn resync_applied(&self, generation: u64, epoch: u64) {
        if self.generation() == generation {
            self.shared.resync_needed.applied(epoch);
            if self.resync_needed() {
                self.shared.receive_wake.notify_one();
            }
        }
    }
    pub(crate) async fn receive_wake(&self) {
        self.shared.receive_wake.notified().await;
    }
    #[cfg(test)]
    pub(crate) fn request_stop(&self, reason: DisconnectReason) {
        *self.shared.stop_reason.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(reason);
        self.stop.send_replace(true);
    }
    pub(crate) async fn stop(&self) {
        self.stop_with_reason(DisconnectReason::Stop).await;
    }
    pub(crate) async fn stop_with_reason(&self, reason: DisconnectReason) {
        *self.shared.stop_reason.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(reason);
        self.stop.send_replace(true);
        let mut finished = self.finished.clone();
        while !*finished.borrow_and_update() {
            if finished.changed().await.is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CallRemoval {
    pub cause: &'static str,
    pub deadline: Instant,
}

struct CancelOnDrop {
    cancel: watch::Sender<bool>,
    changed: Arc<Notify>,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
        self.changed.notify_one();
    }
}
fn full() -> SdkError {
    ramflux_transport::TransportError::BackpressureRejected {
        capacity: CALL_QUEUE as u64,
        in_flight: CALL_QUEUE as u64,
    }
    .into()
}
fn expired() -> SdkError {
    super::command_admission::unavailable("session call deadline expired")
}

fn expire_calls(handle: &ConnectionHandle, queue: &mut VecDeque<Call>) {
    let now = Instant::now();
    let mut survivors = VecDeque::with_capacity(queue.len());
    while let Some(call) = queue.pop_front() {
        if now >= call.deadline {
            handle.record_removal("QueuedCallExpired", call.deadline);
            tracing::trace!(generation = call.generation, "QueuedCallExpired");
            let _ = call.reply.send(Err(expired()));
        } else if *call.cancelled.borrow() || call.reply.is_closed() {
            handle.record_removal("CallerDropped", call.deadline);
        } else {
            survivors.push_back(call);
        }
    }
    *queue = survivors;
}
fn next_deadline(queue: &VecDeque<Call>) -> Option<Instant> {
    queue.iter().map(|call| call.deadline).min()
}
async fn sleep_until_optional(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
struct LiveWaiter<'a>(&'a std::sync::atomic::AtomicUsize);
#[cfg(test)]
impl<'a> LiveWaiter<'a> {
    fn new(count: &'a std::sync::atomic::AtomicUsize) -> Self {
        count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self(count)
    }
}
#[cfg(test)]
impl Drop for LiveWaiter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
#[cfg(test)]
impl ConnectionHandle {
    pub(crate) fn test_live_waiters(&self) -> usize {
        self.shared.live_waiters.load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn test_finished(&self) -> bool {
        *self.finished.borrow()
    }
}
