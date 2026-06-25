// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use std::sync::Arc;
use std::time::Instant;

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
use std::collections::hash_map::DefaultHasher;
#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
use std::hash::{Hash, Hasher};
#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
use std::path::{Path, PathBuf};
#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
use std::sync::{Mutex, MutexGuard, mpsc};

pub(crate) struct TokioRouterRuntime {
    state: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
}

impl TokioRouterRuntime {
    pub(crate) fn new(
        state: Arc<ramflux_node_core::RouterCore>,
        store: Arc<ramflux_node_core::RouterRedbStore>,
    ) -> Self {
        Self { state, store }
    }
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
const ROUTER_TARGET_SHARD_COUNT: usize = 64;

// Frozen runtime path: retained only for regression comparison and historical
// experiments. Owner direction moved hot-path runtime work to compio federation
// forwarding.
#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
pub(crate) struct GlommioRouterRuntime {
    state: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
    workers: Vec<mpsc::Sender<GlommioCommand>>,
    handles: Vec<glommio::ExecutorJoinHandle<()>>,
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
enum GlommioCommand {
    Shutdown,
    Submit {
        envelope: ramflux_protocol::Envelope,
        total_started: Instant,
        reply: mpsc::SyncSender<anyhow::Result<ramflux_node_core::ItestMvp0SubmitResponse>>,
    },
    TargetSubmit {
        accepted: ramflux_node_core::ReplayAcceptedEnvelope,
        total_started: Instant,
        target_dispatch_started: Instant,
        reply: mpsc::SyncSender<anyhow::Result<ramflux_node_core::ItestMvp0SubmitResponse>>,
    },
    BoundAck {
        request: ramflux_node_core::ItestMvp0BoundAckRequest,
        reply: mpsc::SyncSender<anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse>>,
    },
    BoundNack {
        request: ramflux_node_core::ItestMvp0BoundNackRequest,
        reply: mpsc::SyncSender<anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse>>,
    },
    Fanout {
        request: ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
        reply:
            mpsc::SyncSender<anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse>>,
    },
    TargetFanoutDelivery {
        delivery: ramflux_node_core::ReplayAcceptedFanoutDelivery,
        aggregate: Arc<FanoutAggregate>,
    },
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
struct FanoutAggregate {
    remaining: AtomicUsize,
    delivered: Mutex<Vec<ramflux_node_core::ItestMvp10OwnDeviceFanoutDelivery>>,
    reply: Mutex<
        Option<
            mpsc::SyncSender<anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse>>,
        >,
    >,
    principal_id: String,
    source_device_id: String,
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
impl GlommioRouterRuntime {
    pub(crate) fn new(
        state: Arc<ramflux_node_core::RouterCore>,
        store: Arc<ramflux_node_core::RouterRedbStore>,
    ) -> anyhow::Result<Self> {
        let worker_count = glommio_worker_count();
        let core_stores = open_core_stores(store.path(), worker_count)?;
        for core_store in &core_stores {
            if let Some(restored) = core_store.load_router()? {
                state.merge_restored_router(&restored);
            }
        }
        let mut senders = Vec::with_capacity(worker_count);
        let mut receivers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (sender, receiver) = mpsc::channel();
            senders.push(sender);
            receivers.push(receiver);
        }

        let mut handles = Vec::with_capacity(worker_count);
        for (worker_id, receiver) in receivers.into_iter().enumerate() {
            let worker = GlommioWorker {
                worker_id,
                state: Arc::clone(&state),
                core_store: Arc::clone(&core_stores[worker_id]),
                workers: senders.clone(),
            };
            let handle = glommio::LocalExecutorBuilder::new(glommio::Placement::Fixed(worker_id))
                .name(&format!("ramflux-router-glommio-{worker_id}"))
                .spawn(move || async move {
                    worker.run(receiver);
                })
                .map_err(|error| {
                    anyhow::anyhow!("glommio router worker {worker_id} failed to spawn: {error:?}")
                })?;
            handles.push(handle);
        }

        Ok(Self { state, store, workers: senders, handles })
    }

    fn replay_owner_for_envelope(&self, envelope: &ramflux_protocol::Envelope) -> usize {
        replay_owner_for_key(
            &ramflux_node_core::envelope_replay_tuple_key(envelope),
            self.workers.len(),
        )
    }

    fn request(
        &self,
        owner: usize,
        command: impl FnOnce(
            mpsc::SyncSender<anyhow::Result<ramflux_node_core::ItestMvp0SubmitResponse>>,
        ) -> GlommioCommand,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0SubmitResponse> {
        let (reply, response) = mpsc::sync_channel(1);
        self.workers
            .get(owner)
            .ok_or_else(|| anyhow::anyhow!("missing glommio worker {owner}"))?
            .send(command(reply))?;
        response.recv()?
    }

    pub(crate) fn submit_envelope(
        &self,
        envelope: ramflux_protocol::Envelope,
        total_started: Instant,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0SubmitResponse> {
        let owner = self.replay_owner_for_envelope(&envelope);
        self.request(owner, |reply| GlommioCommand::Submit { envelope, total_started, reply })
    }

    pub(crate) fn own_device_fanout(
        &self,
        request: ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
        let owner = replay_owner_for_key(
            &ramflux_node_core::envelope_replay_tuple_key(&request.envelope),
            self.workers.len(),
        );
        let (reply, response) = mpsc::sync_channel(1);
        self.workers
            .get(owner)
            .ok_or_else(|| anyhow::anyhow!("missing glommio worker {owner}"))?
            .send(GlommioCommand::Fanout { request, reply })?;
        response.recv()?
    }

    pub(crate) fn apply_bound_ack(
        &self,
        request: ramflux_node_core::ItestMvp0BoundAckRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse> {
        let actual_target =
            self.state.target_for_envelope_id(&request.ack.envelope_id).ok_or_else(|| {
                ramflux_node_core::NodeCoreError::EnvelopeNotFound(request.ack.envelope_id.clone())
            })?;
        let owner = target_owner_for_target(&actual_target, self.workers.len());
        let (reply, response) = mpsc::sync_channel(1);
        self.workers
            .get(owner)
            .ok_or_else(|| anyhow::anyhow!("missing glommio worker {owner}"))?
            .send(GlommioCommand::BoundAck { request, reply })?;
        response.recv()?
    }

    pub(crate) fn apply_bound_nack(
        &self,
        request: ramflux_node_core::ItestMvp0BoundNackRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse> {
        let actual_target =
            self.state.target_for_envelope_id(&request.nack.envelope_id).ok_or_else(|| {
                ramflux_node_core::NodeCoreError::EnvelopeNotFound(request.nack.envelope_id.clone())
            })?;
        let owner = target_owner_for_target(&actual_target, self.workers.len());
        let (reply, response) = mpsc::sync_channel(1);
        self.workers
            .get(owner)
            .ok_or_else(|| anyhow::anyhow!("missing glommio worker {owner}"))?
            .send(GlommioCommand::BoundNack { request, reply })?;
        response.recv()?
    }
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
impl Drop for GlommioRouterRuntime {
    fn drop(&mut self) {
        for worker in &self.workers {
            let _ = worker.send(GlommioCommand::Shutdown);
        }
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
struct GlommioWorker {
    worker_id: usize,
    state: Arc<ramflux_node_core::RouterCore>,
    core_store: Arc<ramflux_node_core::RouterRedbStore>,
    workers: Vec<mpsc::Sender<GlommioCommand>>,
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
impl GlommioWorker {
    fn run(self, receiver: mpsc::Receiver<GlommioCommand>) {
        while let Ok(command) = receiver.recv() {
            match command {
                GlommioCommand::Shutdown => break,
                GlommioCommand::Submit { envelope, total_started, reply } => {
                    self.handle_submit(envelope, total_started, reply);
                }
                GlommioCommand::TargetSubmit {
                    accepted,
                    total_started,
                    target_dispatch_started,
                    reply,
                } => {
                    let result = self.finish_target_submit(accepted, total_started);
                    ramflux_node_core::record_router_submit_target_remote_us(
                        crate::router_engine::elapsed_us(target_dispatch_started),
                    );
                    let _ = reply.send(result);
                }
                GlommioCommand::BoundAck { request, reply } => {
                    let result = self.finish_bound_ack(&request);
                    let _ = reply.send(result);
                }
                GlommioCommand::BoundNack { request, reply } => {
                    let result = self.finish_bound_nack(&request);
                    let _ = reply.send(result);
                }
                GlommioCommand::Fanout { request, reply } => {
                    self.handle_fanout(request, reply);
                }
                GlommioCommand::TargetFanoutDelivery { delivery, aggregate } => {
                    self.finish_fanout_delivery(delivery, aggregate);
                }
            }
        }
    }

    fn handle_submit(
        &self,
        envelope: ramflux_protocol::Envelope,
        total_started: Instant,
        reply: mpsc::SyncSender<anyhow::Result<ramflux_node_core::ItestMvp0SubmitResponse>>,
    ) {
        tracing::info!(
            envelope_id = %envelope.envelope_id,
            target_delivery_id = %envelope.target_delivery_id,
            source_device_id = %envelope.source_device_id,
            "router decoded mvp0 envelope"
        );
        let replay_key = ramflux_node_core::envelope_replay_tuple_key(&envelope);
        let replay_expires_at = match envelope
            .created_at
            .checked_add(i64::from(envelope.ttl))
            .ok_or_else(|| anyhow::anyhow!("envelope ttl overflows replay expiry"))
        {
            Ok(value) => value,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let target_delivery_id = envelope.target_delivery_id.clone();
        let target_owner = target_owner_for_target(&target_delivery_id, self.workers.len());

        ramflux_node_core::record_router_submit_lock_wait_us(0);
        let dispatch_started = Instant::now();
        let outcome = match self.state.accept_envelope_replay(
            envelope,
            i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX),
        ) {
            Ok(accepted) => {
                if let Err(error) =
                    self.core_store.record_replay_tuple(&replay_key, replay_expires_at)
                {
                    let _ = reply.send(Err(anyhow::anyhow!("{error}")));
                    return;
                }
                self.dispatch_target_submit(target_owner, accepted, total_started, reply);
                return;
            }
            Err(error) => ramflux_node_core::RouterSubmitOutcome::RejectedSecurity {
                target_delivery_id,
                reason: error.to_string(),
            },
        };
        ramflux_node_core::record_router_submit_dispatch_us(crate::router_engine::elapsed_us(
            dispatch_started,
        ));

        let save_started = Instant::now();
        ramflux_node_core::record_router_submit_save_us(crate::router_engine::elapsed_us(
            save_started,
        ));

        let response_started = Instant::now();
        let response =
            crate::router_engine::submit_response_from_outcome(self.state.as_ref(), outcome);
        tracing::info!(
            target_delivery_id = %response.target_delivery_id,
            outcome = %response.outcome,
            inbox_seq = ?response.inbox_seq,
            "router mvp0 envelope outcome"
        );
        ramflux_node_core::record_router_submit_response_us(crate::router_engine::elapsed_us(
            response_started,
        ));
        ramflux_node_core::record_router_submit_total_us(crate::router_engine::elapsed_us(
            total_started,
        ));
        let _ = reply.send(Ok(response));
    }

    fn dispatch_target_submit(
        &self,
        owner: usize,
        accepted: ramflux_node_core::ReplayAcceptedEnvelope,
        total_started: Instant,
        reply: mpsc::SyncSender<anyhow::Result<ramflux_node_core::ItestMvp0SubmitResponse>>,
    ) {
        if owner == self.worker_id {
            let target_dispatch_started = Instant::now();
            let result = self.finish_target_submit(accepted, total_started);
            ramflux_node_core::record_router_submit_target_local_us(
                crate::router_engine::elapsed_us(target_dispatch_started),
            );
            let _ = reply.send(result);
            return;
        }
        let target_dispatch_started = Instant::now();
        if let Err(error) = self
            .workers
            .get(owner)
            .ok_or_else(|| anyhow::anyhow!("missing glommio worker {owner}"))
            .and_then(|worker| {
                worker
                    .send(GlommioCommand::TargetSubmit {
                        accepted,
                        total_started,
                        target_dispatch_started,
                        reply: reply.clone(),
                    })
                    .map_err(Into::into)
            })
        {
            let _ = reply.send(Err(error));
        }
    }

    fn finish_target_submit(
        &self,
        accepted: ramflux_node_core::ReplayAcceptedEnvelope,
        total_started: Instant,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0SubmitResponse> {
        let outcome = self.state.submit_replay_accepted_envelope(accepted);
        ramflux_node_core::record_router_submit_dispatch_us(crate::router_engine::elapsed_us(
            total_started,
        ));
        let save_started = Instant::now();
        let persistent_entry = crate::router_engine::persistent_entry_from_outcome(&outcome);
        if let Some(entry) = persistent_entry.as_ref() {
            self.core_store.record_inbox_entry(entry)?;
        }
        ramflux_node_core::record_router_submit_save_us(crate::router_engine::elapsed_us(
            save_started,
        ));
        let response_started = Instant::now();
        let response =
            crate::router_engine::submit_response_from_outcome(self.state.as_ref(), outcome);
        tracing::info!(
            target_delivery_id = %response.target_delivery_id,
            outcome = %response.outcome,
            inbox_seq = ?response.inbox_seq,
            "router mvp0 envelope outcome"
        );
        ramflux_node_core::record_router_submit_response_us(crate::router_engine::elapsed_us(
            response_started,
        ));
        ramflux_node_core::record_router_submit_total_us(crate::router_engine::elapsed_us(
            total_started,
        ));
        Ok(response)
    }

    fn finish_bound_ack(
        &self,
        request: &ramflux_node_core::ItestMvp0BoundAckRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse> {
        let cursor = self.state.apply_ack_for_target(&request.target_delivery_id, &request.ack)?;
        self.core_store.record_ack_increment(&cursor, &request.ack.envelope_id)?;
        Ok(ramflux_node_core::ItestMvp0CursorResponse::from(&cursor))
    }

    fn finish_bound_nack(
        &self,
        request: &ramflux_node_core::ItestMvp0BoundNackRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse> {
        let cursor =
            self.state.apply_nack_for_target(&request.target_delivery_id, &request.nack)?;
        self.core_store.record_nack_increment(&cursor)?;
        Ok(ramflux_node_core::ItestMvp0CursorResponse::from(&cursor))
    }

    fn handle_fanout(
        &self,
        request: ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
        reply: mpsc::SyncSender<
            anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse>,
        >,
    ) {
        let replay_key = ramflux_node_core::envelope_replay_tuple_key(&request.envelope);
        let replay_expires_at = request
            .envelope
            .created_at
            .checked_add(i64::from(request.envelope.ttl))
            .ok_or_else(|| anyhow::anyhow!("fan-out envelope ttl overflows replay expiry"));
        let replay_expires_at = match replay_expires_at {
            Ok(value) => value,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let plan = match self.state.accept_own_device_fanout_replay(request) {
            Ok(plan) => plan,
            Err(error) => {
                let _ = reply.send(Err(anyhow::anyhow!("{error}")));
                return;
            }
        };
        if let Err(error) = self.core_store.record_replay_tuple(&replay_key, replay_expires_at) {
            let _ = reply.send(Err(anyhow::anyhow!("{error}")));
            return;
        }
        if plan.deliveries.is_empty() {
            let _ = reply.send(Ok(ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse {
                principal_id: plan.principal_id,
                source_device_id: plan.source_device_id,
                delivered: Vec::new(),
            }));
            return;
        }
        let aggregate = Arc::new(FanoutAggregate {
            remaining: AtomicUsize::new(plan.deliveries.len()),
            delivered: Mutex::new(Vec::with_capacity(plan.deliveries.len())),
            reply: Mutex::new(Some(reply)),
            principal_id: plan.principal_id,
            source_device_id: plan.source_device_id,
        });
        for delivery in plan.deliveries {
            let owner = target_owner_for_target(&delivery.target_delivery_id, self.workers.len());
            self.dispatch_fanout_delivery(owner, delivery, Arc::clone(&aggregate));
        }
    }

    fn dispatch_fanout_delivery(
        &self,
        owner: usize,
        delivery: ramflux_node_core::ReplayAcceptedFanoutDelivery,
        aggregate: Arc<FanoutAggregate>,
    ) {
        if owner == self.worker_id {
            self.finish_fanout_delivery(delivery, aggregate);
            return;
        }
        if let Err(error) = self
            .workers
            .get(owner)
            .ok_or_else(|| anyhow::anyhow!("missing glommio worker {owner}"))
            .and_then(|worker| {
                worker
                    .send(GlommioCommand::TargetFanoutDelivery {
                        delivery,
                        aggregate: aggregate.clone(),
                    })
                    .map_err(Into::into)
            })
        {
            aggregate.finish_with_error(error);
        }
    }

    fn finish_fanout_delivery(
        &self,
        delivery: ramflux_node_core::ReplayAcceptedFanoutDelivery,
        aggregate: Arc<FanoutAggregate>,
    ) {
        let (fanout_delivery, entry) = self.state.submit_replay_accepted_fanout_delivery(delivery);
        if let Some(entry) = entry {
            if let Err(error) = self.core_store.record_inbox_entry(&entry) {
                aggregate.finish_with_error(anyhow::anyhow!("{error}"));
                return;
            }
        }
        lock_unpoisoned(&aggregate.delivered).push(fanout_delivery);
        aggregate.finish_one();
    }
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
impl FanoutAggregate {
    fn finish_one(&self) {
        if self.remaining.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let result = self.build_response();
        if let Some(reply) = lock_unpoisoned(&self.reply).take() {
            let _ = reply.send(result);
        }
    }

    fn finish_with_error(&self, error: anyhow::Error) {
        if let Some(reply) = lock_unpoisoned(&self.reply).take() {
            let _ = reply.send(Err(error));
        }
    }

    fn build_response(
        &self,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
        let mut delivered = lock_unpoisoned(&self.delivered).clone();
        delivered.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        Ok(ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse {
            principal_id: self.principal_id.clone(),
            source_device_id: self.source_device_id.clone(),
            delivered,
        })
    }
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn glommio_worker_count() -> usize {
    std::env::var("RAMFLUX_ROUTER_GLOMMIO_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(usize::from).unwrap_or(1))
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn replay_owner_for_key(key: &str, worker_count: usize) -> usize {
    hash_to_bucket(key, worker_count)
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn target_owner_for_target(target_delivery_id: &str, worker_count: usize) -> usize {
    hash_to_bucket(target_delivery_id, ROUTER_TARGET_SHARD_COUNT) % worker_count
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn hash_to_bucket(value: &str, bucket_count: usize) -> usize {
    debug_assert!(bucket_count > 0);
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % bucket_count
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn open_core_stores(
    base_path: &Path,
    worker_count: usize,
) -> anyhow::Result<Vec<Arc<ramflux_node_core::RouterRedbStore>>> {
    let parent = base_path.parent().unwrap_or_else(|| Path::new("."));
    let core_dir = router_core_redb_dir(parent, base_path);
    let stores = (0..worker_count)
        .map(|core_id| {
            let path = router_core_redb_path(&core_dir, core_id);
            ramflux_node_core::RouterRedbStore::open(&path).map(Arc::new).map_err(|error| {
                anyhow::anyhow!(
                    "failed to open glommio router core store {}: {error}",
                    path.display()
                )
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(stores)
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn router_core_redb_dir(parent: &Path, base_path: &Path) -> PathBuf {
    let stem = base_path.file_stem().and_then(|stem| stem.to_str()).unwrap_or("router");
    parent.join(format!("{stem}-cores"))
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn router_core_redb_path(core_dir: &Path, core_id: usize) -> PathBuf {
    core_dir.join(format!("router-core-{core_id}.redb"))
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) enum RouterHandle {
    Tokio(Arc<TokioRouterRuntime>),
    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    Glommio(Arc<GlommioRouterRuntime>),
}

impl RouterHandle {
    pub(crate) fn tokio(
        state: Arc<ramflux_node_core::RouterCore>,
        store: Arc<ramflux_node_core::RouterRedbStore>,
    ) -> Self {
        Self::Tokio(Arc::new(TokioRouterRuntime::new(state, store)))
    }

    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    pub(crate) fn glommio(
        state: Arc<ramflux_node_core::RouterCore>,
        store: Arc<ramflux_node_core::RouterRedbStore>,
    ) -> anyhow::Result<Self> {
        Ok(Self::Glommio(Arc::new(GlommioRouterRuntime::new(state, store)?)))
    }

    pub(crate) fn state(&self) -> &ramflux_node_core::RouterCore {
        match self {
            Self::Tokio(runtime) => runtime.state.as_ref(),
            #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
            Self::Glommio(runtime) => runtime.state.as_ref(),
        }
    }

    pub(crate) fn store(&self) -> &ramflux_node_core::RouterRedbStore {
        match self {
            Self::Tokio(runtime) => runtime.store.as_ref(),
            #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
            Self::Glommio(runtime) => runtime.store.as_ref(),
        }
    }

    pub(crate) fn submit_envelope(
        &self,
        envelope: ramflux_protocol::Envelope,
        total_started: Instant,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0SubmitResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::submit_envelope(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                envelope,
                total_started,
            ),
            #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
            Self::Glommio(runtime) => runtime.submit_envelope(envelope, total_started),
        }
    }

    #[cfg(feature = "itest-http")]
    pub(crate) fn apply_ack(
        &self,
        ack: &ramflux_protocol::Ack,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse> {
        match self {
            Self::Tokio(runtime) => {
                crate::router_engine::apply_ack(runtime.state.as_ref(), runtime.store.as_ref(), ack)
            }
            #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
            Self::Glommio(runtime) => {
                crate::router_engine::apply_ack(runtime.state.as_ref(), runtime.store.as_ref(), ack)
            }
        }
    }

    pub(crate) fn apply_bound_ack(
        &self,
        request: &ramflux_node_core::ItestMvp0BoundAckRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::apply_bound_ack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                request,
            ),
            #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
            Self::Glommio(runtime) => runtime.apply_bound_ack(request.clone()),
        }
    }

    #[cfg(feature = "itest-http")]
    pub(crate) fn apply_nack(
        &self,
        nack: &ramflux_protocol::Nack,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::apply_nack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                nack,
            ),
            #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
            Self::Glommio(runtime) => crate::router_engine::apply_nack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                nack,
            ),
        }
    }

    pub(crate) fn apply_bound_nack(
        &self,
        request: &ramflux_node_core::ItestMvp0BoundNackRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp0CursorResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::apply_bound_nack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                request,
            ),
            #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
            Self::Glommio(runtime) => runtime.apply_bound_nack(request.clone()),
        }
    }

    pub(crate) fn own_device_fanout(
        &self,
        request: &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::own_device_fanout(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                request,
            ),
            #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
            Self::Glommio(runtime) => runtime.own_device_fanout(request.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use ramflux_protocol::{DeliveryClass, Ext, Priority, SignatureAlg, SignedFields};

    use super::*;

    #[test]
    fn tokio_handle_matches_submit_and_replay_oracle() -> anyhow::Result<()> {
        let envelope = current_envelope("env_runtime_submit", "target_runtime_submit");
        let (oracle_state, oracle_store, _oracle_path) = test_router("submit_oracle")?;
        let oracle = crate::router_engine::submit_envelope(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            envelope.clone(),
            Instant::now(),
        )?;

        let (handle, _handle_path) = test_handle("submit_handle")?;
        let via_handle = handle.submit_envelope(envelope.clone(), Instant::now())?;
        assert_eq!(via_handle, oracle);

        let replay = handle.submit_envelope(envelope, Instant::now())?;
        assert!(replay.outcome.starts_with("rejected_security:"));
        assert!(replay.outcome.contains("replay:"));
        Ok(())
    }

    #[test]
    fn tokio_handle_matches_bound_ack_and_nack_oracle() -> anyhow::Result<()> {
        let envelope = current_envelope("env_runtime_ack", "target_runtime_ack");

        let (oracle_state, oracle_store, _oracle_path) = test_router("ack_oracle")?;
        let _submitted = crate::router_engine::submit_envelope(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            envelope.clone(),
            Instant::now(),
        )?;
        let ack = ack("env_runtime_ack");
        let ack_request = ramflux_node_core::ItestMvp0BoundAckRequest {
            target_delivery_id: "target_runtime_ack".to_owned(),
            ack: ack.clone(),
        };
        let oracle_ack = crate::router_engine::apply_bound_ack(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &ack_request,
        )?;

        let (handle, _handle_path) = test_handle("ack_handle")?;
        let _submitted = handle.submit_envelope(envelope, Instant::now())?;
        let handle_ack = handle.apply_bound_ack(&ack_request)?;
        assert_eq!(handle_ack, oracle_ack);

        let nack = nack("env_runtime_ack");
        let nack_request = ramflux_node_core::ItestMvp0BoundNackRequest {
            target_delivery_id: "target_runtime_ack".to_owned(),
            nack,
        };
        let oracle_nack_response = crate::router_engine::apply_bound_nack(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &nack_request,
        )?;
        let handle_nack_response = handle.apply_bound_nack(&nack_request)?;
        assert_eq!(handle_nack_response, oracle_nack_response);
        Ok(())
    }

    #[test]
    fn tokio_handle_matches_fanout_oracle() -> anyhow::Result<()> {
        let request = fanout_request("env_runtime_fanout");

        let (oracle_state, oracle_store, _oracle_path) = test_router("fanout_oracle")?;
        register_test_device(oracle_state.as_ref(), "alice", "alice_phone", "target_phone", 1)?;
        register_test_device(oracle_state.as_ref(), "alice", "alice_laptop", "target_laptop", 2)?;
        let oracle = crate::router_engine::own_device_fanout(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &request,
        )?;

        let (handle, _handle_path) = test_handle("fanout_handle")?;
        register_test_device(handle.state(), "alice", "alice_phone", "target_phone", 1)?;
        register_test_device(handle.state(), "alice", "alice_laptop", "target_laptop", 2)?;
        let via_handle = handle.own_device_fanout(&request)?;

        assert_eq!(via_handle, oracle);
        assert_eq!(via_handle.delivered.len(), 1);
        assert_eq!(via_handle.delivered[0].device_id, "alice_laptop");
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    #[test]
    fn glommio_handle_matches_submit_and_replay_oracle() -> anyhow::Result<()> {
        let envelope = current_envelope("env_glommio_runtime_submit", "target_glommio_submit");
        let (oracle_state, oracle_store, _oracle_path) = test_router("glommio_submit_oracle")?;
        let oracle = crate::router_engine::submit_envelope(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            envelope.clone(),
            Instant::now(),
        )?;

        let (handle, _handle_path) = test_glommio_handle("glommio_submit_handle")?;
        let via_handle = handle.submit_envelope(envelope.clone(), Instant::now())?;
        assert_eq!(via_handle, oracle);

        let replay = handle.submit_envelope(envelope, Instant::now())?;
        assert!(replay.outcome.starts_with("rejected_security:"));
        assert!(replay.outcome.contains("replay:"));
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    #[test]
    fn glommio_handle_matches_fanout_oracle() -> anyhow::Result<()> {
        let request = fanout_request("env_glommio_runtime_fanout");

        let (oracle_state, oracle_store, _oracle_path) = test_router("glommio_fanout_oracle")?;
        register_test_device(oracle_state.as_ref(), "alice", "alice_phone", "target_phone", 1)?;
        register_test_device(oracle_state.as_ref(), "alice", "alice_laptop", "target_laptop", 2)?;
        let oracle = crate::router_engine::own_device_fanout(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &request,
        )?;

        let (handle, _handle_path) = test_glommio_handle("glommio_fanout_handle")?;
        register_test_device(handle.state(), "alice", "alice_phone", "target_phone", 1)?;
        register_test_device(handle.state(), "alice", "alice_laptop", "target_laptop", 2)?;
        let via_handle = handle.own_device_fanout(&request)?;

        assert_eq!(via_handle, oracle);
        assert_eq!(via_handle.delivered.len(), 1);
        assert_eq!(via_handle.delivered[0].device_id, "alice_laptop");
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    #[test]
    fn glommio_handle_restores_per_core_replay_inbox_and_cursor() -> anyhow::Result<()> {
        let path = temp_store_path("glommio_restart")?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        let handle = RouterHandle::glommio(Arc::clone(&state), Arc::clone(&store))?;
        let acked = current_envelope("env_glommio_restart_acked", "target_glommio_restart");
        let pending = current_envelope("env_glommio_restart_pending", "target_glommio_restart");
        let _submitted = handle.submit_envelope(acked.clone(), Instant::now())?;
        let _submitted = handle.submit_envelope(pending.clone(), Instant::now())?;
        let ack_request = ramflux_node_core::ItestMvp0BoundAckRequest {
            target_delivery_id: "target_glommio_restart".to_owned(),
            ack: ack("env_glommio_restart_acked"),
        };
        let _cursor = handle.apply_bound_ack(&ack_request)?;
        drop(handle);
        drop(state);
        drop(store);

        let restored_store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let restored_state = Arc::new(ramflux_node_core::RouterCore::new());
        let restored = RouterHandle::glommio(Arc::clone(&restored_state), restored_store)?;
        let replay = restored.submit_envelope(acked, Instant::now())?;
        assert!(replay.outcome.starts_with("rejected_security:"));
        assert!(replay.outcome.contains("replay:"));
        assert_eq!(
            restored
                .state()
                .cursor_state("target_glommio_restart")
                .and_then(|cursor| cursor.last_envelope_id),
            Some("env_glommio_restart_acked".to_owned())
        );
        let pending_entries = restored.state().resume("target_glommio_restart", 0, 10);
        assert_eq!(pending_entries.len(), 1);
        assert_eq!(pending_entries[0].envelope.envelope_id, "env_glommio_restart_pending");
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    #[test]
    fn glommio_bound_ack_routes_by_index_and_rejects_cross_target() -> anyhow::Result<()> {
        let (handle, _handle_path) = test_glommio_handle("glommio_cross_target_ack")?;
        let envelope = current_envelope("env_glommio_cross_target_ack", "target_glommio_b");
        let _submitted = handle.submit_envelope(envelope, Instant::now())?;

        let bad_ack = ramflux_node_core::ItestMvp0BoundAckRequest {
            target_delivery_id: "target_glommio_a".to_owned(),
            ack: ack("env_glommio_cross_target_ack"),
        };
        let error =
            handle.apply_bound_ack(&bad_ack).expect_err("cross-target bound ack must be rejected");
        assert!(matches!(
            error.downcast_ref::<ramflux_node_core::NodeCoreError>(),
            Some(ramflux_node_core::NodeCoreError::EnvelopeTargetMismatch { .. })
        ));

        let good_ack = ramflux_node_core::ItestMvp0BoundAckRequest {
            target_delivery_id: "target_glommio_b".to_owned(),
            ack: ack("env_glommio_cross_target_ack"),
        };
        let cursor = handle.apply_bound_ack(&good_ack)?;
        assert_eq!(cursor.target_delivery_id, "target_glommio_b");
        assert!(cursor.acked_envelope_ids.contains(&"env_glommio_cross_target_ack".to_owned()));
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    #[test]
    fn glommio_bound_nack_after_ack_is_idempotent() -> anyhow::Result<()> {
        let (handle, _handle_path) = test_glommio_handle("glommio_nack_after_ack")?;
        let envelope = current_envelope("env_glommio_nack_after_ack", "target_glommio_nack");
        let _submitted = handle.submit_envelope(envelope, Instant::now())?;

        let ack_request = ramflux_node_core::ItestMvp0BoundAckRequest {
            target_delivery_id: "target_glommio_nack".to_owned(),
            ack: ack("env_glommio_nack_after_ack"),
        };
        let _acked = handle.apply_bound_ack(&ack_request)?;

        let nack_request = ramflux_node_core::ItestMvp0BoundNackRequest {
            target_delivery_id: "target_glommio_nack".to_owned(),
            nack: nack("env_glommio_nack_after_ack"),
        };
        let cursor = handle.apply_bound_nack(&nack_request)?;
        assert_eq!(cursor.target_delivery_id, "target_glommio_nack");
        assert!(cursor.acked_envelope_ids.contains(&"env_glommio_nack_after_ack".to_owned()));
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    #[test]
    fn glommio_bound_ack_uses_restored_pending_index_after_reconnect() -> anyhow::Result<()> {
        let path = temp_store_path("glommio_ack_reconnect")?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        let handle = RouterHandle::glommio(Arc::clone(&state), Arc::clone(&store))?;
        let envelope = current_envelope("env_glommio_ack_reconnect", "target_glommio_reconnect");
        let _submitted = handle.submit_envelope(envelope, Instant::now())?;
        drop(handle);
        drop(state);
        drop(store);

        let restored_store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let restored_state = Arc::new(ramflux_node_core::RouterCore::new());
        let restored = RouterHandle::glommio(restored_state, restored_store)?;
        let ack_request = ramflux_node_core::ItestMvp0BoundAckRequest {
            target_delivery_id: "target_glommio_reconnect".to_owned(),
            ack: ack("env_glommio_ack_reconnect"),
        };
        let cursor = restored.apply_bound_ack(&ack_request)?;
        assert_eq!(cursor.target_delivery_id, "target_glommio_reconnect");
        assert!(cursor.acked_envelope_ids.contains(&"env_glommio_ack_reconnect".to_owned()));
        assert!(restored.state().resume("target_glommio_reconnect", 0, 10).is_empty());
        Ok(())
    }

    fn test_handle(name: &str) -> anyhow::Result<(RouterHandle, PathBuf)> {
        let (state, store, path) = test_router(name)?;
        Ok((RouterHandle::tokio(state, store), path))
    }

    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    fn test_glommio_handle(name: &str) -> anyhow::Result<(RouterHandle, PathBuf)> {
        let (state, store, path) = test_router(name)?;
        Ok((RouterHandle::glommio(state, store)?, path))
    }

    fn test_router(
        name: &str,
    ) -> anyhow::Result<(
        Arc<ramflux_node_core::RouterCore>,
        Arc<ramflux_node_core::RouterRedbStore>,
        PathBuf,
    )> {
        let path = temp_store_path(name)?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        Ok((state, store, path))
    }

    fn current_envelope(envelope_id: &str, target_delivery_id: &str) -> ramflux_protocol::Envelope {
        let mut envelope = envelope(envelope_id, target_delivery_id, DeliveryClass::OpaqueEvent);
        envelope.created_at =
            i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX - 3_600);
        envelope
    }

    fn fanout_request(envelope_id: &str) -> ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
        ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
            principal_id: "alice".to_owned(),
            source_device_id: "alice_phone".to_owned(),
            envelope: current_envelope(envelope_id, "target_unused"),
        }
    }

    fn envelope(
        envelope_id: &str,
        target_delivery_id: &str,
        delivery_class: DeliveryClass,
    ) -> ramflux_protocol::Envelope {
        ramflux_protocol::Envelope {
            schema: "ramflux.envelope.v1".to_owned(),
            version: 1,
            domain: "ramflux.envelope.v1".to_owned(),
            ext: Ext::default(),
            signed: signed_fields(),
            envelope_id: envelope_id.to_owned(),
            source_principal_id: "alice".to_owned(),
            source_device_id: "alice_device".to_owned(),
            target_delivery_id: target_delivery_id.to_owned(),
            routing_set_id: None,
            delivery_class,
            priority: Priority::Normal,
            ttl: 3_600,
            created_at: 1_760_000_000,
            encrypted_payload: "ciphertext".to_owned(),
            payload_hash: "payload_hash".to_owned(),
        }
    }

    fn ack(envelope_id: &str) -> ramflux_protocol::Ack {
        ramflux_protocol::Ack {
            schema: "ramflux.ack.v1".to_owned(),
            version: 1,
            domain: "ramflux.ack.v1".to_owned(),
            ext: Ext::default(),
            signed: signed_fields(),
            ack_id: format!("ack_{envelope_id}"),
            envelope_id: envelope_id.to_owned(),
            receiver_device_id: "device_a".to_owned(),
            received_at: 1_760_000_010,
            cursor_after: None,
        }
    }

    fn nack(envelope_id: &str) -> ramflux_protocol::Nack {
        ramflux_protocol::Nack {
            schema: "ramflux.nack.v1".to_owned(),
            version: 1,
            domain: "ramflux.nack.v1".to_owned(),
            ext: Ext::default(),
            signed: signed_fields(),
            nack_id: format!("nack_{envelope_id}"),
            envelope_id: envelope_id.to_owned(),
            receiver_device_id: "device_a".to_owned(),
            reason: ramflux_protocol::NackReason::MissingDependency,
            received_at: 1_760_000_010,
            retry_after: Some(30),
        }
    }

    fn signed_fields() -> SignedFields {
        SignedFields {
            signing_key_id: "test_key".to_owned(),
            signature_alg: SignatureAlg::Ed25519,
            signature: "test_signature".to_owned(),
        }
    }

    fn register_test_device(
        state: &ramflux_node_core::RouterCore,
        principal_id: &str,
        device_id: &str,
        target_delivery_id: &str,
        nonce: u64,
    ) -> anyhow::Result<()> {
        let root_seed = seed_from_nonce(0x31, nonce);
        let device_seed = seed_from_nonce(0x41, nonce);
        let root = ramflux_crypto::create_identity_root(principal_id, root_seed);
        let device = ramflux_crypto::create_device_branch(principal_id, device_id, 1, device_seed);
        let proof = ramflux_crypto::authorize_device_branch(
            &root,
            &device,
            ramflux_node_core::ITEST_MVP1_AUDIENCE,
            vec![ramflux_node_core::ITEST_MVP1_BIND_CAPABILITY.to_owned()],
            1_760_000_000 + i64::try_from(nonce)?,
            1_760_003_600 + i64::try_from(nonce)?,
        )?;
        let root_public_key =
            ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
        let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
        let request = ramflux_node_core::ItestMvp1RegisterIdentityRequest {
            principal_commitment: ramflux_crypto::blake3_256_base64url(
                "ramflux.identity.root_public_key.commitment.v1",
                &root_public_key_bytes,
            ),
            root_public_key,
            branch_public_key: ramflux_protocol::encode_base64url(
                device.signing_key.verifying_key().to_bytes(),
            ),
            proof,
            target_delivery_id: target_delivery_id.to_owned(),
            gateway_id: "ramflux-gateway".to_owned(),
            session_id: format!("session_{device_id}"),
            push_alias_hash: Some(format!("push_{device_id}")),
            now: 1_760_000_010 + i64::try_from(nonce)?,
            registration_pow: None,
            source_ip_hash: Some("source_ip_hash".to_owned()),
        };
        state.mvp1_register_identity(&request)?;
        Ok(())
    }

    fn seed_from_nonce(prefix: u8, nonce: u64) -> [u8; 32] {
        let mut seed = [prefix; 32];
        seed[24..].copy_from_slice(&nonce.to_be_bytes());
        seed
    }

    fn temp_store_path(test_name: &str) -> anyhow::Result<PathBuf> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(std::env::temp_dir().join(format!(
            "ramflux-router-{test_name}-{}-{}.redb",
            std::process::id(),
            elapsed.as_nanos()
        )))
    }
}
