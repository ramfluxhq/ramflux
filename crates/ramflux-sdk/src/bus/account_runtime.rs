// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account thread lifecycle, ordered command ownership and unconditional DB teardown.

use super::actor::{AccountCommand, AccountInitializer};
use super::events::EventBatch;
use super::readers::AccountReaders;
use crate::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as RoutingMutex};

mod commands;
mod transient;
pub(super) use transient::TransientHost;
mod agent_calls;
mod connection;
mod pairing_calls;
mod pairing_data;
mod pairing_own_sync;
#[cfg(test)]
pub(crate) use connection::apply_ack_flush;
#[cfg(test)]
pub(crate) use connection::settle_retained;
mod directory;
pub(super) mod fetches;
mod head_demand;
pub(crate) mod head_refresh;
pub(crate) mod lifecycle_fence;
mod readers;
pub(crate) mod session_thread;
pub(super) mod uploads;
pub(super) mod writer_slice;

#[cfg(test)]
type ReceiveGateHook = (tokio::sync::oneshot::Sender<()>, tokio::sync::oneshot::Receiver<()>);

type ReaderSlot = Arc<RoutingMutex<Option<AccountReaders>>>;

/// Depth of the account writer's connection-work queue.
const CONNECTION_WORK_QUEUE: usize = 2;

// Two five-second directory attempts plus local backfill staging.

pub(super) struct Bootstrap {
    pub timeouts: super::runtime_limits::RuntimeTimeouts,
    pub account_id: String,
    pub config: LocalBusConfig,
    pub nodes: crate::node::NodeStore,
    pub index: AccountIndex,
    pub events: mpsc::Sender<EventBatch>,
    pub initial: Option<AccountInitializer>,
    pub receiver: mpsc::Receiver<AccountCommand>,
    pub lifecycle: mpsc::Receiver<AccountCommand>,
    pub preempt: watch::Receiver<u64>,
    pub readers: ReaderSlot,
    pub command_waiting: Arc<AtomicUsize>,
    pub shutdown: watch::Receiver<bool>,
    pub ready: std::sync::mpsc::SyncSender<()>,
}

struct AccountRuntime {
    timeouts: super::runtime_limits::RuntimeTimeouts,
    id: String,
    state: LocalBusDaemonState,
    receiver: mpsc::Receiver<AccountCommand>,
    lifecycle: mpsc::Receiver<AccountCommand>,
    preempt: watch::Receiver<u64>,
    readers: ReaderSlot,
    command_waiting: Arc<AtomicUsize>,
    events: mpsc::Sender<EventBatch>,
    shutdown: watch::Receiver<bool>,
    courier: Option<super::task_courier::TaskCourier>,
    networking_expiry_pending: Option<i64>,
    networking_expiry_warned: bool,
    networking_observation_warned: bool,
    transfers: uploads::Transfers,
    connection_sender: mpsc::Sender<super::connection_manager::AccountWork>,
    connection_work: mpsc::Receiver<super::connection_manager::AccountWork>,
    /// Generic connection work skipped so a demanded head can be applied first.
    deferred: std::collections::VecDeque<super::connection_manager::AccountWork>,
    ledger: Option<super::push_receiver::executor::LedgerExecutor>,
    transient: TransientHost,
    pairing: pairing_calls::Calls,
    #[cfg(test)]
    receive_gate_hook: Option<ReceiveGateHook>,
    #[cfg(test)]
    courier_events: Option<mpsc::UnboundedSender<tests::CourierEvent>>,
}

pub(super) fn run(bootstrap: Bootstrap) -> Result<(), SdkError> {
    #[cfg(test)]
    if let Some(budget) = bootstrap.config.test_retry_budget {
        crate::custody::retry::set_thread_budget(budget);
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    // The session host gets its own thread so database work here cannot freeze its timers.
    let session = session_thread::SessionThread::start()?;
    let result = session.install(|| LocalSet::new().block_on(&runtime, run_async(bootstrap)));
    // `run_async` stopped the connection and awaited its worker before returning.
    drop(session);
    result
}

pub(super) async fn run_async(bootstrap: Bootstrap) -> Result<(), SdkError> {
    let Bootstrap {
        timeouts,
        account_id,
        config,
        nodes,
        index,
        events,
        initial,
        receiver,
        lifecycle,
        preempt,
        readers,
        command_waiting,
        shutdown,
        ready,
    } = bootstrap;
    #[cfg(test)]
    let timeouts = {
        let mut timeouts = timeouts;
        if let Some(budget) = config.test_retry_budget {
            timeouts.retry_budget = budget;
        }
        if config.test_suppress_receive_timers {
            timeouts.receive_min = Duration::from_secs(600);
            timeouts.receive_max = Duration::from_secs(600);
        }
        timeouts
    };
    let initial = initial.map(|initialize| initialize(index.clone())).transpose()?;
    let state = LocalBusDaemonState {
        account_index: Some(index),
        config,
        nodes,
        accounts: initial
            .map(|account| BTreeMap::from([(account_id.clone(), account)]))
            .unwrap_or_default(),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let (connection_sender, connection_work) = mpsc::channel(CONNECTION_WORK_QUEUE);
    let mut account = AccountRuntime {
        timeouts,
        id: account_id,
        state,
        receiver,
        lifecycle,
        preempt,
        readers,
        command_waiting,
        events,
        shutdown,
        courier: None,
        networking_expiry_pending: None,
        networking_expiry_warned: false,
        networking_observation_warned: false,
        transfers: uploads::Transfers::start(),
        connection_sender,
        connection_work,
        deferred: std::collections::VecDeque::new(),
        ledger: None,
        transient: TransientHost::default(),
        pairing: pairing_calls::Calls::default(),
        #[cfg(test)]
        receive_gate_hook: None,
        #[cfg(test)]
        courier_events: None,
    };
    let result = Box::pin(account.serve(ready)).await;
    account.pairing.stop().await;
    account.ledger = None;
    account.transfers.stop().await;
    if let Some(state) = account.state.accounts.get(&account.id) {
        let _ = state.client.recover_received_attachment_fetches();
    }
    account.stop_courier().await;
    account.stop_connection().await;
    let request = LocalBusFrame::request(
        "shutdown",
        Some(account.id.clone()),
        "account",
        "account.flush",
        serde_json::json!({}),
    );
    let flushed = account.publish(&request).await;
    account.close_readers().await;
    let pairing = crate::custody::pairing::remove_actor_and_drain(
        &account.state.config.data_root,
        &account.id,
    )
    .await;
    result.and(flushed).and(pairing)
}

impl AccountRuntime {
    fn networking_expiry_request(&self) -> LocalBusFrame {
        LocalBusFrame::request(
            "networking-expiry",
            Some(self.id.clone()),
            "runtime",
            "account.networking.expired",
            serde_json::json!({"cause":"runtime"}),
        )
    }

    async fn refresh_networking_expiry(&mut self) {
        match self.publish_networking_expiry().await {
            Ok(_) => self.networking_expiry_warned = false,
            Err(error) => {
                if !self.networking_expiry_warned {
                    tracing::warn!(account_id = %self.id,
                        error_code = local_bus_error_code(&error),
                        "networking expiry publication deferred; account remains open");
                    self.networking_expiry_warned = true;
                }
            }
        }
    }

    async fn publish_networking_expiry(&mut self) -> Result<bool, SdkError> {
        if let Some(account) = self.state.accounts.get(&self.id)
            && super::networking_events::refresh_expired(account)?
        {
            self.networking_expiry_pending =
                account.client.account_db()?.pending_actor_state_sequence("account/networking")?;
        }
        if self.networking_expiry_pending.is_none() {
            return Ok(false);
        }
        // Project expiry before another attempt can replace the actor-state snapshot.
        let request = LocalBusFrame::request(
            "sync",
            Some(self.id.clone()),
            "runtime",
            "sync.run",
            serde_json::json!({}),
        );
        self.publish(&request).await?;
        self.networking_expiry_pending = None;
        Ok(true)
    }

    fn start_courier(&mut self) {
        if self.courier.is_none()
            && let Some(account) = self.state.accounts.get(&self.id)
            && super::task_courier_queue::networking_ready(account)
        {
            let courier =
                super::task_courier::TaskCourier::with_limits(self.timeouts.network_wait, 4);
            self.courier = Some(courier);
        }
        if let Some(courier) = &self.courier
            && let Some(account) = self.state.accounts.get_mut(&self.id)
        {
            account.task_courier_wake = Some(courier.wake_sender());
        }
    }

    async fn stop_courier(&mut self) {
        if let Some(courier) = self.courier.take() {
            if let Some(account) = self.state.accounts.get_mut(&self.id) {
                account.task_courier_wake = None;
            }
            courier.stop().await;
        }
    }

    fn apply_courier_outcome(
        &mut self,
        outcome: super::task_courier::Outcome,
    ) -> Result<(), SdkError> {
        #[cfg(test)]
        if let Some(events) = &self.courier_events {
            let _ = events.send(tests::CourierEvent::from_outcome(
                &outcome,
                self.state.accounts.get(&self.id),
            )?);
        }
        match outcome {
            super::task_courier::Outcome::Requested { job_id } => {
                tracing::trace!(job_id, "task courier pass requested");
                let requests = if let Some(account) = self
                    .state
                    .accounts
                    .get_mut(&self.id)
                    .filter(|account| super::task_courier_queue::networking_ready(account))
                {
                    super::dispatch::task_approval::prepare_queue(account);
                    match super::task_courier_queue::manifest_requests(account) {
                        Ok(requests) => requests,
                        Err(error) if super::task_courier_queue::stop_class(&error) => {
                            return Err(error);
                        }
                        Err(_) => Vec::new(),
                    }
                } else {
                    Vec::new()
                };
                if let Some(courier) = &self.courier {
                    courier.prepare(requests);
                }
            }
            super::task_courier::Outcome::Item { item, preparation } => {
                if let Some(handle) = self
                    .state
                    .accounts
                    .get(&self.id)
                    .and_then(|account| account.connection.as_ref())
                {
                    handle.enqueue_task_delivery(item, preparation);
                }
            }
            super::task_courier::Outcome::Finished => {}
        }
        Ok(())
    }

    fn queued_command(&mut self, checkpoints: &mut u8) -> Option<AccountCommand> {
        // A waiting command skips the eight-checkpoint gate. Its residence
        // budget is five seconds; a page can wait.
        let waiting = self.command_waiting.load(Ordering::Acquire) > 0;
        if !waiting {
            if *checkpoints < 8 {
                return None;
            }
            *checkpoints = 0;
        }
        let command = self
            .lifecycle
            .try_recv()
            .inspect(|_| {
                self.preempt.borrow_and_update();
            })
            .or_else(|_| self.receiver.try_recv())
            .ok();
        if command.is_some() {
            self.note_command_taken();
        }
        command
    }

    async fn initialize_actor(
        &mut self,
        ready: std::sync::mpsc::SyncSender<()>,
    ) -> Result<bool, SdkError> {
        self.initialize_readers()?;
        self.start_connection()?;
        self.start_courier();
        let _ = ready.send(());
        let restore = LocalBusFrame::request(
            "restore",
            Some(self.id.clone()),
            "account",
            "account.unlock",
            serde_json::json!({}),
        );
        let mut shutdown = self.shutdown.clone();
        tokio::select! {
            _ = shutdown.changed() => return Ok(false),
            result = self.publish(&restore) => result?,
        }
        Ok(true)
    }

    fn reap_transfer_jobs(&mut self) {
        self.reap_upload_jobs();
        self.reap_fetch_jobs();
    }

    async fn service_courier_outcome(
        &mut self,
        outcome: Option<super::task_courier::Outcome>,
    ) -> Result<(), SdkError> {
        if let Some(outcome) = outcome {
            self.apply_courier_outcome(outcome)?;
        } else {
            tracing::warn!(account_id = %self.id, "task preparation courier stopped; restarting");
            self.stop_courier().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.start_connection()?;
            self.start_courier();
        }
        Ok(())
    }

    fn maintain_expired_object_holds(&self) {
        if let Some(account) = self.state.accounts.get(&self.id)
            && let Err(error) = account
                .client
                .account_db()
                .and_then(|db| db.maintain_expired_object_holds().map_err(SdkError::from))
        {
            tracing::warn!(
                error_code = local_bus_error_code(&error),
                "expired object cleanup deferred; account remains open"
            );
        }
    }

    /// Unlock writes in `initialize_actor` finish before a queued command can pause the writer.
    #[cfg(not(test))]
    fn arm_writer_budget(&self) -> ramflux_storage::writer_budget::Armed {
        ramflux_storage::writer_budget::Armed::arm(
            Arc::clone(&self.command_waiting),
            super::runtime_limits::WRITER_SLICE,
        )
    }

    async fn serve(&mut self, ready: std::sync::mpsc::SyncSender<()>) -> Result<(), SdkError> {
        if !self.initialize_actor(ready).await? {
            return Ok(());
        }
        #[cfg(not(test))]
        let _writer_budget = self.arm_writer_budget();
        let mut schedule = super::sync_driver::Schedule {
            min: self.timeouts.receive_min,
            max: self.timeouts.receive_max,
            interval: self.timeouts.receive_min,
        };
        let mut next = tokio::time::Instant::now() + schedule.min;
        let mut checkpoints = 0_u8;
        loop {
            self.refresh_transient_host().await;
            self.publish_transient_updates();
            let transient_deadline = self.transient_deadline();
            Box::pin(self.refresh_pairing_reader_generation()).await?;
            if let Some(command) = self.queued_command(&mut checkpoints) {
                if Box::pin(self.apply(command)).await? {
                    break;
                }
                continue;
            }
            self.reap_transfer_jobs();
            let pairing =
                crate::custody::pairing::work_signal(&self.state.config.data_root, &self.id);
            let command = tokio::select! {
                biased;
                _ = self.shutdown.changed() => break,
                command = self.lifecycle.recv() => {self.preempt.borrow_and_update();command},
                checkpoint=self.transfers.receive.recv()=>{checkpoints += 1;if let Some(checkpoint)=checkpoint {self.apply_transfer_checkpoint(checkpoint);}continue;},
                work=head_demand::recv(&mut self.deferred,&mut self.connection_work)=>{
                    checkpoints += 1;
                    if let Some(work)=work {
                        let mut shutdown=self.shutdown.clone();let mut preempt=self.preempt.clone();
                        tokio::select! {biased;_=shutdown.changed()=>break,_=preempt.changed()=>{},result=self.apply_connection_work(work)=>result?}
                    }
                    continue;
                },
                frame = self.transient.next(&self.state, &self.id) => {
                    self.apply_transient_frame(frame);
                    continue;
                },
                () = async {
                    match transient_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => { self.publish_transient_updates(); continue; },
                completion = self.pairing.receive() => {
                    if let Some(completion) = completion
                        && self.finish_pairing_begin(completion).await? { break; }
                    continue;
                },
                command = self.receiver.recv() => command,
                () = wait_pairing_signal(pairing) => {
                    Box::pin(self.service_pairing_data()).await;
                    continue;
                },
                outcome = async {
                    match self.courier.as_mut() {
                        Some(courier) => courier.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.service_courier_outcome(outcome).await?;
                    continue;
                },
                () = tokio::time::sleep_until(next), if !self.state.accounts.is_empty() => {
                    self.maintain_expired_object_holds();
                    let mut shutdown = self.shutdown.clone();
                    let active = tokio::select! {
                        _ = shutdown.changed() => break,
                        result = self.sync() => match result {
                            Ok(active) => active,
                            Err(error) => {
                                tracing::warn!(account_id = %self.id, %error,
                                    error_code = local_bus_error_code(&error),
                                    "background synchronization deferred; account remains open");
                                false
                            }
                        },
                    };
                    schedule.completed(active);
                    next = tokio::time::Instant::now() + schedule.interval;
                    continue;
                },
            };
            checkpoints = 0;
            let Some(command) = command else {
                break;
            };
            self.note_command_taken();
            if Box::pin(self.apply(command)).await? {
                break;
            }
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<bool, SdkError> {
        let deadline = tokio::time::Instant::now() + self.timeouts.sync;
        tokio::time::timeout_at(deadline, self.sync_pass())
            .await
            .map_err(|_| SdkError::LocalBus("background sync deadline exceeded".into()))?
    }

    async fn sync_pass(&mut self) -> Result<bool, SdkError> {
        self.refresh_networking_expiry().await;
        self.service_waiting_commands().await?;
        self.maintain_pairing_own_sync().await;
        self.service_waiting_commands().await?;
        self.maintain_agent_record_broadcast();
        self.service_waiting_commands().await?;
        let activity = self.record_local_maintenance().await?;
        // Native admission may have completed on this sync pass after a local-only unlock.
        self.start_courier();
        let request = LocalBusFrame::request(
            "sync",
            Some(self.id.clone()),
            "sync",
            "sync.run",
            serde_json::json!({}),
        );
        self.publish(&request).await?;
        // Publish message receipt before spending any transfer budget on its deferred objects.
        let fetched = self.start_next_fetch()?;
        self.publish(&request).await?;
        Ok(activity || fetched)
    }

    async fn record_local_maintenance(&mut self) -> Result<bool, SdkError> {
        loop {
            ramflux_storage::writer_budget::begin_attempt();
            let activity = {
                let _scope = ramflux_storage::writer_budget::PauseScope::enter();
                let Some(account) = self.state.accounts.get_mut(&self.id) else {
                    return Ok(false);
                };
                let result = super::sync_driver::maintain_local(account);
                let paused = matches!(&result, Err(error) if writer_slice::is_writer_pause(error));
                if paused {
                    None
                } else {
                    let reason = result.as_ref().err().map(local_bus_error_code);
                    let (state, activity) = match result {
                        Ok(count) => (if count == 0 { "idle" } else { "running" }, count > 0),
                        Err(error) => {
                            tracing::debug!(%error, "account local maintenance failed");
                            ("error", false)
                        }
                    };
                    match super::sync_status::record_with_reason(
                        account,
                        state,
                        now_unix_timestamp(),
                        reason,
                    ) {
                        Err(error) if writer_slice::is_writer_pause(&error) => None,
                        Err(error) => return Err(error),
                        Ok(()) => Some(activity),
                    }
                }
            };
            match activity {
                Some(activity) => return Ok(activity),
                None => self.service_waiting_commands().await?,
            }
        }
    }
}

fn stopped() -> SdkError {
    SdkError::LocalBus("account runtime stopped".to_owned())
}

#[cfg(test)]
#[path = "tests/task_courier.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/networking_expiry.rs"]
mod expiry_tests;

#[cfg(feature = "test-support")]
pub mod testing;

#[cfg(feature = "test-support")]
pub mod testing_calls;

#[cfg(feature = "test-support")]
mod testing_authority;

#[cfg(feature = "test-support")]
pub mod testing_messages;
async fn wait_pairing_signal(signal: Option<std::sync::Arc<tokio::sync::Notify>>) {
    match signal {
        Some(signal) => signal.notified().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
#[path = "account_runtime/layer_publish_tests.rs"]
mod layer_publish_tests;
