// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account thread lifecycle, ordered command ownership and unconditional DB teardown.

use super::actor::{AccountCommand, AccountInitializer};
use super::events::EventBatch;
use super::readers::AccountReaders;
use crate::prelude::*;
use std::sync::{Arc, Mutex as RoutingMutex};

type ReaderSlot = Arc<RoutingMutex<Option<AccountReaders>>>;

pub(super) struct Bootstrap {
    pub account_id: String,
    pub config: LocalBusConfig,
    pub nodes: crate::node::NodeStore,
    pub index: AccountIndex,
    pub events: mpsc::Sender<EventBatch>,
    pub initial: Option<AccountInitializer>,
    pub receiver: mpsc::Receiver<AccountCommand>,
    pub readers: ReaderSlot,
    pub shutdown: watch::Receiver<bool>,
    pub ready: std::sync::mpsc::SyncSender<()>,
}

struct AccountRuntime {
    id: String,
    state: LocalBusDaemonState,
    receiver: mpsc::Receiver<AccountCommand>,
    readers: ReaderSlot,
    events: mpsc::Sender<EventBatch>,
    shutdown: watch::Receiver<bool>,
    courier: Option<super::task_courier::TaskCourier>,
    #[cfg(test)]
    courier_events: Option<mpsc::UnboundedSender<tests::CourierEvent>>,
}

pub(super) fn run(bootstrap: Bootstrap) -> Result<(), SdkError> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    LocalSet::new().block_on(&runtime, async move {
        let Bootstrap {
            account_id,
            config,
            nodes,
            index,
            events,
            initial,
            receiver,
            readers,
            shutdown,
            ready,
        } = bootstrap;
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
        let mut account = AccountRuntime {
            id: account_id,
            state,
            receiver,
            readers,
            events,
            shutdown,
            courier: None,
            #[cfg(test)]
            courier_events: None,
        };
        let result = Box::pin(account.serve(ready)).await;
        account.stop_courier().await;
        let request = LocalBusFrame::request(
            "shutdown",
            Some(account.id.clone()),
            "account",
            "account.flush",
            serde_json::json!({}),
        );
        let flushed = account.publish(&request).await;
        account.close_readers().await;
        result.and(flushed)
    })
}

impl AccountRuntime {
    fn start_courier(&mut self) {
        if self.courier.is_none()
            && let Some(account) = self.state.accounts.get_mut(&self.id)
        {
            let courier = super::task_courier::TaskCourier::start();
            account.task_courier_wake = Some(courier.wake_sender());
            self.courier = Some(courier);
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

    async fn apply_courier_outcome(
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
                let requests = if let Some(account) = self.state.accounts.get_mut(&self.id) {
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
                if let Some(account) = self.state.accounts.get_mut(&self.id)
                    && super::task_courier_apply::apply(account, item, preparation).await?
                    && let Some(courier) = &self.courier
                {
                    courier.signal();
                }
            }
            super::task_courier::Outcome::Finished => {}
        }
        Ok(())
    }

    fn initialize_readers(&mut self) -> Result<(), SdkError> {
        let missing = self.readers.lock().map_err(|_| stopped())?.is_none();
        if missing && let Some(account) = self.state.accounts.get_mut(&self.id) {
            account.client.object_store.set_cache_capacity(8);
            super::control_state::trim(account);
            super::read_model::initialize(account)?;
            let db = account.client.account_db()?;
            let path = local_bus_account_manifest_path(&self.state.config.data_root, &self.id);
            let node_id =
                super::sync_status::optional_manifest(&path).and_then(|manifest| manifest.node_id);
            db.persist_actor_state("sync/node-id", &node_id)?;
            let tick = db.journal_bounds()?.head_seq;
            db.append_journal(
                &format!("account:unlocked:{tick}"),
                "account.state",
                &serde_json::json!({"local_account_id":self.id,"state":"unlocked"}),
                now_unix_timestamp(),
                None,
            )?;
            let pool = AccountReaders::start(db, account.client.owned_device_identity().ok())?;
            *self.readers.lock().map_err(|_| stopped())? = Some(pool);
        }
        Ok(())
    }

    async fn close_readers(&self) {
        let pool = self.readers.lock().ok().and_then(|mut readers| readers.take());
        if let Some(pool) = pool {
            pool.stop().await;
        }
    }

    async fn publish(&self, request: &LocalBusFrame) -> Result<(), SdkError> {
        if let Some(account) = self.state.accounts.get(&self.id) {
            if let Some(pool) = self.readers.lock().map_err(|_| stopped())?.as_ref() {
                pool.set_identity(account.client.owned_device_identity().ok())?;
            }
            super::events::publish(&account.client, &self.id, request, &self.events).await?;
        }
        Ok(())
    }

    async fn serve(&mut self, ready: std::sync::mpsc::SyncSender<()>) -> Result<(), SdkError> {
        self.initialize_readers()?;
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
            _ = shutdown.changed() => return Ok(()),
            result = self.publish(&restore) => result?,
        }
        let mut schedule = super::sync_driver::Schedule::new()?;
        let mut next = tokio::time::Instant::now() + schedule.min;
        loop {
            let command = tokio::select! {
                _ = self.shutdown.changed() => break,
                command = self.receiver.recv() => command,
                outcome = async {
                    match self.courier.as_mut() {
                        Some(courier) => courier.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(outcome) = outcome {
                        self.apply_courier_outcome(outcome).await?;
                    } else {
                        tracing::warn!(account_id = %self.id, "task preparation courier stopped; restarting");
                        self.stop_courier().await;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        self.start_courier();
                    }
                    continue;
                },
                () = tokio::time::sleep_until(next), if !self.state.accounts.is_empty() => {
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
            let Some(command) = command else {
                break;
            };
            let sent = matches!(command.request.method.rsplit('.').next(), Some("send" | "submit"))
                || command.request.method == "a2i.append"
                || command.request.method.starts_with("message.receipt.");
            if Box::pin(self.apply(command)).await? {
                break;
            }
            if sent {
                next = tokio::time::Instant::now();
            }
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<bool, SdkError> {
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(false);
        };
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            if let Err(error) = super::own_contact_backfill::drive(account).await {
                tracing::debug!(%error, "own-device contact backfill deferred");
            }
            super::sync_driver::run(account).await
        })
        .await;
        let reason = match &result {
            Ok(Err(error)) => Some(local_bus_error_code(error)),
            Err(_) => Some("SyncTimeout"),
            _ => None,
        };
        let (state, activity) = match result {
            Ok(Ok(count)) => (if count == 0 { "idle" } else { "running" }, count > 0),
            Ok(Err(error)) => {
                tracing::debug!(%error,"account sync failed");
                ("error", false)
            }
            Err(_) => ("error", false),
        };
        super::sync_status::record_with_reason(account, state, now_unix_timestamp(), reason)?;
        let request = LocalBusFrame::request(
            "sync",
            Some(self.id.clone()),
            "sync",
            "sync.run",
            serde_json::json!({}),
        );
        self.publish(&request).await?;
        // Publish message receipt before spending any transfer budget on its deferred objects.
        let fetched = if let Some(account) = self.state.accounts.get_mut(&self.id) {
            super::attachment_scheduler::run_next(account).await?
        } else {
            false
        };
        self.publish(&request).await?;
        Ok(activity || fetched)
    }

    async fn apply(&mut self, mut command: AccountCommand) -> Result<bool, SdkError> {
        if let Some(backup) = command.backup.take() {
            match backup {
                super::actor::BackupCommand::Capture(reply) => {
                    if !reply.is_closed() {
                        let result = (|| {
                            let account = local_bus_account(&self.state, &self.id)?;
                            let reader = account.client.account_db()?.open_backup_reader()?;
                            let manifest =
                                read_local_bus_account_manifest(&local_bus_account_manifest_path(
                                    &self.state.config.data_root,
                                    &self.id,
                                ))?;
                            Ok(super::backup_jobs::CapturedAccount { reader, manifest })
                        })();
                        let _ = reply.send(result);
                    }
                }
            }
            return Ok(false);
        }
        if *self.shutdown.borrow() {
            return Ok(true);
        }
        let mut reply = command.reply.take().ok_or_else(stopped)?;
        if reply.is_closed() {
            return Ok(false);
        }
        let locking = command.request.method == "account.lock";
        let lifecycle = locking || command.request.method == "account.passphrase.rotate";
        if lifecycle {
            self.stop_courier().await;
            self.close_readers().await;
        }
        let mut stopping = false;
        let mut cancelled = false;
        let result = if lifecycle {
            super::mutations::execute(&mut self.state, &self.id, &command).await
        } else {
            tokio::select! {
                biased;
                _ = self.shutdown.changed() => { stopping = true; Err(stopped()) },
                () = reply.closed() => { cancelled = true; Err(stopped()) },
                result = super::mutations::execute(&mut self.state, &self.id, &command) => result,
            }
        };
        if let Some(account) = self.state.accounts.get_mut(&self.id) {
            super::control_state::trim(account);
        }
        if stopping {
            return Ok(true);
        }
        if cancelled {
            if let Err(error) = self.publish(&command.request).await {
                tracing::warn!(account_id = %self.id, %error,
                    "cancelled request publication deferred; account remains open");
            }
            return Ok(false);
        }
        let result = match self.initialize_readers() {
            Ok(()) => result,
            Err(error) => Err(error),
        };
        self.start_courier();
        if let Some(courier) = &self.courier {
            courier.signal();
        }
        let result = match self.publish(&command.request).await {
            Ok(()) => result,
            Err(error) => Err(error),
        };
        let _ = reply.send(result);
        Ok(locking && self.state.accounts.is_empty())
    }
}

fn stopped() -> SdkError {
    SdkError::LocalBus("account runtime stopped".to_owned())
}

#[cfg(test)]
#[path = "tests/task_courier.rs"]
mod tests;
