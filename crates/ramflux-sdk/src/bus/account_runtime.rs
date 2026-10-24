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
        let mut account =
            AccountRuntime { id: account_id, state, receiver, readers, events, shutdown };
        let result = Box::pin(account.serve(ready)).await;
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
                () = tokio::time::sleep_until(next), if !self.state.accounts.is_empty() => {
                    let mut shutdown = self.shutdown.clone();
                    let active = tokio::select! {
                        _ = shutdown.changed() => break,
                        result = self.sync() => result?,
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
            self.publish(&command.request).await?;
            return Ok(false);
        }
        let result = match self.initialize_readers() {
            Ok(()) => result,
            Err(error) => Err(error),
        };
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
