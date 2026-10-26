// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One ordered mutation mailbox and independent readers per unlocked account.

use super::events::EventBatch;
use super::readers::{AccountReaders, is_reader_request};
use crate::prelude::*;
use std::sync::{Arc, Mutex as RoutingMutex};
use tokio::sync::oneshot;

pub(super) type AccountInitializer =
    Box<dyn FnOnce(AccountIndex) -> Result<LocalBusAccountState, SdkError> + Send>;

pub(super) enum BackupCommand {
    Capture(oneshot::Sender<Result<super::backup_jobs::CapturedAccount, SdkError>>),
    Missing {
        after: String,
        reply: oneshot::Sender<Result<super::backup_jobs::MissingAttachmentPage, SdkError>>,
    },
}
pub(super) struct AccountCommand {
    pub backup: Option<BackupCommand>,
    pub request: LocalBusFrame,
    pub connection_id: u64,
    pub topics: BTreeSet<String>,
    pub attended: bool,
    pub nodes: Option<crate::node::NodeStore>,
    pub outbound: mpsc::Sender<LocalBusFrame>,
    pub reply: Option<oneshot::Sender<Result<ActorResponse, SdkError>>>,
}

pub(super) struct ActorResponse {
    pub body: serde_json::Value,
    pub events: Vec<LocalBusFrame>,
    pub nodes: Option<crate::node::NodeStore>,
}

#[derive(Clone)]
enum ActorExit {
    Running,
    Complete(Result<(), String>),
}

#[derive(Clone)]
pub(super) struct AccountActor {
    sender: mpsc::Sender<AccountCommand>,
    shutdown_signal: watch::Sender<bool>,
    done: watch::Receiver<ActorExit>,
    readers: Arc<RoutingMutex<Option<AccountReaders>>>,
    #[cfg(test)]
    backup_captures: Arc<std::sync::atomic::AtomicUsize>,
}

impl AccountActor {
    pub(super) fn start(
        account_id: String,
        config: LocalBusConfig,
        nodes: crate::node::NodeStore,
        index: AccountIndex,
        events: mpsc::Sender<EventBatch>,
    ) -> Result<Self, SdkError> {
        Self::start_loaded(account_id, config, nodes, index, events, None)
    }

    pub(super) fn start_loaded(
        account_id: String,
        config: LocalBusConfig,
        nodes: crate::node::NodeStore,
        index: AccountIndex,
        events: mpsc::Sender<EventBatch>,
        initial: Option<AccountInitializer>,
    ) -> Result<Self, SdkError> {
        let wait_for_initial = initial.is_some();
        let (ready, initialized) = std::sync::mpsc::sync_channel(1);
        let (sender, receiver) = mpsc::channel(64);
        let (lifetime, shutdown) = watch::channel(false);
        let (finished, done) = watch::channel(ActorExit::Running);
        let readers = Arc::new(RoutingMutex::new(None));
        let reader_slot = Arc::clone(&readers);
        std::thread::Builder::new().name("ramflux-account".to_owned()).spawn(move || {
            let result = super::account_runtime::run(super::account_runtime::Bootstrap {
                account_id,
                config,
                nodes,
                index,
                events,
                initial,
                receiver,
                readers: reader_slot,
                shutdown,
                ready,
            });
            if let Err(error) = &result {
                tracing::warn!(%error, "account actor stopped");
            }
            let _ = finished.send(ActorExit::Complete(result.map_err(|error| error.to_string())));
        })?;
        if wait_for_initial {
            initialized.recv().map_err(|_| stopped())?;
        }
        Ok(Self {
            sender,
            readers,
            shutdown_signal: lifetime,
            done,
            #[cfg(test)]
            backup_captures: Arc::default(),
        })
    }

    pub(super) async fn capture_backup(
        &self,
    ) -> Result<super::backup_jobs::CapturedAccount, SdkError> {
        #[cfg(test)]
        self.backup_captures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (backup, received) = oneshot::channel();
        self.send_backup(BackupCommand::Capture(backup)).await?;
        received.await.map_err(|_| stopped())?
    }
    pub(super) async fn backup_missing_page(
        &self,
        after: String,
    ) -> Result<super::backup_jobs::MissingAttachmentPage, SdkError> {
        let (reply, received) = oneshot::channel();
        self.send_backup(BackupCommand::Missing { after, reply }).await?;
        received.await.map_err(|_| stopped())?
    }
    async fn send_backup(&self, backup: BackupCommand) -> Result<(), SdkError> {
        let (outbound, _events) = mpsc::channel(1);
        self.sender
            .send(AccountCommand {
                backup: Some(backup),
                request: LocalBusFrame::request(
                    "backup-query",
                    None,
                    "account",
                    "account.backup.capture",
                    serde_json::json!({}),
                ),
                connection_id: 0,
                topics: BTreeSet::new(),
                attended: false,
                nodes: None,
                outbound,
                reply: None,
            })
            .await
            .map_err(|_| stopped())
    }

    #[cfg(test)]
    pub(super) fn backup_capture_count(&self) -> usize {
        self.backup_captures.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub(super) fn reader_pool(&self) -> Result<AccountReaders, SdkError> {
        self.readers.lock().map_err(|_| stopped())?.clone().ok_or_else(stopped)
    }

    pub(super) fn is_open(&self) -> bool {
        self.readers.lock().is_ok_and(|readers| readers.is_some())
    }

    #[cfg(test)]
    pub(super) fn has_stopped(&self) -> bool {
        matches!(*self.done.borrow(), ActorExit::Complete(_))
    }

    pub(super) async fn stop(&self) -> Result<(), SdkError> {
        let _ = self.shutdown_signal.send(true);
        let mut done = self.done.clone();
        loop {
            let status = done.borrow().clone();
            match status {
                ActorExit::Running => {
                    done.changed().await.map_err(|_| stopped())?;
                }
                ActorExit::Complete(result) => return result.map_err(SdkError::LocalBus),
            }
        }
    }

    pub(super) async fn request(&self, command: AccountCommand) -> Result<ActorResponse, SdkError> {
        let readers = if is_reader_request(&command.request.method) {
            self.readers.lock().map_err(|_| stopped())?.clone()
        } else {
            None
        };
        if let Some(readers) = readers {
            return Ok(ActorResponse {
                body: readers.request(command.request).await?,
                events: Vec::new(),
                nodes: None,
            });
        }
        let (sender, receiver) = oneshot::channel();
        let command = AccountCommand { reply: Some(sender), ..command };
        self.sender.send(command).await.map_err(|_| stopped())?;
        receiver.await.map_err(|_| stopped())?
    }
}

fn stopped() -> SdkError {
    SdkError::LocalBus("account actor stopped".to_owned())
}

#[cfg(test)]
#[path = "runtime_tests/surface_restore.rs"]
mod surface_restore_tests;
