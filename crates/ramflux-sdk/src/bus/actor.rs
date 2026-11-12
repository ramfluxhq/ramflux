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

pub(super) enum PrivateCommand {
    #[cfg(test)]
    #[cfg_attr(
        not(feature = "itest-local-mint"),
        expect(dead_code, reason = "Used by local-mint transfer fixtures")
    )]
    TransferCheckpoint {
        checkpoint: Box<super::account_runtime::uploads::Checkpoint>,
        applied: oneshot::Sender<()>,
    },
    #[cfg(test)]
    HoldLocalMutation {
        entered: oneshot::Sender<tokio::time::Instant>,
        release: oneshot::Receiver<()>,
    },
    #[cfg(test)]
    ReleasePreSendHold {
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
    NativeUnlock {
        passphrase: zeroize::Zeroizing<String>,
        home_node_id: Option<String>,
        reply: oneshot::Sender<Result<crate::LocalBusCreatedAccount, SdkError>>,
    },
    Capture(oneshot::Sender<Result<super::backup_jobs::CapturedAccount, SdkError>>),
    AuthorizeBackup {
        generation: i64,
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
}
pub(super) struct AccountCommand {
    pub admission: Option<Arc<super::command_admission::CommandAdmission>>,
    pub private: Option<PrivateCommand>,
    pub request: LocalBusFrame,
    pub connection_id: u64,
    pub topics: BTreeSet<String>,
    pub attended: bool,
    pub nodes: Option<crate::node::NodeStore>,
    pub outbound: mpsc::Sender<LocalBusFrame>,
    pub reply: Option<oneshot::Sender<Result<ActorResponse, SdkError>>>,
}

#[derive(Clone)]
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
    timeouts: super::runtime_limits::RuntimeTimeouts,
    sender: mpsc::Sender<AccountCommand>,
    lifecycle: mpsc::Sender<AccountCommand>,
    preempt: watch::Sender<u64>,
    shutdown_signal: watch::Sender<bool>,
    done: watch::Receiver<ActorExit>,
    readers: Arc<RoutingMutex<Option<AccountReaders>>>,
    #[cfg(test)]
    expired_replies: Option<Arc<super::command_admission::ExpiredReplies>>,
    #[cfg(test)]
    backup_captures: Arc<std::sync::atomic::AtomicUsize>,
}

pub(super) struct ActorOptions {
    pub initial: Option<AccountInitializer>,
    pub timeouts: super::runtime_limits::RuntimeTimeouts,
}

struct ActorLaunch {
    actor: AccountActor,
    bootstrap: super::account_runtime::Bootstrap,
    initialized: std::sync::mpsc::Receiver<()>,
    finished: watch::Sender<ActorExit>,
    wait_for_initial: bool,
}

impl AccountActor {
    #[cfg(test)]
    pub(super) fn connection_for_test(
        &self,
    ) -> Option<super::connection_manager::ConnectionHandle> {
        self.readers.lock().ok()?.as_ref()?.connection_for_test()
    }
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
        let launch = Self::prepare(
            account_id,
            config,
            nodes,
            index,
            events,
            ActorOptions {
                initial,
                timeouts: super::runtime_limits::RuntimeTimeouts::configured()?,
            },
        );
        let ActorLaunch { actor, bootstrap, initialized, finished, wait_for_initial } = launch;
        std::thread::Builder::new().name("ramflux-account".to_owned()).spawn(move || {
            let result = super::account_runtime::run(bootstrap);
            if let Err(error) = &result {
                tracing::warn!(%error, "account actor stopped");
            }
            let _ = finished.send(ActorExit::Complete(result.map_err(|error| error.to_string())));
        })?;
        if wait_for_initial {
            initialized.recv().map_err(|_| stopped())?;
        }
        Ok(actor)
    }

    fn prepare(
        account_id: String,
        config: LocalBusConfig,
        nodes: crate::node::NodeStore,
        index: AccountIndex,
        events: mpsc::Sender<EventBatch>,
        setup: ActorOptions,
    ) -> ActorLaunch {
        let ActorOptions { initial, timeouts } = setup;
        let wait_for_initial = initial.is_some();
        let (ready, initialized) = std::sync::mpsc::sync_channel(1);
        let (sender, receiver) = mpsc::channel(64);
        let (lifecycle, lifecycle_receiver) = mpsc::channel(super::runtime_limits::LIFECYCLE_QUEUE);
        let (preempt, preempt_receiver) = watch::channel(0);
        let (lifetime, shutdown) = watch::channel(false);
        let (finished, done) = watch::channel(ActorExit::Running);
        let readers = Arc::new(RoutingMutex::new(None));
        let bootstrap = super::account_runtime::Bootstrap {
            timeouts: timeouts.clone(),
            account_id,
            config,
            nodes,
            index,
            events,
            initial,
            receiver,
            lifecycle: lifecycle_receiver,
            preempt: preempt_receiver,
            readers: Arc::clone(&readers),
            shutdown,
            ready,
        };
        let actor = Self {
            timeouts,
            sender,
            lifecycle,
            preempt,
            readers,
            shutdown_signal: lifetime,
            done,
            #[cfg(test)]
            expired_replies: None,
            #[cfg(test)]
            backup_captures: Arc::default(),
        };
        ActorLaunch { actor, bootstrap, initialized, finished, wait_for_initial }
    }

    #[cfg(test)]
    pub(super) async fn start_local(
        account_id: String,
        config: LocalBusConfig,
        nodes: crate::node::NodeStore,
        index: AccountIndex,
        events: mpsc::Sender<EventBatch>,
        setup: ActorOptions,
    ) -> Result<Self, SdkError> {
        // The same actor loop runs on the test's LocalSet so paused time has one clock.
        let ActorLaunch { actor, bootstrap, initialized, finished, .. } =
            Self::prepare(account_id, config, nodes, index, events, setup);
        tokio::task::spawn_local(async move {
            let result = super::account_runtime::run_async(bootstrap).await;
            let _ = finished.send(ActorExit::Complete(result.map_err(|error| error.to_string())));
        });
        loop {
            match initialized.try_recv() {
                Ok(()) => return Ok(actor),
                Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    actor.stop().await?;
                    return Err(stopped());
                }
            }
        }
    }

    pub(super) async fn unlock_native(
        &self,
        passphrase: zeroize::Zeroizing<String>,
        home_node_id: Option<String>,
    ) -> Result<crate::LocalBusCreatedAccount, SdkError> {
        let (reply, response) = oneshot::channel();
        self.send_private(PrivateCommand::NativeUnlock { passphrase, home_node_id, reply })?;
        response.await.map_err(|_| stopped())?
    }

    /// Releases a pre-send hold on the actor so it never shares the account connection across
    /// threads (the connection tracks one transaction at a time and is not a cross-thread lock).
    #[cfg(test)]
    pub(super) async fn release_pre_send_hold(&self) -> Result<(), SdkError> {
        let (reply, response) = oneshot::channel();
        self.send_private(PrivateCommand::ReleasePreSendHold { reply })?;
        response.await.map_err(|_| stopped())?
    }

    pub(super) async fn capture_backup(
        &self,
    ) -> Result<super::backup_jobs::CapturedAccount, SdkError> {
        #[cfg(test)]
        self.backup_captures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (backup, received) = oneshot::channel();
        self.send_private(PrivateCommand::Capture(backup))?;
        let mut captured = received.await.map_err(|_| stopped())??;
        captured.actor = Some(self.clone());
        Ok(captured)
    }

    pub(super) fn authorize_backup_publication(&self, generation: i64) -> Result<(), SdkError> {
        let (reply, response) = oneshot::channel();
        let (outbound, _events) = mpsc::channel(1);
        self.sender
            .try_send(AccountCommand {
                admission: None,
                private: Some(PrivateCommand::AuthorizeBackup { generation, reply }),
                request: LocalBusFrame::request(
                    "backup-publication",
                    None,
                    "account",
                    "account.backup.authorize",
                    serde_json::json!({}),
                ),
                connection_id: 0,
                topics: BTreeSet::new(),
                attended: false,
                nodes: None,
                outbound,
                reply: None,
            })
            .map_err(|_| stopped())?;
        response.blocking_recv().map_err(|_| stopped())?
    }
    pub(super) async fn backup_missing_references(
        &self,
    ) -> Result<super::backup_jobs::MissingAttachments, SdkError> {
        self.reader_pool()?.backup_missing_references().await
    }
    fn send_private(&self, backup: PrivateCommand) -> Result<(), SdkError> {
        let (outbound, _events) = mpsc::channel(1);
        let lifecycle = matches!(backup, PrivateCommand::NativeUnlock { .. });
        self.enqueue(
            AccountCommand {
                admission: None,
                private: Some(backup),
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
            },
            lifecycle,
        )
    }

    #[cfg(test)]
    pub(super) fn backup_capture_count(&self) -> usize {
        self.backup_captures.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    #[cfg_attr(
        not(feature = "itest-local-mint"),
        expect(dead_code, reason = "Used by local-mint transfer fixtures")
    )]
    pub(super) async fn inject_transfer_checkpoint(
        &self,
        checkpoint: super::account_runtime::uploads::Checkpoint,
    ) -> Result<(), SdkError> {
        let (applied, completed) = oneshot::channel();
        self.send_private(PrivateCommand::TransferCheckpoint {
            checkpoint: Box::new(checkpoint),
            applied,
        })?;
        completed.await.map_err(|_| stopped())
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
        let method = super::method_table::classify(&command.request.method);
        let lifecycle = method
            .is_some_and(|method| method.route == super::method_table::MethodRoute::Lifecycle);
        let needs_network =
            !super::generated_typing::is_request(&command.request.method, &command.request.body)
                && self.reader_pool().map_or_else(
                    |_| {
                        method.is_some_and(|method| {
                            method.class == super::method_table::MethodClass::NeedsNetwork
                        })
                    },
                    |pool| pool.requires_network(&command.request),
                );
        let admission = super::command_admission::CommandAdmission::new(
            tokio::time::Instant::now(),
            &self.timeouts,
        );
        #[cfg(test)]
        let admission = {
            let mut admission = admission;
            admission.expired_replies.clone_from(&self.expired_replies);
            admission
        };
        let admission = Arc::new(admission);
        let command = AccountCommand {
            reply: Some(sender),
            admission: Some(Arc::clone(&admission)),
            ..command
        };
        self.enqueue(command, lifecycle)?;
        admission
            .response(receiver, needs_network, || {
                self.reader_pool()
                    .map_or(SdkError::NetworkingPending, |pool| pool.networking_pending())
            })
            .await
    }

    fn enqueue(&self, command: AccountCommand, lifecycle: bool) -> Result<(), SdkError> {
        if lifecycle {
            let permit = self.lifecycle.try_reserve().map_err(|_| {
                super::command_admission::unavailable("account lifecycle queue full")
            })?;
            self.preempt.send_modify(|version| *version = version.wrapping_add(1));
            permit.send(command);
            Ok(())
        } else {
            self.sender
                .try_send(command)
                .map_err(|_| super::command_admission::unavailable("account command queue full"))
        }
    }
}

fn stopped() -> SdkError {
    SdkError::LocalBus("account actor stopped".to_owned())
}

#[cfg(test)]
#[path = "runtime_tests/surface_restore.rs"]
mod surface_restore_tests;

#[cfg(test)]
#[path = "runtime_tests/admission.rs"]
mod admission_tests;

#[cfg(test)]
#[path = "runtime_tests/queue_deadlines.rs"]
mod queue_deadline_tests;

#[cfg(test)]
#[path = "runtime_tests/keyed_admission.rs"]
mod keyed_admission_tests;
