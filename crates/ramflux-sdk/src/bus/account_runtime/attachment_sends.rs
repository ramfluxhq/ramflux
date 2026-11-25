// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attachment sends parked off the account actor.
//!
//! A `conversation.send` with prepares reaches its upload stage. The upload worker takes an
//! owned copy of what it needs, and the actor records the command here and returns to its
//! loop. The loop serves the worker's journal calls and every other command meanwhile. When
//! the worker finishes, the same command is applied again under the same operation: the
//! slices are already acknowledged, so the resume continues with wrap and delivery and
//! resolves the original waiter. A live twin of a parked operation is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};

use super::super::actor::{AccountCommand, ActorResponse};
use crate::SdkError;
use crate::attachment_send::transfer;
use crate::attachment_send::upload::JournalCall;
use crate::bus::dispatch::attachment_prepare::answer;
use crate::prelude::LocalBusAccountState;

/// Stop error for a drained send: the operation stays Pending and resumes on a same-operation send.
pub(crate) fn shutdown_draining() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}

/// Refusal used only inside the admission path; it never reaches a client because the actor
/// intercepts the parked upload before it replies.
pub(crate) const PARKED: &str = "upload_parked";
/// Parked sends one account may hold. Each holds a worker thread and a journal queue.
pub(crate) const MAX_PARKED: usize = 64;
/// How long a drain waits for parked workers to stop after their uploads are paused.
const DRAIN_DEADLINE: Duration = Duration::from_secs(30);

type Reply = oneshot::Sender<Result<ActorResponse, SdkError>>;

/// The upload worker of the send being admitted, handed from the send path to the actor.
pub(crate) struct ParkedUpload {
    pub(crate) calls: tokio::sync::mpsc::Receiver<JournalCall>,
    pub(crate) worker: JoinHandle<()>,
}

/// Per-account slot the send path writes through `LocalBusAccountState`.
#[derive(Default)]
pub(crate) struct Slot {
    /// True while the first admission of a prepared send may park its upload.
    pub(crate) parking: bool,
    /// Set by the send path when it parks; the actor takes it right after dispatch returns.
    pub(crate) upload: Option<ParkedUpload>,
    /// Set by a download admission; the actor parks it right after dispatch returns.
    pub(crate) import: Option<ParkedImport>,
}

/// A download worker running off the actor. It writes its journal through `calls`; `done`
/// closes when it stops. `stop` is set at shutdown: the journal stays Pending and a same-operation
/// begin resumes from the verified segments.
pub(crate) struct ParkedImport {
    pub(crate) import_id: String,
    pub(crate) calls: tokio::sync::mpsc::Receiver<JournalCall>,
    pub(crate) done: oneshot::Receiver<()>,
    pub(crate) stop: Arc<AtomicBool>,
}

struct Parked {
    command: AccountCommand,
    reply: Reply,
    upload: ParkedUpload,
}

/// What the loop must serve next.
pub(super) enum Event {
    Call(JournalCall),
    Finished(String),
    ImportDone(String),
}

#[derive(Default)]
pub(super) struct AttachmentSends {
    parked: BTreeMap<String, Parked>,
    resumed: BTreeSet<String>,
    imports: BTreeMap<String, ParkedImport>,
}

impl AttachmentSends {
    pub(super) fn contains(&self, operation: &str) -> bool {
        self.parked.contains_key(operation)
    }

    pub(super) fn active(&self) -> bool {
        !self.parked.is_empty() || !self.imports.is_empty()
    }

    /// Records a download worker. Its journal calls are served from the loop until it stops.
    pub(super) fn park_import(&mut self, import: ParkedImport) {
        self.imports.insert(import.import_id.clone(), import);
    }

    /// Forgets a download worker that has stopped.
    pub(super) fn finish_import(&mut self, import_id: &str) {
        self.imports.remove(import_id);
    }

    /// Records a parked send. The caller has checked `contains` and the bound.
    pub(super) fn park(
        &mut self,
        operation: String,
        command: AccountCommand,
        reply: Reply,
        upload: ParkedUpload,
    ) {
        self.parked.insert(operation, Parked { command, reply, upload });
    }

    pub(super) fn full(&self) -> bool {
        self.parked.len() >= MAX_PARKED
    }

    /// Marks the operation so its next admission runs inline instead of parking again.
    pub(super) fn mark_resumed(&mut self, operation: &str) {
        self.resumed.insert(operation.to_owned());
    }

    pub(super) fn take_resumed(&mut self, operation: &str) -> bool {
        self.resumed.remove(operation)
    }

    /// Returns the parked command with its waiter restored, ready to apply again.
    pub(super) fn take(&mut self, operation: &str) -> Option<(AccountCommand, Reply)> {
        let parked = self.parked.remove(operation)?;
        let Parked { mut command, reply, .. } = parked;
        command.reply = None;
        Some((command, reply))
    }

    /// Resolves to the next journal call or finished worker. Pending while nothing is parked.
    pub(super) async fn next(&mut self) -> Event {
        poll_fn(|cx| {
            for (operation, parked) in &mut self.parked {
                if let Poll::Ready(Some(call)) = parked.upload.calls.poll_recv(cx) {
                    return Poll::Ready(Event::Call(call));
                }
                if std::pin::Pin::new(&mut parked.upload.worker).poll(cx).is_ready() {
                    return Poll::Ready(Event::Finished(operation.clone()));
                }
            }
            self.poll_imports(cx)
        })
        .await
    }

    fn poll_imports(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Event> {
        for (import_id, import) in &mut self.imports {
            if let Poll::Ready(Some(call)) = import.calls.poll_recv(cx) {
                return Poll::Ready(Event::Call(call));
            }
            if std::pin::Pin::new(&mut import.done).poll(cx).is_ready() {
                return Poll::Ready(Event::ImportDone(import_id.clone()));
            }
        }
        Poll::Pending
    }

    /// Stops every download worker at shutdown and serves their journal calls until each stops,
    /// within the drain deadline. Imports left behind stay Pending in the journal.
    pub(super) async fn drain_imports(&mut self, account: Option<&LocalBusAccountState>) {
        for import in self.imports.values() {
            import.stop.store(true, Ordering::Release);
        }
        let deadline = Instant::now() + DRAIN_DEADLINE;
        while !self.imports.is_empty() {
            match tokio::time::timeout_at(deadline, poll_fn(|cx| self.poll_imports(cx))).await {
                Ok(Event::Call(call)) => {
                    if let Some(account) = account {
                        answer(account, call);
                    }
                }
                Ok(Event::ImportDone(import_id)) => self.finish_import(&import_id),
                Ok(Event::Finished(_)) | Err(_) => break,
            }
        }
        self.imports.clear();
    }

    /// Pauses the uploads of the named prepares (or of every parked send, when `only` is None),
    /// serves their journal calls until each worker stops, and resolves their waiters with
    /// `stopped`. The operations stay Pending, so a later same-operation send resumes them.
    pub(super) async fn drain(
        &mut self,
        account_id: &str,
        account: Option<&LocalBusAccountState>,
        only: Option<&str>,
        stopped: fn() -> SdkError,
    ) {
        if only.is_none() {
            self.drain_imports(account).await;
        }
        let targets: Vec<String> = self
            .parked
            .iter()
            .filter(|(operation, parked)| {
                only.is_none_or(|prepare| {
                    operation.as_str() == prepare || prepares_of(&parked.command).contains(&prepare)
                })
            })
            .map(|(operation, _)| operation.clone())
            .collect();
        if targets.is_empty() {
            return;
        }
        // A lock or suspend drain is durable: a replay after restart starts paused.
        if only.is_none()
            && let Some(account) = account
        {
            for operation in &targets {
                let _ = super::super::dispatch::conversation_send::record_paused(
                    &account.client,
                    operation,
                    true,
                );
            }
        }
        // A cancel stops its uploads outright: a paused worker waits in `gate`, which only returns
        // once its registry entry is gone, so the entry goes now and the worker ends at once.
        let cancelling = only.is_some();
        if cancelling {
            for operation in &targets {
                if let Some(parked) = self.parked.get(operation) {
                    for prepare in prepares_of(&parked.command) {
                        transfer::forget(account_id, prepare);
                    }
                }
            }
        }
        let deadline = Instant::now() + DRAIN_DEADLINE;
        while targets.iter().any(|operation| self.parked.contains_key(operation)) {
            for operation in &targets {
                if let Some(parked) = self.parked.get(operation).filter(|_| !cancelling) {
                    for prepare in prepares_of(&parked.command) {
                        // A worker not yet in the transfer registry is paused on the next pass.
                        let _ = transfer::set_paused(account_id, prepare, true);
                    }
                }
            }
            match tokio::time::timeout_at(deadline, self.next()).await {
                Ok(Event::Call(call)) => {
                    if let Some(account) = account {
                        answer(account, call);
                    }
                }
                Ok(Event::Finished(operation)) => {
                    if targets.contains(&operation)
                        && let Some(parked) = self.parked.remove(&operation)
                    {
                        let _ = parked.reply.send(Err(stopped()));
                    }
                }
                Ok(Event::ImportDone(import_id)) => self.finish_import(&import_id),
                // Past the deadline the dropped journal queues make each worker's next call
                // fail, so it stops at its next slice boundary.
                Err(_) => break,
            }
        }
        for operation in targets {
            if let Some(parked) = self.parked.remove(&operation) {
                let _ = parked.reply.send(Err(stopped()));
            }
        }
    }
}

fn prepares_of(command: &AccountCommand) -> Vec<&str> {
    command
        .request
        .body
        .get("prepares")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.get("prepare_id").and_then(serde_json::Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}
