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
use std::task::Poll;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::super::actor::{AccountCommand, ActorResponse};
use crate::SdkError;
use crate::attachment_send::upload::JournalCall;

/// Refusal used only inside the admission path; it never reaches a client because the actor
/// intercepts the parked upload before it replies.
pub(crate) const PARKED: &str = "upload_parked";
/// Parked sends one account may hold. Each holds a worker thread and a journal queue.
pub(crate) const MAX_PARKED: usize = 64;

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
}

#[derive(Default)]
pub(super) struct AttachmentSends {
    parked: BTreeMap<String, Parked>,
    resumed: BTreeSet<String>,
}

impl AttachmentSends {
    pub(super) fn contains(&self, operation: &str) -> bool {
        self.parked.contains_key(operation)
    }

    pub(super) fn active(&self) -> bool {
        !self.parked.is_empty()
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
                if let Poll::Ready(_) = std::pin::Pin::new(&mut parked.upload.worker).poll(cx) {
                    return Poll::Ready(Event::Finished(operation.clone()));
                }
            }
            Poll::Pending
        })
        .await
    }
}
