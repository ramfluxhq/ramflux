// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Command readiness waits parked off the account actor.
//!
//! The actor records the command and returns to its loop. A later install
//! or receive signal, or the command deadline, makes the command ready; the actor then
//! runs it again. The wait itself never holds the serial slot. A parked
//! command is not put back on the bounded mailbox, so it does not consume
//! one of those slots or count as a waiting command.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use tokio::sync::{oneshot, watch};
use tokio::time::Instant;

use super::super::actor::{AccountCommand, ActorResponse};
use crate::SdkError;
use crate::bus::connection_manager::ConnectionHandle;

struct Waiting {
    command: AccountCommand,
    deadline: Instant,
    wake: Wake,
    started: Instant,
    method: String,
}

enum Wake {
    Publication(u64),
    InitialReceive { connection: Box<ConnectionHandle>, generation: u64 },
}

impl Wake {
    fn ready(&self) -> bool {
        match self {
            Self::Publication(generation) => generation_moved(*generation),
            Self::InitialReceive { connection, generation } => {
                !connection.initial_receive_pending(*generation)
            }
        }
    }

    fn phase(&self) -> &'static str {
        match self {
            Self::Publication(_) => "publication_wait",
            Self::InitialReceive { .. } => "initial_receive_wait",
        }
    }
}

thread_local! {
    static WAITING: std::cell::RefCell<VecDeque<Waiting>> =
        const { std::cell::RefCell::new(VecDeque::new()) };
    static FINAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SKIP_NOTE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn is_final() -> bool {
    FINAL.with(std::cell::Cell::get)
}

pub(super) fn set_final(value: bool) {
    FINAL.with(|cell| cell.set(value));
}

pub(super) fn set_skip_note(value: bool) {
    SKIP_NOTE.with(|cell| cell.set(value));
}

pub(super) fn take_skip_note() -> bool {
    SKIP_NOTE.with(|cell| cell.replace(false))
}

pub(super) fn pending() -> bool {
    WAITING.with(|queue| !queue.borrow().is_empty())
}

pub(super) fn park(
    command: AccountCommand,
    reply: oneshot::Sender<Result<ActorResponse, SdkError>>,
    deadline: Instant,
    generation: u64,
) {
    // Keep the generation observed before dispatch, including a settlement before enqueue.
    enqueue(command, reply, deadline, Wake::Publication(generation));
}

pub(super) fn park_receive(
    command: AccountCommand,
    reply: oneshot::Sender<Result<ActorResponse, SdkError>>,
    deadline: Instant,
    connection: Box<ConnectionHandle>,
    generation: u64,
) {
    enqueue(command, reply, deadline, Wake::InitialReceive { connection, generation });
}

fn enqueue(
    mut command: AccountCommand,
    reply: oneshot::Sender<Result<ActorResponse, SdkError>>,
    deadline: Instant,
    wake: Wake,
) {
    command.reply = Some(reply);
    let method = command.request.method.clone();
    tracing::debug!(phase = wake.phase(), event = "park", method = %method,
        elapsed_ms = 0_u64, "account command phase");
    WAITING.with(|queue| {
        queue.borrow_mut().push_back(Waiting {
            command,
            deadline,
            wake,
            started: Instant::now(),
            method,
        });
    });
}

pub(super) fn take_ready() -> Option<AccountCommand> {
    let now = Instant::now();
    WAITING.with(|queue| {
        let mut queue = queue.borrow_mut();
        let index = queue.iter().position(|item| item.wake.ready() || now >= item.deadline)?;
        let item = queue.remove(index)?;
        let elapsed_ms = elapsed_ms(item.started);
        let timed_out = now >= item.deadline;
        tracing::debug!(
            phase = item.wake.phase(),
            event = "resume",
            method = %item.method,
            timed_out,
            elapsed_ms,
            "account command phase"
        );
        set_final(timed_out);
        set_skip_note(true);
        Some(item.command)
    })
}

/// Wakes the actor when a parked command may run again.
pub(super) async fn until_ready() {
    if due() {
        return;
    }
    let deadline = earliest_deadline();
    let mut receive = receive_watch();
    if let Some(changed) = &mut receive {
        let _ = changed.borrow_and_update();
    }
    let generation = crate::custody::pairing::activate::INSTALL_GENERATION.load(Ordering::Acquire);
    let notified = crate::custody::pairing::activate::INSTALL_SETTLED.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    if due() || generation_moved(generation) {
        return;
    }
    tokio::select! {
        biased;
        () = &mut notified => {}
        () = wait_receive(receive) => {}
        () = wait_deadline(deadline) => {}
    }
}

fn receive_watch() -> Option<watch::Receiver<u64>> {
    WAITING.with(|queue| {
        queue.borrow().iter().find_map(|item| match &item.wake {
            Wake::InitialReceive { connection, .. } => Some(connection.snapshot_watch()),
            Wake::Publication(_) => None,
        })
    })
}

async fn wait_receive(changed: Option<watch::Receiver<u64>>) {
    match changed {
        Some(mut changed) => {
            let _ = changed.changed().await;
        }
        None => std::future::pending().await,
    }
}

async fn wait_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn due() -> bool {
    let now = Instant::now();
    WAITING
        .with(|queue| queue.borrow().iter().any(|item| item.wake.ready() || now >= item.deadline))
}

fn earliest_deadline() -> Option<Instant> {
    WAITING.with(|queue| queue.borrow().iter().map(|item| item.deadline).min())
}

fn generation_moved(generation: u64) -> bool {
    crate::custody::pairing::activate::INSTALL_GENERATION.load(Ordering::Acquire) != generation
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
