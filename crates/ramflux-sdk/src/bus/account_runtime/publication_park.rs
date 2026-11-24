// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publication waits parked off the account actor.
//!
//! The actor records the command and returns to its loop. A later install
//! signal or the command deadline makes the command ready; the actor then
//! runs it again. The wait itself never holds the serial slot. A parked
//! command is not put back on the bounded mailbox, so it does not consume
//! one of those slots or count as a waiting command.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use tokio::sync::oneshot;
use tokio::time::Instant;

use super::super::actor::{AccountCommand, ActorResponse};
use crate::SdkError;

struct Waiting {
    command: AccountCommand,
    deadline: Instant,
    generation: u64,
    started: Instant,
    method: String,
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
    mut command: AccountCommand,
    reply: oneshot::Sender<Result<ActorResponse, SdkError>>,
    deadline: Instant,
) {
    command.reply = Some(reply);
    let method = command.request.method.clone();
    let generation = crate::custody::pairing::activate::INSTALL_GENERATION.load(Ordering::Acquire);
    tracing::debug!(
        phase = "publication_wait",
        event = "park",
        method = %method,
        elapsed_ms = 0_u64,
        "account command phase"
    );
    WAITING.with(|queue| {
        queue.borrow_mut().push_back(Waiting {
            command,
            deadline,
            generation,
            started: Instant::now(),
            method,
        });
    });
}

pub(super) fn take_ready() -> Option<AccountCommand> {
    let now = Instant::now();
    let generation = crate::custody::pairing::activate::INSTALL_GENERATION.load(Ordering::Acquire);
    WAITING.with(|queue| {
        let mut queue = queue.borrow_mut();
        let index =
            queue.iter().position(|item| item.generation != generation || now >= item.deadline)?;
        let item = queue.remove(index)?;
        let elapsed_ms = elapsed_ms(item.started);
        let timed_out = now >= item.deadline;
        tracing::debug!(
            phase = "publication_wait",
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
    let generation = crate::custody::pairing::activate::INSTALL_GENERATION.load(Ordering::Acquire);
    let notified = crate::custody::pairing::activate::INSTALL_SETTLED.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    if due() || generation_moved(generation) {
        return;
    }
    match deadline {
        Some(deadline) => {
            tokio::select! {
                biased;
                () = &mut notified => {}
                () = tokio::time::sleep_until(deadline) => {}
            }
        }
        None => notified.await,
    }
}

fn due() -> bool {
    let now = Instant::now();
    let generation = crate::custody::pairing::activate::INSTALL_GENERATION.load(Ordering::Acquire);
    WAITING.with(|queue| {
        queue.borrow().iter().any(|item| item.generation != generation || now >= item.deadline)
    })
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
