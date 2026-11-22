// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Priority-first uncorrelated RPC ownership, independent queued expiry, and session retirement.

use super::{
    Call, Child, ConnectionHandle, DisconnectReason, RuntimeTimeouts, expire_calls, expired,
    next_deadline, sleep_until_optional,
};
use crate::GatewaySessionEngine;
use std::collections::VecDeque;
use tokio::{
    sync::{mpsc, watch},
    time::{Instant, timeout_at},
};

tokio::task_local! { static PRIORITY_EXCHANGE: bool; }
pub(crate) fn priority_exchange_active() -> bool {
    PRIORITY_EXCHANGE.try_with(|priority| *priority).unwrap_or(false)
}

pub(super) enum HostExit {
    Stop,
    Retired(DisconnectReason),
}

pub(super) struct HostIo<'a> {
    pub calls: &'a mut mpsc::Receiver<Call>,
    pub registrations: &'a mut mpsc::Receiver<Child>,
    pub children: &'a mut super::worker::Children,
    pub stopping: &'a mut watch::Receiver<bool>,
}

pub(super) async fn run(
    handle: &ConnectionHandle,
    engine: &mut GatewaySessionEngine,
    io: HostIo<'_>,
    timeouts: &RuntimeTimeouts,
) -> HostExit {
    let HostIo { calls, registrations, children, stopping } = io;
    let mut queue = VecDeque::new();
    loop {
        if let Some(reason) = handle.take_retirement() {
            return HostExit::Retired(reason);
        }
        while let Ok(call) = calls.try_recv() {
            queue.push_back(call);
        }
        expire_calls(handle, &mut queue);
        let next = queue
            .iter()
            .position(|call| call.class == super::CallClass::Priority)
            .or_else(|| (!queue.is_empty()).then_some(0));
        if let Some(call) = next.and_then(|index| queue.remove(index)) {
            if call.generation != handle.generation() {
                let _ = call.reply.send(Err(handle.pending()));
                continue;
            }
            let reason = exchange(
                call,
                handle,
                engine,
                ExchangeIo { incoming: calls, queue: &mut queue, stopping },
                timeouts,
            )
            .await;
            if let Some(reason) = reason {
                for call in queue {
                    let _ = call.reply.send(Err(handle.pending()));
                }
                return HostExit::Retired(reason);
            }
            if handle.resync_needed() {
                handle.shared.receive_wake.notify_one();
            }
            continue;
        }
        tokio::select! {
            biased;
            _ = stopping.changed()=>return HostExit::Stop,
            ()=handle.shared.call_changed.notified()=>{},
            ()=handle.shared.retirement_changed.notified()=>{},
            call=calls.recv()=>{
                let Some(call)=call else {return HostExit::Stop;};
                queue.push_back(call);
            }
            child=registrations.recv()=>{
                if let Some(child)=child {children.register(child,handle,engine.session()).await;}
            }
            result=engine.idle_read()=>{
                if let Err(error)=result {
                    tracing::debug!(%error,"resident gateway read ended");
                    return HostExit::Retired(engine.terminal_reason.unwrap_or(DisconnectReason::Transport));
                }
                super::worker::publish_metadata(handle,engine);
                if handle.resync_needed() {handle.shared.receive_wake.notify_one();}
            }
        }
    }
}

struct ExchangeIo<'a> {
    incoming: &'a mut mpsc::Receiver<Call>,
    queue: &'a mut VecDeque<Call>,
    stopping: &'a mut watch::Receiver<bool>,
}

/// Runs one exchange. Which outcomes retire the resident session:
///
/// - Stop, Lock, Restart, a transport/protocol terminal reason, or an exchange that is still
///   unanswered at its session budget (`CallTimeout`) retire it. A Bulk exchange's session
///   budget is its own deadline, so the keepalive heartbeat (Bulk, 10 s) still retires a dead
///   session exactly as before.
/// - A Priority exchange (delivery receipts, pair-material fetches, call submits) is
///   best effort for its caller: at its own shorter budget, or when its caller goes away, only
///   the caller fails. The host keeps reading that exchange's reply up to the session call
///   budget, so the uncorrelated reply stream is never reused while a reply is still owed, and
///   the session retires only if that reply never comes.
async fn exchange(
    call: Call,
    handle: &ConnectionHandle,
    engine: &mut GatewaySessionEngine,
    io: ExchangeIo<'_>,
    timeouts: &RuntimeTimeouts,
) -> Option<DisconnectReason> {
    let ExchangeIo { incoming, queue, stopping } = io;
    if *call.cancelled.borrow() || call.reply.is_closed() {
        return None;
    }
    if call.deadline <= Instant::now() {
        let _ = call.reply.send(Err(expired()));
        return None;
    }
    drop(call.place);
    let before = engine.wire_writes;
    let started = Instant::now();
    let caller_at = call.deadline.min(started + call.exchange_timeout.unwrap_or(timeouts.call));
    let best_effort = call.class == super::CallClass::Priority;
    let session_at = if best_effort { caller_at.max(started + timeouts.call) } else { caller_at };
    let generation = call.generation;
    let mut cancelled = call.cancelled;
    let mut reply = Some(call.reply);
    let operation = (call.operation)(engine);
    let mut result = Err(expired());
    let mut interrupted = None;
    {
        let operation = PRIORITY_EXCHANGE.scope(best_effort, timeout_at(session_at, operation));
        tokio::pin!(operation);
        loop {
            expire_calls(handle, queue);
            let queued_deadline = next_deadline(queue);
            let waiting = reply.is_some();
            let caller_budget =
                (best_effort && waiting && caller_at < session_at).then_some(caller_at);
            tokio::select! {
                biased;
                _=stopping.changed()=>{
                    interrupted=Some(handle.shared.stop_reason.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .unwrap_or(DisconnectReason::Stop));
                    result=Err(handle.pending());break;
                }
                ()=handle.shared.retirement_changed.notified()=>{if let Some(reason)=handle.take_retirement() {interrupted=Some(reason);result=Err(handle.pending());break;}}
                _=cancelled.changed(), if waiting=>{
                    if best_effort { reply=None; } else { interrupted=Some(DisconnectReason::CallerCancelled);break; }
                }
                ()=caller_closed(&mut reply), if waiting=>{
                    if best_effort { reply=None; } else { interrupted=Some(DisconnectReason::CallerCancelled);break; }
                }
                ()=sleep_until_optional(caller_budget)=>{
                    tracing::debug!("best-effort exchange outlived its caller budget; draining its reply");
                    if let Some(waiting) = reply.take() {
                        let _ = waiting.send(Err(expired()));
                    }
                }
                ()=sleep_until_optional(queued_deadline)=>{},
                ()=handle.shared.call_changed.notified()=>{},
                incoming=incoming.recv()=>{if let Some(call)=incoming {queue.push_back(call);}}
                answer=&mut operation=>{
                    if let Ok(answer) = answer { result=answer.map(|value|(value,generation)); } else {interrupted=Some(DisconnectReason::CallTimeout);}
                    break;
                }
            }
        }
    }
    super::worker::publish_metadata(handle, engine);
    if let Some(reply) = reply {
        let _ = reply.send(result);
    }
    if let Some(reason) = engine.terminal_reason {
        return Some(reason);
    }
    if let Some(reason) = interrupted
        && (matches!(
            reason,
            DisconnectReason::Stop
                | DisconnectReason::Lock
                | DisconnectReason::CallTimeout
                | DisconnectReason::Restart
        ) || engine.wire_writes != before)
    {
        return Some(reason);
    }
    None
}

async fn caller_closed<T>(reply: &mut Option<tokio::sync::oneshot::Sender<T>>) {
    match reply {
        Some(reply) => reply.closed().await,
        None => std::future::pending().await,
    }
}
