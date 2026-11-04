// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! FIFO uncorrelated RPC ownership, independent queued expiry, and cancellation retirement.

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
        expire_calls(handle, &mut queue);
        if let Some(call) = queue.pop_front() {
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

async fn exchange(
    mut call: Call,
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
    let deadline = call.deadline.min(Instant::now() + timeouts.call);
    let operation = (call.operation)(engine);
    let result;
    let mut interrupted = None;
    {
        let operation = timeout_at(deadline, operation);
        tokio::pin!(operation);
        loop {
            expire_calls(handle, queue);
            let queued_deadline = next_deadline(queue);
            tokio::select! {
                biased;
                _=stopping.changed()=>{interrupted=Some(DisconnectReason::Stop);result=Err(handle.pending());break;}
                ()=handle.shared.retirement_changed.notified()=>{if let Some(reason)=handle.take_retirement() {interrupted=Some(reason);result=Err(handle.pending());break;}}
                _=call.cancelled.changed()=>{interrupted=Some(DisconnectReason::CallerCancelled);result=Err(expired());break;}
                ()=call.reply.closed()=>{interrupted=Some(DisconnectReason::CallerCancelled);result=Err(expired());break;}
                ()=sleep_until_optional(queued_deadline)=>{},
                ()=handle.shared.call_changed.notified()=>{},
                incoming=incoming.recv()=>{if let Some(call)=incoming {queue.push_back(call);}}
                answer=&mut operation=>{
                    if let Ok(answer) = answer { result=answer.map(|value|(value,call.generation)) } else {interrupted=Some(DisconnectReason::CallTimeout);result=Err(expired());}
                    break;
                }
            }
        }
    }
    super::worker::publish_metadata(handle, engine);
    let _ = call.reply.send(result);
    if let Some(reason) = engine.terminal_reason {
        return Some(reason);
    }
    if let Some(reason) = interrupted
        && (matches!(
            reason,
            DisconnectReason::Stop | DisconnectReason::CallTimeout | DisconnectReason::Restart
        ) || engine.wire_writes != before)
    {
        return Some(reason);
    }
    None
}
