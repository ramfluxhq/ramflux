// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account task registration and joinable observation/receive ownership.

use super::{
    AccountWork, ConnectionEvent, ConnectionHandle, RuntimeTimeouts, metadata_child, receive,
};
use std::sync::Arc;
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::JoinHandle,
};

pub(super) fn start(
    handle: &ConnectionHandle,
    timeouts: &RuntimeTimeouts,
    safety_requests: mpsc::Receiver<String>,
    task_requests: mpsc::Receiver<crate::bus::task_courier_apply::background::Work>,
    stopping: &watch::Receiver<bool>,
) -> Vec<JoinHandle<()>> {
    let mut auxiliary = Vec::new();
    let _ = handle.spawn_session_child("keepalive", |context| {
        Box::pin(crate::bus::push_receiver::keepalive::run(context))
    });
    if let Some(work) = handle.shared.account_work.clone() {
        let task_writer = work.clone();
        let task_requests = Arc::new(tokio::sync::Mutex::new(task_requests));
        let _ = handle.spawn_session_child("task-delivery", move |context| {
            Box::pin(crate::bus::task_courier_apply::background::run(
                context,
                task_writer.clone(),
                Arc::clone(&task_requests),
            ))
        });
        register_courier(handle, &work, "surface-resync", crate::bus::couriers::surface::pass);
        register_courier(handle, &work, "pair-reset", crate::bus::couriers::reset::pass);
        register_courier(
            handle,
            &work,
            "call-signaling",
            crate::bus::dispatch::call::signaling_pass,
        );
        register_courier(
            handle,
            &work,
            "group-requests",
            crate::bus::shared_group_sync::request_pass,
        );
        register_courier(
            handle,
            &work,
            "group-delivery",
            crate::bus::shared_group_sync::deliver_pass,
        );
        register_courier(handle, &work, "group-stage", |_, writer| async move {
            writer
                .apply(|account| {
                    crate::bus::shared_group_sync::stage(account).map(|count| count > 0)
                })
                .await
        });
        let contact_work = work.clone();
        let _ = handle.spawn_session_child("contact-control", move |context| {
            Box::pin(crate::client::contact_requests::run_background(context, contact_work.clone()))
        });
        let own_copy_work = work.clone();
        let _ = handle.spawn_session_child("own-device-copy", move |context| {
            Box::pin(crate::bus::own_device_copy::run_background(context, own_copy_work.clone()))
        });
        let receipt_work = work.clone();
        let _ = handle.spawn_session_child("delivery-receipts", move |context| {
            Box::pin(crate::bus::delivery_receipts::run_background(context, receipt_work.clone()))
        });
        let refresh_work = work.clone();
        let _ = handle.spawn_session_child("head-refresh", move |context| {
            Box::pin(crate::bus::couriers::head_refresh::run(context, refresh_work.clone()))
        });
        let backfill_work = work.clone();
        let _ = handle.spawn_session_child("own-contact-backfill", move |context| {
            Box::pin(crate::bus::couriers::directory::backfill(context, backfill_work.clone()))
        });
        let safety_work = work.clone();
        let safety_requests = Arc::new(tokio::sync::Mutex::new(safety_requests));
        let _ = handle.spawn_session_child("contact-verification-refresh", move |context| {
            Box::pin(crate::bus::couriers::directory::safety(
                context,
                safety_work.clone(),
                Arc::clone(&safety_requests),
            ))
        });
        let child_work = work.clone();
        let _ = handle.spawn_session_child("push-route-state", move |context| {
            Box::pin(metadata_child::run(context, child_work.clone()))
        });
        let mut events = handle.events();
        let mut stop = stopping.clone();
        auxiliary.push(tokio::spawn(async move {
                loop {
                    let event =
                        tokio::select! {biased;_=stop.changed()=>break,event=events.recv()=>event};
                    match event {
                        Ok(event) => {
                            let generation = event_generation(&event);
                            tokio::select! {biased;_=stop.changed()=>break,result=work.send(AccountWork::ReceiveObservation {generation,event})=>{if result.is_err(){break;}}}
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }));
    }
    if let Some(work) = handle.shared.account_work.clone() {
        auxiliary.push(spawn_account_receive(handle, work, timeouts));
    }
    auxiliary
}

fn spawn_account_receive(
    handle: &ConnectionHandle,
    work: mpsc::Sender<AccountWork>,
    timeouts: &RuntimeTimeouts,
) -> JoinHandle<()> {
    if handle.shared.session_push_advertise {
        spawn_receive(receive::run_anchored(
            handle.clone(),
            work,
            timeouts.clone(),
            crate::bus::push_receiver::sweep::SweepSetting::from_process(),
            crate::bus::push_receiver::sweep::SweepMode::Push,
        ))
    } else {
        spawn_receive(receive::run(handle.clone(), work, timeouts.clone()))
    }
}

/// Tests drive receive under `LocalSet`; `spawn_local` keeps the loop on that set so
/// pause/advance wakes `sleep_until`. Production uses the multi-thread spawn.
fn spawn_receive(fut: impl std::future::Future<Output = ()> + Send + 'static) -> JoinHandle<()> {
    #[cfg(test)]
    {
        tokio::task::spawn_local(fut)
    }
    #[cfg(not(test))]
    {
        tokio::spawn(fut)
    }
}

fn register_courier<F, R>(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    name: &'static str,
    pass: F,
) where
    F: Fn(super::SessionContext, crate::bus::couriers::writer::Writer) -> R
        + Copy
        + Send
        + Sync
        + 'static,
    R: std::future::Future<Output = Result<bool, crate::SdkError>> + Send + 'static,
{
    let work = work.clone();
    let _ = handle.spawn_session_child(name, move |context| {
        Box::pin(crate::bus::couriers::runner::run(context, work.clone(), name, pass))
    });
}

fn event_generation(event: &ConnectionEvent) -> u64 {
    match event {
        ConnectionEvent::Connected { generation, .. }
        | ConnectionEvent::Disconnected { generation, .. }
        | ConnectionEvent::AttemptFailed { generation, .. } => *generation,
    }
}
