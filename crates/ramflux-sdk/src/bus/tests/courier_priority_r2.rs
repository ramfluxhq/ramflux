// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real actor priority wiring and delayed gateway replies, with explicit clock barriers.
use super::*;
use fixture::Hold;

fn hold() -> (Hold, mpsc::Receiver<()>) {
    let (entered, observed) = mpsc::channel(1);
    (Hold { entered, release: Arc::new(tokio::sync::Notify::new()) }, observed)
}

async fn entered(observed: &mut mpsc::Receiver<()>) -> Case {
    // Yielding keeps paused time fixed while real loopback TLS reaches the held operation.
    // Wall time is only an outer guard, never the operation that resolves the race.
    let guard = std::time::Instant::now();
    loop {
        match observed.try_recv() {
            Ok(()) => return Ok(()),
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(error) => return Err(error.into()),
        }
        if guard.elapsed() > Duration::from_secs(10) {
            return Err("gateway did not reach the explicit barrier".into());
        }
        tokio::task::yield_now().await;
    }
}

async fn complete<T>(task: tokio::task::JoinHandle<T>) -> Case<T> {
    let guard = std::time::Instant::now();
    while !task.is_finished() {
        if guard.elapsed() > Duration::from_secs(10) {
            return Err("released gateway operation did not complete".into());
        }
        tokio::task::yield_now().await;
    }
    Ok(task.await?)
}

// Mutation: empty the production impl Couriers for Task::priority.
#[tokio::test]
async fn due_receipt_is_sent_by_actor_priority_before_stalled_task_submit() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let f = Box::pin(Fixture::new("courier-priority-receipt-r2")).await?;
            let packet = carrier(&f.source, "healthy", "priority-task")?;
            ack(&f.source, "task/ack/priority-r2", &packet)?;
            let source = f.source.client.owned_device_identity()?;
            let peer = f.peer.client.owned_device_identity()?;
            let receipt_key = format!("{}priority-r2", crate::client::delivery_receipts::PREFIX);
            f.source.client.account_db()?.persist_actor_state(
                &receipt_key,
                &crate::client::delivery_receipts::Work {
                    status_id: "priority-r2".into(),
                    conversation: "healthy".into(),
                    message: "received-priority-r2".into(),
                    wire_message: None,
                    receiver: source.storage_key().into(),
                    sender: peer.storage_key().into(),
                    root: Some(peer.root_commitment().into()),
                    at: now_unix_timestamp(),
                    attempts: 0,
                    next_at: 0,
                    packet: None,
                },
            )?;
            let (gate, mut observed) = hold();
            let released = Arc::clone(&gate.release);
            {
                let mut gateway = f.gateway.lock().map_err(|_| "gateway")?;
                gateway.priority_submit_hold = Some(gate);
                gateway.receipt_bypass = true;
            }
            let gateway = Arc::clone(&f.gateway);
            // D1/D2: a due receipt waits for at most the one bulk exchange in flight.
            let (actor, stop, running) = start_runtime(f.source, &f.root.join("source"))?;
            entered(&mut observed).await?;
            let handle = actor.clone();
            wait_until(|| {
                Ok(handle.queued_calls() > 0
                    || gateway
                        .lock()
                        .map_err(|_| "gateway")?
                        .sent
                        .iter()
                        .any(|e| e.envelope_id.starts_with("receipt_evt_")))
            })
            .await?;
            gateway.lock().map_err(|_| "gateway")?.priority_submit_hold = None;
            released.notify_one();
            wait_until(|| {
                Ok(gateway
                    .lock()
                    .map_err(|_| "gateway")?
                    .sent
                    .iter()
                    .any(|e| e.envelope_id.starts_with("receipt_evt_")))
            })
            .await?;
            let sent = gateway.lock().map_err(|_| "gateway")?.sent.clone();
            let receipt = sent
                .iter()
                .position(|e| e.envelope_id.starts_with("receipt_evt_"))
                .ok_or("receipt")?;
            assert!(
                receipt <= 1,
                "receipt must precede queued bulk, after at most one in-flight submit"
            );
            stop.send(true)?;
            running.await??;
            Ok(())
        }))
        .await
}

fn outgoing_call(account: &mut LocalBusAccountState, peer: &RamfluxClient) -> Case<String> {
    let id = ramflux_protocol::encode_base64url([28; 16]);
    let call = crate::client::call::state::LiveCall::outgoing(
        id.clone(),
        "healthy".into(),
        account.client.call_local_endpoint()?,
        vec![peer.call_local_endpoint()?],
        now_unix_timestamp(),
    )?;
    account.client.persist_call_row(&call.row)?;
    account.client.voice_calls.insert(id.clone(), call);
    Ok(id)
}

// D2: receive and receipt couriers have independent budgets, without a shared floor.
#[tokio::test]
async fn newly_received_messages_send_receipts_in_the_same_pass_with_eight_seconds_left() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("courier-receive-receipt-r3")).await?;
            f.inbound().await?;
            let reader = f.source.client.account_db()?.open_reader()?;
            let gateway = Arc::clone(&f.gateway);
            let (gate, mut observed) = hold();
            let released = Arc::clone(&gate.release);
            {
                let mut server = gateway.lock().map_err(|_| "gateway")?;
                server.inbox.truncate(1);
                server.resume_hold = Some(gate);
            }
            tokio::time::pause();
            let (_, stop, running) = start_runtime(f.source, &f.root.join("source"))?;
            entered(&mut observed).await?;
            tokio::time::advance(Duration::from_secs(12)).await;
            released.notify_one();
            wait_until(|| {
                Ok(gateway
                    .lock()
                    .map_err(|_| "gateway")?
                    .sent
                    .iter()
                    .filter(|e| e.envelope_id.starts_with("receipt_evt_"))
                    .count()
                    == 1)
            })
            .await?;
            assert_eq!(reader.direct_messages("healthy")?.len(), 1);
            wait_until(|| {
                Ok(reader.actor_state_usage(crate::client::delivery_receipts::PREFIX)?.0 == 0)
            })
            .await?;
            stop.send(true)?;
            running.await??;
            Ok(())
        }))
        .await
}

// The delay exceeds the receive allowance but stays inside the ten-second resolution window.
#[tokio::test]
async fn call_signaling_delivers_within_resolution_window_without_retiring_the_session() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("courier-call-budget-r2")).await?;
            let id = outgoing_call(&mut f.source, &f.peer.client)?;
            let (gate, mut observed) = hold();
            let released = Arc::clone(&gate.release);
            f.gateway.lock().map_err(|_| "gateway")?.priority_submit_hold = Some(gate);
            let gateway = Arc::clone(&f.gateway);
            let before = gateway.lock().map_err(|_| "gateway")?.sessions.clone();
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let task = tokio::task::spawn_local(async move {
                let mut account = f.source;
                // D2: production signaling retains its own allowance independent of receive.
                let sent = crate::bus::couriers::test_pass::drive(
                    &mut account,
                    crate::bus::dispatch::call::signaling_pass,
                )
                .await;
                (account, sent)
            });
            entered(&mut observed).await?;
            tokio::time::advance(Duration::from_secs(8)).await;
            tokio::task::yield_now().await;
            let still_waiting = !task.is_finished();
            released.notify_one();
            let (account, sent) = complete(task).await?;
            assert!(
                still_waiting,
                "the call allowance must survive an eight-second reply inside the resolution window"
            );
            assert!(sent?, "the correlated control was not admitted");
            let call = account.client.voice_calls.get(&id).ok_or("test: outgoing call missing")?;
            assert!(call.pending.is_empty(), "the accepted control remained queued");
            assert!(call.media_held, "the scheduling peer's correlated refusal released media");
            assert!(account.has_pooled_engine(), "a valid slow submit must not force a reconnect");
            assert_eq!(
                gateway.lock().map_err(|_| "gateway")?.sessions,
                before,
                "a reply inside the resolution window retired the established session"
            );
            assert_eq!(
                gateway.lock().map_err(|_| "gateway")?.sent.len(),
                1,
                "the held call control was not delivered exactly once"
            );
            assert_eq!(
                started.elapsed(),
                Duration::from_secs(8),
                "the held reply changed the explicit paused-time delay"
            );
            Ok(())
        }))
        .await
}

// D2: backfill progresses independently while receive is busy; no 11-second gate remains.
#[tokio::test]
async fn background_backfill_skipped_after_busy_sync_runs_on_next_idle_cycle() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let f = Box::pin(Fixture::new("courier-backfill-budget-r3")).await?;
            let (gate, mut observed) = hold();
            let released = Arc::clone(&gate.release);
            let gateway = Arc::clone(&f.gateway);
            gateway.lock().map_err(|_| "gateway")?.resume_hold = Some(gate);
            let before = gateway.lock().map_err(|_| "gateway")?.manifest_requests.len();
            let reader = f.source.client.account_db()?.open_reader()?;
            let (_, stop, running) = start_runtime(f.source, &f.root.join("source"))?;
            entered(&mut observed).await?;
            wait_until(|| {
                Ok(gateway.lock().map_err(|_| "gateway")?.manifest_requests.len() > before)
            })
            .await?;
            assert!(reader.load_actor_state::<i64>("own-contact/last-refresh")?.is_some());
            assert!(!running.is_finished(), "receive remains held while backfill advances");
            released.notify_one();
            stop.send(true)?;
            running.await??;
            Ok(())
        }))
        .await
}

async fn wait_until(mut ready: impl FnMut() -> Case<bool>) -> Case {
    let guard = std::time::Instant::now();
    while !ready()? {
        if guard.elapsed() > Duration::from_secs(10) {
            return Err("production progress watchdog".into());
        }
        tokio::task::yield_now().await;
    }
    Ok(())
}

type Running = (
    crate::bus::connection_manager::ConnectionHandle,
    watch::Sender<bool>,
    tokio::task::JoinHandle<Result<(), SdkError>>,
);

fn start_runtime(account: LocalBusAccountState, root: &Path) -> Case<Running> {
    let (mut actor, commands, stop, _observed) = runtime(account, root);
    actor.start_connection()?;
    let handle = actor.state.accounts["sender"].connection.clone().ok_or("fixture host")?;
    let (ready, _ready) = std::sync::mpsc::sync_channel(1);
    let running = tokio::task::spawn_local(async move {
        let _commands = commands;
        let result = actor.serve(ready).await;
        actor.stop_courier().await;
        actor.stop_connection().await;
        actor.close_readers().await;
        result
    });
    Ok((handle, stop, running))
}
