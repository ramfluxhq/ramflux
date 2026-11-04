// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real actor priority wiring and delayed gateway replies, with explicit clock barriers.
use super::*;
use fixture::Hold;

fn hold() -> (Hold, mpsc::UnboundedReceiver<()>) {
    let (entered, observed) = mpsc::unbounded_channel();
    (Hold { entered, release: Arc::new(tokio::sync::Notify::new()) }, observed)
}

async fn entered(observed: &mut mpsc::UnboundedReceiver<()>) -> Case {
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
            let mut f = Box::pin(Fixture::new("courier-priority-receipt-r2")).await?;
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
            let item = task_courier_queue::manifest_requests(&mut f.source)?
                .into_iter()
                .next()
                .ok_or("item")?;
            let manifests = f
                .gateway
                .lock()
                .map_err(|_| "gateway")?
                .manifests
                .values()
                .cloned()
                .map(serde_json::from_value)
                .collect::<Result<Vec<SdkDeviceManifestResponse>, _>>()?;
            let (gate, mut observed) = hold();
            let released = Arc::clone(&gate.release);
            {
                let mut gateway = f.gateway.lock().map_err(|_| "gateway")?;
                gateway.priority_submit_hold = Some(gate);
                gateway.receipt_bypass = true;
            }
            let gateway = Arc::clone(&f.gateway);
            let (mut actor, _, _, _) = runtime(f.source, &f.root.join("source"));
            actor.stop_courier().await;
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let task = tokio::task::spawn_local(async move {
                let result = actor.apply_courier_outcome(Outcome::Item {
                    item,
                    preparation: Preparation::Ready {
                        manifests,
                        fetched_after: std::time::Instant::now(),
                    },
                });
                (actor, result)
            });
            entered(&mut observed).await?;
            let receipt_preceded_task = gateway
                .lock()
                .map_err(|_| "gateway")?
                .sent
                .iter()
                .any(|e| e.envelope_id.starts_with("receipt_evt_"));
            let stalled = !task.is_finished();
            let elapsed = started.elapsed();
            // The task fan-out includes the peer and sibling; only the first submit is held.
            gateway.lock().map_err(|_| "gateway")?.priority_submit_hold = None;
            released.notify_one();
            let (actor, result) = complete(task).await?;
            result?;
            assert!(
                receipt_preceded_task,
                "production Task::priority must submit the due receipt before task work"
            );
            assert!(
                stalled,
                "receipt service must not rely on the task submit completing or timing out"
            );
            assert_eq!(elapsed, Duration::ZERO);
            assert_eq!(started.elapsed(), Duration::ZERO);
            assert!(
                !actor.state.accounts["sender"]
                    .client
                    .account_db()?
                    .actor_state_exists("task/ack/priority-r2")?,
                "the released task must complete without a production timeout"
            );
            assert!(
                !actor.state.accounts["sender"]
                    .client
                    .account_db()?
                    .actor_state_exists(&receipt_key)?
            );
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

// Mutation: raise the shared post-receive admission floor to nineteen seconds.
#[tokio::test]
async fn newly_received_messages_send_receipts_in_the_same_pass_with_eight_seconds_left() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            for call_seconds in [0, 10] {
                let mut f = Box::pin(Fixture::new("courier-receive-receipt-r3")).await?;
                f.inbound().await?;
                let call_gate = if call_seconds > 0 {
                    outgoing_call(&mut f.source, &f.peer.client)?;
                    let (gate, observed) = hold();
                    let released = Arc::clone(&gate.release);
                    f.gateway.lock().map_err(|_| "gateway")?.priority_submit_hold = Some(gate);
                    Some((observed, released))
                } else {
                    None
                };
                let (gate, mut observed) = hold();
                let released = Arc::clone(&gate.release);
                let gateway = Arc::clone(&f.gateway);
                {
                    let mut server = gateway.lock().map_err(|_| "gateway")?;
                    // Only the ordinary DM: the other fixture entry is a call invitation.
                    server.inbox.truncate(1);
                    server.resume_hold = Some(gate);
                    assert_eq!(server.sent, Vec::<ramflux_protocol::Envelope>::new());
                }
                assert_eq!(
                    f.source
                        .client
                        .account_db()?
                        .actor_state_usage(crate::client::delivery_receipts::PREFIX)?
                        .0,
                    0
                );
                tokio::time::pause();
                let started = tokio::time::Instant::now();
                let task = tokio::task::spawn_local(async move {
                    let mut account = f.source;
                    let result = crate::bus::sync_driver::run(&mut account).await;
                    (account, result)
                });
                if let Some((mut observed, release)) = call_gate {
                    entered(&mut observed).await?;
                    tokio::time::advance(Duration::from_secs(call_seconds)).await;
                    gateway.lock().map_err(|_| "gateway")?.priority_submit_hold = None;
                    release.notify_one();
                }
                entered(&mut observed).await?;
                tokio::time::advance(Duration::from_secs(2)).await;
                released.notify_one();
                let (account, result) = complete(task).await?;
                result?;
                assert_eq!(account.client.direct_messages("healthy")?.len(), 1);
                assert_eq!(
                    gateway
                        .lock()
                        .map_err(|_| "gateway")?
                        .sent
                        .iter()
                        .filter(|envelope| envelope.envelope_id.starts_with("receipt_evt_"))
                        .count(),
                    1,
                    "a newly received message must send its receipt in this same sync pass"
                );
                assert_eq!(
                    account
                        .client
                        .account_db()?
                        .actor_state_usage(crate::client::delivery_receipts::PREFIX)?
                        .0,
                    0
                );
                assert_eq!(started.elapsed(), Duration::from_secs(call_seconds + 2));
                tokio::time::resume();
            }
            Ok(())
        }))
        .await
}

// Mutation: cap the independent call allowance at four seconds again.
#[tokio::test]
async fn ten_second_call_signaling_delivers_without_retiring_the_session() -> Case {
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
                let sent = crate::bus::dispatch::call::drive(&mut account).await;
                (account, sent)
            });
            entered(&mut observed).await?;
            tokio::time::advance(Duration::from_secs(10)).await;
            tokio::task::yield_now().await;
            let still_waiting = !task.is_finished();
            released.notify_one();
            let (account, sent) = complete(task).await?;
            assert!(still_waiting, "the submit allowance must survive a ten-second gateway reply");
            assert_eq!(sent?, 1);
            assert_eq!(account.client.voice_calls[&id].pending.len(), 0);
            assert!(account.has_pooled_engine(), "a valid slow submit must not force a reconnect");
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.sessions, before);
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.sent.len(), 1);
            assert_eq!(started.elapsed(), Duration::from_secs(10));
            Ok(())
        }))
        .await
}

// Mutation: always run backfill regardless of the remaining cycle budget.
#[tokio::test]
async fn background_backfill_skipped_after_busy_sync_runs_on_next_idle_cycle() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let f = Box::pin(Fixture::new("courier-backfill-budget-r2")).await?;
            let (gate, mut observed) = hold();
            let released = Arc::clone(&gate.release);
            f.gateway.lock().map_err(|_| "gateway")?.resume_hold = Some(gate);
            let gateway = Arc::clone(&f.gateway);
            let before = gateway.lock().map_err(|_| "gateway")?.manifest_requests.len();
            let (mut actor, _, _, _) = runtime(f.source, &f.root.join("source"));
            actor.stop_courier().await;
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let task = tokio::task::spawn_local(async move {
                let result = actor.sync().await;
                (actor, result)
            });
            entered(&mut observed).await?;
            tokio::time::advance(Duration::from_secs(10)).await;
            released.notify_one();
            let (mut actor, result) = complete(task).await?;
            result?;
            assert_eq!(started.elapsed(), Duration::from_secs(10));
            let status =
                crate::bus::sync_status::read(actor.state.accounts["sender"].client.account_db()?)?;
            assert_eq!(
                status["sync_status"]["body"]["state"], "idle",
                "backfill must skip after successful busy receive, not a sync timeout"
            );
            assert!(
                actor.state.accounts["sender"]
                    .client
                    .account_db()?
                    .load_actor_state::<i64>("own-contact/last-refresh")?
                    .is_none(),
                "a busy sync must leave backfill for later"
            );
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.manifest_requests.len(), before);
            // Keep paused time fixed while the next real TLS/HTTP request completes.
            let task = tokio::task::spawn_local(async move {
                let result = actor.sync().await;
                (actor, result)
            });
            let (actor, result) = complete(task).await?;
            result?;
            assert!(
                actor.state.accounts["sender"]
                    .client
                    .account_db()?
                    .load_actor_state::<i64>("own-contact/last-refresh")?
                    .is_some(),
                "an idle cycle must attempt the deferred backfill"
            );
            assert!(gateway.lock().map_err(|_| "gateway")?.manifest_requests.len() > before);
            Ok(())
        }))
        .await
}
