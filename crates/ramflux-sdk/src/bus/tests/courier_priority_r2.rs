// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real actor priority wiring and delayed gateway replies, with explicit clock barriers.
use super::*;
use fixture::Hold;

struct WarnCounter(Arc<std::sync::atomic::AtomicUsize>);
impl tracing::Subscriber for WarnCounter {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() == tracing::Level::WARN {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

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
                gateway.submit_hold = Some(gate);
                gateway.receipt_bypass = true;
            }
            let gateway = Arc::clone(&f.gateway);
            let (mut actor, _, _, _) = runtime(f.source, &f.root.join("source"));
            actor.stop_courier().await;
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let task = tokio::task::spawn_local(async move {
                let result = actor
                    .apply_courier_outcome(Outcome::Item {
                        item,
                        preparation: Preparation::Ready {
                            manifests,
                            fetched_after: std::time::Instant::now(),
                        },
                    })
                    .await;
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
            gateway.lock().map_err(|_| "gateway")?.submit_hold = None;
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
                    f.gateway.lock().map_err(|_| "gateway")?.submit_hold = Some(gate);
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
                    gateway.lock().map_err(|_| "gateway")?.submit_hold = None;
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
            f.gateway.lock().map_err(|_| "gateway")?.submit_hold = Some(gate);
            let gateway = Arc::clone(&f.gateway);
            let before = gateway.lock().map_err(|_| "gateway")?.sessions.clone();
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let task = tokio::task::spawn_local(async move {
                let mut account = f.source;
                let sent = crate::bus::courier_cycle::priority(&mut account).await;
                (account, sent)
            });
            entered(&mut observed).await?;
            tokio::time::advance(Duration::from_secs(10)).await;
            tokio::task::yield_now().await;
            let still_waiting = !task.is_finished();
            released.notify_one();
            let (account, sent) = complete(task).await?;
            assert!(still_waiting, "the submit allowance must survive a ten-second gateway reply");
            assert_eq!(sent, 1);
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

fn outgoing_named(
    account: &mut LocalBusAccountState,
    peer: &RamfluxClient,
    byte: u8,
) -> Case<String> {
    let id = ramflux_protocol::encode_base64url([byte; 16]);
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

fn renew_call(f: &mut Fixture) -> Case<String> {
    let id = outgoing_call(&mut f.source, &f.peer.client)?;
    let peer = f.peer.client.call_local_endpoint()?;
    let key = ramflux_protocol::encode_base64url(
        f.peer
            .client
            .device_branch
            .as_ref()
            .ok_or("peer branch")?
            .signing_key
            .verifying_key()
            .as_bytes(),
    );
    let call = f.source.client.voice_calls.get_mut(&id).ok_or("call")?;
    call.pin_peer(peer, key)?;
    call.row.state = "active".into();
    call.row.seq += 1;
    call.row.answered_at = Some(now_unix_timestamp());
    call.receive_key = Some(zeroize::Zeroizing::new([3; 32]));
    let allocation = fixture::allocation(0);
    let mut consent = ramflux_protocol::VoiceLeaseConsent {
        scope: call.lease_scope(),
        lease_id: allocation.lease_id.clone(),
        expires_at: allocation.hard_expires_at,
        signature: String::new(),
    };
    consent.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::voice_lease_consent_bytes(&consent)?,
        f.peer.client.device_branch.as_ref().ok_or("peer branch")?,
    );
    call.lease_consent = Some(consent);
    call.allocation = Some(allocation);
    let row = call.row.clone();
    f.source.client.persist_call_row(&row)?;
    Ok(id)
}

fn connecting_call(f: &mut Fixture, callee: bool) -> Case<String> {
    use crate::client::call::state::LiveCall;
    let now = now_unix_timestamp();
    let local = f.source.client.call_local_endpoint()?;
    let peer = f.peer.client.call_local_endpoint()?;
    let id = ramflux_protocol::encode_base64url([28; 16]);
    let mut call = if callee {
        let caller = LiveCall::outgoing(
            id.clone(),
            "healthy".into(),
            peer.clone(),
            vec![local.clone()],
            now,
        )?;
        let mut call = LiveCall::incoming(&caller.pending[0], local, now)?;
        call.answer(now)?;
        call.lease_offer = Some(fixture::allocation(0).for_callee());
        call
    } else {
        let mut caller =
            LiveCall::outgoing(id.clone(), "healthy".into(), local, vec![peer.clone()], now)?;
        let mut receiver = LiveCall::incoming(&caller.pending[0], peer.clone(), now)?;
        receiver.answer(now)?;
        caller.apply(receiver.pending.last().ok_or("answer")?, now)?;
        caller
    };
    call.pin_peer(
        peer,
        ramflux_protocol::encode_base64url(
            f.peer
                .client
                .device_branch
                .as_ref()
                .ok_or("peer branch")?
                .signing_key
                .verifying_key()
                .as_bytes(),
        ),
    )?;
    f.source.client.persist_call_row(&call.row)?;
    f.source.client.voice_calls.insert(id.clone(), call);
    Ok(id)
}

fn checkpoint_count(account: &LocalBusAccountState) -> usize {
    account.resume_checkpoint_writes.get()
}
fn assert_checkpoint(account: &LocalBusAccountState, before: usize) -> Case {
    assert_eq!(checkpoint_count(account), before + 1, "one retirement checkpoint must be written");
    let saved = account
        .client
        .projection_checkpoint(LocalBusAccountState::GATEWAY_RESUME_CHECKPOINT)?
        .ok_or("checkpoint")?;
    let saved: Value = serde_json::from_str(&saved)?;
    assert_eq!(saved["previous_session_id"], "courier-session");
    assert_eq!(saved["resume_token"], "courier-resume");
    assert_eq!(saved["last_seen_inbox_seq"], account.gateway_config.last_seen_inbox_seq);
    assert!(!account.has_pooled_engine());
    Ok(())
}

fn assert_outcome(account: &LocalBusAccountState, id: &str, expected: &str) {
    assert!(
        account.call_outcomes.iter().any(|(call, outcome)| call == id && *outcome == expected),
        "missing {expected} for {id}: {:?}",
        account.call_outcomes
    );
}

#[tokio::test]
async fn post_receive_pass_defers_a_call_that_lacks_a_full_submit_allowance() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("call-post-receive-deferral")).await?;
            let id = f.inbound().await?;
            let (receive, mut received) = hold();
            let release_receive = receive.release.clone();
            let (submit, submitted) = hold();
            let release_submit = submit.release.clone();
            let gateway = f.gateway.clone();
            {
                let mut g = gateway.lock().map_err(|_| "gateway")?;
                g.resume_hold = Some(receive);
                g.submit_hold = Some(submit);
                g.receipt_bypass = true;
            }
            let sessions = gateway.lock().map_err(|_| "gateway")?.sessions.clone();
            let writes = checkpoint_count(&f.source);
            tokio::time::pause();
            let task = tokio::task::spawn_local(async move {
                let mut account = f.source;
                let result = crate::bus::sync_driver::run(&mut account).await;
                (account, result)
            });
            entered(&mut received).await?;
            tokio::time::advance(Duration::from_secs(10)).await;
            release_receive.notify_one();
            crate::test_peers::wait_for(|| task.is_finished() || !submitted.is_empty(), 10).await;
            let call_submitted = !submitted.is_empty();
            if call_submitted {
                tokio::time::advance(Duration::from_secs(10)).await;
            }
            let (mut account, result) = complete(task).await?;
            result?;
            assert!(!call_submitted, "post-receive pass admitted a truncated call item");
            assert_outcome(&account, &id, "Deferred");
            assert_eq!(checkpoint_count(&account), writes);
            assert!(account.has_pooled_engine());
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.sessions, sessions);
            assert_eq!(account.client.voice_calls[&id].pending.len(), 1);
            assert_eq!(
                gateway
                    .lock()
                    .map_err(|_| "gateway")?
                    .sent
                    .iter()
                    .filter(|e| e.envelope_id.starts_with("receipt_evt_"))
                    .count(),
                1
            );
            let task = tokio::task::spawn_local(async move {
                let result = crate::bus::courier_cycle::priority(&mut account).await;
                (account, result)
            });
            let mut submitted = submitted;
            entered(&mut submitted).await?;
            tokio::time::advance(Duration::from_secs(12)).await;
            gateway.lock().map_err(|_| "gateway")?.submit_hold = None;
            release_submit.notify_one();
            let (account, count) = complete(task).await?;
            assert_eq!(count, 1);
            assert!(account.client.voice_calls[&id].pending.is_empty());
            assert_eq!(
                gateway
                    .lock()
                    .map_err(|_| "gateway")?
                    .sent
                    .iter()
                    .filter(|e| !e.envelope_id.starts_with("receipt_evt_"))
                    .count(),
                1
            );
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn second_slow_call_is_deferred_instead_of_cutting_the_courier() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("call-two-item-admission")).await?;
            let first = outgoing_named(&mut f.source, &f.peer.client, 28)?;
            let second = outgoing_named(&mut f.source, &f.peer.client, 29)?;
            assert!(first < second);
            let (submit, mut observed) = hold();
            let release = submit.release.clone();
            let gateway = f.gateway.clone();
            gateway.lock().map_err(|_| "gateway")?.submit_hold = Some(submit);
            let sessions = gateway.lock().map_err(|_| "gateway")?.sessions.clone();
            let writes = checkpoint_count(&f.source);
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let task = tokio::task::spawn_local(async move {
                let mut account = f.source;
                let result = crate::bus::sync_driver::run(&mut account).await;
                (account, result)
            });
            entered(&mut observed).await?;
            tokio::time::advance(Duration::from_secs(10)).await;
            release.notify_one();
            crate::test_peers::wait_for(|| task.is_finished() || !observed.is_empty(), 10).await;
            if !task.is_finished() {
                tokio::time::advance(Duration::from_secs(6)).await;
            }
            let (mut account, result) = complete(task).await?;
            result?;
            assert_eq!(started.elapsed(), Duration::from_secs(10));
            assert_outcome(&account, &first, "Completed");
            assert_outcome(&account, &second, "Deferred");
            assert!(account.client.voice_calls[&first].pending.is_empty());
            assert_eq!(account.client.voice_calls[&second].pending.len(), 1);
            assert_eq!(checkpoint_count(&account), writes);
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.sessions, sessions);
            let task = tokio::task::spawn_local(async move {
                let result = crate::bus::courier_cycle::priority(&mut account).await;
                (account, result)
            });
            entered(&mut observed).await?;
            tokio::time::advance(Duration::from_secs(10)).await;
            gateway.lock().map_err(|_| "gateway")?.submit_hold = None;
            release.notify_one();
            let (account, sent) = complete(task).await?;
            assert_eq!(sent, 1);
            assert!(account.client.voice_calls[&second].pending.is_empty());
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.sent.len(), 2);
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn admission_deferral_does_not_retire() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("call-admission-no-retire")).await?;
            let id = outgoing_call(&mut f.source, &f.peer.client)?;
            let before = checkpoint_count(&f.source);
            let sessions = f.gateway.lock().map_err(|_| "gateway")?.sessions.clone();
            let warnings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let _subscriber = tracing::subscriber::set_default(WarnCounter(warnings.clone()));
            tokio::time::pause();
            assert_eq!(
                crate::bus::dispatch::call::drive_until(
                    &mut f.source,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                    Duration::ZERO
                )
                .await?,
                0
            );
            assert_outcome(&f.source, &id, "Deferred");
            assert_eq!(warnings.load(std::sync::atomic::Ordering::Relaxed), 0);
            assert_eq!(checkpoint_count(&f.source), before);
            let call = &f.source.client.voice_calls[&id];
            assert!(call.network_backoff_until.is_none());
            assert_eq!(call.network_timeouts, 0);
            assert_eq!(call.retry_at, 0);
            assert_eq!(call.pending.len(), 1);
            assert!(f.source.has_pooled_engine());
            let g = f.gateway.lock().map_err(|_| "gateway")?;
            assert_eq!(g.sessions, sessions);
            assert!(g.sent.is_empty());
            assert!(g.lease_requests.is_empty());
            Ok(())
        }))
        .await
}

fn due_ring(account: &mut LocalBusAccountState, peer: &RamfluxClient) -> Case<String> {
    let id = ramflux_protocol::encode_base64url([29; 16]);
    let call = crate::client::call::state::LiveCall::outgoing(
        id.clone(),
        "healthy".into(),
        account.client.call_local_endpoint()?,
        vec![peer.call_local_endpoint()?],
        now_unix_timestamp() - 46,
    )?;
    account.client.persist_call_row(&call.row)?;
    account.client.voice_calls.insert(id.clone(), call);
    Ok(id)
}
fn assert_expired(account: &LocalBusAccountState, id: &str) -> Case {
    let row = account
        .client
        .account_db()?
        .voice_call_rows(false)?
        .into_iter()
        .find(|r| r.call_id == id)
        .ok_or("expired row")?;
    assert_eq!(row.state, "ended");
    assert_eq!(row.end_reason.as_deref(), Some("timeout"));
    Ok(())
}

#[tokio::test]
async fn call_item_exceeding_its_total_budget_times_out_at_its_item_deadline() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("call-total-budget")).await?;
            let id = renew_call(&mut f)?;
            let expired = due_ring(&mut f.source, &f.peer.client)?;
            let (lease, mut leases) = hold();
            let lease_release = lease.release.clone();
            let (submit, mut submits) = hold();
            let submit_release = submit.release.clone();
            let (receive, mut receives) = hold();
            let receive_release = receive.release.clone();
            let gateway = f.gateway.clone();
            {
                let mut g = gateway.lock().map_err(|_| "gateway")?;
                g.lease_hold = Some(lease);
                g.submit_hold = Some(submit);
                g.resume_hold = Some(receive);
            }
            let writes = checkpoint_count(&f.source);
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let task = tokio::task::spawn_local(async move {
                let mut account = f.source;
                let result = crate::bus::sync_driver::run(&mut account).await;
                (account, result)
            });
            entered(&mut leases).await?;
            tokio::time::advance(Duration::from_secs(6)).await;
            gateway.lock().map_err(|_| "gateway")?.lease_hold = None;
            lease_release.notify_one();
            entered(&mut submits).await?;
            tokio::time::advance(Duration::from_secs(9)).await;
            entered(&mut receives).await?;
            assert_eq!(started.elapsed(), Duration::from_secs(15));
            receive_release.notify_one();
            let (account, result) = complete(task).await?;
            result?;
            assert_outcome(&account, &id, "ItemTimeout");
            // Receive reconnected after the retirement. Its normal checkpoint is separate.
            assert_eq!(checkpoint_count(&account), writes + 1);
            let call = &account.client.voice_calls[&id];
            assert_eq!(call.pending.len(), 2, "renewed ACK and original control remain pending");
            assert_eq!(call.retry_at, 0);
            assert_eq!(call.retry_attempts, 0);
            assert_eq!(call.network_backoff_until, Some(started + Duration::from_secs(16)));
            assert_expired(&account, &expired)?;
            tokio::time::advance(Duration::from_secs(1)).await;
            submit_release.notify_one();
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn held_lease_renew_times_out_at_the_item_deadline_and_backs_off_all_network_work() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("call-renew-backoff")).await?;
            let id = renew_call(&mut f)?;
            f.source.call_probe.enabled = true;
            let (lease, mut leases) = hold();
            let release = lease.release.clone();
            let gateway = f.gateway.clone();
            gateway.lock().map_err(|_| "gateway")?.lease_hold = Some(lease);
            let writes = checkpoint_count(&f.source);
            let sessions = gateway.lock().map_err(|_| "gateway")?.sessions.clone();
            let peer = f.peer;
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let task = tokio::task::spawn_local(async move {
                let mut account = f.source;
                let result = crate::bus::courier_cycle::priority_until(
                    &mut account,
                    started + Duration::from_secs(20),
                    Duration::from_secs(4),
                )
                .await;
                (account, result)
            });
            entered(&mut leases).await?;
            tokio::time::advance(Duration::from_secs(15)).await;
            // M2 lacks the item timer; let the step backstop resolve it, then fail exact time/outcome.
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
            if !task.is_finished() {
                tokio::time::advance(Duration::from_secs(1)).await;
            }
            let (mut account, _) = complete(task).await?;
            assert_eq!(started.elapsed(), Duration::from_secs(15));
            assert_outcome(&account, &id, "ItemTimeout");
            assert_checkpoint(&account, writes)?;
            assert_eq!(
                account.client.voice_calls[&id].network_backoff_until,
                Some(started + Duration::from_secs(16))
            );
            tokio::time::advance(Duration::from_millis(500)).await;
            let expired = due_ring(&mut account, &peer.client)?;
            account.call_probe.events.clear();
            let requests = gateway.lock().map_err(|_| "gateway")?.lease_requests.len();
            let network_requests = gateway.lock().map_err(|_| "gateway")?.network_requests;
            let manifests = gateway.lock().map_err(|_| "gateway")?.manifest_requests.len();
            let task = tokio::task::spawn_local(async move {
                let result = crate::bus::dispatch::call::drive_until(
                    &mut account,
                    tokio::time::Instant::now() + Duration::from_secs(20),
                    Duration::ZERO,
                )
                .await;
                (account, result)
            });
            crate::test_peers::wait_for(|| task.is_finished() || !leases.is_empty(), 10).await;
            // A broken backoff starts the held Renew. Unblock it to keep failure cleanup bounded.
            if !task.is_finished() {
                gateway.lock().map_err(|_| "gateway")?.lease_hold = None;
                release.notify_waiters();
            }
            let (mut account, result) = complete(task).await?;
            result?;
            assert!(
                account.call_probe.events.is_empty(),
                "pre-backoff tick performed network work: {:?}",
                account.call_probe.events
            );
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.sessions, sessions);
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.lease_requests.len(), requests);
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.network_requests, network_requests);
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.manifest_requests.len(), manifests);
            assert_expired(&account, &expired)?;
            gateway.lock().map_err(|_| "gateway")?.lease_hold = None;
            tokio::time::advance(Duration::from_millis(500)).await;
            let task = tokio::task::spawn_local(async move {
                let result = crate::bus::dispatch::call::drive_until(
                    &mut account,
                    tokio::time::Instant::now() + Duration::from_secs(20),
                    Duration::ZERO,
                )
                .await;
                (account, result)
            });
            let (account, result) = complete(task).await?;
            result?;
            let call = &account.client.voice_calls[&id];
            assert!(call.network_backoff_until.is_none());
            assert_eq!(call.network_timeouts, 0);
            assert!(call.pending.is_empty());
            assert_eq!(
                gateway.lock().map_err(|_| "gateway")?.sessions.get("device-sender"),
                Some(&(sessions["device-sender"] + 1))
            );
            assert_eq!(gateway.lock().map_err(|_| "gateway")?.lease_requests.len(), requests + 1);
            tokio::time::advance(Duration::from_secs(14)).await;
            release.notify_waiters();
            Ok(())
        }))
        .await
}

fn due_receipt(account: &LocalBusAccountState, peer: &RamfluxClient) -> Case {
    let source = account.client.owned_device_identity()?;
    let peer = peer.owned_device_identity()?;
    account.client.account_db()?.persist_actor_state(
        &format!("{}reserve-proof", crate::client::delivery_receipts::PREFIX),
        &crate::client::delivery_receipts::Work {
            status_id: "reserve-proof".into(),
            conversation: "healthy".into(),
            message: "reserve-proof".into(),
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
    Ok(())
}

#[tokio::test]
async fn first_pass_call_keeps_the_receive_reserve() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("call-actor-receive-reserve")).await?;
            f.inbound().await?;
            let id = outgoing_call(&mut f.source, &f.peer.client)?;
            due_receipt(&f.source, &f.peer.client)?;
            let (receipt, mut receipts) = hold();
            let receipt_release = receipt.release.clone();
            let (submit, mut submits) = hold();
            let submit_release = submit.release.clone();
            let (receive, mut receives) = hold();
            let receive_release = receive.release.clone();
            let gateway = f.gateway.clone();
            {
                let mut g = gateway.lock().map_err(|_| "gateway")?;
                g.inbox.truncate(1);
                g.receipt_hold = Some(receipt);
                g.receipt_bypass = true;
                g.submit_hold = Some(submit);
                g.resume_hold = Some(receive);
            }
            let (mut actor, _, _, _) = runtime(f.source, &f.root.join("source"));
            actor.stop_courier().await;
            let events_before = actor.state.accounts["sender"]
                .client
                .account_db()?
                .journal_after(0, 10000)?
                .iter()
                .filter(|e| e.topic == "sync.status")
                .count();
            tokio::time::pause();
            let task = tokio::task::spawn_local(async move {
                let result = actor.sync().await;
                (actor, result)
            });
            entered(&mut receipts).await?;
            tokio::time::advance(Duration::from_millis(1500)).await;
            gateway.lock().map_err(|_| "gateway")?.receipt_hold = None;
            receipt_release.notify_one();
            crate::test_peers::wait_for(
                || !receives.is_empty() || !submits.is_empty() || task.is_finished(),
                10,
            )
            .await;
            let call_admitted = !submits.is_empty();
            if call_admitted {
                entered(&mut submits).await?;
                tokio::time::advance(Duration::from_millis(14900)).await;
                submit_release.notify_one();
            }
            entered(&mut receives).await?;
            if call_admitted {
                // Observe the actor cutoff while receive is still held; inner-first
                // polling cannot turn an already released receive into a late success.
                tokio::time::advance(Duration::from_millis(3600)).await;
                crate::test_peers::wait_for(|| task.is_finished(), 10).await;
                tokio::time::advance(Duration::from_millis(900)).await;
            } else {
                tokio::time::advance(Duration::from_millis(4500)).await;
            }
            receive_release.notify_one();
            let (mut actor, result) = complete(task).await?;
            result?;
            let account = &actor.state.accounts["sender"];
            let events = account.client.account_db()?.journal_after(0, 10000)?;
            assert_eq!(
                events.iter().filter(|e| e.topic == "sync.status").count(),
                events_before + 1
            );
            let status = crate::bus::sync_status::read(account.client.account_db()?)?;
            assert_ne!(
                status["sync_status"]["body"]["reason_code"], "SyncTimeout",
                "the actor wrote a new SyncTimeout record for this cycle"
            );
            assert_outcome(account, &id, "Deferred");
            assert_eq!(account.client.direct_messages("healthy")?.len(), 1);
            assert_eq!(account.client.voice_calls[&id].pending.len(), 1);
            let task = tokio::task::spawn_local(async move {
                let count = crate::bus::courier_cycle::priority(
                    actor.state.accounts.get_mut("sender").ok_or("account")?,
                )
                .await;
                Ok::<_, Box<dyn std::error::Error>>((actor, count))
            });
            entered(&mut submits).await?;
            tokio::time::advance(Duration::from_millis(14900)).await;
            gateway.lock().map_err(|_| "gateway")?.submit_hold = None;
            submit_release.notify_one();
            let (mut actor, sent) = complete(task).await??;
            assert_eq!(sent, 1);
            assert!(actor.state.accounts["sender"].client.voice_calls[&id].pending.is_empty());
            actor.stop_courier().await;
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn held_call_phase_times_out_with_resume_evidence() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let phases = ["allocate", "accept", "lookup", "engine", "submit", "release"];
            let selected = std::env::var("RAMFLUX_TEST_HELD_CALL_PHASE").ok();
            assert!(selected.as_ref().is_none_or(|phase| phases.contains(&phase.as_str())));
            for phase in phases {
                if selected.as_ref().is_some_and(|selected| selected != phase) {
                    continue;
                }
                eprintln!("held call phase: {phase}");
                let mut f = Box::pin(Fixture::new("call-held-network-phase")).await?;
                let id = match phase {
                    "allocate" => connecting_call(&mut f, false)?,
                    "accept" => connecting_call(&mut f, true)?,
                    _ => renew_call(&mut f)?,
                };
                {
                    let call = f.source.client.voice_calls.get_mut(&id).ok_or("call")?;
                    match phase {
                        "release" => call.end(false, now_unix_timestamp())?,
                        "allocate" | "accept" => {}
                        _ => call.next_lease_refresh = i64::MAX,
                    }
                    let row = call.row.clone();
                    f.source.client.persist_call_row(&row)?;
                }
                let (gate, mut observed) = hold();
                let release = gate.release.clone();
                f.source.call_probe.enabled = true;
                let gateway = f.gateway.clone();
                match phase {
                    "lookup" | "engine" => {
                        f.source.call_probe.holds.insert(phase, (gate.entered, gate.release));
                    }
                    "submit" => gateway.lock().map_err(|_| "gateway")?.submit_hold = Some(gate),
                    _ => gateway.lock().map_err(|_| "gateway")?.lease_hold = Some(gate),
                }
                let writes = checkpoint_count(&f.source);
                let pending = f.source.client.voice_calls[&id].pending.clone();
                let row = f.source.client.voice_calls[&id].row.clone();
                let sessions = gateway.lock().map_err(|_| "gateway")?.sessions.clone();
                tokio::time::pause();
                let started = tokio::time::Instant::now();
                let task = tokio::task::spawn_local(async move {
                    let mut account = f.source;
                    let result = crate::bus::dispatch::call::drive_until(
                        &mut account,
                        started + Duration::from_secs(20),
                        Duration::ZERO,
                    )
                    .await;
                    (account, result)
                });
                entered(&mut observed).await?;
                if matches!(phase, "allocate" | "accept" | "release") {
                    use ramflux_protocol::VoiceLeaseRequest as R;
                    let g = gateway.lock().map_err(|_| "gateway")?;
                    assert!(matches!(
                        (phase, g.lease_requests.last()),
                        ("allocate", Some(R::Allocate { .. }))
                            | ("accept", Some(R::Accept { .. }))
                            | ("release", Some(R::Release { .. }))
                    ));
                }
                tokio::time::advance(Duration::from_secs(15)).await;
                let (mut account, result) = complete(task).await?;
                result?;
                assert_eq!(started.elapsed(), Duration::from_secs(15), "{phase}");
                assert_outcome(&account, &id, "ItemTimeout");
                assert_checkpoint(&account, writes)?;
                let call = &account.client.voice_calls[&id];
                assert_eq!(call.row, row, "last persisted row changed in held {phase}");
                if phase == "release" {
                    assert!(call.pending.is_empty());
                } else {
                    assert!(call.pending == pending, "pending changed in held {phase}");
                }
                assert_eq!(call.retry_at, 0);
                assert_eq!(call.network_backoff_until, Some(started + Duration::from_secs(16)));
                let requests = gateway.lock().map_err(|_| "gateway")?.lease_requests.len();
                let network_requests = gateway.lock().map_err(|_| "gateway")?.network_requests;
                account.call_probe.events.clear();
                tokio::time::advance(Duration::from_millis(500)).await;
                crate::bus::dispatch::call::drive_until(
                    &mut account,
                    tokio::time::Instant::now() + Duration::from_secs(20),
                    Duration::ZERO,
                )
                .await?;
                assert!(
                    account.call_probe.events.is_empty(),
                    "network work before backoff in {phase}"
                );
                assert_eq!(gateway.lock().map_err(|_| "gateway")?.sessions, sessions);
                assert_eq!(gateway.lock().map_err(|_| "gateway")?.lease_requests.len(), requests);
                assert_eq!(
                    gateway.lock().map_err(|_| "gateway")?.network_requests,
                    network_requests
                );
                let sent_before_due = gateway.lock().map_err(|_| "gateway")?.sent.len();
                account.call_probe.holds.clear();
                {
                    let mut g = gateway.lock().map_err(|_| "gateway")?;
                    g.lease_hold = None;
                    g.submit_hold = None;
                }
                tokio::time::advance(Duration::from_millis(500)).await;
                let task = tokio::task::spawn_local(async move {
                    let result = crate::bus::dispatch::call::drive_until(
                        &mut account,
                        tokio::time::Instant::now() + Duration::from_secs(20),
                        Duration::ZERO,
                    )
                    .await;
                    (account, result)
                });
                let (account, result) = complete(task).await?;
                result?;
                // A completed ended call may be removed once its Release is acknowledged.
                if let Some(call) = account.client.voice_calls.get(&id) {
                    assert!(call.network_backoff_until.is_none(), "{phase}");
                    assert_eq!(call.network_timeouts, 0, "{phase}");
                    assert!(call.pending.is_empty(), "{phase}");
                    if matches!(phase, "allocate" | "accept") {
                        assert_eq!(call.row.state, "active");
                    }
                } else {
                    assert_eq!(phase, "release");
                }
                assert_eq!(
                    gateway.lock().map_err(|_| "gateway")?.sessions.get("device-sender"),
                    Some(&(sessions["device-sender"] + 1)),
                    "{phase}"
                );
                let lease_delta = usize::from(matches!(phase, "allocate" | "accept" | "release"));
                assert_eq!(
                    gateway.lock().map_err(|_| "gateway")?.lease_requests.len(),
                    requests + lease_delta,
                    "{phase}"
                );
                let expected_sent = match phase {
                    "allocate" => 2,
                    "accept" => 3,
                    "release" => 0,
                    _ => 1,
                };
                assert_eq!(
                    gateway.lock().map_err(|_| "gateway")?.sent.len() - sent_before_due,
                    expected_sent,
                    "{phase}"
                );
                release.notify_waiters();
                tokio::time::resume();
            }
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn delayed_poll_past_both_deadlines_reports_item_timeout_once() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("call-delayed-item-poll")).await?;
            let id = outgoing_call(&mut f.source, &f.peer.client)?;
            let (submit, observed) = hold();
            let release = submit.release.clone();
            f.gateway.lock().map_err(|_| "gateway")?.submit_hold = Some(submit);
            let mut account = f.source;
            let polls = account.call_probe.polls.clone();
            let writes = checkpoint_count(&account);
            let pending = account.client.voice_calls[&id].pending.clone();
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let mut operation = Box::pin(crate::bus::dispatch::call::drive_until(
                &mut account,
                started + Duration::from_secs(20),
                Duration::ZERO,
            ));
            // A noop waker lets us explicitly stop polling even when both timers become ready.
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let wall = std::time::Instant::now();
            while observed.is_empty() {
                assert!(operation.as_mut().poll(&mut cx).is_pending());
                assert!(wall.elapsed() < Duration::from_secs(10));
                tokio::task::yield_now().await;
            }
            let before_pause = polls.load(std::sync::atomic::Ordering::Relaxed);
            assert!(before_pause > 0);
            tokio::time::advance(Duration::from_secs(17)).await;
            let result = operation.as_mut().poll(&mut cx);
            assert!(result.is_ready());
            drop(operation);
            assert_eq!(
                polls.load(std::sync::atomic::Ordering::Relaxed),
                before_pause,
                "expired item polled its inner future again"
            );
            assert_outcome(&account, &id, "ItemTimeout");
            assert_checkpoint(&account, writes)?;
            let call = &account.client.voice_calls[&id];
            assert!(call.pending == pending, "deadline handling changed pending controls");
            assert_eq!(call.retry_at, 0);
            assert_eq!(call.retry_attempts, 0);
            assert_eq!(call.network_backoff_until, Some(started + Duration::from_secs(18)));
            release.notify_waiters();
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn nested_deadline_error_is_typed_not_a_failed_flush() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut f = Box::pin(Fixture::new("call-nested-typed-deadline")).await?;
            let id = outgoing_call(&mut f.source, &f.peer.client)?;
            let (submit, mut observed) = hold();
            let release = submit.release.clone();
            f.gateway.lock().map_err(|_| "gateway")?.submit_hold = Some(submit);
            let pending = f.source.client.voice_calls[&id].pending.clone();
            let returned_id = id.clone();
            tokio::time::pause();
            let started = tokio::time::Instant::now();
            let task = tokio::task::spawn_local(async move {
                let mut account = f.source;
                let result = crate::bus::dispatch::call::deliver_pending_for_test(
                    &mut account,
                    &id,
                    now_unix_timestamp(),
                    started + Duration::from_secs(1),
                )
                .await;
                (account, result)
            });
            entered(&mut observed).await?;
            tokio::time::advance(Duration::from_secs(1)).await;
            let (account, result) = complete(task).await?;
            assert!(
                matches!(result, Err(crate::bus::task_delivery::SubmitError::DeadlineExceeded)),
                "{result:?}"
            );
            let call = &account.client.voice_calls[&returned_id];
            assert_eq!(call.retry_at, 0);
            assert_eq!(call.retry_attempts, 0);
            assert!(call.pending == pending, "deadline handling changed pending controls");
            assert!(call.network_backoff_until.is_none());
            release.notify_waiters();
            Ok(())
        }))
        .await
}
