// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Real native stores, pair crypto, resident host and actor handoff; injected frame transport.
use crate::bus::account_runtime::{AccountRuntime, TransientHost, uploads};
use crate::bus::events::EventBatch;
use crate::bus::state::{LocalBusAccountState, LocalBusDaemonState};
use crate::client::native_test_support::{Fixture, TestResult};
use crate::{GatewayServerFrame, LocalBusConfig};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};

fn runtime(
    account: LocalBusAccountState,
    root: &std::path::Path,
    id: String,
) -> (AccountRuntime, mpsc::Receiver<EventBatch>) {
    let (_, receiver) = mpsc::channel(1);
    let (_, lifecycle) = mpsc::channel(1);
    let (_, preempt) = watch::channel(0);
    let (_, shutdown) = watch::channel(false);
    let (events, batches) = mpsc::channel(8);
    let (connection_sender, connection_work) = mpsc::channel(2);
    let (head_completion_sender, head_rx) = mpsc::channel(1);
    (
        AccountRuntime {
            timeouts: crate::bus::runtime_limits::RuntimeTimeouts::default(),
            state: LocalBusDaemonState {
                account_index: None,
                config: LocalBusConfig::new(root.join("bus.sock"), root),
                nodes: crate::node::NodeStore::default(),
                accounts: BTreeMap::from([(id.clone(), account)]),
                active_account_id: None,
                attended_accounts: BTreeSet::new(),
                subscribers: BTreeMap::new(),
            },
            id,
            receiver,
            lifecycle,
            preempt,
            command_waiting: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            events,
            shutdown,
            readers: Arc::new(Mutex::new(None)),
            courier: None,
            networking_expiry_pending: None,
            networking_expiry_warned: false,
            networking_observation_warned: false,
            transfers: uploads::Transfers::start(),
            connection_sender,
            connection_work,
            head_completion_sender,
            head_rx,
            deferred: std::collections::VecDeque::new(),
            ledger: None,
            resume_receive_until: None,
            pairing: super::super::pairing_calls::Calls::default(),
            username: super::super::username_calls::Calls::default(),
            transient: TransientHost::default(),
            receive_gate_hook: None,
            courier_events: None,
        },
        batches,
    )
}

const CASE_WALL: std::time::Duration = std::time::Duration::from_secs(30);

/// Real-time flag. A paused Tokio clock does not advance while the yield witness runs,
/// so this deadline sleeps on a std thread.
fn arm_wall() -> tokio::sync::watch::Receiver<bool> {
    let (sender, receiver) = tokio::sync::watch::channel(false);
    let thread = std::thread::Builder::new()
        .name("typing-case-wall".into())
        .spawn(move || {
            std::thread::sleep(CASE_WALL);
            let _ = sender.send(true);
        })
        .expect("test: typing case wall thread");
    drop(thread);
    receiver
}

async fn until_wall(flag: &mut tokio::sync::watch::Receiver<bool>) {
    if *flag.borrow() {
        return;
    }
    loop {
        if flag.changed().await.is_err() || *flag.borrow() {
            return;
        }
    }
}

async fn within<T>(
    flag: &mut tokio::sync::watch::Receiver<bool>,
    work: impl std::future::Future<Output = T>,
    expired: &'static str,
) -> Result<T, Box<dyn std::error::Error>> {
    tokio::pin!(work);
    tokio::select! {
        biased;
        value = &mut work => Ok(value),
        () = until_wall(flag) => Err(expired.into()),
    }
}

/// Keeps the paused runtime polling across store and host waits. The stop signal ends it;
/// abort is only the backstop when that signal was not observed.
fn spawn_yield_witness() -> (tokio::sync::watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let (stop, mut stop_rx) = tokio::sync::watch::channel(false);
    let witness = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        break;
                    }
                }
                () = tokio::task::yield_now() => {}
            }
        }
    });
    (stop, witness)
}

async fn stop_yield_witness(
    stop: tokio::sync::watch::Sender<bool>,
    witness: tokio::task::JoinHandle<()>,
) {
    let _ = stop.send(true);
    for _ in 0..8 {
        if witness.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    if !witness.is_finished() {
        witness.abort();
    }
    let _ = witness.await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn native_typing_host_consumer_projects_without_durable_intake_and_clears_on_stop()
-> TestResult {
    let (stop, witness) = spawn_yield_witness();
    let wall = arm_wall();
    let mut outer = wall.clone();
    let local = tokio::task::LocalSet::new();
    let run = local.run_until(Box::pin(case(false, wall)));
    let result = tokio::select! {
        biased;
        value = run => value,
        () = until_wall(&mut outer) => Err("test: typing host case deadline".into()),
    };
    stop_yield_witness(stop, witness).await;
    result
}

#[test]
fn full_router_keeps_the_typing_frame_until_a_slot_is_free() {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
    let worker = std::thread::Builder::new()
        .name("typing-router-case".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = tx.send(Err(error.to_string()));
                    return;
                }
            };
            let result = runtime.block_on(async {
                let (stop, witness) = spawn_yield_witness();
                let wall = arm_wall();
                let mut outer = wall.clone();
                let local = tokio::task::LocalSet::new();
                let run = local.run_until(Box::pin(case(true, wall)));
                let result = tokio::select! {
                    biased;
                    value = run => value,
                    () = until_wall(&mut outer) => {
                        Err("test: typing router case deadline".into())
                    }
                };
                stop_yield_witness(stop, witness).await;
                result
            });
            // Tear the runtime down (bounded) before reporting, so the parent's
            // join after a result never waits on an unbounded runtime drop. A stalled
            // teardown leaves the result unsent and the parent's recv_timeout fires.
            runtime.shutdown_timeout(std::time::Duration::from_secs(5));
            let _ = tx.send(result.map_err(|error| error.to_string()));
        })
        .expect("test: typing router worker");
    match rx.recv_timeout(CASE_WALL + std::time::Duration::from_secs(5)) {
        Ok(result) => {
            worker.join().expect("test: typing router worker panicked");
            result.expect("test: typing router case");
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // A stalled worker is still on the paused runtime. Joining it would wait
            // past this wall deadline. Process teardown ends that thread.
            panic!("test: typing router case wall deadline");
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("test: typing router worker ended without a result");
        }
    }
}

async fn case(hold: bool, mut wall: tokio::sync::watch::Receiver<bool>) -> TestResult {
    use crate::gateway::access::GatewaySessionAccess;
    let (a, b): (Fixture, Fixture) =
        Box::pin(crate::client::routed::native_typing_pair_fixture()).await?;
    let (handle, io) =
        crate::bus::connection_manager::tests::ephemeral_fixture_for(b.config.clone()).await?;
    let now = crate::time::now_unix_timestamp();
    let _wall = crate::time::FixedClock::set(now);
    let (envelope, allowed) = crate::client::routed::native_typing_delivery_fixture(&a, &b)?;
    let before = b.client.account_db()?.test_table_fingerprints(&allowed)?;
    let head = b.client.account_db()?.journal_bounds()?.head_seq;
    let id = b.client.account_db()?.local_account_id.clone();
    let root = b.root.0.clone();
    within(
        &mut wall,
        handle.call(
            move |engine| {
                Box::pin(async move {
                    engine.ephemeral_inbox.set_clock(crate::ReceiverClock {
                        local_now_ms: u64::try_from(now).unwrap_or(0).saturating_mul(1000),
                        monotonic_ms: 0,
                    });
                    Ok(())
                })
            },
            tokio::time::Instant::now() + std::time::Duration::from_secs(600),
        ),
        "test: clock install deadline",
    )
    .await??;
    let mut account =
        LocalBusAccountState::disconnected(b.client, b.config, b.manifest.principal_commitment);
    account.connection = Some(handle);
    let (mut runtime, mut batches) = runtime(account, &root, id.clone());
    within(&mut wall, runtime.refresh_transient_host(), "test: transient host deadline").await?;
    assert!(runtime.transient.consumer.is_some(), "test: actor owns the transient consumer");
    let mut port = runtime.state.accounts.get(&id).ok_or("account")?.live_session_client()?;
    let taken =
        within(&mut wall, port.take_ephemeral_consumer(), "test: consumer takeover deadline")
            .await??;
    assert!(taken.is_none(), "test: actor must own the sole consumer");
    let expires_at_ms = u64::try_from(envelope.created_at)? * 1000 + 5000;
    let mut tampered = envelope.clone();
    tampered.encrypted_payload = ramflux_protocol::encode_base64url([99; 64]);
    io.input.send(serde_json::to_vec(&GatewayServerFrame::Ephemeral {
        envelope: tampered,
        expires_at_ms,
    })?)?;
    io.input
        .send(serde_json::to_vec(&GatewayServerFrame::Ephemeral { envelope, expires_at_ms })?)?;
    let frame = within(
        &mut wall,
        runtime.transient.next(&runtime.state, &id),
        "test: transient frame deadline",
    )
    .await?;
    assert!(frame.is_some(), "test: the host delivered a transient frame");
    if hold {
        occupy_until_one_spare(&runtime)?;
    }
    runtime.apply_transient_frame(frame);
    let batch = if hold {
        held_publication(&runtime, &mut batches)?
    } else {
        within(&mut wall, batches.recv(), "test: transient update deadline")
            .await?
            .ok_or("test: transient update")?
    };
    assert_typing(&batch, &id, true)?;
    let client = &runtime.state.accounts.get(&id).ok_or("account")?.client;
    assert_eq!(
        client.account_db()?.journal_bounds()?.head_seq,
        head,
        "test: typing does not append the journal"
    );
    assert_eq!(
        client.account_db()?.test_table_fingerprints(&allowed)?,
        before,
        "test: typing does not write durable intake"
    );
    within(&mut wall, runtime.stop_connection(), "test: connection stop deadline").await?;
    let clear = within(&mut wall, batches.recv(), "test: source-end clear deadline")
        .await?
        .ok_or("test: source end clear")?;
    assert_typing(&clear, &id, false)?;
    assert!(runtime.transient.consumer.is_none(), "test: stop drops the transient consumer");
    Ok(())
}

fn occupy_until_one_spare(runtime: &AccountRuntime) -> TestResult {
    // The router channel has 8 slots. Occupy every slot but one so publication
    // must refuse. The bound is the channel capacity.
    for _ in 0..8 {
        if runtime.events.capacity() <= 1 {
            break;
        }
        let (accepted, _done) = tokio::sync::oneshot::channel();
        runtime
            .events
            .try_send(EventBatch { events: Vec::new(), accepted })
            .map_err(|_| "test: router hold slot")?;
    }
    assert!(runtime.events.capacity() <= 1, "test: router has no spare slot");
    Ok(())
}

fn held_publication(
    runtime: &AccountRuntime,
    batches: &mut mpsc::Receiver<EventBatch>,
) -> Result<EventBatch, Box<dyn std::error::Error>> {
    let mut occupied = 0_u32;
    for _ in 0..8 {
        let Ok(queued) = batches.try_recv() else {
            break;
        };
        assert!(queued.events.is_empty(), "test: a full router must not take the typing frame");
        occupied += 1;
    }
    assert!(occupied > 0, "test: the hold occupied the router");
    runtime.publish_transient_updates();
    batches.try_recv().map_err(|_| "test: held typing frame publishes once a slot is free".into())
}

fn assert_typing(batch: &EventBatch, account: &str, active: bool) -> TestResult {
    use ramflux_protocol::message::{content, message_update};
    assert_eq!(batch.events.len(), 1, "test: one transient event");
    let event = batch.events.first().ok_or("test: one transient event")?;
    assert_eq!(event.method, ramflux_protocol::message::TRANSIENT_TOPIC, "test: transient topic");
    assert_eq!(event.seq, Some(0), "test: transient events are unsequenced");
    let update = crate::bindings::decode_message_update(&event.body)?;
    assert_eq!(update.account_id, account, "test: typing account");
    assert_eq!(update.journal_sequence, 0, "test: typing is not journaled");
    let Some(message_update::State::Content(content)) = update.state else {
        return Err("test: expected content".into());
    };
    let Some(content::Value::Typing(typing)) = content.value else {
        return Err("test: expected Typing".into());
    };
    assert_eq!(typing.active, active, "test: typing active flag");
    Ok(())
}
