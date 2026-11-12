// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::large_futures
)]
//! Actor-path WA flush and routed early-return cover (S6b P24b2b r3).

use super::fixture::{Case, Fixture};
use super::lifecycle_fence::{
    PUSH_E, account_of, acked, open_account, push_engine, runtime_for, stage,
};
use crate::bus::connection_manager::{
    NetworkingState, ReceiveTrigger, receive::test_catch_up, receive::test_pass,
    receive::test_pass_anchored,
};
use crate::bus::dispatch::task_transport::{Target, seal};
use crate::bus::push_receiver::executor::{ExecutorOwner, LedgerExecutor};
use crate::bus::push_receiver::sweep::SweepSetting;
use crate::gateway::access::CountingGateway;
use crate::prelude::*;
use ramflux_storage::{ACK_FLUSH_COUNT, ReceiveLedgerSnap, ReceiveMigrate};
use std::sync::Arc;
use std::time::Duration;

fn snap(runtime: &super::super::AccountRuntime) -> Result<ReceiveLedgerSnap, SdkError> {
    let account = account_of(runtime)?;
    Ok(account.client.account_db()?.receive_ledger_snap_for_test(&account.target_delivery_id)?)
}

fn activate(account: &LocalBusAccountState) -> Result<(), SdkError> {
    let target = account.target_delivery_id.clone();
    let _ = account
        .client
        .account_db()?
        .activate_receive_ledger(ReceiveMigrate { target: &target, incarnation: PUSH_E })?;
    Ok(())
}

fn sweep_hold() -> Duration {
    Duration::from_hours(24)
}

fn sweep_timeouts() -> crate::bus::runtime_limits::RuntimeTimeouts {
    let hold = sweep_hold();
    crate::bus::runtime_limits::RuntimeTimeouts {
        network_wait: hold,
        attempt: hold,
        call: hold,
        receipt: hold,
        task_approval: hold,
        task_submit: hold,
        http: hold,
        command: hold,
        post_claim: hold,
        frame: hold,
        transport_open: hold,
        retry_budget: hold,
        receive_min: hold,
        receive_max: hold,
        sync: hold,
        fetch: hold,
        keepalive_idle: hold,
        keepalive_call: hold,
        #[cfg(feature = "itest-local-mint")]
        relay_http: hold,
    }
}

async fn start_runtime(
    fixture: &mut Fixture,
) -> Result<super::super::AccountRuntime, Box<dyn std::error::Error>> {
    let mut runtime = start_runtime_live(fixture)?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    wait_until_live(&mut runtime, &handle).await?;
    wait_connected_receive(&mut runtime, &handle).await?;
    Ok(runtime)
}

fn start_runtime_live(
    fixture: &mut Fixture,
) -> Result<super::super::AccountRuntime, Box<dyn std::error::Error>> {
    let config = fixture.source.gateway_config.clone();
    let commitment = fixture.source.principal_commitment.clone();
    let mut carrier = push_engine(fixture.source.engine.take().ok_or("engine")?)?;
    let account = open_account(&fixture.root, &config, &commitment)?;
    activate(&account)?;
    let mut runtime = runtime_for(account, &fixture.root);
    let hold = sweep_hold();
    carrier.frame_timeout = hold;
    carrier.config.timeout = hold;
    carrier.config.quic_fallback_timeout = hold;
    runtime.timeouts = sweep_timeouts();
    if let Some(account) = runtime.state.accounts.get_mut("sender") {
        account.gateway_config.timeout = hold;
        account.gateway_config.quic_fallback_timeout = hold;
        account.timeouts = runtime.timeouts.clone();
    }
    runtime.start_connection()?;
    runtime.state.accounts.get_mut("sender").ok_or("account")?.engine = Some(carrier);
    Ok(runtime)
}

async fn start_runtime_default_on(
    fixture: &mut Fixture,
) -> Result<super::super::AccountRuntime, Box<dyn std::error::Error>> {
    let mut runtime = start_runtime_default_on_live(fixture)?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    wait_until_live(&mut runtime, &handle).await?;
    wait_connected_receive(&mut runtime, &handle).await?;
    Ok(runtime)
}

fn start_runtime_default_on_live(
    fixture: &mut Fixture,
) -> Result<super::super::AccountRuntime, Box<dyn std::error::Error>> {
    let config = fixture.source.gateway_config.clone();
    let commitment = fixture.source.principal_commitment.clone();
    let _ = fixture.source.engine.take();
    let account = open_account(&fixture.root, &config, &commitment)?;
    // The predecessor carries these same recovery tests with first activation off.
    if !ramflux_storage::FIRST_ACTIVATION_DEFAULT
        && account.client.account_db()?.receive_activation()?
            == ramflux_storage::ReceiveActivation::Inactive
    {
        let incarnation = fixture
            .gateway
            .lock()
            .map_err(|_| "gateway")?
            .inbox_incarnation
            .clone()
            .unwrap_or_else(|| PUSH_E.into());
        let _ = account.client.account_db()?.activate_receive_ledger(ReceiveMigrate {
            target: &account.target_delivery_id,
            incarnation: &incarnation,
        })?;
    }
    let mut runtime = runtime_for(account, &fixture.root);
    let hold = sweep_hold();
    runtime.timeouts = sweep_timeouts();
    if let Some(account) = runtime.state.accounts.get_mut("sender") {
        account.gateway_config.timeout = hold;
        account.gateway_config.quic_fallback_timeout = hold;
        account.timeouts = runtime.timeouts.clone();
        account.engine = None;
    }
    runtime.start_connection()?;
    Ok(runtime)
}

async fn drive_full_pass(
    runtime: &mut super::super::AccountRuntime,
    trigger: ReceiveTrigger,
) -> Case {
    let _ = drive_spawned(runtime, |handle, work, generation| {
        Box::pin(async move {
            test_pass(&handle, &work, generation, trigger, Duration::from_secs(8)).await
        })
    })
    .await?;
    Ok(())
}

async fn drive_pass(runtime: &mut super::super::AccountRuntime, trigger: ReceiveTrigger) -> Case {
    let _ = drive_spawned(runtime, |handle, work, generation| {
        Box::pin(async move {
            test_catch_up(&handle, &work, generation, trigger, Duration::from_secs(8)).await
        })
    })
    .await?;
    Ok(())
}

async fn drive_flush(runtime: &mut super::super::AccountRuntime, force: bool) -> Case {
    drive_spawned(runtime, |handle, work, generation| {
        Box::pin(async move {
            crate::bus::connection_manager::receive::flush_acks(
                &handle,
                &work,
                generation,
                force,
                Duration::from_secs(8),
            )
            .await
        })
    })
    .await?;
    Ok(())
}

/// `handle.call` runs on `tokio::spawn`; a bare `connection_work.recv()` starves it.
async fn drive_spawned<F, Fut, T>(runtime: &mut super::super::AccountRuntime, start: F) -> Case<T>
where
    F: FnOnce(
        crate::bus::connection_manager::ConnectionHandle,
        tokio::sync::mpsc::Sender<crate::bus::connection_manager::AccountWork>,
        u64,
    ) -> Fut,
    Fut: Future<Output = Result<T, SdkError>> + 'static,
    T: 'static,
{
    let handle = account_of(runtime)?.connection.clone().ok_or("handle")?;
    let generation = handle.generation();
    let work = runtime.connection_sender.clone();
    let mut pass = tokio::task::spawn_local(start(handle, work, generation));
    loop {
        tokio::select! {
            biased;
            result = &mut pass => return Ok(result??),
            work = runtime.connection_work.recv() => {
                runtime.apply_connection_work(work.ok_or("closed")?).await?;
            }
            () = poll_spawned() => {}
        }
    }
}

async fn fill_sealed(fixture: &mut Fixture, start: u64, n: u64) -> Case {
    let target = Target {
        device: "device-sender".into(),
        identity: fixture.source.client.owned_device_identity()?,
        delivery: "sender".into(),
        federation: None,
        own: false,
    };
    let mut engine = fixture.peer.session_client().await?;
    let mut entries = Vec::new();
    for offset in 0..n {
        let seq = start.saturating_add(offset);
        let dm = seal(
            &fixture.peer,
            &mut engine,
            &target,
            "healthy",
            format!("wa-{seq}").as_bytes(),
            crate::client::routed::Route::direct(),
        )
        .await?;
        entries.push(GatewayInboxEntry {
            forwarded: false,
            inbox_seq: seq,
            target_delivery_id: "sender".into(),
            envelope: dm.envelope,
        });
    }
    fixture.peer.install_test_session(engine);
    let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
    gateway.ack_target = fixture.source.target_delivery_id.clone();
    gateway.inbox = entries;
    Ok(())
}

async fn watch<F>(secs: u64, fut: F) -> Case
where
    F: Future<Output = Case>,
{
    tokio::time::timeout(
        Duration::from_secs(secs),
        LocalSet::new()
            .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(fut)))),
    )
    .await
    .expect("hang")
}

#[tokio::test(flavor = "current_thread")]
async fn never_ack_above_c() -> Case {
    watch(25, never_ack_above_c_case()).await
}

async fn never_ack_above_c_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("wa-never-above")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    let mut runtime = start_runtime(&mut fixture).await?;
    fill_sealed(&mut fixture, 1, 1).await?;
    {
        let _clock = crate::time::test_clock::FrozenClock::freeze();
        drive_pass(&mut runtime, ReceiveTrigger::Tick).await?;
    }
    assert_eq!(snap(&runtime)?.cursor, 1);
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    let net = handle.snapshot();
    let generation = handle.generation();
    let now = crate::time::now_unix_timestamp();
    let (epoch, activation, selected) = {
        let account = account_of(&runtime)?;
        let db = account.client.account_db()?;
        let target = account.target_delivery_id.clone();
        let epoch = db.receive_epoch(&target)?;
        let activation = db.receive_activation()?;
        let turn = crate::bus::push_receiver::apply_w1::capture_turn(db, generation, &target)?;
        let selected = crate::bus::push_receiver::ack_batch::SourceWa {
            expected: turn.expected(),
            generation,
        }
        .select(db, now, true)?;
        (epoch, activation, selected)
    };
    drive_flush(&mut runtime, true).await?;
    let (ack_sends, resumes, fetches) = {
        let gateway = gateway.lock().map_err(|_| "gateway")?;
        (gateway.ack_sends, gateway.resumes.clone(), gateway.fetches.clone())
    };
    assert_eq!(
        ack_sends,
        1,
        "WA ACKs only seq <= C snap={:?} ack_sends={} push={} mode={:?} net={:?} reason={:?} cause={:?} phase={:?} gen={} epoch={:?} act={:?} now={} selected={:?} resumes={:?} fetches={:?}",
        snap(&runtime)?,
        ack_sends,
        handle.session_is_push(),
        handle.session_mode(),
        net.state,
        net.last_reason,
        net.cause,
        net.phase,
        generation,
        epoch,
        activation,
        now,
        selected,
        resumes,
        fetches
    );
    assert_eq!(snap(&runtime)?.intents, Vec::<u64>::new());
    {
        let account = account_of(&runtime)?;
        let target = account.target_delivery_id.clone();
        let db = account.client.account_db()?;
        db.seed_held_receive_for_test(&target, PUSH_E, 1, b"{}")?;
        db.seed_ack_intent_for_test(&target, PUSH_E, 1)?;
        db.seed_held_receive_for_test(&target, PUSH_E, 2, b"{}")?;
        db.seed_ack_intent_for_test(&target, PUSH_E, 2)?;
        db.seed_ack_intent_for_test(&target, PUSH_E, 9)?;
        assert_eq!(
            db.receive_ledger_snap_for_test(&target)?.intents,
            vec![1, 2, 9],
            "held seq<=C plus held seq 2 and seq>C 9"
        );
    }
    crate::time::test_clock::set_frozen(Some(100));
    let flushed = drive_flush(&mut runtime, true).await;
    crate::time::test_clock::set_frozen(None);
    flushed?;
    assert_eq!(acked(&gateway)?, 1, "actor never ACKs held or seq>C intents");
    assert_eq!(snap(&runtime)?.intents, vec![1, 2, 9]);
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ack_batch_timing() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog_for(
            Duration::from_secs(120),
            Box::pin(ack_batch_timing_case()),
        )))
        .await
}

async fn ack_batch_timing_case() -> Case {
    let n = u64::try_from(ACK_FLUSH_COUNT)?;
    let mut thirty_three = Box::pin(Fixture::new("wa-timing-33")).await?;
    let gateway33 = Arc::clone(&thirty_three.gateway);
    let mut runtime33 = start_runtime(&mut thirty_three).await?;
    fill_sealed(&mut thirty_three, 1, n.saturating_mul(2).saturating_add(1)).await?;
    {
        let _clock = crate::time::test_clock::FrozenClock::freeze();
        drive_pass(&mut runtime33, ReceiveTrigger::Tick).await?;
    }
    assert_eq!(
        acked(&gateway33)?,
        ACK_FLUSH_COUNT.saturating_mul(2).saturating_add(1),
        "33 entries: 16+16 mid catch-up plus Tick remainder force-flush"
    );
    assert_eq!(snap(&runtime33)?.intents, Vec::<u64>::new());
    runtime33.stop_connection().await;
    drop(runtime33);
    std::fs::remove_dir_all(thirty_three.root)?;

    let mut three = Box::pin(Fixture::new("wa-timing-3")).await?;
    let gateway3 = Arc::clone(&three.gateway);
    let mut runtime3 = start_runtime(&mut three).await?;
    fill_sealed(&mut three, 1, 3).await?;
    let _clock = crate::time::test_clock::FrozenClock::freeze();
    drive_pass(&mut runtime3, ReceiveTrigger::Tick).await?;
    assert_eq!(acked(&gateway3)?, 3, "Tick that applied work force-flushes a short remainder");
    runtime3.stop_connection().await;
    drop(runtime3);
    std::fs::remove_dir_all(three.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ack_lost_before_and_after_commit() -> Case {
    watch(25, ack_lost_case()).await
}

async fn ack_lost_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("wa-lost")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    let mut runtime = start_runtime(&mut fixture).await?;
    fill_sealed(&mut fixture, 1, 2).await?;
    gateway.lock().map_err(|_| "gateway")?.ack_fail = true;
    let guard = crate::bus::push_receiver::ack_batch::arm_fault();
    let lost = {
        let _clock = crate::time::test_clock::FrozenClock::freeze();
        drive_pass(&mut runtime, ReceiveTrigger::Tick).await
    };
    drop(guard);
    assert!(lost.is_err(), "before-commit fault must fail the flush");
    assert_eq!(snap(&runtime)?.intents, vec![1, 2], "abort after apply rolls back");
    drive_flush(&mut runtime, true).await?;
    assert_eq!(snap(&runtime)?.intents, vec![1, 2], "Uncertain after WR retains");
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn catch_up_yields_real_pass() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog_for(
            Duration::from_secs(90),
            Box::pin(catch_up_yields_real_pass_case()),
        )))
        .await
}

async fn catch_up_yields_real_pass_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2c-yield")).await?;
    fixture.gateway.lock().map_err(|_| "gateway")?.resume_page_size = Some(1);
    let mut runtime = start_runtime(&mut fixture).await?;
    fill_sealed(&mut fixture, 1, 17).await?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    let competitor = tokio::task::spawn_local(async {
        loop {
            crate::bus::connection_manager::ConnectionHandle::bump_yield_witness();
            tokio::task::yield_now().await;
        }
    });
    drive_pass_anchored(&mut runtime, ReceiveTrigger::Tick).await?;
    competitor.abort();
    assert!(
        handle.test_catch_up_yields() >= 1,
        "17 one-entry resume pages must yield after 16: {}",
        handle.test_catch_up_yields()
    );
    assert!(
        handle.test_catch_up_yield_progress() >= 1,
        "must yield after 16: {}",
        handle.test_catch_up_yield_progress()
    );
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

async fn drive_pass_anchored(
    runtime: &mut super::super::AccountRuntime,
    trigger: ReceiveTrigger,
) -> Case {
    let handle = account_of(runtime)?.connection.clone().ok_or("handle")?;
    let generation = handle.generation();
    let work = runtime.connection_sender.clone();
    let mut pass = tokio::task::spawn_local(async move {
        test_pass_anchored(&handle, &work, generation, trigger, Duration::from_secs(8)).await
    });
    loop {
        tokio::select! {
            biased;
            result = &mut pass => {
                result??;
                break;
            }
            work = runtime.connection_work.recv() => {
                runtime.apply_connection_work(work.ok_or("closed")?).await?;
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connected_and_sweep() -> Case {
    // Real-time watchdog only: a tokio timeout would fire when the paused clock
    // advances through the 900 s sweep.
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            connected_and_sweep_real(),
        ))))
        .await
}

async fn drain_ready(runtime: &mut super::super::AccountRuntime) -> Case<bool> {
    let mut progressed = false;
    for _ in 0..64 {
        tokio::task::yield_now().await;
        let mut any = false;
        while let Ok(work) = runtime.connection_work.try_recv() {
            any = true;
            progressed = true;
            runtime.apply_connection_work(work).await?;
        }
        if !any {
            break;
        }
    }
    Ok(progressed)
}

/// `LocalSet` starves `tokio::spawn` (session worker). Waiting on a spawned oneshot
/// forces the current-thread scheduler to poll that queue. Do not `sleep` after
/// `pause()`: auto-advance is off, so a sleep never completes.
async fn poll_spawned() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = tx.send(());
    });
    let _ = rx.await;
}

async fn wait_until_live(
    runtime: &mut super::super::AccountRuntime,
    handle: &crate::bus::connection_manager::ConnectionHandle,
) -> Case {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if handle.snapshot().state == NetworkingState::Live {
            return Ok(());
        }
        match tokio::time::timeout(Duration::from_millis(20), runtime.connection_work.recv()).await
        {
            Ok(Some(work)) => runtime.apply_connection_work(work).await?,
            Ok(None) => return Err("connection work closed".into()),
            Err(_) => poll_spawned().await,
        }
    }
    Err(format!("session did not become Live: {:?}", handle.snapshot()).into())
}

/// A Live handshake can still have an automatic catch-up in flight. Wait for its
/// semantic completion before starting a manual pass against the same C fence.
async fn wait_connected_receive(
    runtime: &mut super::super::AccountRuntime,
    handle: &crate::bus::connection_manager::ConnectionHandle,
) -> Case {
    pump_until(runtime, Duration::from_secs(10), || {
        handle.test_receive_trace().contains(&(ReceiveTrigger::Connected, true))
    })
    .await?;
    if !handle.test_receive_trace().contains(&(ReceiveTrigger::Connected, true)) {
        return Err(format!(
            "Connected receive did not finish: {:?}; trace={:?}",
            handle.test_receive_last_error(),
            handle.test_receive_trace()
        )
        .into());
    }
    Ok(())
}

/// Drain actor work until `done` or a wall-clock deadline.
/// Writer/ApplyPage oneshots are not engine calls, so `queued_calls` can be 0
/// while the receive worker is still blocked. Do not `recv()` here: under pause
/// plus a `spawn_blocking` inhibit, a missing message hangs the current-thread
/// runtime.
async fn pump_until(
    runtime: &mut super::super::AccountRuntime,
    wall: Duration,
    mut done: impl FnMut() -> bool,
) -> Case {
    let start = std::time::Instant::now();
    while start.elapsed() < wall {
        drain_ready(runtime).await?;
        poll_spawned().await;
        drain_ready(runtime).await?;
        if done() {
            return Ok(());
        }
        match runtime.connection_work.try_recv() {
            Ok(work) => runtime.apply_connection_work(work).await?,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => tokio::task::yield_now().await,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                return Err("connection work closed".into());
            }
        }
    }
    Ok(())
}

async fn pump_anchored(
    runtime: &mut super::super::AccountRuntime,
    handle: &crate::bus::connection_manager::ConnectionHandle,
) -> Case {
    handle.notify_receive_wake();
    let mut idle = 0_u32;
    for _ in 0..256 {
        let mut progressed = drain_ready(runtime).await?;
        poll_spawned().await;
        // Intake/ApplyPage oneshots are not engine calls; drain after polling spawn.
        progressed = drain_ready(runtime).await? || progressed;
        let live = handle.snapshot().state == NetworkingState::Live;
        let busy = handle.queued_calls() > 0
            || handle.in_flight_calls() > 0
            || handle.reorder().in_flight();
        if !live || busy || progressed {
            idle = 0;
            // Engine RPCs run on tokio::spawn; blocking recv() starves them under pause.
            match runtime.connection_work.try_recv() {
                Ok(work) => runtime.apply_connection_work(work).await?,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    tokio::task::yield_now().await;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    return Err("connection work closed".into());
                }
            }
            continue;
        }
        tokio::task::yield_now().await;
        idle = idle.saturating_add(1);
        if idle >= 8 {
            break;
        }
    }
    Ok(())
}

async fn stop_peer_session(fixture: &mut Fixture) {
    if let Some(handle) = fixture.peer.connection.take() {
        handle.stop().await;
    }
}

async fn connected_and_sweep_real() -> Case {
    let mut fixture = Box::pin(Fixture::build("p24b2c-sweep", false, Some(sweep_hold()))).await?;
    let gateway = Arc::clone(&fixture.gateway);
    // Empty inbox: a sealed entry makes Connected ack_batch retire the live
    // session on Linux (cursor/target) or hang the actor pump. Catch-up and
    // Sweep still issue resume_page on an empty page.
    stop_peer_session(&mut fixture).await;
    let mut runtime = start_runtime_live(&mut fixture)?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    // Pause before Live so Connected I/O is measured on the virtual clock.
    tokio::time::pause();
    let handshake = std::time::Instant::now();
    let catch_up = Duration::from_millis(SweepSetting::CATCH_UP_MS);
    handle.notify_receive_wake();
    while handle.snapshot().state != NetworkingState::Live {
        if handshake.elapsed() > Duration::from_secs(10) {
            return Err("session did not become Live".into());
        }
        drain_ready(&mut runtime).await?;
        poll_spawned().await;
        match runtime.connection_work.try_recv() {
            Ok(work) => runtime.apply_connection_work(work).await?,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => tokio::task::yield_now().await,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                return Err("connection work closed".into());
            }
        }
    }
    let live_at = tokio::time::Instant::now();
    handle.notify_receive_wake();
    // spawn_blocking inhibits auto-advance while catch-up waits on redb / a
    // std-thread oneshot, and while the 900s sweep is jumped on a live TCP
    // session. Dropping the hold lets paused-clock auto-advance fire connect
    // timeouts instead of polling the loopback socket.
    let (release_hold, hold) = std::sync::mpsc::channel::<()>();
    let inhibit = tokio::task::spawn_blocking(move || {
        let _ = hold.recv();
    });
    let wait_resume = std::time::Instant::now();
    let mut resume_elapsed = None;
    pump_until(&mut runtime, Duration::from_secs(10), || {
        if resume_elapsed.is_none()
            && let Ok(n) = gateway.lock().map(|g| g.resumes.len())
            && n > 0
        {
            resume_elapsed = Some(live_at.elapsed());
        }
        handle.test_receive_trace().contains(&(ReceiveTrigger::Connected, true))
            || wait_resume.elapsed() > Duration::from_secs(10)
    })
    .await?;
    if !handle.test_receive_trace().contains(&(ReceiveTrigger::Connected, true)) {
        return Err(format!(
            "Connected pass did not finish: resumes={:?} trace={:?} err={:?} snap={:?}",
            gateway.lock().map_err(|_| "gateway")?.resumes.len(),
            handle.test_receive_trace(),
            handle.test_receive_last_error(),
            handle.snapshot(),
        )
        .into());
    }
    let within = resume_elapsed.unwrap_or_else(|| live_at.elapsed());
    let in_100 = gateway.lock().map_err(|_| "gateway")?.resumes.len();
    assert_eq!(in_100, 1, "Connected catch-up Resume within 100ms: {in_100} elapsed={within:?}");
    assert!(within <= catch_up, "first Resume measured at {within:?}");
    assert_eq!(
        handle.snapshot().state,
        NetworkingState::Live,
        "session must stay Live after Connected ok snap={:?} err={:?} within={within:?} virtual={:?}",
        handle.snapshot(),
        handle.test_receive_last_error(),
        live_at.elapsed()
    );
    if within < catch_up {
        tokio::time::advance(catch_up.saturating_sub(within)).await;
    }
    assert_eq!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len(),
        1,
        "exactly one Resume before the virtual 100ms deadline"
    );
    assert_eq!(
        handle.test_context().keepalive_idle(),
        sweep_hold(),
        "keepalive must outlive the 900s sweep"
    );
    assert_eq!(
        handle.snapshot().state,
        NetworkingState::Live,
        "session must stay Live before the 900s sweep snap={:?} err={:?} within={within:?}",
        handle.snapshot(),
        handle.test_receive_last_error()
    );
    tokio::time::advance(Duration::from_secs(899)).await;
    pump_until(&mut runtime, Duration::from_millis(200), || {
        handle.snapshot().state != NetworkingState::Live
    })
    .await?;
    assert_eq!(
        handle.snapshot().state,
        NetworkingState::Live,
        "session must stay Live through 899s snap={:?} err={:?}",
        handle.snapshot(),
        handle.test_receive_last_error()
    );
    assert_eq!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len(),
        1,
        "no Resume until 900s snap={:?}",
        handle.snapshot()
    );
    tokio::time::advance(Duration::from_millis(1_000)).await;
    pump_until(&mut runtime, Duration::from_secs(10), || {
        gateway.lock().map_or(0, |g| g.resumes.len()) >= 2
            || handle.snapshot().state != NetworkingState::Live
    })
    .await?;
    let resumes = gateway.lock().map_err(|_| "gateway")?.resumes.len();
    assert!(
        resumes >= 2,
        "Sweep Resume at 900s: resumes={resumes} trace={:?} err={:?} snap={:?}",
        handle.test_receive_trace(),
        handle.test_receive_last_error(),
        handle.snapshot()
    );
    drop(release_hold);
    let _ = inhibit.await;
    tokio::time::resume();
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn stale_page_suffix_progress() -> Case {
    watch(40, stale_page_suffix_progress_case()).await
}

async fn stale_page_suffix_progress_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2c-stale")).await?;
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.resume_losses = vec![(1, 10, "expired")];
        gateway.resume_issued = Some(10);
    }
    let mut runtime = start_runtime(&mut fixture).await?;
    assert_eq!(snap(&runtime)?.cursor, 10, "prefix losses cover through 10");
    fill_sealed(&mut fixture, 12, 1).await?;
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.resume_losses = vec![(11, 11, "expired"), (13, 20, "nacked")];
        gateway.resume_issued = Some(20);
    }
    drive_full_pass(&mut runtime, ReceiveTrigger::Tick).await?;
    let after = snap(&runtime)?;
    assert_eq!(after.cursor, 20, "stale suffix covers through 20: {after:?}");
    assert!(
        after.losses.iter().any(|loss| loss.0 == 13 && loss.1 == 20),
        "nacked suffix is recorded: {after:?}"
    );
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn routed_seen_duplicate_covers_and_acks() -> Case {
    watch(25, seen_duplicate_case()).await
}

async fn seen_duplicate_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("h1-seen")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    let mut runtime = start_runtime(&mut fixture).await?;
    fill_sealed(&mut fixture, 1, 1).await?;
    let first = gateway.lock().map_err(|_| "gateway")?.inbox.first().cloned().ok_or("entry")?;
    account_of(&runtime)?.client.persist_routed_seen(&first)?;
    drive_pass(&mut runtime, ReceiveTrigger::Tick).await?;
    drive_flush(&mut runtime, true).await?;
    assert_eq!(snap(&runtime)?.cursor, 1, "seen seq above C covers");
    assert_eq!(acked(&gateway)?, 1, "duplicate early return is ACKed once");
    fill_sealed(&mut fixture, 2, 1).await?;
    drive_pass(&mut runtime, ReceiveTrigger::Tick).await?;
    drive_flush(&mut runtime, true).await?;
    assert_eq!(snap(&runtime)?.cursor, 2, "seen seq above C must not wedge the next seq");
    assert_eq!(acked(&gateway)?, 2, "next seq is ACKed once");
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn routed_contact_request_covers_and_acks() -> Case {
    watch(30, contact_request_case()).await
}

async fn contact_request_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("h1-contact")).await?;
    let mut source_manifest =
        crate::client::identity_authority::test_support::public_manifest(&fixture.source.client)?;
    source_manifest.devices.retain(|device| device.device_id == "device-sender");
    source_manifest.devices[0].target_delivery_id = "sender".into();
    {
        let config =
            fixture.source.gateway_config.clone().with_account_identity(&fixture.peer.client)?;
        fixture.peer.gateway_config = config;
        fixture.peer.engine = None;
        fixture.peer.client.stage_contact_request(&source_manifest, "h1-link", None)?;
        crate::client::contact_requests::flush(&mut fixture.peer).await?;
    }
    let envelope = {
        let served = fixture.gateway.lock().map_err(|_| "gateway")?;
        served
            .attempts
            .iter()
            .rev()
            .find(|envelope| envelope.target_delivery_id == "sender")
            .cloned()
            .ok_or("contact request submit")?
    };
    {
        let mut served = fixture.gateway.lock().map_err(|_| "gateway")?;
        served.ack_target = fixture.source.target_delivery_id.clone();
        served.inbox = vec![GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: "sender".into(),
            envelope,
        }];
    }
    let gateway = Arc::clone(&fixture.gateway);
    let mut runtime = start_runtime(&mut fixture).await?;
    drive_pass(&mut runtime, ReceiveTrigger::Tick).await?;
    drive_flush(&mut runtime, true).await?;
    assert_eq!(snap(&runtime)?.cursor, 1, "contact-request bootstrap covers C");
    assert_eq!(acked(&gateway)?, 1, "contact-request bootstrap is ACKed once");
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restart_staged_applies_after_empty_page() -> Case {
    watch(40, restart_staged_applies_after_empty_page_case()).await
}

async fn restart_staged_applies_after_empty_page_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2c-restart-staged")).await?;
    fill_sealed(&mut fixture, 1, 1).await?;
    let entry =
        fixture.gateway.lock().map_err(|_| "gateway")?.inbox.first().cloned().ok_or("entry")?;
    fixture.gateway.lock().map_err(|_| "gateway")?.inbox.clear();
    let config = fixture.source.gateway_config.clone();
    let commitment = fixture.source.principal_commitment.clone();
    let carrier = push_engine(fixture.source.engine.take().ok_or("engine")?)?;
    let account = open_account(&fixture.root, &config, &commitment)?;
    activate(&account)?;
    stage(&account, &entry)?;
    let mut runtime = runtime_for(account, &fixture.root);
    let hold = sweep_hold();
    runtime.timeouts = sweep_timeouts();
    if let Some(account) = runtime.state.accounts.get_mut("sender") {
        account.gateway_config.timeout = hold;
        account.gateway_config.quic_fallback_timeout = hold;
        account.timeouts = runtime.timeouts.clone();
    }
    runtime.start_connection()?;
    runtime.state.accounts.get_mut("sender").ok_or("account")?.engine = Some(carrier);
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    wait_until_live(&mut runtime, &handle).await?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while snap(&runtime)?.cursor != 1 && std::time::Instant::now() < deadline {
        pump_anchored(&mut runtime, &handle).await?;
    }
    assert_eq!(snap(&runtime)?.cursor, 1, "staged retry must apply after an empty Connected page");
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn oversize_fetch_entry_refreshes_cursor() -> Case {
    watch(40, oversize_fetch_entry_refreshes_cursor_case()).await
}

async fn oversize_fetch_entry_refreshes_cursor_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2c-oversize")).await?;
    fill_sealed(&mut fixture, 1, 1).await?;
    let entry =
        fixture.gateway.lock().map_err(|_| "gateway")?.inbox.first().cloned().ok_or("entry")?;
    fixture.gateway.lock().map_err(|_| "gateway")?.inbox.clear();
    let mut runtime = start_runtime(&mut fixture).await?;
    assert_eq!(snap(&runtime)?.cursor, 0, "empty Connected page leaves C at 0");
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.inbox.push(entry);
        gateway.oversize_next = Some(1);
        gateway.fetches.clear();
    }
    drive_pass_anchored(&mut runtime, ReceiveTrigger::Tick).await?;
    assert!(
        !fixture.gateway.lock().map_err(|_| "gateway")?.fetches.is_empty(),
        "oversize catch-up must issue fetch_entry"
    );
    assert_eq!(
        snap(&runtime)?.cursor,
        1,
        "oversize fetch_entry must refresh C before the next resume"
    );
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn start_connection_bind_refuses_standalone_receive() -> Case {
    watch(40, start_connection_bind_refuses_standalone_receive_case()).await
}

async fn start_connection_bind_refuses_standalone_receive_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2c-d5-runtime-bind")).await?;
    let mut runtime = start_runtime_live(&mut fixture)?;
    let account_key = {
        let db = account_of(&runtime)?.client.account_db()?;
        format!("{}:{}", db.path.display(), db.local_account_id)
    };
    let config = account_of(&runtime)?.gateway_config.clone();
    let mut counting = CountingGateway::new(config);
    let account = runtime.state.accounts.get_mut("sender").ok_or("account")?;
    let Err(error) = crate::bus::sync_driver::receive(account, &mut counting, 1).await else {
        panic!("standalone while start_connection bound the actor");
    };
    assert!(
        matches!(
            error,
            SdkError::Storage(StorageError::AccountWriterBusy(ref id)) if *id == account_key
        ),
        "standalone must refuse after start_connection bind: {error:?}"
    );
    assert_eq!(LedgerExecutor::last_bound_owner(), Some(ExecutorOwner::Actor));
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

fn push_incarnation() -> crate::gateway::session_push::IncarnationId {
    crate::gateway::session_push::IncarnationId::try_from(PUSH_E.to_owned()).expect("incarnation")
}

fn publish_deliver(
    handle: &crate::bus::connection_manager::ConnectionHandle,
    entry: GatewayInboxEntry,
) {
    handle.publish_capable(crate::gateway::session_push::CapableEvent::Deliver {
        entry,
        incarnation_id: push_incarnation(),
        retain_until: crate::time::now_unix_timestamp().saturating_add(300),
    });
}

fn publish_resync(handle: &crate::bus::connection_manager::ConnectionHandle, after: u64) {
    handle.publish_capable(crate::gateway::session_push::CapableEvent::Resync {
        incarnation_id: push_incarnation(),
        target_delivery_id: "sender".into(),
        after_inbox_seq: after,
        reason: crate::gateway::session_push::ResyncReason::QueueFull,
    });
}

#[tokio::test(flavor = "current_thread")]
async fn routed_committed_covers_and_acks() -> Case {
    watch(25, routed_committed_covers_and_acks_case()).await
}

async fn routed_committed_covers_and_acks_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("h1-committed")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    let mut runtime = start_runtime(&mut fixture).await?;
    fill_sealed(&mut fixture, 1, 2).await?;
    let first = gateway.lock().map_err(|_| "gateway")?.inbox.first().cloned().ok_or("entry")?;
    {
        let account = account_of(&runtime)?;
        let key = account.client.authenticated_committed_key(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            &first,
        )?;
        account.client.account_db()?.persist_actor_state(
            &key,
            &crate::client::routed::Committed {
                routing: crate::client::routed::Routing {
                    kind: crate::client::routed::Kind::Direct,
                    conversation_id: "healthy".into(),
                    group_id: None,
                    message_id: "committed-seed".into(),
                    group_message_id: None,
                    attachments: false,
                },
                entry: first,
                projected: false,
            },
        )?;
    }
    crate::bus::push_receiver::apply_w1::set_projection_error(SdkError::IdentityRootMissing);
    drive_pass(&mut runtime, ReceiveTrigger::Tick).await?;
    drive_flush(&mut runtime, true).await?;
    assert_eq!(snap(&runtime)?.cursor, 2, "committed-receipt cover via IdentityRootMissing");
    assert_eq!(acked(&gateway)?, 2);
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn reorder_and_gap() -> Case {
    watch(25, reorder_and_gap_case()).await
}

async fn reorder_and_gap_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2d-reorder")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    stop_peer_session(&mut fixture).await;
    let mut runtime = start_runtime(&mut fixture).await?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    fill_sealed(&mut fixture, 1, 2).await?;
    let entries = gateway.lock().map_err(|_| "gateway")?.inbox.clone();
    let seq2 = entries.iter().find(|e| e.inbox_seq == 2).cloned().ok_or("seq2")?;
    let seq1 = entries.iter().find(|e| e.inbox_seq == 1).cloned().ok_or("seq1")?;
    tokio::time::pause();
    publish_deliver(&handle, seq2);
    pump_anchored(&mut runtime, &handle).await?;
    assert_eq!(snap(&runtime)?.cursor, 0, "hole stays until the sibling arrives");
    assert!(
        snap(&runtime)?.receipts.iter().any(|row| row.0 == 2 && row.1 == "staged"),
        "Deliver seq 2 is durable W0: {:?}",
        snap(&runtime)?.receipts
    );
    tokio::time::advance(Duration::from_millis(200)).await;
    pump_anchored(&mut runtime, &handle).await?;
    assert_eq!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len(),
        1,
        "no Resume before the sibling arrives"
    );
    publish_deliver(&handle, seq1);
    pump_anchored(&mut runtime, &handle).await?;
    assert_eq!(snap(&runtime)?.cursor, 2, "contiguous apply of 1 then 2");
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn gap_timer() -> Case {
    watch(25, gap_timer_case()).await
}

async fn gap_timer_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2d-gap")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    stop_peer_session(&mut fixture).await;
    let mut runtime = start_runtime(&mut fixture).await?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    fill_sealed(&mut fixture, 1, 2).await?;
    let seq2 = gateway
        .lock()
        .map_err(|_| "gateway")?
        .inbox
        .iter()
        .find(|e| e.inbox_seq == 2)
        .cloned()
        .ok_or("seq2")?;
    let connected = gateway.lock().map_err(|_| "gateway")?.resumes.len();
    let receive_baseline = handle.test_receive_trace().iter().filter(|entry| entry.1).count();
    tokio::time::pause();
    publish_deliver(&handle, seq2);
    pump_anchored(&mut runtime, &handle).await?;
    tokio::time::advance(Duration::from_millis(499)).await;
    pump_anchored(&mut runtime, &handle).await?;
    assert_eq!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len(),
        connected,
        "no Resume before 500 ms"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    handle.notify_receive_wake();
    let gateway_gap = Arc::clone(&gateway);
    pump_until(&mut runtime, Duration::from_secs(2), || {
        gateway_gap.lock().is_ok_and(|g| g.resumes.len() > connected)
    })
    .await?;
    assert!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len() > connected,
        "exactly one Resume at 500 ms err={:?} trace={:?}",
        handle.test_receive_last_error(),
        handle.test_receive_trace()
    );
    // A recorded Resume request precedes response intake and actor ApplyPage work.
    // Wait for the completed receive pass, rather than a fixed number of idle yields.
    let completion = handle.clone();
    pump_until(&mut runtime, Duration::from_secs(2), || {
        completion.test_receive_trace().iter().filter(|entry| entry.1).count() > receive_baseline
    })
    .await?;
    assert!(
        handle.test_receive_trace().iter().filter(|entry| entry.1).count() > receive_baseline,
        "gap receive pass must finish before the cursor oracle: {:?}",
        handle.test_receive_trace()
    );
    assert_eq!(snap(&runtime)?.cursor, 2, "gap catch-up covers the hole");
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn coalesced_resync() -> Case {
    // Real-time watchdog only: a tokio timeout can fire if catch-up registers a
    // long `limits.sync` sleep under a paused clock.
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            coalesced_resync_case(),
        ))))
        .await
}

async fn coalesced_resync_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2d-resync")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    stop_peer_session(&mut fixture).await;
    let mut runtime = start_runtime(&mut fixture).await?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    fill_sealed(&mut fixture, 1, 2).await?;
    let seq2 = gateway
        .lock()
        .map_err(|_| "gateway")?
        .inbox
        .iter()
        .find(|e| e.inbox_seq == 2)
        .cloned()
        .ok_or("seq2")?;
    let connected = gateway.lock().map_err(|_| "gateway")?.resumes.len();
    tokio::time::pause();
    publish_deliver(&handle, seq2);
    pump_anchored(&mut runtime, &handle).await?;
    publish_resync(&handle, 0);
    publish_resync(&handle, 0);
    handle.notify_receive_wake();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        pump_anchored(&mut runtime, &handle).await?;
        let resumes = gateway.lock().map_err(|_| "gateway")?.resumes.len();
        if resumes > connected {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "Resync hint runs catch-up: {resumes} vs {connected} err={:?} trace={:?}",
                handle.test_receive_last_error(),
                handle.test_receive_trace()
            )
            .into());
        }
    }
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn buffered_push_survives_router_retirement() -> Case {
    // Real-time watchdog only: catch-up under a paused clock can register a
    // long `limits.sync` sleep that would fire `watch(25)`.
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            buffered_push_survives_router_retirement_case(),
        ))))
        .await
}

async fn buffered_push_survives_router_retirement_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2d-retire")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    stop_peer_session(&mut fixture).await;
    let mut runtime = start_runtime(&mut fixture).await?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    fill_sealed(&mut fixture, 1, 2).await?;
    let seq2 = gateway
        .lock()
        .map_err(|_| "gateway")?
        .inbox
        .iter()
        .find(|e| e.inbox_seq == 2)
        .cloned()
        .ok_or("seq2")?;
    tokio::time::pause();
    publish_deliver(&handle, seq2);
    pump_anchored(&mut runtime, &handle).await?;
    {
        let mut served = gateway.lock().map_err(|_| "gateway")?;
        served.resume_losses = vec![(1, 2, "expired")];
        served.resume_issued = Some(2);
        served.inbox.clear();
    }
    handle.reorder().note_hint(crate::bus::push_receiver::reorder::CatchUpHint::Resync);
    handle.notify_receive_wake();
    pump_anchored(&mut runtime, &handle).await?;
    let held = snap(&runtime)?;
    assert!(
        held.receipts.iter().any(|row| row.0 == 2 && row.1 == "staged"),
        "durable W0 survives retirement: {held:?}"
    );
    assert!(
        !held.losses.iter().any(|row| row.0 <= 2 && row.1 >= 2 && row.3 == "expired" && row.0 != 1),
        "seq 2 is not a loss: {held:?}"
    );
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn push_without_polling() -> Case {
    watch(25, push_without_polling_case()).await
}

async fn push_without_polling_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p24b2d-nopoll")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    stop_peer_session(&mut fixture).await;
    let mut runtime = start_runtime(&mut fixture).await?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    fill_sealed(&mut fixture, 1, 1).await?;
    let connected = gateway.lock().map_err(|_| "gateway")?.resumes.len();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(5)).await;
    pump_anchored(&mut runtime, &handle).await?;
    assert_eq!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len(),
        connected,
        "idle 5s must not Resume"
    );
    let seq1 = gateway.lock().map_err(|_| "gateway")?.inbox.first().cloned().ok_or("seq1")?;
    publish_deliver(&handle, seq1);
    pump_anchored(&mut runtime, &handle).await?;
    assert_eq!(snap(&runtime)?.cursor, 1, "Deliver applies without a poll");
    assert_eq!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len(),
        connected,
        "Deliver path does not Resume"
    );
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

/// Two SDK accounts, default-on activation: peer seals through the real `RouterCore` bound to
/// the TLS gateway, recipient catch-up/ACK on the wire, then restart with pending messages.
#[tokio::test(flavor = "current_thread")]
async fn session_push_two_account_restart_catch_up() -> Case {
    watch(40, session_push_two_account_restart_catch_up_case()).await
}

async fn session_push_two_account_restart_catch_up_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("p25-e2e-restart")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    stop_peer_session(&mut fixture).await;
    let router = Arc::new(ramflux_node_core::RouterCore::new());
    let store = Arc::new(
        ramflux_node_core::RouterRedbStore::open(fixture.root.join("router.redb"))
            .map_err(|error| SdkError::LocalBus(error.to_string()))?,
    );
    store.bootstrap_router(&router).map_err(|error| SdkError::LocalBus(error.to_string()))?;
    let incarnation =
        store.initialize_inbox("sender").map_err(|error| SdkError::LocalBus(error.to_string()))?;
    {
        let mut gateway = gateway.lock().map_err(|_| "gateway")?;
        for account in [&fixture.source, &fixture.peer, &fixture.sibling] {
            let identity = account.client.owned_device_identity()?;
            gateway.router_sources.insert(identity.device_id().to_owned(), identity);
        }
        gateway.inbox_incarnation = Some(incarnation.clone());
        gateway.router = Some((Arc::clone(&router), Arc::clone(&store)));
    }

    let mut runtime = start_runtime_default_on(&mut fixture).await?;
    assert_eq!(
        account_of(&runtime)?.client.account_db()?.receive_activation()?,
        ramflux_storage::ReceiveActivation::Activated
    );
    assert_eq!(
        account_of(&runtime)?
            .client
            .account_db()?
            .receive_epoch(&account_of(&runtime)?.target_delivery_id)?
            .as_deref(),
        Some(incarnation.as_str()),
        "fresh default-on Push binds the gateway incarnation"
    );
    router
        .prepare_publication_target(&store, "sender")
        .map_err(|error| SdkError::LocalBus(error.to_string()))?;
    let first_ids = submit_peer_through_gateway(&mut fixture, 1, 2).await?;
    drive_pass(&mut runtime, ReceiveTrigger::Connected).await?;
    drive_flush(&mut runtime, true).await?;
    assert_eq!(snap(&runtime)?.cursor, 2, "first catch-up applies both live messages");
    assert_eq!(acked(&gateway)?, 2, "WA ACKs both live sequences");
    assert!(snap(&runtime)?.intents.is_empty(), "ACK settles live intents");
    let applied = applied_message_ids(&runtime)?;
    assert_eq!(
        applied.iter().collect::<std::collections::BTreeSet<_>>(),
        first_ids.iter().collect::<std::collections::BTreeSet<_>>(),
        "live application is complete"
    );
    assert_eq!(applied.len(), 2, "live application is duplicate-free");

    let config = fixture.source.gateway_config.clone();
    let commitment = fixture.source.principal_commitment.clone();
    runtime.stop_connection().await;
    drop(runtime);

    let pending_ids = submit_peer_through_gateway(&mut fixture, 3, 2).await?;
    let mut expected = first_ids.clone();
    expected.extend(pending_ids);

    let restarted = open_account(&fixture.root, &config, &commitment)?;
    assert_eq!(
        restarted.client.account_db()?.receive_activation()?,
        ramflux_storage::ReceiveActivation::Activated,
        "restart keeps the discriminator"
    );
    let mut runtime = runtime_for(restarted, &fixture.root);
    runtime.timeouts = sweep_timeouts();
    if let Some(account) = runtime.state.accounts.get_mut("sender") {
        account.timeouts = runtime.timeouts.clone();
        account.engine = None;
    }
    runtime.start_connection()?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    wait_until_live(&mut runtime, &handle).await?;
    wait_connected_receive(&mut runtime, &handle).await?;
    drive_pass(&mut runtime, ReceiveTrigger::Connected).await?;
    drive_flush(&mut runtime, true).await?;
    assert_eq!(snap(&runtime)?.cursor, 4, "restart catch-up applies pending messages");
    assert!(snap(&runtime)?.intents.is_empty(), "restart has no leftover ACK intent");
    let applied = applied_message_ids(&runtime)?;
    assert_eq!(
        applied.iter().collect::<std::collections::BTreeSet<_>>(),
        expected.iter().collect::<std::collections::BTreeSet<_>>(),
        "restart application is complete"
    );
    assert_eq!(applied.len(), 4, "restart application is duplicate-free");
    assert_eq!(acked(&gateway)?, 4, "node ACKs all four sequences on the wire");
    let acked_ids = gateway.lock().map_err(|_| "gateway")?.acked.clone();
    for id in &expected {
        assert!(acked_ids.contains(id), "node settled {id}");
    }
    drop(runtime);
    drop(store);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

async fn submit_peer_through_gateway(
    fixture: &mut Fixture,
    start: u64,
    n: u64,
) -> Case<Vec<String>> {
    let target = Target {
        device: "device-sender".into(),
        identity: fixture.source.client.owned_device_identity()?,
        delivery: "sender".into(),
        federation: None,
        own: false,
    };
    let source = fixture.peer.client.owned_device_identity()?;
    let mut engine = fixture.peer.session_client().await?;
    let mut envelopes = Vec::new();
    for offset in 0..n {
        let seq = start.saturating_add(offset);
        let dm = seal(
            &fixture.peer,
            &mut engine,
            &target,
            "healthy",
            format!("wa-{seq}").as_bytes(),
            crate::client::routed::Route::direct(),
        )
        .await?;
        envelopes.push(dm.envelope);
    }
    fixture.peer.install_test_session(engine);
    let router = {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.ack_target = "sender".into();
        gateway.router.clone().ok_or("router bound to gateway")?
    };
    let mut ids = Vec::new();
    let mut queued_entries = Vec::new();
    for envelope in envelopes {
        ids.push(envelope.envelope_id.clone());
        let queued =
            super::fixture::publish_router_envelope(&router.0, &router.1, &source, envelope)
                .await?;
        queued_entries.push(queued);
    }
    let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
    for queued in queued_entries {
        gateway.inbox.push(GatewayInboxEntry {
            forwarded: false,
            inbox_seq: queued.inbox_seq,
            target_delivery_id: queued.target_delivery_id.clone(),
            envelope: queued.envelope.clone(),
        });
    }
    Ok(ids)
}

fn applied_message_ids(
    runtime: &super::super::AccountRuntime,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let account = account_of(runtime)?;
    Ok(account
        .client
        .direct_messages("healthy")?
        .into_iter()
        .map(|message| message.message_id)
        .collect())
}

#[tokio::test(flavor = "current_thread")]
async fn resume_fixture_isolates_target_watermarks() -> Case {
    let mut fixture = Fixture::new("resume-target-watermarks").await?;
    fill_sealed(&mut fixture, 4, 1).await?;
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        let mut other = gateway.inbox.first().ok_or("entry")?.clone();
        other.target_delivery_id = "other".into();
        other.envelope.target_delivery_id = "other".into();
        other.inbox_seq = 1;
        gateway.inbox.push(other);
    }
    let request = serde_json::json!({ "incarnation_id": PUSH_E,
        "resume": { "target_delivery_id": "sender", "after_inbox_seq": 2, "limit": 64 } });
    let page = super::fixture::resume_page_response(&fixture.gateway, &request)?;
    assert_eq!(page["issued_inbox_seq"], 4);
    assert_eq!(page["covered_through_seq"], 4);
    assert!(
        page["entries"]
            .as_array()
            .ok_or("entries")?
            .iter()
            .all(|row| row["entry"]["target_delivery_id"] == "sender")
    );
    drop(fixture);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn compat_then_push_actor_keeps_receive_live() -> Case {
    watch(30, async {
        let mut fixture = Fixture::new("compat-push-actor").await?;
        let target = fixture.source.target_delivery_id.clone();
        let _ = fixture.source.client.account_db()?.activate_receive_ledger(ReceiveMigrate {
            target: &target,
            incarnation: "compat-local",
        })?;
        fill_sealed(&mut fixture, 1, 1).await?;
        let entry = fixture
            .gateway
            .lock()
            .map_err(|_| "gateway")?
            .inbox
            .first()
            .cloned()
            .ok_or("Compat entry")?;
        let turn = crate::bus::sync_driver::source::w0::actor_turn(&fixture.source, 1)?
            .ok_or("Compat turn")?;
        let _ = crate::bus::push_receiver::intake::stage_on_actor(
            &fixture.source,
            1,
            &entry,
            "compat-local",
            crate::time::now_unix_timestamp() + 300,
        )?;
        let db = fixture.source.client.account_db()?;
        let _ = db.receive_transaction(turn.expected(), 1, |tx| {
            tx.cover(ramflux_storage::ReceiveCover {
                sequence: 1,
                kind: ramflux_storage::ReceiveCoverKind::CompatTerminal,
                gaps: &[],
                retain_until: 0,
            })
        })?;
        assert_eq!(
            db.receive_ledger_snap_for_test(&target)?.intents,
            vec![1],
            "real Compat cover plants the old ACK intent"
        );
        let mut runtime = start_runtime_default_on(&mut fixture).await?;
        drive_pass(&mut runtime, ReceiveTrigger::Connected).await?;
        drive_flush(&mut runtime, true).await?;
        let account = account_of(&runtime)?;
        assert_eq!(account.client.account_db()?.receive_epoch(&target)?.as_deref(), Some(PUSH_E));
        assert_eq!(snap(&runtime)?.cursor, 1);
        assert_eq!(
            snap(&runtime)?.intents,
            Vec::<u64>::new(),
            "actor transition settles all ACK intents"
        );
        assert_eq!(acked(&fixture.gateway)?, 1);
        assert_eq!(applied_message_ids(&runtime)?.len(), 1);
        runtime.stop_connection().await;
        Ok(())
    })
    .await
}

/// A Compat application with a lost ACK is re-fetched after C resets from 1 to S=0.
/// The application receipt and projection claim must survive the epoch change.
#[tokio::test(flavor = "current_thread")]
async fn compat_ack_lag_reset_does_not_reapply_or_project() -> Case {
    watch(40, compat_ack_lag_reset_case()).await
}

async fn compat_ack_lag_reset_case() -> Case {
    let mut fixture = Fixture::new("compat-ack-lag-reset").await?;
    let target = fixture.source.target_delivery_id.clone();
    let db = fixture.source.client.account_db()?;
    let _ = db
        .activate_receive_ledger(ReceiveMigrate { target: &target, incarnation: "compat-local" })?;
    db.mark_receive_incarnation_unverified_for_test(&target)?;
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.compat_ack_loss = Some(0);
    }
    fill_sealed(&mut fixture, 1, 1).await?;
    let mut runtime =
        start_runtime_default_on(&mut fixture).await.map_err(|e| format!("Compat connect: {e}"))?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    assert!(!handle.session_is_push(), "first application must use Compat");
    // ACK transport loss can surface as an error or a committed Uncertain result.
    // The durable cursor/message/intent assertions below pin the required cut.
    let compat_pass = drive_pass(&mut runtime, ReceiveTrigger::Connected).await;
    assert_eq!(snap(&runtime)?.cursor, 1, "Compat application committed: {compat_pass:?}");
    // Make this persisted intent due without a sleep or virtual-time advancement.
    let now = crate::time::now_unix_timestamp();
    account_of(&runtime)?.client.account_db()?.set_ack_intent_clock_for_test(now - 2, now - 1)?;
    let compat_flush = drive_flush(&mut runtime, true).await;
    assert_eq!(
        snap(&runtime)?.intents,
        vec![1],
        "old ACK remains pending after transport loss: {compat_flush:?}"
    );
    let ids = applied_message_ids(&runtime)?;
    assert_eq!(ids.len(), 1, "one durable application before reset");
    {
        let account = runtime.state.accounts.get_mut("sender").ok_or("account")?;
        assert_eq!(account.pending_deliveries.len(), 1, "one initial projection");
        account.pending_deliveries.clear(); // Application consumed the original event.
    }
    {
        let gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        assert!(gateway.acked.is_empty(), "node has not settled the Compat ACK");
        assert_eq!(gateway.compat_ack_loss, Some(1), "ACK actually reached the wire");
    }
    let config = account_of(&runtime)?.gateway_config.clone();
    let commitment = account_of(&runtime)?.principal_commitment.clone();
    runtime.stop_connection().await;
    drop(runtime);
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.compat_ack_loss = None;
    }
    let restarted = open_account(&fixture.root, &config, &commitment)
        .map_err(|e| format!("reopen after ACK loss: {e}"))?;
    assert_eq!(restarted.client.gateway_receive_cursor(&target)?, 1);
    let mut runtime = runtime_for(restarted, &fixture.root);
    runtime.timeouts = sweep_timeouts();
    runtime.state.accounts.get_mut("sender").ok_or("account")?.engine = None;
    runtime.start_connection().map_err(|e| format!("start Push: {e}"))?;
    let handle = account_of(&runtime)?.connection.clone().ok_or("handle")?;
    wait_until_live(&mut runtime, &handle).await.map_err(|e| format!("reconcile Push: {e}"))?;
    assert_eq!(snap(&runtime)?.cursor, 0, "reset uses S=0 < C_old=1");
    assert_eq!(
        account_of(&runtime)?.client.account_db()?.receive_epoch(&target)?.as_deref(),
        Some(PUSH_E)
    );
    assert!(snap(&runtime)?.intents.is_empty(), "old-E intent retired before new receive");
    wait_connected_receive(&mut runtime, &handle)
        .await
        .map_err(|e| format!("Push refetch: {e}"))?;
    drive_flush(&mut runtime, true).await.map_err(|e| format!("Push ACK: {e}"))?;
    assert_eq!(applied_message_ids(&runtime)?, ids, "no duplicate durable message");
    assert_eq!(
        account_of(&runtime)?.pending_deliveries.len(),
        0,
        "no duplicate application projection after refetch"
    );
    assert_eq!(snap(&runtime)?.cursor, 1);
    assert!(snap(&runtime)?.losses.is_empty(), "refetch is not classified as loss");
    assert!(snap(&runtime)?.intents.is_empty(), "new-E ACK settled");
    assert_eq!(acked(&fixture.gateway)?, 1, "one new-E terminal ACK");
    runtime.stop_connection().await;
    Ok(())
}
