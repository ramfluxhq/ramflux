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
    PUSH_E, account_of, acked, open_account, pump_quiet, push_engine, runtime_for, stage,
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
use ramflux_storage::{ACK_FLUSH_COUNT, ACK_FLUSH_SECS, ReceiveLedgerSnap, ReceiveMigrate};
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
    pump_quiet(&mut runtime, Duration::from_millis(150)).await?;
    Ok(runtime)
}

fn start_runtime_live(
    fixture: &mut Fixture,
) -> Result<super::super::AccountRuntime, Box<dyn std::error::Error>> {
    let config = fixture.source.gateway_config.clone();
    let commitment = fixture.source.principal_commitment.clone();
    let carrier = push_engine(fixture.source.engine.take().ok_or("engine")?)?;
    let account = open_account(&fixture.root, &config, &commitment)?;
    activate(&account)?;
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
    Ok(runtime)
}

async fn drive_full_pass(
    runtime: &mut super::super::AccountRuntime,
    trigger: ReceiveTrigger,
) -> Case {
    let handle = account_of(runtime)?.connection.clone().ok_or("handle")?;
    let generation = handle.generation();
    let work = runtime.connection_sender.clone();
    let mut pass = tokio::task::spawn_local(async move {
        test_pass(&handle, &work, generation, trigger, Duration::from_secs(8)).await
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

async fn drive_pass(runtime: &mut super::super::AccountRuntime, trigger: ReceiveTrigger) -> Case {
    let handle = account_of(runtime)?.connection.clone().ok_or("handle")?;
    let generation = handle.generation();
    let work = runtime.connection_sender.clone();
    let mut pass = tokio::task::spawn_local(async move {
        test_catch_up(&handle, &work, generation, trigger, Duration::from_secs(8)).await
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

async fn drive_flush(runtime: &mut super::super::AccountRuntime, force: bool) -> Case {
    let handle = account_of(runtime)?.connection.clone().ok_or("handle")?;
    let generation = handle.generation();
    let work = runtime.connection_sender.clone();
    let mut pass = tokio::task::spawn_local(async move {
        crate::bus::connection_manager::receive::flush_acks(
            &handle,
            &work,
            generation,
            force,
            Duration::from_secs(8),
        )
        .await
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
    drive_flush(&mut runtime, true).await?;
    assert_eq!(acked(&gateway)?, 1, "WA ACKs only seq <= C");
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
        ACK_FLUSH_COUNT.saturating_mul(2),
        "33 entries on one FrozenClock Tick flush 32 mid catch-up"
    );
    assert_eq!(snap(&runtime33)?.intents, vec![n.saturating_mul(2).saturating_add(1)]);
    runtime33.stop_connection().await;
    drop(runtime33);
    std::fs::remove_dir_all(thirty_three.root)?;

    let mut three = Box::pin(Fixture::new("wa-timing-3")).await?;
    let gateway3 = Arc::clone(&three.gateway);
    let mut runtime3 = start_runtime(&mut three).await?;
    fill_sealed(&mut three, 1, 3).await?;
    let _clock = crate::time::test_clock::FrozenClock::freeze();
    drive_pass(&mut runtime3, ReceiveTrigger::Tick).await?;
    assert_eq!(acked(&gateway3)?, 0, "Tick does not force a 3-intent flush");
    // ACK age is unix seconds; FrozenClock is the harness paused clock for this bound.
    let aged = crate::time::now_unix_timestamp().saturating_add(ACK_FLUSH_SECS);
    crate::time::test_clock::set_frozen(Some(aged));
    drive_pass(&mut runtime3, ReceiveTrigger::Tick).await?;
    assert_eq!(acked(&gateway3)?, 3, "1s-old intents flush on Tick");
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
    {
        let _clock = crate::time::test_clock::FrozenClock::freeze();
        drive_pass(&mut runtime, ReceiveTrigger::Tick).await?;
    }
    assert_eq!(snap(&runtime)?.intents, vec![1, 2]);
    gateway.lock().map_err(|_| "gateway")?.ack_fail = true;
    let guard = crate::bus::push_receiver::ack_batch::arm_fault();
    let lost = drive_flush(&mut runtime, true).await;
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

async fn drain_ready(runtime: &mut super::super::AccountRuntime) -> Case {
    for _ in 0..64 {
        tokio::task::yield_now().await;
        let mut any = false;
        while let Ok(work) = runtime.connection_work.try_recv() {
            any = true;
            runtime.apply_connection_work(work).await?;
        }
        if !any {
            break;
        }
    }
    Ok(())
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
            drain_ready(runtime).await?;
            return Ok(());
        }
        match tokio::time::timeout(Duration::from_millis(20), runtime.connection_work.recv()).await
        {
            Ok(Some(work)) => runtime.apply_connection_work(work).await?,
            Ok(None) => return Err("connection work closed".into()),
            Err(_) => poll_spawned().await,
        }
    }
    Err("session did not become Live".into())
}

async fn pump_anchored(
    runtime: &mut super::super::AccountRuntime,
    handle: &crate::bus::connection_manager::ConnectionHandle,
) -> Case {
    handle.notify_receive_wake();
    let mut idle = 0_u32;
    for _ in 0..256 {
        drain_ready(runtime).await?;
        poll_spawned().await;
        let live = handle.snapshot().state == NetworkingState::Live;
        let busy = handle.queued_calls() > 0 || handle.in_flight_calls() > 0;
        if !live || busy {
            idle = 0;
            // Park on the work channel so the current-thread runtime polls TCP.
            // Do not use tokio::time::timeout: a paused clock never fires it.
            let work = runtime.connection_work.recv().await.ok_or("connection work closed")?;
            runtime.apply_connection_work(work).await?;
            continue;
        }
        tokio::task::yield_now().await;
        idle = idle.saturating_add(1);
        if idle >= 4 {
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
    let mut fixture = Box::pin(Fixture::new("p24b2c-sweep")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    fill_sealed(&mut fixture, 1, 1).await?;
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
    // std-thread oneshot (not a tokio timer). Measure the 100 ms bound only
    // after that work finishes, over time the actor actually controls.
    let (release_hold, hold) = std::sync::mpsc::channel::<()>();
    let inhibit = tokio::task::spawn_blocking(move || {
        let _ = hold.recv();
    });
    let wait_resume = std::time::Instant::now();
    loop {
        drain_ready(&mut runtime).await?;
        poll_spawned().await;
        if !gateway.lock().map_err(|_| "gateway")?.resumes.is_empty() {
            break;
        }
        if wait_resume.elapsed() > Duration::from_secs(10) {
            break;
        }
        let busy = handle.queued_calls() > 0 || handle.in_flight_calls() > 0;
        if busy {
            let work = runtime.connection_work.recv().await.ok_or("connection work closed")?;
            runtime.apply_connection_work(work).await?;
            continue;
        }
        tokio::task::yield_now().await;
    }
    drop(release_hold);
    let _ = inhibit.await;
    let within = live_at.elapsed();
    let in_100 = gateway.lock().map_err(|_| "gateway")?.resumes.len();
    assert_eq!(in_100, 1, "Connected catch-up Resume within 100ms: {in_100} elapsed={within:?}");
    assert!(within <= catch_up, "first Resume measured at {within:?}");
    if within < catch_up {
        tokio::time::advance(catch_up.saturating_sub(within)).await;
        pump_anchored(&mut runtime, &handle).await?;
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
    pump_anchored(&mut runtime, &handle).await?;
    tokio::time::advance(Duration::from_secs(899)).await;
    pump_anchored(&mut runtime, &handle).await?;
    assert_eq!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len(),
        1,
        "no Resume until 900s snap={:?}",
        handle.snapshot()
    );
    tokio::time::advance(Duration::from_millis(1_000)).await;
    pump_anchored(&mut runtime, &handle).await?;
    let resumes = gateway.lock().map_err(|_| "gateway")?.resumes.len();
    assert!(
        resumes >= 2,
        "Sweep Resume at 900s: resumes={resumes} trace={:?} err={:?} snap={:?}",
        handle.test_receive_trace(),
        handle.test_receive_last_error(),
        handle.snapshot()
    );
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
    pump_anchored(&mut runtime, &handle).await?;
    assert!(
        gateway.lock().map_err(|_| "gateway")?.resumes.len() > connected,
        "exactly one Resume at 500 ms err={:?} trace={:?}",
        handle.test_receive_last_error(),
        handle.test_receive_trace()
    );
    pump_anchored(&mut runtime, &handle).await?;
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
