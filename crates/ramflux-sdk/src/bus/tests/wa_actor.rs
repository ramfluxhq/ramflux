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
    PUSH_E, account_of, acked, open_account, pump_quiet, push_engine, runtime_for,
};
use crate::bus::connection_manager::{ReceiveTrigger, receive::test_catch_up};
use crate::bus::dispatch::task_transport::{Target, seal};
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

async fn start_runtime(
    fixture: &mut Fixture,
) -> Result<super::super::AccountRuntime, Box<dyn std::error::Error>> {
    let config = fixture.source.gateway_config.clone();
    let commitment = fixture.source.principal_commitment.clone();
    let carrier = push_engine(fixture.source.engine.take().ok_or("engine")?)?;
    let account = open_account(&fixture.root, &config, &commitment)?;
    activate(&account)?;
    let mut runtime = runtime_for(account, &fixture.root);
    runtime.start_connection()?;
    runtime.state.accounts.get_mut("sender").ok_or("account")?.engine = Some(carrier);
    pump_quiet(&mut runtime, Duration::from_millis(150)).await?;
    Ok(runtime)
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
        db.seed_held_receive_for_test(&target, PUSH_E, 2, b"{}")?;
        db.seed_ack_intent_for_test(&target, PUSH_E, 2)?;
        db.seed_ack_intent_for_test(&target, PUSH_E, 9)?;
        assert_eq!(
            db.receive_ledger_snap_for_test(&target)?.intents,
            vec![2, 9],
            "held seq 2 and seq>C 9 sit above C"
        );
    }
    crate::time::test_clock::set_frozen(Some(100));
    let flushed = drive_flush(&mut runtime, true).await;
    crate::time::test_clock::set_frozen(None);
    flushed?;
    assert_eq!(acked(&gateway)?, 1, "actor never ACKs held or seq>C intents");
    assert_eq!(snap(&runtime)?.intents, vec![2, 9]);
    runtime.stop_connection().await;
    drop(runtime);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ack_batch_timing() -> Case {
    watch(60, ack_batch_timing_case()).await
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
    {
        let _clock = crate::time::test_clock::FrozenClock::freeze();
        drive_pass(&mut runtime3, ReceiveTrigger::Tick).await?;
    }
    assert_eq!(acked(&gateway3)?, 0, "Tick does not force a 3-intent flush");
    account_of(&runtime3)?.client.account_db()?.set_ack_intent_clock_for_test(100, 100)?;
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
