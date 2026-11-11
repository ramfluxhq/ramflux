// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Overflow recovery reaches the real writer without ticks, reconnects, or subscriber pulls.

use super::fixture::{Case, Fixture};
use super::receive_ack::{command, limits, start};
use crate::bus::connection_manager::{
    ConnectionHandle, ReceiveTrigger, subscriptions::SessionEvent,
};
use crate::client::identity_authority::HeadUse;
use crate::gateway::frame_dispatch::FrameKind;
use crate::prelude::*;
use serde_json::json;
use std::time::Instant as WallClock;

#[path = "receive_resync/work.rs"]
mod work;

// Wall-clock cap on the durable recovery phase. It sits below the 120 s nextest kill window
// for these tests (.config/nextest.toml) so a slow run fails with its own trace, not a SIGKILL.
const DURABLE_RECOVERY_COMPLETION_LIMIT: Duration = Duration::from_secs(180);

struct Recovery {
    started: super::receive_ack::Started,
    reader: ramflux_storage::AccountDb,
    handle: ConnectionHandle,
    io: crate::bus::connection_manager::tests::SessionIo,
    entries: Vec<GatewayInboxEntry>,
    receipts: Vec<String>,
    slow: Option<crate::bus::connection_manager::SessionSubscription>,
    draining: Option<tokio::task::JoinHandle<()>>,
    released: WallClock,
    probe: Option<ramflux_storage::SqlWorkProbe>,
}

#[tokio::test(flavor = "current_thread")]
async fn receive_resync_recovers_entry_overflow_with_two_subscribers() -> Case {
    run(266, None, true).await
}
#[tokio::test(flavor = "current_thread")]
async fn receive_resync_recovers_entry_overflow_without_subscribers() -> Case {
    run(266, None, false).await
}
#[tokio::test(flavor = "current_thread")]
async fn receive_resync_recovers_byte_overflow_below_the_entry_cap() -> Case {
    run(9, Some(960 * 1024), true).await
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Completion {
    Trigger,
    Durable,
}
#[tokio::test(flavor = "current_thread")]
async fn resync_trigger_requests_entry_overflow_with_two_subscribers() -> Case {
    run_mode(266, None, true, Completion::Trigger).await
}
#[tokio::test(flavor = "current_thread")]
async fn resync_trigger_requests_entry_overflow_without_subscribers() -> Case {
    run_mode(266, None, false, Completion::Trigger).await
}
#[tokio::test(flavor = "current_thread")]
async fn resync_trigger_requests_byte_overflow_below_the_entry_cap() -> Case {
    run_mode(9, Some(960 * 1024), true, Completion::Trigger).await
}
async fn run(count: usize, frame_bytes: Option<usize>, subscribers: bool) -> Case {
    run_mode(count, frame_bytes, subscribers, Completion::Durable).await
}
async fn run_mode(
    count: usize,
    frame_bytes: Option<usize>,
    subscribers: bool,
    completion: Completion,
) -> Case {
    LocalSet::new()
        .run_until(Box::pin(async move {
            let mut fixture = Box::pin(Fixture::new("receive-resync-overflow")).await?;
            let prepared = WallClock::now();
            let entries = Box::pin(entries(&mut fixture, count, frame_bytes)).await?;
            eprintln!("prepared {count} authenticated inbox entries in {:?}", prepared.elapsed());
            let receipts = if completion == Completion::Durable {
                entries
                    .iter()
                    .map(|entry| {
                        fixture
                            .source
                            .client
                            .authenticated_committed_key(HeadUse::NewAuthorization, entry)
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            };
            if completion == Completion::Trigger {
                return crate::bus::connection_manager::tests::watchdog(Box::pin(async {
                    let state = Box::pin(prepare_case(
                        fixture,
                        entries,
                        receipts,
                        frame_bytes,
                        subscribers,
                        completion,
                    ))
                    .await?;
                    Box::pin(cleanup(state.started, state.reader, state.slow, state.draining)).await
                }))
                .await;
            }
            let mut state = liveness(Box::pin(prepare_case(
                fixture,
                entries,
                receipts,
                frame_bytes,
                subscribers,
                completion,
            )))
            .await?;
            let acked = tokio::time::timeout(
                DURABLE_RECOVERY_COMPLETION_LIMIT,
                recover(
                    &state.handle,
                    &mut state.io,
                    &state.entries,
                    &state.reader,
                    &state.receipts,
                    state.probe.as_ref(),
                ),
            )
            .await??;
            eprintln!(
                "durable recovery completed after {:?}: {} ACKs; phases: {:?}",
                state.released.elapsed(),
                acked.len(),
                state.handle.test_receive_profile()
            );
            liveness(Box::pin(finish_case(state, acked))).await
        }))
        .await
}
async fn prepare_case(
    mut fixture: Fixture,
    entries: Vec<GatewayInboxEntry>,
    receipts: Vec<String>,
    frame_bytes: Option<usize>,
    subscribers: bool,
    completion: Completion,
) -> Case<Recovery> {
    let count = entries.len();
    let reader = fixture.source.client.account_db()?.open_reader()?;
    let (engine, mut io) = crate::bus::connection_manager::tests::seeded_engine(
        fixture.source.gateway_config.clone(),
        &limits(),
    );
    fixture.source.install_test_session(engine);
    let started = Box::pin(start(fixture)).await?;
    let handle = started.actor.connection_for_test().ok_or("connection handle")?;
    let initial = wait_for(io.output.recv(), "initial Connected Resume frame")
        .await?
        .ok_or("session output closed before initial Connected Resume frame")?;
    assert!(
        matches!(initial, GatewayClientFrame::Resume { resume } if resume.after_inbox_seq == 0)
    );
    send(&io, &GatewayServerFrame::Resume { entries: Vec::new() })?;
    wait_for(
        handle.test_wait_receive(ReceiveTrigger::Connected),
        "Connected receive completion event",
    )
    .await?;
    let mut slow = subscribers.then(|| handle.subscribe([FrameKind::Deliver]));
    let (drained_tx, mut drained_rx) = tokio::sync::mpsc::unbounded_channel();
    let draining = subscribers.then(|| {
        let mut subscription = handle.subscribe([FrameKind::Deliver]);
        tokio::spawn(async move {
            while let Some(event) = subscription.recv().await {
                if drained_tx.send(event).is_err() {
                    break;
                }
            }
        })
    });
    let held = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .call(
                    |engine| Box::pin(engine.cursor()),
                    tokio::time::Instant::now() + Duration::from_secs(600),
                )
                .await
        })
    };
    let cursor_request = wait_for(io.output.recv(), "held Cursor RPC request")
        .await?
        .ok_or("session output closed before held Cursor RPC request")?;
    assert!(matches!(cursor_request, GatewayClientFrame::Cursor { .. }));
    let mut second_subscriber_lagged = false;
    for entry in &entries {
        send(&io, &GatewayServerFrame::Deliver { entry: entry.clone() })?;
        if subscribers && !second_subscriber_lagged {
            match wait_for(drained_rx.recv(), "second subscriber delivery or overflow event")
                .await?
                .ok_or("second subscriber closed before its delivery or overflow event")?
            {
                SessionEvent::Frame { frame, .. }
                    if matches!(frame.as_ref(), GatewayServerFrame::Deliver { .. }) => {}
                SessionEvent::Lagged { .. } => second_subscriber_lagged = true,
                _ => return Err("second subscriber received an unexpected event".into()),
            }
        }
    }
    wait_until(|| {
        let stats = handle.test_buffer_stats();
        stats.entries + stats.dropped == count
    })
    .await?;
    assert_buffer_limits(&handle, frame_bytes.is_some());
    eprintln!("overflow barrier reached: {count} frames");
    if let Some(slow) = &mut slow {
        let event = wait_for(slow.recv(), "slow subscriber Lagged event")
            .await?
            .ok_or("slow subscriber closed before its Lagged event")?;
        assert!(matches!(event, SessionEvent::Lagged { .. }));
    }
    assert!(io.output.try_recv().is_err(), "no Resume or ACK may pass the held RPC");
    assert_eq!(
        handle.test_receive_trace(),
        vec![(ReceiveTrigger::Connected, false), (ReceiveTrigger::Connected, true)]
    );
    let released = WallClock::now();
    send(&io, &GatewayServerFrame::Cursor { cursor: None })?;
    wait_for(held, "held Cursor RPC completion").await???;
    let first = wait_for(io.output.recv(), "Resync Resume").await?.ok_or("Resync Resume")?;
    assert!(released.elapsed() < Duration::from_secs(15));
    assert!(matches!(first, GatewayClientFrame::Resume { resume } if resume.after_inbox_seq == 0));
    assert!(handle.test_receive_trace().contains(&(ReceiveTrigger::Resync, false)));
    eprintln!("first recovery Resume after {:?}", released.elapsed());
    let probe = if completion == Completion::Durable {
        Some(handle.test_observe_sql().await?)
    } else {
        None
    };
    Ok(Recovery { started, reader, handle, io, entries, receipts, slow, draining, released, probe })
}
async fn finish_case(state: Recovery, acked: BTreeSet<String>) -> Case {
    let Recovery { started, reader, handle, entries, receipts, slow, draining, probe, .. } = state;
    let count = entries.len();
    work::assert_complete(&handle, probe.as_ref().ok_or("missing SQL observer")?, count);
    assert_eq!(acked.len(), count);
    assert!(!handle.resync_needed(), "clear only after the complete durable handoff");
    assert_completed_trace(&handle);
    let response = started
        .actor
        .request(command("message.read", json!({"conversation_id":"healthy","limit":1000})))
        .await?;
    let messages = response.body["messages"].as_array().ok_or("messages")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["body_utf8"], "resync recovery");
    assert_eq!(reader.actor_state_keys("routed/committed/")?.len(), count);
    for key in &receipts {
        assert!(reader.actor_state_exists(key)?);
    }
    assert_control_effects(&reader, count - 1)?;
    Box::pin(cleanup(started, reader, slow, draining)).await
}
async fn liveness<T>(future: impl std::future::Future<Output = Case<T>>) -> Case<T> {
    let mut value = None;
    crate::bus::connection_manager::tests::watchdog(Box::pin(async {
        value = Some(future.await?);
        Ok(())
    }))
    .await?;
    value.ok_or_else(|| "liveness phase produced no result".into())
}

async fn cleanup(
    started: super::receive_ack::Started,
    reader: ramflux_storage::AccountDb,
    slow: Option<crate::bus::connection_manager::SessionSubscription>,
    draining: Option<tokio::task::JoinHandle<()>>,
) -> Case {
    let stopped = WallClock::now();
    started.actor.stop().await?;
    assert!(stopped.elapsed() < Duration::from_secs(1));
    if let Some(draining) = draining {
        draining.abort();
        let _ = draining.await;
    }
    drop(slow);
    let root = started.root.clone();
    started.router.await?;
    drop(started.actor);
    drop(reader);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn assert_control_effects(reader: &ramflux_storage::AccountDb, expected: usize) -> Case {
    let mut cursor = 0;
    let mut resets = 0;
    loop {
        let page = reader.journal_after(cursor, 128)?;
        let Some(last) = page.last() else { break };
        cursor = last.seq;
        resets += page.iter().filter(|event| event.topic == "session.reset").count();
    }
    assert_eq!(resets, expected, "every authenticated control must project exactly once");
    Ok(())
}
fn assert_completed_trace(handle: &ConnectionHandle) {
    assert_eq!(
        handle.test_receive_trace(),
        vec![
            (ReceiveTrigger::Connected, false),
            (ReceiveTrigger::Connected, true),
            (ReceiveTrigger::Resync, false),
            (ReceiveTrigger::Resync, true),
        ]
    );
}
fn assert_buffer_limits(handle: &ConnectionHandle, byte_bound: bool) {
    let stats = handle.test_buffer_stats();
    assert_eq!(stats.entries, if byte_bound { 8 } else { 256 });
    assert_eq!(stats.dropped, if byte_bound { 1 } else { 10 });
    assert!(stats.bytes <= crate::bus::runtime_limits::SESSION_BUFFER_BYTES);
    assert!(handle.resync_needed(), "overflow must set the explicit recovery flag");
}
async fn recover(
    handle: &ConnectionHandle,
    io: &mut crate::bus::connection_manager::tests::SessionIo,
    entries: &[GatewayInboxEntry],
    reader: &ramflux_storage::AccountDb,
    receipts: &[String],
    probe: Option<&ramflux_storage::SqlWorkProbe>,
) -> Case<BTreeSet<String>> {
    let mut acked = BTreeSet::new();
    respond_page(io, entries, 0, 64)?;
    // Subscriber and no-subscriber overflow both run receive::run's Resync pass.
    // (Resync, true) is recorded only when that pass returns Ok; wait for it, and
    // panic after 10s of silence rather than a total-time cap on the work.
    let completion = handle.test_wait_receive(ReceiveTrigger::Resync);
    tokio::pin!(completion);
    loop {
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(10), io.output.recv()) => {
                match recovery_frame(result, handle, acked.len())? {
                    GatewayClientFrame::Resume { resume } => respond_page(io, entries, resume.after_inbox_seq, resume.limit)?,
                    GatewayClientFrame::Ack { ack } => {
                        let index = entries.iter().position(|entry| entry.envelope.envelope_id == ack.envelope_id).ok_or("unexpected ACK")?;
                        assert!(reader.actor_state_exists(&receipts[index])?, "ACK preceded the durable receive commit");
                        assert!(acked.insert(ack.envelope_id.clone()), "a recovered entry was acknowledged twice");
                        if let Some(probe) = probe { work::assert_prefix_not_rescanned(probe); }
                        if acked.len().is_multiple_of(32) { eprintln!("durable recovery ACK {}: {:?}", acked.len(), handle.test_receive_profile()); }
                        let cursor = GatewayCursor {
                            target_delivery_id: "sender".into(), inbox_seq: entries[index].inbox_seq,
                            last_envelope_id: Some(ack.envelope_id.clone()), acked_envelope_ids: vec![ack.envelope_id],
                            nacked_envelope_ids: BTreeMap::new(),
                        };
                        send(io, &GatewayServerFrame::Ack { cursor: cursor.clone() })?;
                        send(io, &GatewayServerFrame::Cursor { cursor: Some(cursor) })?;
                    }
                    GatewayClientFrame::Submit { submit } => {
                        send(io, &GatewayServerFrame::Deliver { entry: GatewayInboxEntry {
                            forwarded: false, inbox_seq: 1,
                            target_delivery_id: submit.envelope.target_delivery_id.clone(),
                            envelope: submit.envelope,
                        } })?;
                    }
                    GatewayClientFrame::OwnDeviceFanout { fanout } => {
                        send(io, &super::fixture::own_copy_response(fanout)?)?;
                    }
                    other => return Err(format!("unexpected recovery frame {}", serde_json::to_value(other)?["frame_type"]).into()),
                }
            }
            () = &mut completion => break,
        }
    }
    Ok(acked)
}

fn recovery_frame(
    result: Result<Option<GatewayClientFrame>, tokio::time::error::Elapsed>,
    handle: &ConnectionHandle,
    acked: usize,
) -> Case<GatewayClientFrame> {
    assert!(
        result.is_ok(),
        "timed out awaiting recovery frame or Resync receive completion; acked={} trace={:?} profile={:?}",
        acked,
        handle.test_receive_trace(),
        handle.test_receive_profile()
    );
    match result {
        Ok(Some(frame)) => Ok(frame),
        Ok(None) => Err("session output closed".into()),
        Err(error) => Err(Box::new(error)),
    }
}
async fn wait_until(mut predicate: impl FnMut() -> bool) -> Case {
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    assert!(result.is_ok(), "timed out awaiting receive buffer overflow barrier");
    Ok(())
}
async fn wait_for<T>(future: impl std::future::Future<Output = T>, event: &'static str) -> Case<T> {
    let result = tokio::time::timeout(Duration::from_secs(10), future).await;
    assert!(result.is_ok(), "timed out awaiting {event}");
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(Box::new(error)),
    }
}
fn send(io: &crate::bus::connection_manager::tests::SessionIo, frame: &GatewayServerFrame) -> Case {
    io.input.send(serde_json::to_vec(frame)?)?;
    Ok(())
}
fn respond_page(
    io: &crate::bus::connection_manager::tests::SessionIo,
    entries: &[GatewayInboxEntry],
    cursor: u64,
    limit: usize,
) -> Case {
    let mut page = Vec::new();
    let mut bytes = 0;
    for entry in entries.iter().filter(|entry| entry.inbox_seq > cursor).take(limit) {
        let size = serde_json::to_vec(entry)?.len();
        if !page.is_empty() && bytes + size > ramflux_transport::MAX_GATEWAY_FRAME_BYTES - 1024 {
            break;
        }
        bytes += size;
        page.push(entry.clone());
    }
    send(io, &GatewayServerFrame::Resume { entries: page })
}
async fn entries(
    fixture: &mut Fixture,
    count: usize,
    frame_bytes: Option<usize>,
) -> Case<Vec<GatewayInboxEntry>> {
    use crate::bus::dispatch::task_transport::{Target, seal};
    let target = Target {
        device: "device-sender".into(),
        identity: fixture.source.client.owned_device_identity()?,
        delivery: "sender".into(),
        federation: None,
        own: false,
    };
    let mut engine = fixture.peer.session_client().await?;
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        // A direct message and authenticated controls exercise durable application
        // and exactly-once control projection through the same overflow recovery.
        let (body, route) = if index == 0 {
            (b"resync recovery".as_slice(), crate::client::routed::Route::direct())
        } else {
            (
                br#"{"type":"pair.session.reset.ack.v1"}"#.as_slice(),
                crate::client::routed::Route::control(),
            )
        };
        let packet = seal(&fixture.peer, &mut engine, &target, "healthy", body, route).await?;
        let mut entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: u64::try_from(index + 1)?,
            target_delivery_id: "sender".into(),
            envelope: packet.envelope,
        };
        if let Some(frame_bytes) = frame_bytes {
            entry.envelope.ext.ext.insert("padding".into(), json!(""));
            let length =
                serde_json::to_vec(&GatewayServerFrame::Deliver { entry: entry.clone() })?.len();
            entry.envelope.ext.ext.insert(
                "padding".into(),
                json!("x".repeat(frame_bytes.checked_sub(length).ok_or("frame size")?)),
            );
            entry.envelope.signed.signature =
                ramflux_crypto::sign_protocol_object_with_device_branch(
                    fixture.peer.client.device_branch.as_ref().ok_or("device branch")?,
                    &entry.envelope,
                )?;
        }
        let size = serde_json::to_vec(&GatewayServerFrame::Deliver { entry: entry.clone() })?.len();
        assert!(size <= frame_bytes.unwrap_or(16 * 1024));
        if let Some(expected) = frame_bytes {
            assert_eq!(size, expected);
        }
        entries.push(entry);
    }
    fixture.peer.install_test_session(engine);
    Ok(entries)
}
