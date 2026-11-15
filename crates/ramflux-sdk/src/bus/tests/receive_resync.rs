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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant as WallClock;

#[path = "receive_resync/work.rs"]
mod work;

// Isolated recovery of 266 entries is ~24 s; two of them in parallel is ~36 s.
// A loaded `cargo test --lib bus` pool stretched one past 240 s with no 10 s
// silence panic. Durable cases take turns so they do not double-load SQL.
// A loaded miss is reported. This cap is not raised to hide it.
const DURABLE_RECOVERY_COMPLETION_LIMIT: Duration = Duration::from_secs(360);
const DURABLE_RECOVERY_WATCHDOG: Duration = Duration::from_secs(420);
static DURABLE_TURN: AtomicU64 = AtomicU64::new(0);
static DURABLE_DONE: AtomicU64 = AtomicU64::new(0);

struct DurableTurn;
impl Drop for DurableTurn {
    fn drop(&mut self) {
        DURABLE_DONE.fetch_add(1, Ordering::SeqCst);
    }
}

async fn wait_durable_turn() -> DurableTurn {
    let ticket = DURABLE_TURN.fetch_add(1, Ordering::SeqCst);
    while DURABLE_DONE.load(Ordering::SeqCst) != ticket {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    DurableTurn
}

struct Recovery {
    started: super::receive_ack::Started,
    reader: ramflux_storage::AccountDb,
    handle: ConnectionHandle,
    gateway: std::sync::Arc<std::sync::Mutex<super::fixture::Gateway>>,
    io: crate::bus::connection_manager::tests::SessionIo,
    entries: Vec<GatewayInboxEntry>,
    receipts: Vec<String>,
    expected_messages: usize,
    slow: Option<crate::bus::connection_manager::SessionSubscription>,
    draining: Option<tokio::task::JoinHandle<()>>,
    released: WallClock,
    probe: Option<ramflux_storage::SqlWorkProbe>,
}

/// Wall-clock deadline for a whole resync scenario, fixtures included: the scenario future is
/// dropped on expiry, so its temporary directories go before the runner's kill window.
async fn bounded(scenario: impl std::future::Future<Output = Case>) -> Case {
    tokio::time::timeout(Duration::from_secs(240), scenario)
        .await
        .map_err(|_| "resync scenario exceeded its 240 s deadline")?
}

#[tokio::test(flavor = "current_thread")]
async fn receive_resync_recovers_entry_overflow_with_two_subscribers() -> Case {
    bounded(Box::pin(run(266, None, true))).await
}
#[tokio::test(flavor = "current_thread")]
async fn receive_resync_recovers_entry_overflow_without_subscribers() -> Case {
    bounded(Box::pin(run(266, None, false))).await
}
#[tokio::test(flavor = "current_thread")]
async fn receive_resync_recovers_byte_overflow_below_the_entry_cap() -> Case {
    bounded(Box::pin(run(26, Some(384 * 1024), true))).await
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
    run_mode(26, Some(384 * 1024), true, Completion::Trigger).await
}
async fn run(count: usize, frame_bytes: Option<usize>, subscribers: bool) -> Case {
    let _turn = wait_durable_turn().await;
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
            let (entries, receipts) = Box::pin(entries(&mut fixture, count, frame_bytes)).await?;
            eprintln!("prepared {count} authenticated inbox entries in {:?}", prepared.elapsed());
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
            crate::bus::connection_manager::tests::watchdog_for(
                DURABLE_RECOVERY_WATCHDOG,
                Box::pin(async {
                    let mut state = Box::pin(prepare_case(
                        fixture,
                        entries,
                        receipts,
                        frame_bytes,
                        subscribers,
                        completion,
                    ))
                    .await?;
                    let acked = tokio::time::timeout(
                        DURABLE_RECOVERY_COMPLETION_LIMIT,
                        recover(&mut state),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "durable recovery exceeded {:?}; trace={:?} profile={:?}",
                            DURABLE_RECOVERY_COMPLETION_LIMIT,
                            state.handle.test_receive_trace(),
                            state.handle.test_receive_profile()
                        )
                    })?;
                    eprintln!(
                        "durable recovery completed after {:?}: {} ACKs; phases: {:?}",
                        state.released.elapsed(),
                        acked.len(),
                        state.handle.test_receive_profile()
                    );
                    Box::pin(finish_case(state, acked)).await
                }),
            )
            .await
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
    let gateway = std::sync::Arc::clone(&fixture.gateway);
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
    let (drained_tx, mut drained_rx) = tokio::sync::mpsc::channel(512);
    let draining = subscribers.then(|| {
        let mut subscription = handle.subscribe([FrameKind::Deliver]);
        tokio::spawn(async move {
            while let Some(event) = subscription.recv().await {
                if drained_tx.send(event).await.is_err() {
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
    feed_overflow(&io, &entries, subscribers.then_some(&mut drained_rx)).await?;
    wait_until(|| {
        let stats = handle.test_buffer_stats();
        stats.entries + stats.dropped == count
    })
    .await?;
    assert_buffer_limits(&handle, &entries, frame_bytes.is_some())?;
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
    let first = next_recovery_resume(&mut io, &gateway).await?;
    assert!(released.elapsed() < Duration::from_secs(15));
    assert!(matches!(first, GatewayClientFrame::Resume { resume } if resume.after_inbox_seq == 0));
    assert!(handle.test_receive_trace().contains(&(ReceiveTrigger::Resync, false)));
    eprintln!("first recovery Resume after {:?}", released.elapsed());
    let probe = if completion == Completion::Durable {
        Some(handle.test_observe_sql().await?)
    } else {
        None
    };
    let expected_messages = if frame_bytes.is_some() { count } else { 1 };
    Ok(Recovery {
        started,
        reader,
        handle,
        gateway,
        io,
        entries,
        receipts,
        expected_messages,
        slow,
        draining,
        released,
        probe,
    })
}
async fn feed_overflow(
    io: &crate::bus::connection_manager::tests::SessionIo,
    entries: &[GatewayInboxEntry],
    mut drain: Option<&mut tokio::sync::mpsc::Receiver<SessionEvent>>,
) -> Case {
    for entry in entries {
        send(io, &GatewayServerFrame::Deliver { entry: entry.clone() })?;
        if let Some(receiver) = drain.as_mut() {
            match wait_for(receiver.recv(), "second subscriber delivery or overflow event")
                .await?
                .ok_or("second subscriber closed before delivery or overflow")?
            {
                SessionEvent::Frame { frame, .. }
                    if matches!(frame.as_ref(), GatewayServerFrame::Deliver { .. }) => {}
                SessionEvent::Lagged { .. } => drain = None,
                _ => return Err("second subscriber received an unexpected event".into()),
            }
        }
    }
    Ok(())
}

async fn finish_case(state: Recovery, acked: BTreeSet<String>) -> Case {
    let Recovery {
        started,
        reader,
        handle,
        entries,
        receipts,
        expected_messages,
        slow,
        draining,
        probe,
        ..
    } = state;
    let count = entries.len();
    work::assert_complete(&handle, probe.as_ref().ok_or("missing SQL observer")?, count);
    assert_eq!(acked.len(), count);
    assert!(!handle.resync_needed(), "clear only after the complete durable handoff");
    assert_completed_trace(&handle);
    assert_message_pages(&started, expected_messages).await?;
    assert_eq!(
        reader.actor_state_keys("routed/committed/")?.len(),
        count,
        "each authenticated entry retains its durable receive receipt"
    );
    assert_eq!(
        reader.actor_state_keys("routed/pair-control-applied/")?.len(),
        count - expected_messages,
        "every generated Control has its durable effect fence"
    );
    for key in &receipts {
        assert!(reader.actor_state_exists(key)?);
    }
    assert_control_effects(&reader, count - expected_messages)?;
    Box::pin(cleanup(started, reader, slow, draining)).await
}

async fn assert_message_pages(started: &super::receive_ack::Started, expected: usize) -> Case {
    let mut before = serde_json::Value::Null;
    let mut ids = BTreeSet::new();
    for _ in 0..expected {
        let response = started
            .actor
            .request(command(
                "message.read",
                json!({
                    "conversation_id":started.conversation,"limit":100,"read_model":true,
                    "before_order_key":before,
                }),
            ))
            .await?;
        let messages = response.body["messages"].as_array().ok_or("messages")?;
        if messages.is_empty() {
            return Err("a recovery page must make progress".into());
        }
        for message in messages {
            assert!(
                message["text"].as_str().is_some_and(|text| text.starts_with("resync recovery"))
            );
            assert!(
                ids.insert(message["id"].as_str().ok_or("canonical id")?.to_owned()),
                "a recovery page cannot repeat an already rendered message"
            );
        }
        let next = response.body["next_before"].clone();
        if next.is_null() {
            break;
        }
        assert_ne!(next, before, "the durable reader cursor must advance");
        before = next;
    }
    assert_eq!(
        ids.len(),
        expected,
        "all recovered messages remain readable across response budgets"
    );
    Ok(())
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
fn assert_buffer_limits(
    handle: &ConnectionHandle,
    entries: &[GatewayInboxEntry],
    byte_bound: bool,
) -> Case {
    let mut expected = 0;
    let mut bytes = 0;
    for entry in entries {
        let size = serde_json::to_vec(&GatewayServerFrame::Deliver { entry: entry.clone() })?.len();
        if expected < crate::bus::runtime_limits::SESSION_BUFFER
            && bytes + size <= crate::bus::runtime_limits::SESSION_BUFFER_BYTES
        {
            expected += 1;
            bytes += size;
        }
    }
    let stats = handle.test_buffer_stats();
    assert_eq!(stats.entries, expected, "buffered entries match the actual signed wire sizes");
    assert_eq!(stats.dropped, entries.len() - expected);
    assert_eq!(stats.bytes, bytes);
    if byte_bound {
        assert!(expected < crate::bus::runtime_limits::SESSION_BUFFER);
    } else {
        assert_eq!(expected, crate::bus::runtime_limits::SESSION_BUFFER);
    }
    assert!(stats.dropped > 0);
    assert!(handle.resync_needed(), "overflow must set the explicit recovery flag");
    Ok(())
}
async fn next_recovery_resume(
    io: &mut crate::bus::connection_manager::tests::SessionIo,
    gateway: &std::sync::Arc<std::sync::Mutex<super::fixture::Gateway>>,
) -> Case<GatewayClientFrame> {
    loop {
        let frame = wait_for(io.output.recv(), "Resync Resume").await?.ok_or("Resync Resume")?;
        if matches!(frame, GatewayClientFrame::Resume { .. }) {
            return Ok(frame);
        }
        reply_to_courier(io, gateway, frame)?;
    }
}

fn reply_to_courier(
    io: &crate::bus::connection_manager::tests::SessionIo,
    gateway: &std::sync::Arc<std::sync::Mutex<super::fixture::Gateway>>,
    frame: GatewayClientFrame,
) -> Case {
    let response = match frame {
        GatewayClientFrame::Submit { submit } => GatewayServerFrame::Deliver {
            entry: GatewayInboxEntry {
                forwarded: false,
                inbox_seq: 1,
                target_delivery_id: submit.envelope.target_delivery_id.clone(),
                envelope: submit.envelope,
            },
        },
        GatewayClientFrame::OwnDeviceFanout { fanout } => {
            super::fixture::own_copy_response(fanout)?
        }
        GatewayClientFrame::PrekeyFetch { device_id } => {
            GatewayServerFrame::Prekey { response: super::fixture::prekey(gateway, &device_id)? }
        }
        other => {
            return Err(format!(
                "unexpected courier frame: {}",
                serde_json::to_value(other)?["frame_type"]
            )
            .into());
        }
    };
    send(io, &response)
}

async fn recover(state: &mut Recovery) -> Case<BTreeSet<String>> {
    let Recovery { handle, io, gateway, entries, reader, receipts, probe, .. } = state;
    let probe = probe.as_ref();
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
                        assert!(reader.actor_state_exists(&receipts[index])?,
                            "ACK preceded the durable receive commit: seq={}, ledger={:?}, journal={:?}",
                            entries[index].inbox_seq,
                            reader.receive_state_for_test(entries[index].inbox_seq),
                            reader.latest_journal_event("message.undeliverable"));
                        assert!(acked.insert(ack.envelope_id.clone()), "a recovered entry was acknowledged twice");
                        if let Some(probe) = probe { work::assert_prefix_not_rescanned(probe); }
                        if acked.len().is_multiple_of(32) { eprintln!("durable recovery ACK {}: {:?}", acked.len(), handle.test_receive_profile()); }
                        let cursor = GatewayCursor {
                            target_delivery_id: entries[index].target_delivery_id.clone(), inbox_seq: entries[index].inbox_seq,
                            last_envelope_id: Some(ack.envelope_id.clone()), acked_envelope_ids: vec![ack.envelope_id],
                            nacked_envelope_ids: BTreeMap::new(),
                        };
                        send(io, &GatewayServerFrame::Ack { cursor: cursor.clone() })?;
                        send(io, &GatewayServerFrame::Cursor { cursor: Some(cursor) })?;
                    }
                    frame @ (GatewayClientFrame::Submit { .. }
                        | GatewayClientFrame::OwnDeviceFanout { .. }
                        | GatewayClientFrame::PrekeyFetch { .. }) => reply_to_courier(io, gateway, frame)?,
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
) -> Case<(Vec<GatewayInboxEntry>, Vec<String>)> {
    use super::fixture::seal_content_with_identity as seal;
    use crate::bus::dispatch::task_transport::Target;
    use ramflux_protocol::message as g;
    let target = Target {
        device: "device-sender".into(),
        identity: fixture.source.client.owned_device_identity()?,
        delivery: fixture.source.target_delivery_id.clone(),
        federation: None,
        own: false,
    };
    let mut engine = fixture.peer.session_client().await?;
    let mut entries = Vec::with_capacity(count);
    let mut receipts = Vec::with_capacity(count);
    for index in 0..count {
        // A direct message and authenticated controls exercise durable application
        // and exactly-once control projection through the same overflow recovery.
        let content = if index == 0 || frame_bytes.is_some() {
            g::Content {
                value: Some(g::content::Value::Message(g::Message {
                    text: if frame_bytes.is_some() {
                        let mut text = String::from("resync recovery");
                        text.extend(std::iter::repeat_n(
                            'x',
                            ramflux_protocol::message::validation::MAX_TEXT_BYTES - text.len(),
                        ));
                        text
                    } else {
                        "resync recovery".into()
                    },
                    ..Default::default()
                })),
            }
        } else {
            g::Content {
                value: Some(g::content::Value::Control(
                    crate::client::generated_control::control_from_payload(
                        g::control::Payload::ResetAck(g::PairResetAck {
                            rejected_bootstrap_floor: 0,
                        }),
                    )?,
                )),
            }
        };
        let (packet, _) = seal(&fixture.peer, &mut engine, &target, content, None, None).await?;
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: u64::try_from(index + 1)?,
            target_delivery_id: packet.envelope.target_delivery_id.clone(),
            envelope: packet.envelope,
        };
        ramflux_protocol::message::outer::check_ingress_caps(
            ramflux_protocol::message::outer::IngressSizes::measure_wire(
                &entry.envelope,
                0,
                &[],
                &[],
            )?,
        )?;
        let size = serde_json::to_vec(&GatewayServerFrame::Deliver { entry: entry.clone() })?.len();
        assert!(size <= frame_bytes.unwrap_or(16 * 1024));
        let key =
            fixture.source.client.authenticated_committed_key(HeadUse::NewAuthorization, &entry)?;
        receipts.push(key);
        entries.push(entry);
    }
    fixture.peer.install_test_session(engine);
    Ok((entries, receipts))
}
