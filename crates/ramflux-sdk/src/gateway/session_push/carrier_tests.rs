// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
//! `capable_events_survive_buffer_and_subscription`: the lossless capable event carrier.
//!
//! Frames come from node-core typed values and travel through the real reader, the real
//! delivery buffer and a real `SessionHub`.
use super::routing_tests::{
    E, capable_deliver, capable_resync, envelope, heartbeat, id, node_entry, push, scripted,
};
use super::{CapableEvent, PushMeta, ResyncReason, SessionMode};
use crate::bus::connection_manager::resync::ResyncState;
use crate::bus::connection_manager::subscriptions::SessionEvent;
use crate::bus::connection_manager::{SessionHub, SessionSubscription};
use crate::bus::runtime_limits::{SESSION_BUFFER, SESSION_BUFFER_BYTES, SUBSCRIBER_QUEUE};
use crate::gateway::frame_dispatch::{ExpectedReply, FrameKind};
use crate::gateway::host_frames::HostFrames;
use crate::gateway::{GatewayInboxEntry, GatewayServerFrame, GatewaySessionEngine};
use ramflux_node_core as n;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const GENERATION: u64 = 7;

/// Attaches a real hub and resync state to the engine, as the connection manager does.
pub(super) fn attach_host(
    engine: &mut GatewaySessionEngine,
) -> (Arc<SessionHub>, Arc<ResyncState>) {
    let hub = Arc::new(SessionHub::new(GENERATION));
    let resync = Arc::new(ResyncState::default());
    engine.host = Some(HostFrames {
        hub: Arc::clone(&hub),
        resync_needed: Arc::clone(&resync),
        buffer_stats: Arc::default(),
    });
    (hub, resync)
}

fn entry(seq: u64) -> GatewayInboxEntry {
    GatewayInboxEntry {
        forwarded: false,
        inbox_seq: seq,
        target_delivery_id: "target-route".into(),
        envelope: envelope(),
    }
}

fn meta(retain_until: i64) -> PushMeta {
    PushMeta { incarnation_id: id(), retain_until }
}

fn deliver_with_seq(seq: u64) -> serde_json::Value {
    let mut entry = node_entry();
    entry.inbox_seq = seq;
    serde_json::to_value(n::SessionPushServerFrame::Deliver {
        entry,
        incarnation_id: E.into(),
        retain_until: 9_000,
    })
    .unwrap()
}

fn resync_event() -> CapableEvent {
    CapableEvent::Resync {
        incarnation_id: id(),
        target_delivery_id: "target-route".into(),
        after_inbox_seq: 1,
        reason: ResyncReason::NotPushed,
    }
}

fn deliver_event(seq: u64) -> CapableEvent {
    CapableEvent::Deliver { entry: entry(seq), incarnation_id: id(), retain_until: 1 }
}

async fn recv(subscription: &mut SessionSubscription) -> SessionEvent {
    tokio::time::timeout(Duration::from_secs(10), subscription.recv())
        .await
        .expect("subscription timed out")
        .expect("subscription ended")
}

#[tokio::test]
async fn capable_events_survive_buffer_and_subscription() {
    // (p1) a Push deliver reaches take_pending_capable with E and retain_until equal, and the
    // same frame reaches a Deliver subscriber as Capable with the same values and the hub
    // generation.
    let mut engine = scripted(push(), vec![capable_deliver(), heartbeat()]);
    let (hub, _) = attach_host(&mut engine);
    let mut deliveries = hub.subscribe([FrameKind::Deliver]);
    engine.read_reply(ExpectedReply::Heartbeat).await.unwrap();
    let pending = engine.take_pending_capable();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0.inbox_seq, 71);
    assert_eq!(pending[0].1, Some(meta(7_777)));
    match recv(&mut deliveries).await {
        SessionEvent::Capable { event, generation } => {
            assert_eq!(generation, GENERATION);
            match &*event {
                CapableEvent::Deliver { entry, incarnation_id, retain_until } => {
                    assert_eq!(entry.inbox_seq, 71);
                    assert_eq!(incarnation_id, &id());
                    assert_eq!(*retain_until, 7_777);
                }
                other @ CapableEvent::Resync { .. } => panic!("not a deliver: {other:?}"),
            }
        }
        other => panic!("not a capable event: {other:?}"),
    }

    // (p2) a resync reaches a Resync subscriber with all four fields equal and is never buffered.
    let mut engine = scripted(push(), vec![capable_resync(), heartbeat()]);
    let (hub, _) = attach_host(&mut engine);
    let mut resyncs = hub.subscribe([FrameKind::Resync]);
    engine.read_reply(ExpectedReply::Heartbeat).await.unwrap();
    match recv(&mut resyncs).await {
        SessionEvent::Capable { event, generation } => {
            assert_eq!(generation, GENERATION);
            assert_eq!(
                *event,
                CapableEvent::Resync {
                    incarnation_id: id(),
                    target_delivery_id: "target-route".into(),
                    after_inbox_seq: 72,
                    reason: ResyncReason::QueueFull,
                }
            );
        }
        other => panic!("not a capable event: {other:?}"),
    }
    assert!(engine.pending_deliveries.is_empty());

    // (p3) the 256th buffered capable delivery is accepted (255 buffered directly, the 256th
    // read from the wire); (r1) the 257th is dropped, a resync is requested and the
    // subscriber is told it lagged.
    let frames = vec![deliver_with_seq(900), deliver_with_seq(901), heartbeat()];
    let mut engine = scripted(push(), frames);
    let (hub, resync) = attach_host(&mut engine);
    let mut lagged = hub.subscribe([FrameKind::Resync]);
    for seq in 1..SESSION_BUFFER {
        engine.last_frame_bytes = 1;
        engine.buffer_capable_delivery(entry(u64::try_from(seq).unwrap()), meta(1));
    }
    assert_eq!(engine.pending_deliveries.len(), SESSION_BUFFER - 1);
    engine.read_reply(ExpectedReply::Heartbeat).await.unwrap();
    assert_eq!(engine.pending_deliveries.len(), SESSION_BUFFER);
    let last: Vec<u64> = engine.pending_deliveries.iter().map(|p| p.entry.inbox_seq).collect();
    assert!(last.contains(&900) && !last.contains(&901), "256th accepted, 257th dropped");
    assert!(resync.needed(), "the 257th delivery requested a resync (r1)");
    assert!(matches!(recv(&mut lagged).await, SessionEvent::Lagged { .. }));

    // (p4) a delivery landing exactly on SESSION_BUFFER_BYTES is accepted; (r2) one byte more
    // is dropped the same way.
    let mut engine = scripted(SessionMode::Legacy, vec![]);
    let (hub, resync) = attach_host(&mut engine);
    let mut lagged = hub.subscribe([FrameKind::Resync]);
    engine.last_frame_bytes = SESSION_BUFFER_BYTES;
    engine.buffer_capable_delivery(entry(1), meta(1));
    assert_eq!(engine.pending_deliveries.len(), 1, "exact byte bound accepted (p4)");
    assert!(!resync.needed());
    engine.take_pending_capable();
    engine.last_frame_bytes = SESSION_BUFFER_BYTES + 1;
    engine.buffer_capable_delivery(entry(2), meta(1));
    assert!(engine.pending_deliveries.is_empty(), "one byte over is dropped (r2)");
    assert!(resync.needed());
    assert!(matches!(recv(&mut lagged).await, SessionEvent::Lagged { .. }));

    // (p5) take_pending_deliveries on a mixed buffer returns entries in arrival order.
    let mut engine = scripted(SessionMode::Legacy, vec![]);
    engine.last_frame_bytes = 1;
    engine.buffer_delivery(entry(1));
    engine.buffer_capable_delivery(entry(2), meta(2));
    engine.buffer_delivery(entry(3));
    let seqs: Vec<u64> =
        engine.take_pending_deliveries().iter().map(|entry| entry.inbox_seq).collect();
    assert_eq!(seqs, [1, 2, 3]);

    // (p6) a Legacy session deliver still publishes SessionEvent::Frame.
    let legacy = json!({"frame_type":"deliver","entry":{
        "inbox_seq":71,"target_delivery_id":"target-route","envelope":envelope()}});
    let mut engine = scripted(SessionMode::Legacy, vec![legacy, heartbeat()]);
    let (hub, _) = attach_host(&mut engine);
    let mut deliveries = hub.subscribe([FrameKind::Deliver]);
    engine.read_reply(ExpectedReply::Heartbeat).await.unwrap();
    match recv(&mut deliveries).await {
        SessionEvent::Frame { frame, generation } => {
            assert_eq!(generation, GENERATION);
            assert!(
                matches!(&*frame, GatewayServerFrame::Deliver { entry } if entry.inbox_seq == 71)
            );
        }
        other => panic!("not a legacy frame: {other:?}"),
    }

    // (r3) a slow subscriber at SUBSCRIBER_QUEUE gets exactly one Lagged per overflow episode,
    // ahead of the queued events.
    let hub = SessionHub::new(GENERATION);
    let mut slow = hub.subscribe([FrameKind::Deliver]);
    let overflow = 3;
    for seq in 0..SUBSCRIBER_QUEUE + overflow {
        hub.publish_capable(deliver_event(u64::try_from(seq).unwrap() + 1));
    }
    match recv(&mut slow).await {
        SessionEvent::Lagged { dropped, generation } => {
            assert_eq!((dropped, generation), (u64::try_from(overflow).unwrap(), GENERATION));
        }
        other => panic!("expected one Lagged first: {other:?}"),
    }
    for expected in 1..=SUBSCRIBER_QUEUE {
        match recv(&mut slow).await {
            SessionEvent::Capable { event, .. } => match &*event {
                CapableEvent::Deliver { entry, .. } => {
                    assert_eq!(entry.inbox_seq, u64::try_from(expected).unwrap());
                }
                other @ CapableEvent::Resync { .. } => panic!("not a deliver: {other:?}"),
            },
            other => panic!("queued capable events follow the marker: {other:?}"),
        }
    }

    // (r4) a generation-checking consumer (the metadata child pattern) ignores an event of an
    // earlier session and acts only on the current one.
    let old = SessionHub::new(GENERATION);
    let new = SessionHub::new(GENERATION + 1);
    let mut from_old = old.subscribe([FrameKind::Resync]);
    let mut from_new = new.subscribe([FrameKind::Resync]);
    let resync_at = |after_inbox_seq| CapableEvent::Resync {
        incarnation_id: id(),
        target_delivery_id: "target-route".into(),
        after_inbox_seq,
        reason: ResyncReason::NotPushed,
    };
    old.publish_capable(resync_at(11));
    new.publish_capable(resync_at(22));
    let current_generation = GENERATION + 1;
    let mut acted_on = Vec::new();
    for subscription in [&mut from_old, &mut from_new] {
        match recv(subscription).await {
            SessionEvent::Capable { event, generation } => {
                if generation != current_generation {
                    continue;
                }
                if let CapableEvent::Resync { after_inbox_seq, .. } = &*event {
                    acted_on.push(*after_inbox_seq);
                }
            }
            other => panic!("not a capable event: {other:?}"),
        }
    }
    assert_eq!(acted_on, [22], "only the current-generation event changes the consumer");

    // (r5) a subscriber to other kinds receives no capable event: the next event it sees is
    // the heartbeat published after them.
    let hub = SessionHub::new(GENERATION);
    let mut others = hub.subscribe([FrameKind::Heartbeat]);
    hub.publish_capable(deliver_event(1));
    hub.publish_capable(resync_event());
    hub.publish(GatewayServerFrame::Heartbeat { now: 9 });
    match recv(&mut others).await {
        SessionEvent::Frame { frame, .. } => {
            assert_eq!(*frame, GatewayServerFrame::Heartbeat { now: 9 });
        }
        other => panic!("a capable event reached a heartbeat subscriber: {other:?}"),
    }
}
