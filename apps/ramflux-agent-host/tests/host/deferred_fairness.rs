// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conversation shares and sequence ordering prevent one deferred producer from starving another.
use super::{
    support::{Fixture, TestResult, incoming},
    surface_bus::{SurfaceBus, event},
    surfaces::fixture,
};
use ramflux_agent_host::{AgentBus, AgentHost, Error, Result, RuleEngine};
use ramflux_sdk::{LocalBusFrame, SurfaceRefusalCode as Code};
use serde_json::{Value, json};
#[derive(Default)]
struct PairBus {
    x: SurfaceBus,
    y: SurfaceBus,
    reads: Vec<String>,
    polls: usize,
    head: u64,
}
impl AgentBus for PairBus {
    async fn request(&mut self, method: &str, body: Value, op: Option<&str>) -> Result<Value> {
        if method == "bus.subscribe" {
            return Ok(json!({"head_seq":self.head.max(10),"floor_seq":1,"subscribed":true}));
        }
        if method == "conversation.directory" {
            return Ok(
                json!({"conversations":[{"id":"group-thread","kind":"group","group_id":"group"},{"id":"other-thread","kind":"group","group_id":"other-group"}],"next_cursor":null}),
            );
        }
        if method == "message.receive" {
            self.polls += 1;
        }
        let other = body["conversation_id"] == "other-thread" || body["surface_ref"] == "ref-y";
        if method == "surface.get" {
            self.reads.push(if other { "ref-y" } else { "ref-x" }.into());
        }
        let mut value = if other {
            self.y.request(method, body, op).await?
        } else {
            self.x.request(method, body, op).await?
        };
        if other && method == "surface.get" {
            value["conversation_id"] = json!("other-thread");
            value["surface_ref"] = json!("ref-y");
        }
        Ok(value)
    }
    async fn next_event(&mut self) -> Result<LocalBusFrame> {
        if !self.reads.is_empty() {
            return Err(Error::Bus);
        }
        std::future::pending().await
    }
}
fn notification(seq: u64, other: bool, id: &str) -> LocalBusFrame {
    let mut frame = event(seq, false);
    frame.body["conversation_id"] = json!(if other { "other-thread" } else { "group-thread" });
    frame.body["surface_ref"] = json!(if other { "ref-y" } else { "ref-x" });
    frame.body["last_action_id"] = json!(id);
    frame
}
fn decision(bus: &mut SurfaceBus, conversation: &str, id: &str) -> TestResult {
    bus.decision()?;
    let row = bus.action.as_mut().ok_or("action")?;
    let mut wire: Value = serde_json::from_slice(&ramflux_protocol::decode_base64url(
        row["wire_base64"].as_str().ok_or("wire")?,
    )?)?;
    wire["conversationId"] = json!(conversation);
    row["id"] = json!(id);
    row["wire_base64"] = json!(ramflux_protocol::encode_base64url(serde_json::to_vec(&wire)?));
    Ok(())
}
async fn setup()
-> std::result::Result<(Fixture, PairBus, AgentHost<RuleEngine>), Box<dyn std::error::Error>> {
    let f = fixture()?;
    let mut bus = PairBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    let mut other = incoming(12, true);
    other.body["message"]["conversation_id"] = json!("other-thread");
    host.apply(&mut bus, other, 2000).await?;
    decision(&mut bus.x, "group-thread", "x-choice-0")?;
    decision(&mut bus.y, "other-thread", "decision")?;
    Ok((f, bus, host))
}
async fn drain(host: &mut AgentHost<RuleEngine>, bus: &mut PairBus) -> TestResult {
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(2), host.run(bus)).await?,
        Err(Error::Bus)
    ));
    assert_eq!(bus.polls, 1, "all eligible conversations must be considered in the same poll");
    Ok(())
}
#[tokio::test]
async fn r5_one_conversation_fills_only_its_share_and_another_choice_is_served() -> TestResult {
    let (_f, mut bus, mut host) = setup().await?;
    for n in 0..9 {
        host.apply(&mut bus, notification(20 + n, false, &format!("x-choice-{n}")), 2001).await?;
    }
    let state = serde_json::to_value(host.checkpoint())?;
    let queue = state["deferred_surfaces"].as_object().ok_or("queue")?;
    assert_eq!(queue.len(), 4);
    assert!(queue.values().all(|row| row["action"].as_str().is_some_and(|id| {
        ["x-choice-0", "x-choice-1", "x-choice-2", "x-choice-3", "decision"].contains(&id)
    })));
    assert_eq!(host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason, Code::TooLarge);
    host.apply(&mut bus, notification(29, true, "decision"), 2001).await?;
    assert_eq!(
        serde_json::to_value(host.checkpoint())?["deferred_surfaces"]
            .as_object()
            .ok_or("queue")?
            .len(),
        5
    );
    drain(&mut host, &mut bus).await?;
    assert!(bus.y.state.is_closed());
    assert_eq!(bus.y.state.content().ok_or("surface")?.fallback_text, "You chose Thursday.");
    assert_eq!(host.checkpoint().cursor, Some(29));
    Ok(())
}
fn queue_key(other: bool, id: &str) -> std::result::Result<String, Box<dyn std::error::Error>> {
    let (conversation, reference) =
        if other { ("other-thread", "ref-y") } else { ("group-thread", "ref-x") };
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.agent.deferred_surface.v1",
        &ramflux_protocol::canonical_json_bytes(&(conversation, reference, Some(id)))?,
    ))
}
#[tokio::test]
async fn r5_due_choices_follow_sequence_order_and_finish_in_one_poll() -> TestResult {
    let (_f, mut bus, mut host) = setup().await?;
    // Pick arrival order opposite the persisted map's hash order.
    let x_first = queue_key(false, "x-choice-0")? > queue_key(true, "decision")?;
    let first = notification(20, !x_first, if x_first { "x-choice-0" } else { "decision" });
    let second = notification(21, x_first, if x_first { "decision" } else { "x-choice-0" });
    host.apply(&mut bus, first, 2001).await?;
    host.apply(&mut bus, second, 2001).await?;
    drain(&mut host, &mut bus).await?;
    assert_eq!(bus.reads, if x_first { vec!["ref-x", "ref-y"] } else { vec!["ref-y", "ref-x"] });
    assert!(bus.x.state.is_closed());
    assert!(bus.y.state.is_closed());
    Ok(())
}
#[tokio::test]
async fn r5_a_stale_resync_notification_cannot_run_on_a_replica() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.replica = true;
    bus.out_of_sync = true;
    let mut frame = event(20, false);
    frame.body.as_object_mut().ok_or("event")?.remove("last_action_id");
    frame.body["out_of_sync"] = json!(true);
    host.apply(&mut bus, frame, 4000).await?;
    assert_eq!(bus.resyncs, [] as [Value; 0]);
    assert_eq!(
        host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason,
        Code::NotActionExecutor
    );
    assert_eq!(host.checkpoint().cursor, Some(20));
    Ok(())
}

#[tokio::test]
async fn r5_an_older_oversized_conversation_queue_retires_its_newest_rows_before_serving_others()
-> TestResult {
    let (f, mut bus, mut host) = setup().await?;
    host.apply(&mut bus, notification(20, false, "x-choice-0"), 2001).await?;
    host.apply(&mut bus, notification(21, true, "decision"), 2001).await?;
    let mut state = serde_json::to_value(host.checkpoint())?;
    drop(host);
    let rows = state["deferred_surfaces"].as_object_mut().ok_or("queue")?;
    let original =
        rows.values().find(|row| row["conversation"] == "group-thread").ok_or("x row")?.clone();
    for n in 1..9 {
        let id = format!("x-choice-{n}");
        let mut row = original.clone();
        row["seq"] = json!(20 + n);
        row["action"] = json!(id);
        rows.insert(queue_key(false, &id)?, row);
    }
    for row in rows.values_mut().filter(|row| row["conversation"] == "other-thread") {
        row["seq"] = json!(40);
    }
    state["cursor"] = json!(40);
    std::fs::write(&f.config.state_file, serde_json::to_vec(&state)?)?;
    bus.head = 40;
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let state = serde_json::to_value(host.checkpoint())?;
    let rows = state["deferred_surfaces"].as_object().ok_or("queue")?;
    assert_eq!(rows.len(), 5);
    assert!(rows.values().all(|row| row["action"].as_str().is_some_and(|id| {
        ["x-choice-0", "x-choice-1", "x-choice-2", "x-choice-3", "decision"].contains(&id)
    })));
    assert_eq!(host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason, Code::TooLarge);
    drain(&mut host, &mut bus).await?;
    assert!(bus.y.state.is_closed());
    assert_eq!(host.checkpoint().cursor, Some(40));
    Ok(())
}

#[tokio::test]
async fn eight_busy_conversations_leave_durable_headroom_for_a_new_conversation() -> TestResult {
    let (f, mut bus, host) = setup().await?;
    let mut state = serde_json::to_value(host.checkpoint())?;
    drop(host);
    let mut rows = serde_json::Map::new();
    for conversation in 0..8 {
        for action in 0..8 {
            let seq = 20 + conversation * 8 + action;
            rows.insert(
                format!("busy-{conversation}-{action}"),
                json!({
                    "seq":seq,"conversation":format!("busy-{conversation}"),
                    "reference":"ref-busy","action":format!("choice-{action}"),"ready_at":3000,
                }),
            );
        }
    }
    state["deferred_surfaces"] = json!(rows);
    state["cursor"] = json!(83);
    std::fs::write(&f.config.state_file, serde_json::to_vec(&state)?)?;
    bus.head = 83;
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let normalized = serde_json::to_value(host.checkpoint())?;
    assert_eq!(normalized["deferred_surfaces"].as_object().ok_or("queue")?.len(), 32);
    assert_eq!(host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason, Code::TooLarge);
    host.apply(&mut bus, notification(90, true, "decision"), 2001).await?;
    let state = serde_json::to_value(host.checkpoint())?;
    assert_eq!(state["deferred_surfaces"].as_object().ok_or("queue")?.len(), 33);
    drop(host);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert_eq!(
        serde_json::to_value(host.checkpoint())?["deferred_surfaces"]
            .as_object()
            .ok_or("queue")?
            .len(),
        33
    );
    drain(&mut host, &mut bus).await?;
    assert!(bus.y.state.is_closed());
    assert_eq!(host.checkpoint().cursor, Some(90));
    Ok(())
}

#[tokio::test]
async fn new_deferred_work_above_fifty_six_rows_is_refused_without_losing_stored_work() -> TestResult
{
    let (f, mut bus, host) = setup().await?;
    let mut state = serde_json::to_value(host.checkpoint())?;
    drop(host);
    let mut rows = serde_json::Map::new();
    for n in 0..56 {
        rows.insert(format!("busy-{n}"), json!({"seq":20+n,"conversation":format!("busy-{n}"),"reference":"ref-busy","action":"choice","ready_at":3000}));
    }
    state["deferred_surfaces"] = json!(rows);
    state["cursor"] = json!(83);
    std::fs::write(&f.config.state_file, serde_json::to_vec(&state)?)?;
    bus.head = 83;
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, notification(90, true, "decision"), 2001).await?;
    let after = serde_json::to_value(host.checkpoint())?;
    assert_eq!(after["deferred_surfaces"], state["deferred_surfaces"]);
    assert_eq!(host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason, Code::TooLarge);
    assert_eq!(host.checkpoint().cursor, Some(90));
    Ok(())
}
