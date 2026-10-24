// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current-wire refusals and crash windows preserve semantic goals without replaying stale deltas.
use super::{
    support::{TestResult, incoming},
    surface_bus::{SurfaceBus, event},
    surfaces::fixture,
};
use ramflux_agent_host::{AgentHost, Error, RuleEngine};
use ramflux_sdk::SurfaceRefusalCode as Code;
#[tokio::test]
async fn stale_stream_reloads_and_appends_only_the_missing_suffix_with_a_final_marker() -> TestResult
{
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    bus.faults.stale_stream = true;
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    assert_eq!(
        bus.state.content().ok_or("surface")?.components[0]["text"],
        f.config.rules[0].reply
    );
    assert_eq!(bus.state.stream_states()["reply"], ramflux_protocol::SurfaceStreamState::Final);
    assert_ne!(bus.requests[1]["message_id"], bus.requests[2]["message_id"]);
    assert_eq!(host.checkpoint().cursor, Some(11));
    Ok(())
}
#[tokio::test]
async fn disconnect_after_stale_action_refusal_never_replays_the_refused_request() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.decision()?;
    bus.conflict = true;
    bus.faults.disconnect_after_conflict = true;
    assert!(matches!(host.apply(&mut bus, event(20, false), 4000).await, Err(Error::Bus)));
    let rejected = bus.requests.last().ok_or("request")?["message_id"].clone();
    let count = bus.requests.len();
    drop(host);
    let mut resumed = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    resumed.start(&mut bus).await?;
    assert!(bus.requests[count..].iter().all(|body| body["message_id"] != rejected));
    assert_eq!(bus.state.content().ok_or("surface")?.fallback_text, "You chose Thursday.");
    assert!(bus.state.is_closed());
    Ok(())
}
#[tokio::test]
async fn permanent_refusals_are_recorded_and_not_retried_after_restart() -> TestResult {
    for reason in [Code::NotAuthor, Code::TooLarge] {
        let f = fixture()?;
        let mut bus = SurfaceBus::default();
        bus.refusal = Some(reason);
        let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
        host.start(&mut bus).await?;
        host.apply(&mut bus, incoming(11, true), 2000).await?;
        assert_eq!(host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason, reason);
        assert_eq!(host.checkpoint().cursor, Some(11));
        assert_eq!(bus.requests.len(), 1);
        drop(host);
        let mut resumed = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
        resumed.start(&mut bus).await?;
        resumed.apply(&mut bus, incoming(11, true), 6000).await?;
        assert_eq!(bus.requests.len(), 1);
    }
    Ok(())
}
#[tokio::test]
async fn whole_snapshot_budget_refuses_an_oversized_rule_before_any_create() -> TestResult {
    let mut f = fixture()?;
    f.config.rules[0].reply = "x".repeat(16_384);
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    assert_eq!(host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason, Code::TooLarge);
    assert_eq!(bus.requests, [] as [serde_json::Value; 0]);
    assert_eq!(host.checkpoint().cursor, Some(11));
    Ok(())
}
#[tokio::test]
async fn own_out_of_sync_uses_durable_resync_and_lost_ack_keeps_its_request_id() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    let count = bus.sent.len();
    bus.out_of_sync = true;
    bus.faults.lose_resync = true;
    let mut gap = event(20, false);
    gap.body.as_object_mut().ok_or("body")?.remove("last_action_id");
    gap.body["out_of_sync"] = serde_json::json!(true);
    assert!(matches!(host.apply(&mut bus, gap, 4000).await, Err(Error::Bus)));
    assert_eq!(bus.resyncs.len(), 1);
    assert!(bus.resyncs[0].get("wire_base64").is_none());
    drop(host);
    let mut resumed = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    resumed.start(&mut bus).await?;
    assert_eq!(bus.resyncs.len(), 1);
    assert_eq!(bus.sent.len(), count);
    assert_eq!(resumed.checkpoint().cursor, Some(20));
    Ok(())
}
#[tokio::test]
async fn action_waiting_on_local_resync_is_derived_from_the_recovered_snapshot() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.decision()?;
    bus.out_of_sync = true;
    host.apply(&mut bus, event(20, false), 4000).await?;
    assert_eq!(bus.resyncs.len(), 1);
    assert!(bus.state.is_closed());
    assert_eq!(bus.state.content().ok_or("surface")?.fallback_text, "You chose Thursday.");
    Ok(())
}

#[tokio::test]
async fn unresolved_resync_stops_action_durably_without_an_unbounded_reply_loop() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.decision()?;
    bus.out_of_sync = true;
    bus.resync_failures = 1;
    let sent = bus.sent.len();
    host.apply(&mut bus, event(20, false), 4000).await?;
    assert_eq!(bus.resyncs.len(), 1);
    assert_eq!(host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason, Code::OutOfSync);
    assert_eq!(host.checkpoint().cursor, Some(20));
    drop(host);
    let mut resumed = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    resumed.start(&mut bus).await?;
    assert_eq!(bus.resyncs.len(), 1);
    assert_eq!(bus.sent.len(), sent);
    Ok(())
}
