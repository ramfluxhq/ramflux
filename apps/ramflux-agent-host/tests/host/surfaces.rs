// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    support::{Fixture, TestResult, incoming},
    surface_bus::{SurfaceBus, event},
};
use ramflux_agent_host::{AgentHost, Choice, Error, Rule, RuleEngine, SurfaceRule};
pub(super) fn fixture() -> std::io::Result<Fixture> {
    let mut f = Fixture::new()?;
    f.config.rules = vec![Rule {
        pattern: "@agent checklist".into(),
        reply: "Checklist\n- verify protocol\n- verify fallback 🦀".repeat(12),
        surface: Some(SurfaceRule {
            chunk_bytes: 256,
            choices: vec![
                Choice { id: "thu".into(), label: "Thursday".into() },
                Choice { id: "mon".into(), label: "Monday".into() },
            ],
            close_on_action: true,
        }),
    }];
    Ok(f)
}
#[tokio::test]
async fn streamed_reply_choice_result_and_restart_have_no_duplicate_surfaces() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    let content = bus.state.content().ok_or("surface")?;
    assert_eq!(content.components[0]["text"], f.config.rules[0].reply);
    assert_eq!(content.fallback_text, f.config.rules[0].reply);
    assert!(!bus.state.is_closed());
    assert_eq!(bus.state.stream_states()["reply"], ramflux_protocol::SurfaceStreamState::Final);
    assert!(bus.sent.len() > 3);
    for body in &bus.sent {
        assert_eq!(
            ramflux_protocol::decode_base64url(body["message_id"].as_str().ok_or("id")?)?.len(),
            16
        );
    }
    bus.decision()?;
    host.apply(&mut bus, event(20, false), 4000).await?;
    assert_eq!(bus.state.content().ok_or("surface")?.fallback_text, "You chose Thursday.");
    assert!(bus.state.is_closed());
    let count = bus.sent.len();
    drop(host);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, event(21, false), 6000).await?;
    host.apply(&mut bus, incoming(11, true), 6000).await?;
    assert_eq!(bus.sent.len(), count);
    Ok(())
}
#[tokio::test]
async fn lost_response_in_a_stream_batch_reuses_wire_and_resumes_remaining_chunks() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    bus.lose_at = Some(2);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert!(matches!(host.apply(&mut bus, incoming(11, true), 2000).await, Err(Error::Bus)));
    assert_eq!(bus.sent.len(), 2);
    let id = bus.id()?.to_string();
    drop(host);
    let mut resumed = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    resumed.start(&mut bus).await?;
    assert_eq!(bus.requests[1], bus.requests[2]);
    assert_eq!(bus.id()?, id);
    assert_eq!(
        bus.state.content().ok_or("surface")?.components[0]["text"],
        f.config.rules[0].reply
    );
    assert_eq!(resumed.checkpoint().cursor, Some(11));
    Ok(())
}
#[tokio::test]
async fn conflict_reloads_current_snapshot_and_rebuilds_the_result_patch() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.decision()?;
    let before = bus.requests.len();
    bus.conflict = true;
    host.apply(&mut bus, event(20, false), 4000).await?;
    assert_eq!(bus.requests.len() - before, 3, "conflict, rebuilt result, close");
    assert_ne!(bus.requests[before]["message_id"], bus.requests[before + 1]["message_id"]);
    let decode = |row: &serde_json::Value| -> std::result::Result<
        ramflux_protocol::A2uiConversationEvent,
        Box<dyn std::error::Error>,
    > {
        Ok(ramflux_protocol::A2uiConversationEvent::from_wire_bytes(
            &ramflux_protocol::decode_base64url(row["wire_base64"].as_str().ok_or("wire")?)?,
        )?)
    };
    assert_eq!(
        decode(&bus.requests[before + 1])?.version(),
        decode(&bus.requests[before])?.version() + 1
    );
    assert_eq!(bus.state.content().ok_or("surface")?.fallback_text, "You chose Thursday.");
    assert!(bus.state.is_closed());
    Ok(())
}
#[tokio::test]
async fn mirrored_actions_never_execute_on_a_replica_terminal() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.replica = true;
    bus.decision()?;
    let before = bus.sent.len();
    host.apply(&mut bus, event(20, true), 4000).await?;
    // Even a stale executor notification cannot override the current read's replica flag.
    assert!(matches!(host.apply(&mut bus, event(21, false), 4000).await, Err(Error::Unauthorized)));
    assert_eq!(bus.sent.len(), before);
    Ok(())
}

#[tokio::test]
async fn repeated_conflicts_stop_durably_without_resending_a_known_stale_result() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.decision()?;
    bus.conflicts_remaining = 3;
    assert!(matches!(host.apply(&mut bus, event(20, false), 4000).await, Err(Error::Limit)));
    let requests = bus.requests.len();
    drop(host);
    let mut resumed = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    assert!(matches!(resumed.start(&mut bus).await, Err(Error::Limit)));
    assert_eq!(requests, bus.requests.len());
    Ok(())
}
