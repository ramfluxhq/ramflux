// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refused events and finite recent caches cannot poison later work.
use super::{
    support::{Fake, Fault, Fixture, TestResult, incoming},
    surface_bus::{SurfaceBus, event},
    surfaces::fixture,
};
use ramflux_agent_host::{
    AgentBus, AgentHost, Choice, ConversationInput, EngineProvider, Error, Intent, Result,
    RuleEngine,
};
use ramflux_sdk::{LocalBusFrame, SurfaceRefusalCode as Code};
use serde_json::{Value, json};
use std::collections::VecDeque;

#[tokio::test]
async fn native_reply_refreshes_a_temporarily_empty_peer_device_projection() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::with(Fault::EmptyDevices);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, false), 2000).await?;
    assert!(bus.requests.iter().any(|(method, _)| method == "device.refresh"));
    assert_eq!(bus.replies.len(), 1);
    Ok(())
}

#[derive(Default)]
struct RoutedBus {
    inner: Fake,
    revoked: bool,
    many: bool,
    events: VecDeque<LocalBusFrame>,
}
impl AgentBus for RoutedBus {
    async fn request(
        &mut self,
        method: &str,
        body: Value,
        operation: Option<&str>,
    ) -> Result<Value> {
        if method == "conversation.directory" && self.many {
            let offset = body["cursor"].as_str().and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let rows=(offset..(offset+100).min(200)).map(|i| json!({"id":format!("dm-{i}"),"kind":"direct","participants":["agent-principal","human-principal"]})).collect::<Vec<_>>();
            return Ok(
                json!({"conversations":rows,"next_cursor":if offset+100<200 {Some((offset+100).to_string())} else {None}}),
            );
        }
        let mut value = self.inner.request(method, body.clone(), operation).await?;
        if method == "message.read" {
            value["messages"][0]["sender_id"] = json!("human-principal");
        }
        if method == "identity.directory" {
            value["identities"][1]["devices"] = json!([
                {"device_id":"human-device","target_delivery_id":"target-one","revoked":self.revoked},
                {"device_id":"human-two","target_delivery_id":"target-two","revoked":self.revoked},
                {"device_id":"human-revoked","target_delivery_id":"never","revoked":true}
            ]);
        }
        Ok(value)
    }
    async fn next_event(&mut self) -> Result<LocalBusFrame> {
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }
        std::future::pending().await
    }
}
#[tokio::test]
async fn r3_two_hundred_conversations_do_not_exhaust_a_recent_reply_cache() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = RoutedBus { many: true, ..Default::default() };
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    for i in 0..200 {
        let mut event = incoming(11 + i, false);
        event.body["message"]["conversation_id"] = json!(format!("dm-{i}"));
        host.apply(&mut bus, event, 2000 + i * 1001).await?;
    }
    assert_eq!(bus.inner.replies.len(), 400);
    assert_eq!(host.checkpoint().cursor, Some(210));
    assert!(host.checkpoint().last_reply_ms.len() <= 1);
    Ok(())
}
#[tokio::test]
async fn r3_a_peer_revoked_after_prompting_is_refused_and_the_next_prompt_is_served() -> TestResult
{
    let f = Fixture::new()?;
    let mut bus = RoutedBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    bus.revoked = true;
    host.apply(&mut bus, incoming(11, false), 2000).await?;
    assert_eq!(host.checkpoint().cursor, Some(11));
    assert_eq!(host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason, Code::NotFound);
    assert_eq!(bus.inner.replies, [] as [Value; 0]);
    bus.revoked = false;
    host.apply(&mut bus, incoming(12, false), 4000).await?;
    assert_eq!(bus.inner.replies.len(), 2);
    Ok(())
}
#[tokio::test]
async fn r3_direct_reply_reaches_every_active_peer_device_with_one_logical_message() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = RoutedBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, false), 2000).await?;
    assert_eq!(bus.inner.replies.len(), 2);
    let (a, b) = (&bus.inner.replies[0], &bus.inner.replies[1]);
    assert_eq!(a["recipient_device_id"], "human-device");
    assert_eq!(b["recipient_device_id"], "human-two");
    assert_eq!(a["message_id"], b["message_id"]);
    assert_ne!(a["envelope_id"], b["envelope_id"]);
    assert_eq!(a["plaintext_body_base64"], b["plaintext_body_base64"]);
    drop(host);
    let mut resumed = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    resumed.start(&mut bus).await?;
    resumed.apply(&mut bus, incoming(11, false), 4000).await?;
    assert_eq!(bus.inner.replies.len(), 2);
    Ok(())
}
#[test]
fn r3_unsafe_reply_and_choice_labels_are_refused_at_configuration_load() -> TestResult {
    let mut f = fixture()?;
    f.config.rules[0].reply = "spoof\u{202e}text".into();
    assert!(matches!(f.config.validate(), Err(Error::Config)));
    f.config.rules[0].reply = "safe reply".into();
    f.config.rules[0].surface.as_mut().ok_or("surface")?.choices =
        vec![Choice { id: "a".into(), label: "spoof\u{202e}text".into() }];
    assert!(matches!(f.config.validate(), Err(Error::Config)));
    Ok(())
}
#[tokio::test]
async fn r3_rate_limited_actions_do_not_sleep_or_block_the_next_event() -> TestResult {
    let mut f = fixture()?;
    f.config.per_conversation_interval_ms = 3_600_000;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.decision()?;
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        host.apply(&mut bus, event(20, false), 2001),
    )
    .await??;
    let queued = serde_json::to_value(host.checkpoint())?;
    assert_eq!(queued["deferred_surfaces"].as_object().ok_or("deferred")?.len(), 1);
    let mut next = event(21, false);
    next.method = "device.changed".into();
    host.apply(&mut bus, next, 2002).await?;
    assert_eq!(host.checkpoint().cursor, Some(21));
    Ok(())
}
struct PoisonOnce {
    rules: RuleEngine,
    first: bool,
}
impl EngineProvider for PoisonOnce {
    fn intents(&mut self, input: &ConversationInput<'_>) -> Result<Vec<Intent>> {
        if self.first {
            self.first = false;
            Err(Error::State)
        } else {
            self.rules.intents(input)
        }
    }
}
#[tokio::test]
async fn r3_the_running_host_consumes_a_poison_event_and_handles_the_next_event() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = RoutedBus::default();
    bus.events.extend([incoming(11, false), incoming(12, false)]);
    let mut host = AgentHost::new(
        f.config.clone(),
        PoisonOnce { rules: RuleEngine::new(&f.config)?, first: true },
    )?;
    host.start(&mut bus).await?;
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(1000), host.run(&mut bus)).await;
    assert!(result.is_err(), "the host must keep running after the poison event");
    assert_eq!(host.checkpoint().cursor, Some(12));
    assert_eq!(
        host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason,
        Code::InvalidRequest
    );
    assert_eq!(bus.inner.replies.len(), 2);
    Ok(())
}

#[tokio::test]
async fn r3_an_applied_result_still_closes_after_a_stale_close_refusal() -> TestResult {
    let f = fixture()?;
    let mut bus = SurfaceBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.decision()?;
    bus.faults.stale = super::surface_bus::StalePoint::Close;
    host.apply(&mut bus, event(20, false), 4000).await?;
    assert_eq!(bus.state.content().ok_or("surface")?.fallback_text, "You chose Thursday.");
    assert!(bus.state.is_closed());
    assert_eq!(host.checkpoint().cursor, Some(20));
    Ok(())
}
#[tokio::test]
async fn r3_three_thousand_choices_continue_after_the_recent_action_fifo_wraps() -> TestResult {
    use ramflux_protocol::{A2uiConversationCommand as C, A2uiConversationEvent, SurfaceState};
    let mut f = fixture()?;
    f.config.rules[0].reply = "Ready".into();
    let mut bus = SurfaceBus::default();
    let mut engine = RuleEngine::new(&f.config)?;
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    for i in 0..3000 {
        let intents = engine.intents(&ConversationInput {
            conversation_id: "group-thread",
            message_id: "prompt",
            text: "@agent checklist",
        })?;
        let Intent::CreateSurface(content) = &intents[0] else { return Err("create".into()) };
        let bytes = ramflux_protocol::encode_a2ui_conversation_event(
            "group-thread",
            1,
            &C::CreateSurface(content.clone()),
        )?;
        bus.state =
            SurfaceState::default().apply(&A2uiConversationEvent::from_wire_bytes(&bytes)?)?;
        bus.decision()?;
        let id = format!("choice-{i}");
        bus.action.as_mut().ok_or("action")?["id"] = json!(id);
        let mut frame = event(20 + i, false);
        frame.body["last_action_id"] = json!(id);
        host.apply(&mut bus, frame, 4000 + i * 1001).await?;
        assert!(bus.state.is_closed(), "choice {i}");
    }
    assert_eq!(bus.sent.len(), 6000);
    assert_eq!(host.checkpoint().cursor, Some(3019));
    assert!(host.checkpoint().last_refusal.is_none());
    let state = serde_json::to_value(host.checkpoint())?;
    assert_eq!(state["handled_actions"].as_array().ok_or("cache")?.len(), 2048);
    Ok(())
}

#[tokio::test]
async fn r3_a_peer_device_batch_resumes_after_a_lost_ack_without_duplicate_delivery() -> TestResult
{
    let f = Fixture::new()?;
    let mut bus = RoutedBus::default();
    bus.inner.faults.insert(super::support::Fault::LoseResponse);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert!(matches!(host.apply(&mut bus, incoming(11, false), 2000).await, Err(Error::Bus)));
    assert_eq!(bus.inner.replies.len(), 1);
    let first = bus.inner.replies[0].clone();
    drop(host);
    let mut resumed = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    resumed.start(&mut bus).await?;
    assert_eq!(bus.inner.replies.len(), 2);
    assert_eq!(bus.inner.replies[0], first);
    assert_eq!(bus.inner.replies[1]["recipient_device_id"], "human-two");
    assert_eq!(resumed.checkpoint().cursor, Some(11));
    Ok(())
}

#[tokio::test]
async fn r3_a_sibling_device_revocation_does_not_stop_the_authorized_host() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = RoutedBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let mut revoked = incoming(11, false);
    revoked.method = "identity.device_branch.revoked".into();
    revoked.body = json!({"device_id":"agent-sibling","revoked_at":1234});
    host.apply(&mut bus, revoked, 2000).await?;
    assert_eq!(host.checkpoint().cursor, Some(11));
    host.apply(&mut bus, incoming(12, false), 4000).await?;
    assert_eq!(bus.inner.replies.len(), 2);
    Ok(())
}
