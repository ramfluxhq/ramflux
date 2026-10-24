// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incomplete read-model rows and foreign frames never masquerade as transport failures.
use super::{
    support::{Fixture, TestResult, incoming},
    surface_bus::{SurfaceBus, event},
    surfaces::fixture,
};
use ramflux_agent_host::{AgentBus, AgentHost, Error, Result, Rule, RuleEngine};
use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind, SurfaceRefusalCode as Code};
use serde_json::{Value, json};
use std::collections::{BTreeSet, VecDeque};
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Fault {
    MissingRoot,
    MissingReference,
    RejectPoll,
    ReleaseAfterPoll,
}
#[derive(Default)]
struct RowBus {
    inner: SurfaceBus,
    faults: BTreeSet<Fault>,
    gets: usize,
    fail_get: Option<usize>,
    polls: usize,
    events: VecDeque<LocalBusFrame>,
}
impl AgentBus for RowBus {
    async fn request(&mut self, method: &str, body: Value, op: Option<&str>) -> Result<Value> {
        if method == "message.receive" {
            self.polls += 1;
            if self.faults.remove(&Fault::RejectPoll) {
                return Err(Error::SurfaceRefused(Code::InvalidRequest));
            }
        }
        if method == "surface.get" {
            self.gets += 1;
            if self.fail_get == Some(self.gets) {
                return Err(Error::Bus);
            }
        }
        let mut value = if method == "message.read" && body["conversation_id"] == "dm" {
            let mut value = self.inner.inner.request(method, body, op).await?;
            value["messages"][0]["sender_id"] = json!("human-principal");
            value
        } else {
            self.inner.request(method, body, op).await?
        };
        if method == "identity.directory" && self.faults.contains(&Fault::MissingRoot) {
            value["identities"][1]["contact_identity_commitment"] = Value::Null;
        }
        if method == "surface.get" && self.faults.contains(&Fault::MissingReference) {
            value.as_object_mut().ok_or(Error::State)?.remove("surface_ref");
        }
        Ok(value)
    }
    async fn next_event(&mut self) -> Result<LocalBusFrame> {
        if self.faults.contains(&Fault::ReleaseAfterPoll) && self.polls == 0 {
            return std::future::pending().await;
        }
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }
        std::future::pending().await
    }
}
fn config() -> std::result::Result<Fixture, Box<dyn std::error::Error>> {
    let mut f = fixture()?;
    f.config.rules.push(Rule {
        pattern: "@agent ping".into(),
        reply: "pong".into(),
        surface: None,
    });
    Ok(f)
}
fn assert_refused(host: &AgentHost<RuleEngine>, seq: u64) -> TestResult {
    assert_eq!(host.checkpoint().cursor, Some(seq));
    assert_eq!(
        host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason,
        Code::InvalidRequest
    );
    assert!(serde_json::to_value(host.checkpoint())?["pending"].is_null());
    Ok(())
}
async fn serve_next(host: &mut AgentHost<RuleEngine>, bus: &mut RowBus, seq: u64) -> TestResult {
    host.apply(bus, incoming(seq, false), 8000).await?;
    assert_eq!(bus.inner.inner.replies.len(), 1);
    assert_eq!(host.checkpoint().cursor, Some(seq));
    Ok(())
}
#[tokio::test]
async fn r4_a_peer_without_a_root_commitment_is_refused_before_serving_the_next_prompt()
-> TestResult {
    let f = config()?;
    let mut bus = RowBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    bus.faults.insert(Fault::MissingRoot);
    host.apply(&mut bus, incoming(11, false), 2000).await?;
    assert_refused(&host, 11)?;
    assert_eq!(bus.inner.inner.replies, [] as [Value; 0]);
    bus.faults.remove(&Fault::MissingRoot);
    serve_next(&mut host, &mut bus, 12).await
}
#[tokio::test]
async fn r4_a_message_without_a_conversation_is_refused_before_serving_the_next_prompt()
-> TestResult {
    let f = config()?;
    let mut bus = RowBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let mut malformed = incoming(11, false);
    malformed.body["message"].as_object_mut().ok_or("message")?.remove("conversation_id");
    host.apply(&mut bus, malformed, 2000).await?;
    assert_refused(&host, 11)?;
    serve_next(&mut host, &mut bus, 12).await
}
#[tokio::test]
async fn r4_a_recovered_out_of_sync_view_without_a_reference_does_not_wedge_the_host() -> TestResult
{
    let f = config()?;
    let mut bus = RowBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    bus.inner.decision()?;
    bus.inner.out_of_sync = true;
    bus.fail_get = Some(2);
    assert!(matches!(host.apply(&mut bus, event(20, false), 4000).await, Err(Error::Bus)));
    drop(host);
    bus.faults.insert(Fault::MissingReference);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert_refused(&host, 20)?;
    bus.faults.remove(&Fault::MissingReference);
    bus.inner.out_of_sync = false;
    serve_next(&mut host, &mut bus, 21).await
}
#[tokio::test]
async fn r4_invalid_stream_frames_are_skipped_without_consuming_an_account_cursor() -> TestResult {
    let f = config()?;
    let mut bus = RowBus::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let mut foreign = incoming(99, false);
    foreign.account_id = Some("another-account".into());
    let mut response = incoming(98, false);
    response.kind = LocalBusFrameKind::Response;
    let mut missing = incoming(97, false);
    missing.seq = None;
    for frame in [foreign, response, missing] {
        host.apply(&mut bus, frame, 2000).await?;
        assert_eq!(host.checkpoint().cursor, Some(10));
    }
    serve_next(&mut host, &mut bus, 11).await
}
#[tokio::test]
async fn r4_a_permanent_poll_refusal_keeps_the_stream_connected_for_the_next_prompt() -> TestResult
{
    let f = config()?;
    let mut bus = RowBus::default();
    bus.faults.extend([Fault::RejectPoll, Fault::ReleaseAfterPoll]);
    bus.events.push_back(incoming(11, false));
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(800), host.run(&mut bus)).await;
    assert!(result.is_err(), "a permanent per-poll refusal cannot return from run");
    assert!(bus.polls >= 1);
    assert_refused(&host, 11)?;
    assert_eq!(bus.inner.inner.replies.len(), 1);
    Ok(())
}
#[test]
fn r4_rule_patterns_and_choice_ids_must_pass_text_safety_before_startup() -> TestResult {
    let mut f = config()?;
    f.config.rules[0].pattern = "spoof\u{202e}pattern".into();
    assert!(matches!(f.config.validate(), Err(Error::Config)));
    f.config.rules[0].pattern = "@agent checklist".into();
    f.config.rules[0].surface.as_mut().ok_or("surface")?.choices[0].id = "spoof\u{202e}id".into();
    assert!(matches!(f.config.validate(), Err(Error::Config)));
    Ok(())
}
