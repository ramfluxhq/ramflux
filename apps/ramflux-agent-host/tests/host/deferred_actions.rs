// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Rate-limited choices stay durable while other events progress and are rechecked before use.
use super::{
    support::{TestResult, incoming},
    surface_bus::{SurfaceBus, event},
    surfaces::fixture,
};
use ramflux_agent_host::{AgentBus, AgentHost, Error, Result, RuleEngine};
use ramflux_sdk::{LocalBusFrame, SurfaceRefusalCode as Code};
use serde_json::Value;
struct DeferredBus {
    inner: SurfaceBus,
    gets: usize,
}
impl AgentBus for DeferredBus {
    async fn request(&mut self, method: &str, body: Value, op: Option<&str>) -> Result<Value> {
        if method == "surface.get" {
            self.gets += 1;
        }
        self.inner.request(method, body, op).await
    }
    async fn next_event(&mut self) -> Result<LocalBusFrame> {
        if self.gets > 0 {
            return Err(Error::Bus);
        }
        std::future::pending().await
    }
}
fn now() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(u64::MAX)
}
async fn run_until_rechecked(
    host: &mut AgentHost<RuleEngine>,
    bus: &mut DeferredBus,
) -> TestResult {
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), host.run(bus)).await?;
    assert!(matches!(result, Err(Error::Bus)), "fixture closes only after a fresh surface read");
    Ok(())
}
#[tokio::test]
async fn r4_a_deferred_choice_survives_restart_and_uses_the_actual_recheck_time() -> TestResult {
    let mut f = fixture()?;
    f.config.per_conversation_interval_ms = 100;
    let mut bus = DeferredBus { inner: SurfaceBus::default(), gets: 0 };
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let started = now();
    host.apply(&mut bus, incoming(11, true), started).await?;
    bus.inner.decision()?;
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        host.apply(&mut bus, event(20, false), started + 1),
    )
    .await??;
    assert!(!bus.inner.state.is_closed());
    assert_eq!(bus.gets, 0);
    let mut next = event(21, false);
    next.method = "device.changed".into();
    host.apply(&mut bus, next, started + 2).await?;
    assert_eq!(host.checkpoint().cursor, Some(21));
    drop(host);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    run_until_rechecked(&mut host, &mut bus).await?;
    assert!(bus.inner.state.is_closed());
    assert_eq!(bus.inner.state.content().ok_or("surface")?.fallback_text, "You chose Thursday.");
    assert!(host.checkpoint().last_reply_ms["group-thread"] >= started + 100);
    assert_eq!(host.checkpoint().cursor, Some(21));
    assert!(serde_json::to_value(host.checkpoint())?.get("deferred_surfaces").is_none());
    Ok(())
}
#[tokio::test]
async fn r4_a_due_choice_rechecks_the_executor_instead_of_trusting_the_deferred_notification()
-> TestResult {
    let mut f = fixture()?;
    f.config.per_conversation_interval_ms = 100;
    let mut bus = DeferredBus { inner: SurfaceBus::default(), gets: 0 };
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let started = now();
    host.apply(&mut bus, incoming(11, true), started).await?;
    bus.inner.decision()?;
    host.apply(&mut bus, event(20, false), started + 1).await?;
    bus.inner.replica = true;
    let sent = bus.inner.sent.len();
    run_until_rechecked(&mut host, &mut bus).await?;
    assert_eq!(
        host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason,
        Code::NotActionExecutor
    );
    assert_eq!(bus.inner.sent.len(), sent);
    assert!(!bus.inner.state.is_closed());
    assert!(serde_json::to_value(host.checkpoint())?.get("deferred_surfaces").is_none());
    Ok(())
}
