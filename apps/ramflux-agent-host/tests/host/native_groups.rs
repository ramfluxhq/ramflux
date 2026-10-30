// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native group membership and lease refusals remain scoped across recovery.
use super::support::{Fake, Fixture, TestResult, incoming};
use ramflux_agent_host::{AgentBus, AgentHost, Error, GroupRefusal, Result, RuleEngine};
use ramflux_sdk::LocalBusFrame;
use serde_json::{Value, json};

#[derive(Default)]
struct GroupBus {
    inner: Fake,
    mutation: Option<&'static str>,
    lease_missing: bool,
}
impl AgentBus for GroupBus {
    async fn request(
        &mut self,
        method: &str,
        body: Value,
        operation: Option<&str>,
    ) -> Result<Value> {
        if method == "group.send" && self.lease_missing {
            return Err(Error::GroupLeaseUnavailable);
        }
        let mut value = self.inner.request(method, body, operation).await?;
        if method == "group.members" {
            match self.mutation {
                Some("missing") => {
                    value.as_object_mut().ok_or(Error::State)?.remove("member_roster");
                }
                Some("root") => {
                    value["member_roster"][0]["identity"]["root_commitment"] =
                        json!("foreign-root");
                }
                Some("principal") => {
                    value["member_roster"][0]["identity"]["principal_id"] =
                        json!("foreign-principal");
                }
                Some("key") => {
                    value["member_roster"][0]["identity"]["signing_public_key"] =
                        json!("foreign-key");
                }
                Some("excluded") => {
                    value["excluded_devices"] =
                        json!([{"root_commitment":"agent-commitment","device_id":"agent-device"}]);
                }
                _ => {}
            }
        }
        if method == "message.read" {
            value["messages"][0]["sender_id"] = json!("human-principal");
            value["messages"][0]["sender_device_id"] = json!("human-device");
        }
        Ok(value)
    }
    async fn next_event(&mut self) -> Result<LocalBusFrame> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn native_groups_require_the_verified_root_principal_key_pin_and_effective_membership()
-> TestResult {
    for mutation in ["missing", "root", "principal", "key", "excluded"] {
        let f = Fixture::new()?;
        let mut bus = GroupBus { mutation: Some(mutation), ..GroupBus::default() };
        let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
        host.start(&mut bus).await?;
        host.apply(&mut bus, incoming(11, true), 2000).await?;
        assert!(bus.inner.replies.is_empty(), "spoke with invalid pin: {mutation}");
        assert!(!bus.inner.requests.iter().any(|(method, _)| method == "message.read"));
    }
    Ok(())
}

#[tokio::test]
async fn native_group_lease_refusal_retires_the_intent_and_preserves_its_typed_reason() -> TestResult
{
    let f = Fixture::new()?;
    let mut bus = GroupBus { lease_missing: true, ..GroupBus::default() };
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    assert_eq!(
        host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.group_reason,
        Some(GroupRefusal::LeaseUnavailable)
    );
    assert_eq!(bus.inner.replies.len(), 0);
    drop(host);
    bus.lease_missing = false;
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 4000).await?;
    assert!(bus.inner.replies.is_empty(), "replayed a refused intent after restart");
    host.apply(&mut bus, incoming(12, true), 4000).await?;
    assert_eq!(bus.inner.replies.len(), 1);
    assert_eq!(bus.inner.replies[0]["sender_id"], "agent-principal");
    Ok(())
}
