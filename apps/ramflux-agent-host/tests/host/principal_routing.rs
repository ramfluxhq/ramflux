// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Routed message projections attribute direct senders by principal, not device display names.
use super::support::{Fake, Fixture, TestResult, incoming};
use ramflux_agent_host::{AgentBus, AgentHost, Result, RuleEngine};
use ramflux_sdk::LocalBusFrame;
use serde_json::{Value, json};
struct PrincipalBus(Fake);
impl AgentBus for PrincipalBus {
    async fn request(
        &mut self,
        method: &str,
        body: Value,
        operation: Option<&str>,
    ) -> Result<Value> {
        let mut value = self.0.request(method, body, operation).await?;
        if method == "identity.directory" {
            value["identities"].as_array_mut().ok_or(ramflux_agent_host::Error::Bus)?.insert(0, json!({"principal_id":"outsider","contact_identity_commitment":"outsider-root","devices":[{"device_id":"human-principal","target_delivery_id":"outsider-target"}]}));
        }
        if method == "message.read" {
            value["messages"][0]["sender_id"] = json!("human-principal");
        }
        Ok(value)
    }
    fn next_event(&mut self) -> impl std::future::Future<Output = Result<LocalBusFrame>> {
        std::future::ready(Err(ramflux_agent_host::Error::Bus))
    }
}
#[tokio::test]
async fn direct_reply_routes_to_the_projected_principal_without_treating_it_as_a_device_name()
-> TestResult {
    let f = Fixture::new()?;
    let mut bus = PrincipalBus(Fake::default());
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let mut event = incoming(11, false);
    event.body["message"]["sender_id"] = json!("human-principal");
    host.apply(&mut bus, event, 2000).await?;
    assert_eq!(bus.0.replies.len(), 1);
    assert_eq!(bus.0.replies[0]["recipient_device_id"], "human-device");
    assert_eq!(bus.0.replies[0]["recipient_principal_commitment"], "human-commitment");
    assert_eq!(bus.0.replies[0]["target_delivery_id"], "human-target");
    Ok(())
}
