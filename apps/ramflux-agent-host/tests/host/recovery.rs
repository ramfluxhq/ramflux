// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::support::{Fake, Fault, Fixture, TestResult, incoming};
use ramflux_agent_host::{AgentHost, Error, RuleEngine};
use serde_json::Value;
#[tokio::test]
async fn dm_and_group_reply_as_own_account_then_resume_without_duplicates() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, false), 2000).await?;
    host.apply(&mut bus, incoming(40, true), 2000).await?;
    assert_eq!(bus.replies.len(), 2);
    for reply in &bus.replies {
        assert_eq!(reply["sender_id"], "agent-device");
        assert_eq!(
            ramflux_protocol::decode_base64url(
                reply["plaintext_body_base64"].as_str().ok_or("body")?
            )?,
            b"pong"
        );
    }
    drop(host);
    let mut resumed = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    resumed.start(&mut bus).await?;
    resumed.apply(&mut bus, incoming(40, true), 4000).await?;
    assert_eq!(bus.replies.len(), 2);
    assert!(
        bus.requests
            .iter()
            .any(|(method, body)| method == "bus.subscribe" && body["since_seq"] == 40)
    );
    Ok(())
}
#[tokio::test]
async fn lost_response_reuses_prepared_body_operation_and_cursor_after_restart() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    bus.faults.insert(Fault::LoseResponse);
    assert!(matches!(host.apply(&mut bus, incoming(11, false), 2000).await, Err(Error::Bus)));
    assert_eq!(bus.replies.len(), 1);
    drop(host);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert_eq!(bus.replies.len(), 1);
    assert_eq!(host.checkpoint().cursor, Some(11));
    let saved: Value = serde_json::from_slice(&std::fs::read(&f.config.state_file)?)?;
    assert!(saved["pending"].is_null());
    Ok(())
}
#[tokio::test]
async fn gap_reloads_snapshot_and_uses_fresh_head_without_replaying_old_commands() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    drop(host);
    bus.faults.insert(Fault::Gap);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert_eq!(host.checkpoint().cursor, Some(10));
    assert_eq!(bus.replies.len(), 0);
    assert_eq!(bus.requests.iter().filter(|(m, _)| m == "bus.subscribe").count(), 3);
    assert_eq!(bus.requests.iter().filter(|(m, _)| m == "conversation.directory").count(), 2);
    Ok(())
}
#[tokio::test]
async fn removal_before_pending_recovery_cancels_the_reply() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    bus.faults.insert(Fault::LoseResponse);
    assert!(matches!(host.apply(&mut bus, incoming(11, true), 2000).await, Err(Error::Bus)));
    drop(host);
    let sent = bus.requests.iter().filter(|(m, _)| m == "group.send").count();
    bus.faults.insert(Fault::Removed);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert_eq!(bus.requests.iter().filter(|(m, _)| m == "group.send").count(), sent);
    assert_eq!(host.checkpoint().cursor, Some(11));
    Ok(())
}
#[tokio::test]
async fn a_changed_group_binding_discards_a_prepared_reply() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    bus.faults.insert(Fault::LoseResponse);
    assert!(matches!(host.apply(&mut bus, incoming(11, true), 2000).await, Err(Error::Bus)));
    drop(host);
    let sent = bus.requests.iter().filter(|(m, _)| m == "group.send").count();
    bus.faults.insert(Fault::ChangedContext);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert_eq!(bus.requests.iter().filter(|(m, _)| m == "group.send").count(), sent);
    Ok(())
}
#[tokio::test]
async fn pending_recovery_never_rolls_cursor_back_to_an_older_event() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    bus.faults.insert(Fault::LoseResponse);
    assert!(matches!(host.apply(&mut bus, incoming(40, false), 2000).await, Err(Error::Bus)));
    host.apply(&mut bus, incoming(20, false), 4000).await?;
    assert_eq!(host.checkpoint().cursor, Some(40));
    assert_eq!(bus.replies.len(), 1);
    Ok(())
}

#[tokio::test]
async fn revocation_event_preempts_pending_recovery_even_before_projection_catches_up() -> TestResult
{
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    bus.faults.insert(Fault::LoseResponse);
    assert!(matches!(host.apply(&mut bus, incoming(11, false), 2000).await, Err(Error::Bus)));
    let sent = bus.requests.iter().filter(|(m, _)| m == "message.submit").count();
    let mut revoked = incoming(12, false);
    revoked.method = "identity.device_branch.revoked".into();
    revoked.body["device_id"] = serde_json::json!("agent-device");
    assert!(matches!(host.apply(&mut bus, revoked, 3000).await, Err(Error::IdentityLost)));
    assert_eq!(bus.requests.iter().filter(|(m, _)| m == "message.submit").count(), sent);
    Ok(())
}
