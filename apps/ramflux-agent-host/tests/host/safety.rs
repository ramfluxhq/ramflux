// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::support::{Fake, Fault, Fixture, TestResult, incoming};
use ramflux_agent_host::{
    AgentHost, Config, ConversationInput, EngineProvider, Error, Intent, RuleEngine,
};
use std::os::unix::fs::PermissionsExt;
#[test]
fn rules_are_exact_deterministic_and_multiline() -> TestResult {
    let f = Fixture::new()?;
    let mut engine = RuleEngine::new(&f.config)?;
    let intents = engine.intents(&ConversationInput {
        conversation_id: "c",
        message_id: "m",
        text: " @agent ping ",
    })?;
    assert!(matches!(intents.as_slice(),[Intent::ReplyText(text)] if text=="pong"));
    let intents = engine.intents(&ConversationInput {
        conversation_id: "c",
        message_id: "m",
        text: "@agent summarize",
    })?;
    assert!(matches!(intents.as_slice(),[Intent::ReplyText(text)] if text.lines().count()==3));
    assert!(
        engine
            .intents(&ConversationInput {
                conversation_id: "c",
                message_id: "m",
                text: "please @agent ping"
            })?
            .is_empty()
    );
    Ok(())
}
#[tokio::test]
async fn human_account_cannot_start_even_with_forged_headless_identity_kind() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::with(Fault::Human);
    bus.faults.insert(Fault::SpoofKind);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    let error = host.start(&mut bus).await.err().ok_or("human account accepted")?;
    assert!(matches!(error, Error::IdentityLost));
    assert!(!error.to_string().contains("principal"));
    assert_eq!(bus.replies.len(), 0);
    Ok(())
}
#[tokio::test]
async fn removed_group_absent_conversation_and_self_message_do_not_trigger_replies() -> TestResult {
    for scenario in [Fault::Removed, Fault::Absent, Fault::SelfSender] {
        let f = Fixture::new()?;
        let mut bus = Fake::with(scenario);
        let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
        host.start(&mut bus).await?;
        host.apply(&mut bus, incoming(11, true), 2000).await?;
        assert_eq!(bus.replies.len(), 0);
    }
    Ok(())
}
#[tokio::test]
async fn per_conversation_rate_limit_survives_restart_and_is_independent() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, false), 2000).await?;
    drop(host);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(12, false), 2500).await?;
    host.apply(&mut bus, incoming(13, true), 2500).await?;
    assert_eq!(bus.replies.len(), 2);
    Ok(())
}
#[tokio::test]
async fn lagged_foreign_and_revoked_events_fail_closed() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let mut event = incoming(11, false);
    event.method = "stream.lagged".into();
    assert!(matches!(host.apply(&mut bus, event, 2000).await, Err(Error::Resync)));
    let mut event = incoming(11, false);
    event.account_id = Some("human".into());
    assert!(matches!(host.apply(&mut bus, event, 2000).await, Err(Error::Unauthorized)));
    let mut event = incoming(11, false);
    event.method = "identity.device_branch.revoked".into();
    event.body["device_id"] = serde_json::json!("agent-device");
    assert!(matches!(host.apply(&mut bus, event, 2000).await, Err(Error::IdentityLost)));
    assert_eq!(bus.replies.len(), 0);
    Ok(())
}
#[test]
fn configuration_checkpoint_lock_and_corruption_are_bounded() -> TestResult {
    let f = Fixture::new()?;
    let mut config = f.config.clone();
    config.rules[0].reply = "x".repeat(16385);
    assert!(config.validate().is_err());
    let locked_host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    assert!(AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?).is_err());
    let bad = f.root.join("bad.json");
    std::fs::write(&bad, b"{\"unknown\":true}")?;
    assert!(Config::load(&bad).is_err());
    drop(locked_host);
    std::fs::write(&f.config.state_file, b"not JSON")?;
    assert!(AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?).is_err());
    Ok(())
}
#[tokio::test]
async fn directory_size_is_independent_of_recent_rate_history_capacity() -> TestResult {
    let f = Fixture::new()?;
    let mut config = f.config.clone();
    config.max_conversations = 1;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(config.clone(), RuleEngine::new(&config)?)?;
    host.start(&mut bus).await?;
    assert_eq!(host.checkpoint().cursor, Some(10));
    assert_eq!(bus.replies.len(), 0);
    Ok(())
}
#[tokio::test]
async fn checkpoint_is_owner_only_and_cannot_be_reused_by_another_account() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert_eq!(std::fs::metadata(&f.config.state_file)?.permissions().mode() & 0o777, 0o600);
    drop(host);
    let mut config = f.config.clone();
    config.account_id = "another-account".into();
    let mut host = AgentHost::new(config.clone(), RuleEngine::new(&config)?)?;
    assert!(matches!(host.start(&mut bus).await, Err(Error::IdentityLost)));
    Ok(())
}
#[tokio::test]
async fn removal_between_engine_input_and_delivery_suppresses_output() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::with(Fault::RemoveBeforeSend);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    host.apply(&mut bus, incoming(11, true), 2000).await?;
    assert_eq!(bus.replies.len(), 0);
    assert_eq!(host.checkpoint().cursor, Some(11));
    Ok(())
}
#[tokio::test]
async fn actual_rfd_client_refuses_grant_confirmation_before_sending() -> TestResult {
    use ramflux_agent_host::{AgentBus, RfdBus};
    use tokio::io::AsyncReadExt;
    let f = Fixture::new()?;
    let listener = tokio::net::UnixListener::bind(&f.config.socket)?;
    let mut bus = RfdBus::connect(&f.config.socket, "agent").await?;
    let (mut stream, _) = listener.accept().await?;
    for method in ["grant.approve", "mcp.approval.confirm", "account.create", "device.activate"] {
        assert!(matches!(
            bus.request(method, serde_json::json!({}), None).await,
            Err(Error::Unauthorized)
        ));
    }
    let mut byte = [0u8; 1];
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), stream.read(&mut byte))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn revoked_local_device_is_rejected_even_if_display_directory_still_lists_it() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::with(Fault::Revoked);
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    assert!(matches!(host.start(&mut bus).await, Err(Error::IdentityLost)));
    assert_eq!(bus.replies.len(), 0);
    Ok(())
}
