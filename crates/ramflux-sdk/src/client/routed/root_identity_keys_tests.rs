// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Copied literal device names cannot reserve another root's replay or control identities.
use super::review::{pool, trust};
use super::*;
use crate::client::identity_authority::HeadUse;

#[tokio::test]
async fn copied_device_name_cannot_preclaim_an_honest_envelope_id_in_another_thread()
-> Result<(), SdkError> {
    let mut alice = Fixture::native_principal("alice", "alice").await?;
    let bob = Fixture::native_principal("bob", "bob").await?;
    let mallory = Fixture::native_principal("bob", "mallory").await?;
    trust(&alice, &bob)?;
    trust(&alice, &mallory)?;
    for (link, peer) in [("bob-link", &bob), ("mallory-link", &mallory)] {
        alice.client.establish_friend_link(
            link,
            &alice.client.own_account_anchor()?,
            &peer.client.own_account_anchor()?,
        )?;
    }
    let first = generated_delivery(&bob, &alice, "tui_env_1", "first honest message")?;
    receive_generated(&mut alice, &first.entry).await?;
    let attack = generated_delivery(
        &mallory,
        &alice,
        "tui_env_2",
        "legitimate message in Mallory's own thread",
    )?;
    receive_generated(&mut alice, &attack.entry).await?;
    let honest = generated_delivery(&bob, &alice, "tui_env_2", "second honest message")?;
    receive_generated(&mut alice, &honest.entry).await?;
    assert_eq!(attack.entry.envelope.envelope_id, honest.entry.envelope.envelope_id);
    assert_ne!(attack.message, honest.message);
    assert_ne!(
        alice.client.authenticated_committed_key(HeadUse::NewAuthorization, &attack.entry)?,
        alice.client.authenticated_committed_key(HeadUse::NewAuthorization, &honest.entry)?
    );
    assert_eq!(alice.client.direct_messages(&first.conversation)?.len(), 2);
    assert_eq!(alice.client.direct_messages(&attack.conversation)?.len(), 1);
    assert!(alice.client.account_db()?.actor_state_exists(
        &alice.client.authenticated_committed_key(HeadUse::NewAuthorization, &honest.entry)?
    )?);
    Ok(())
}

fn a2i(device: &str, target: &str) -> A2iControlEvent {
    A2iControlEvent {
        source_principal_id: None,
        source_principal_commitment: None,
        event_id: "same-control-event".into(),
        event_type: "a2i.control".into(),
        source_device_id: device.into(),
        target_device_id: target.into(),
        control_domain: "message".into(),
        action: "test".into(),
        subject_base64: String::new(),
        created_at: now_unix_timestamp(),
        acknowledged: false,
    }
}
#[tokio::test]
async fn copied_name_controls_keep_independent_keys_but_require_native_authority()
-> Result<(), SdkError> {
    let alice = Fixture::native_principal("alice", "alice").await?;
    let bob = Fixture::native_principal("bob", "bob").await?;
    let mallory = Fixture::native_principal("bob", "mallory").await?;
    trust(&alice, &bob)?;
    trust(&alice, &mallory)?;
    let mut keys = std::collections::BTreeSet::new();
    for sender in [&mallory, &bob] {
        let source = sender.client.owned_device_identity()?;
        alice.client.trusted_device(HeadUse::NewAuthorization, &source)?;
        keys.insert(crate::client::routed::control::a2i_key(&source, "same-control-event")?);
        let mut engine =
            GatewaySessionEngine::with_test_transport(sender.config()?, Box::new(NoNetwork));
        assert_a2i_authority_refused(
            sender
                .client
                .send_a2i_control_event_via_gateway(&mut engine, &a2i("bob", "alice"), None)
                .await,
        );
        assert_eq!(sender.client.account_db()?.actor_state_keys("a2i/")?.len(), 0);
    }
    assert_eq!(keys.len(), 2, "independent native roots must have distinct private selectors");
    assert_eq!(alice.client.account_db()?.actor_state_keys("a2i/scoped/")?.len(), 0);
    Ok(())
}
#[tokio::test]
async fn outgoing_a2i_refuses_forged_identity_and_engine_principal_before_peer_io()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 11)?;
    let mut event = a2i("alice", "unresolved-peer");
    event.source_principal_id = Some("mallory".into());
    let mut engine =
        GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    let error = alice
        .client
        .send_a2i_control_event_via_gateway(&mut engine, &event, None)
        .await
        .err()
        .ok_or_else(|| invalid("forged source was submitted"))?;
    assert_a2i_authority_refused::<()>(Err(error));
    event.source_principal_id = None;
    let mut config = alice.config()?;
    config.principal_id = "mallory".into();
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(NoNetwork));
    let error = alice
        .client
        .send_a2i_control_event_via_gateway(&mut engine, &event, None)
        .await
        .err()
        .ok_or_else(|| invalid("foreign engine principal was submitted"))?;
    assert_a2i_authority_refused::<()>(Err(error));
    assert_eq!(alice.client.account_db()?.actor_state_keys("a2i/")?, Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn retired_replay_rows_cannot_replace_current_root_qualified_receipts() -> Result<(), SdkError>
{
    let mut alice = Fixture::native_principal("alice", "alice").await?;
    let bob = Fixture::native_principal("bob", "bob").await?;
    let mallory = Fixture::native_principal("bob", "mallory").await?;
    trust(&alice, &bob)?;
    trust(&alice, &mallory)?;
    alice.client.establish_friend_link(
        "bob-link",
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )?;
    let mut engine =
        GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    let entry = generated_delivery(&bob, &alice, "migrate-id", "body")?.entry;
    alice.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    let key = alice.client.authenticated_committed_key(HeadUse::NewAuthorization, &entry)?;
    let db = alice.client.account_db()?;
    let receipt =
        db.load_actor_state::<serde_json::Value>(&key)?.ok_or_else(|| invalid("receipt"))?;
    // An unqualified retained row is never translated into current replay authority.
    let seen = db.routed_seen_key(&ramflux_protocol::canonical_json_bytes(&entry.envelope)?)?;
    db.remove_actor_state(&seen)?;
    db.remove_actor_state(&key)?;
    db.persist_actor_state("routed/committed/old-name-digest", &receipt)?;
    db.persist_actor_state("legacy/committed/migrate-id", &"mallory-thread")?;
    assert_eq!(alice.client.committed_direct_context(&entry)?, None);
    assert!(
        alice.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await.is_err(),
        "retired receipts cannot resurrect an already consumed ratchet counter"
    );
    let db = alice.client.account_db()?;
    assert!(!db.actor_state_exists(&key)?);
    assert!(db.actor_state_exists("routed/committed/old-name-digest")?);
    let attack = generated_delivery(&mallory, &alice, "migrate-id", "attack")?.entry;
    assert_eq!(alice.client.committed_direct_context(&attack)?, None);
    let messages = alice.client.direct_messages(
        receipt["routing"]["conversation_id"].as_str().ok_or_else(|| invalid("route"))?,
    )?;
    assert_eq!(messages.len(), 1);
    Ok(())
}

#[tokio::test]
async fn reset_work_requires_current_root_bound_state_without_translation() -> Result<(), SdkError>
{
    let alice = Fixture::native_principal("alice", "alice").await?;
    let bob = Fixture::native_principal("bob", "bob").await?;
    trust(&alice, &bob)?;
    let local = alice.client.owned_device_identity()?;
    let remote = bob.client.owned_device_identity()?;
    let key = RamfluxClient::reset_work_key(&local, &remote)?;
    let value = serde_json::json!({"local":local.storage_key(),"remote":remote.storage_key(),"attempts":5,"next_at":120,"first_at":10});
    let db = alice.client.account_db()?;
    db.persist_actor_state(&key, &value)?;
    let restored = alice.client.retained_reset_work(&local)?;
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].attempts, 5);
    assert_eq!(restored[0].first_at, Some(10));
    assert_eq!(restored[0].next_at, 120);
    let malformed = serde_json::json!({"local":"alice","remote":remote.storage_key(),"attempts":5,"next_at":120,"first_at":10});
    db.persist_actor_state("dm-pair/reset-work/unproven", &malformed)?;
    assert!(
        alice.client.retained_reset_work(&local).is_err(),
        "rootless work must fail without translation"
    );
    assert_eq!(db.load_actor_state::<serde_json::Value>(&key)?, Some(value));
    assert_eq!(
        db.load_actor_state::<serde_json::Value>("dm-pair/reset-work/unproven")?,
        Some(malformed)
    );
    assert_eq!(db.actor_state_keys("legacy/reset-work/")?, Vec::<String>::new());
    Ok(())
}

#[test]
fn colliding_device_names_never_escape_inbox_failure_policy() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 11)?;
    let bob = Fixture::owned("shared", "bob", 31, 32)?;
    let mallory = Fixture::owned("shared", "mallory", 51, 52)?;
    trust(&alice, &bob)?;
    trust(&alice, &mallory)?;
    alice.client.establish_friend_link("bob-link", "alice", "bob")?;
    let entry = seal(&bob, &alice, super::r5::outgoing(&bob, &alice, "held"), b"pending")?;
    let key = alice.client.inbox_admission_key(&entry)?;
    assert!(crate::client::inbox_failure::defer_entry(
        &alice.client,
        "alice",
        &entry,
        &key,
        &serde_json::to_vec(&entry)?,
        now_unix_timestamp(),
    )?);
    assert_ne!(alice.client.owned_device_identity()?, bob.client.owned_device_identity()?);
    Ok(())
}

#[tokio::test]
async fn a_cold_native_head_defers_reset_without_retiring_durable_work() -> Result<(), SdkError> {
    let alice = Fixture::native_principal("alice", "alice").await?;
    let bob = Fixture::native_principal("bob", "bob").await?;
    trust(&alice, &bob)?;
    let local = alice.client.owned_device_identity()?;
    let remote = bob.client.owned_device_identity()?;
    alice.client.establish_friend_link(
        "reset-peer",
        local.root_commitment(),
        remote.root_commitment(),
    )?;
    assert!(alice.client.begin_pair_recovery(&local, &remote, now_unix_timestamp())?);
    let key = RamfluxClient::reset_work_key(&local, &remote)?;
    let before = alice.client.account_db()?.load_actor_state::<serde_json::Value>(&key)?;
    *alice.client.native_head_freshness.borrow_mut() =
        crate::client::identity_authority::NativeHeadFreshness::default();
    assert!(
        matches!(alice.client.pair_recovery_allowed(&local, &remote),
        Err(SdkError::FreshHeadRequired { root }) if root == remote.root_commitment()),
        "a missing live observation must defer recovery instead of retiring the pair"
    );
    assert_eq!(alice.client.account_db()?.load_actor_state::<serde_json::Value>(&key)?, before);
    Ok(())
}
