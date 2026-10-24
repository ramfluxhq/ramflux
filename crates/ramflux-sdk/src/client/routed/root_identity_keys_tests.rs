// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Copied literal device names cannot reserve another root's replay or control identities.
use super::review::{pool, trust};
use super::*;

#[tokio::test]
async fn copied_device_name_cannot_preclaim_an_honest_envelope_id_in_another_thread()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 11)?;
    let bob = Fixture::owned("bob", "bob", 31, 32)?;
    let mallory = Fixture::owned("bob", "mallory", 51, 52)?;
    trust(&alice, &bob)?;
    trust(&alice, &mallory)?;
    alice.client.establish_friend_link("bob-link", "alice", "bob")?;
    alice.client.establish_friend_link("mallory-link", "alice", "mallory")?;
    let mut engine =
        GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    let mut first = super::r5::outgoing(&bob, &alice, "tui_env_1");
    first.conversation_id = "alice-bob".into();
    let first = seal(&bob, &alice, first, b"first honest message")?;
    alice.client.apply_routed_entry(&mut engine, &pool()?, &first, false).await?;
    let mut attack = super::r5::outgoing(&mallory, &alice, "tui_env_2");
    attack.conversation_id = "alice-mallory".into();
    let attack = seal(&mallory, &alice, attack, b"legitimate message in Mallory's own thread")?;
    alice.client.apply_routed_entry(&mut engine, &pool()?, &attack, false).await?;
    let mut honest = super::r5::outgoing(&bob, &alice, "tui_env_2");
    honest.conversation_id = "alice-bob".into();
    let honest = seal(&bob, &alice, honest, b"second honest message")?;
    alice.client.apply_routed_entry(&mut engine, &pool()?, &honest, false).await?;
    assert_ne!(
        alice.client.authenticated_committed_key(&attack)?,
        alice.client.authenticated_committed_key(&honest)?
    );

    assert_eq!(alice.client.direct_messages("alice-bob")?.len(), 2);
    assert_eq!(alice.client.direct_messages("alice-mallory")?.len(), 1);
    assert!(
        alice
            .client
            .account_db()?
            .actor_state_exists(&alice.client.authenticated_committed_key(&honest)?)?
    );
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
async fn copied_name_controls_have_independent_keys_and_cannot_forge_bobs_attribution()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 11)?;
    let bob = Fixture::owned("bob", "bob", 31, 32)?;
    let mallory = Fixture::owned("bob", "mallory", 51, 52)?;
    trust(&alice, &bob)?;
    trust(&alice, &mallory)?;
    let mut engine =
        GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    for sender in [&mallory, &bob] {
        let event = a2i("bob", "alice");
        let entry = seal_as(
            sender,
            &alice,
            super::r5::outgoing(sender, &alice, "same-control-envelope"),
            &serde_json::to_vec(&event)?,
            Route::control(),
        )?;
        alice.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    }
    let before = alice.client.account_db()?.list_actor_states::<A2iControlEvent>("a2i/scoped/")?;
    assert_eq!(before.len(), 2);
    assert!(before.iter().any(|event| event.source_principal_id.as_deref() == Some("bob")));
    assert!(before.iter().any(|event| event.source_principal_id.as_deref() == Some("mallory")));
    assert_ne!(before[0].source_principal_commitment, before[1].source_principal_commitment);
    let mut forged = a2i("bob", "alice");
    forged.source_principal_id = Some("bob".into());
    forged.source_principal_commitment = Some(ramflux_crypto::identity_root_commitment(
        &bob.client
            .identity_root
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key(),
    ));
    let entry = seal_as(
        &mallory,
        &alice,
        super::r5::outgoing(&mallory, &alice, "forged-attribution"),
        &serde_json::to_vec(&forged)?,
        Route::control(),
    )?;
    assert!(alice.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await.is_err());
    assert_eq!(
        alice.client.account_db()?.list_actor_states::<A2iControlEvent>("a2i/scoped/")?,
        before
    );
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
    assert!(error.to_string().contains("A2I source attribution"), "{error}");
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
    assert!(error.to_string().contains("A2I source engine mismatch"), "{error}");
    assert_eq!(alice.client.account_db()?.actor_state_keys("a2i/")?, Vec::<String>::new());
    Ok(())
}

#[tokio::test]
async fn verified_old_replay_rows_rekey_but_raw_legacy_ids_never_claim_another_root()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 11)?;
    let bob = Fixture::new("bob", 31)?;
    let mallory = Fixture::owned("bob", "mallory", 51, 52)?;
    trust(&alice, &bob)?;
    trust(&alice, &mallory)?;
    alice.client.establish_friend_link("bob-link", "alice", "bob")?;
    let mut engine =
        GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    let entry = seal(&bob, &alice, super::r5::outgoing(&bob, &alice, "migrate-id"), b"body")?;
    alice.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    let source = alice.client.authenticated_device_identity(&entry)?;
    let key = alice.client.authenticated_committed_key(&entry)?;
    let db = alice.client.account_db()?;
    let receipt =
        db.load_actor_state::<serde_json::Value>(&key)?.ok_or_else(|| invalid("receipt"))?;
    db.remove_actor_state(&key)?;
    db.remove_actor_state(&format!("identity/replay-upgrade/v3/{}", source.storage_key()))?;
    db.persist_actor_state("routed/committed/old-name-digest", &receipt)?;
    db.persist_actor_state("legacy/committed/migrate-id", &"mallory-thread")?;
    assert_eq!(alice.client.committed_direct_context(&entry)?, None);
    alice.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    let db = alice.client.account_db()?;
    assert!(db.actor_state_exists(&key)?);
    assert!(!db.actor_state_exists("routed/committed/old-name-digest")?);
    let attack =
        seal(&mallory, &alice, super::r5::outgoing(&mallory, &alice, "migrate-id"), b"attack")?;
    assert_eq!(alice.client.committed_direct_context(&attack)?, None);
    let messages = alice.client.direct_messages(
        receipt["routing"]["conversation_id"].as_str().ok_or_else(|| invalid("route"))?,
    )?;
    assert_eq!(messages.len(), 1);
    Ok(())
}
