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
