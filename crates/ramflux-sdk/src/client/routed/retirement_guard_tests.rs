// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated bootstrap replay guard survives bounded tombstones and manual erasure.
use super::r5::{fresh, outgoing, settle};
use super::review::pool;
use super::*;
#[tokio::test]
async fn pruned_tombstones_cannot_revive_a_held_bootstrap_or_clear_manual_recovery()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let held = fresh(&alice, &bob, "held-old-bootstrap")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    for n in 0..22 {
        let entry = fresh(&alice, &bob, &format!("successor-{n}"))?;
        bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    }
    let db = bob.client.account_db()?;
    for key in db.actor_state_keys("dm-pair/retired/")? {
        db.remove_actor_state(&key)?;
    }
    let current = super::session_record::active(&bob, "alice")?;
    assert!(bob.client.open_routed(&held, "bob").is_err());
    assert_eq!(super::session_record::active(&bob, "alice")?, current);
    bob.client.mark_pair_manual("bob", &alice.reference()?, now_unix_timestamp())?;
    let pair = RamfluxClient::pair_key(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
    )?;
    let marker = db.load_actor_state::<serde_json::Value>(&format!("{pair}/manual"))?;
    for key in db.actor_state_keys("dm-pair/retired/")? {
        db.remove_actor_state(&key)?;
    }
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &held, false).await.is_err());
    let db = bob.client.account_db()?;
    assert_eq!(db.load_actor_state::<serde_json::Value>(&format!("{pair}/manual"))?, marker);
    assert!(db.load_actor_state::<String>(&pair)?.is_none());
    assert!(!db.actor_state_exists(&format!("dm-pair/reset-work/{pair}"))?);
    Ok(())
}
#[test]
fn changing_the_bootstrap_sequence_without_reencrypting_is_rejected() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let bob = Fixture::new("bob", 61)?;
    let entry = fresh(&alice, &bob, "sequence-tamper")?;
    let mut encrypted = serde_json::to_value(decode(&entry.envelope)?)?;
    let sequence = encrypted["x3dh"]["bootstrap_sequence"].as_u64().unwrap_or(0);
    encrypted["x3dh"]["bootstrap_sequence"] = serde_json::json!(sequence + 1);
    let mut message = outgoing(&alice, &bob, "sequence-tamper");
    message.encrypted_body = serde_json::to_vec(&encrypted)?;
    let tampered = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: "bob".into(),
        envelope: gateway_direct_message_envelope(&alice.config()?, &message, None)?,
    };
    assert!(bob.client.open_routed(&tampered, "bob").is_err());
    assert!(
        bob.client.active_pair("bob", &fixture_peer_reference(&bob.client, "alice")?)?.is_none()
    );
    Ok(())
}
#[tokio::test]
async fn receive_high_water_and_sender_sequence_survive_account_reopen() -> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let held = fresh(&alice, &bob, "before-reopen-held")?;
    let later = fresh(&alice, &bob, "before-reopen-accepted")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &later, false).await?;
    bob.client.unlock_account("bob", b"routed-test")?;
    alice.client.unlock_account("alice", b"routed-test")?;
    assert!(bob.client.open_routed(&held, "bob").is_err());
    let next = fresh(&alice, &bob, "after-reopen")?;
    bob.client.apply_routed_entry(&mut engine, &pool()?, &next, false).await?;
    Ok(())
}
