// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated bootstrap replay guard survives bounded tombstones and manual erasure.
use super::r5::{fresh, settle};
use super::review::pool;
use super::*;
#[tokio::test]
async fn pruned_tombstones_cannot_revive_a_held_bootstrap_or_clear_manual_recovery()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        pruned_tombstones_cannot_revive_a_held_bootstrap_or_clear_manual_recovery_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn pruned_tombstones_cannot_revive_a_held_bootstrap_or_clear_manual_recovery_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
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
    bob.client.mark_pair_manual(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&alice.reference()?)?,
        now_unix_timestamp(),
    )?;
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
#[tokio::test(flavor = "current_thread")]
async fn changing_the_bootstrap_sequence_without_reencrypting_is_rejected() -> Result<(), SdkError>
{
    crate::client::native_test_support::watchdog::within(
        changing_the_bootstrap_sequence_without_reencrypting_is_rejected_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn changing_the_bootstrap_sequence_without_reencrypting_is_rejected_body()
-> Result<(), SdkError> {
    let alice = Fixture::native("alice", 41).await?;
    let bob = Fixture::native("bob", 61).await?;
    let entry = fresh(&alice, &bob, "sequence-tamper")?;
    let calibrated = bob.client.open_routed(&entry, "bob")?;
    assert_eq!(calibrated.routing.kind, Kind::Direct, "the genuine native packet must open first");
    let encoded = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|_| invalid("test: compact payload"))?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&encoded)
        .map_err(|_| invalid("test: compact frame"))?;
    let mut sidecar: serde_json::Value = serde_json::from_slice(compact.sidecar)?;
    let sequence = sidecar["x3dh"]["bootstrap_sequence"]
        .as_u64()
        .ok_or_else(|| invalid("test: authenticated bootstrap sequence missing"))?;
    sidecar["x3dh"]["bootstrap_sequence"] = serde_json::json!(sequence + 1);
    let rebuilt = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )
    .map_err(|_| invalid("test: compact reframe"))?;
    let mut tampered = entry;
    tampered.envelope.encrypted_payload = ramflux_protocol::encode_base64url(rebuilt);
    tampered.envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        tampered.envelope.encrypted_payload.as_bytes(),
    );
    tampered.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        alice.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &tampered.envelope,
    )?;
    assert!(bob.client.open_routed(&tampered, "bob").is_err());
    assert!(
        bob.client
            .active_pair(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
            )?
            .is_none()
    );
    Ok(())
}
#[tokio::test]
async fn receive_high_water_and_sender_sequence_survive_account_reopen() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        receive_high_water_and_sender_sequence_survive_account_reopen_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn receive_high_water_and_sender_sequence_survive_account_reopen_body() -> Result<(), SdkError>
{
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let held = fresh(&alice, &bob, "before-reopen-held")?;
    let later = fresh(&alice, &bob, "before-reopen-accepted")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &later, false).await?;
    for fixture in [&mut bob, &mut alice] {
        fixture.client.active_account_db = None;
        fixture.client.unlock_account(&fixture.id, b"native fixture data passphrase")?;
        let vault = fixture
            .native
            .as_ref()
            .ok_or_else(|| invalid("test: native reopen vault"))?
            .vault
            .clone();
        fixture.client.initialize_born_v3_branch(&fixture.id, vault).await?;
    }
    assert!(bob.client.open_routed(&held, "bob").is_err());
    let next = fresh(&alice, &bob, "after-reopen")?;
    bob.client.apply_routed_entry(&mut engine, &pool()?, &next, false).await?;
    Ok(())
}
