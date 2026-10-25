// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reset budget, relationship lifecycle, manual-recovery and mixed-bootstrap regressions.
use super::r5::{fresh, outgoing, settle};
use super::review::pool;
use super::session_record::{Wire, active, archive, gap, last};
use super::*;
fn pair(bob: &Fixture) -> Result<String, SdkError> {
    RamfluxClient::pair_key(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
    )
}
fn work(bob: &Fixture) -> Result<String, SdkError> {
    Ok(format!("dm-pair/reset-work/{}", pair(bob)?))
}
fn has_work(bob: &Fixture) -> Result<bool, SdkError> {
    Ok(bob.client.account_db()?.load_actor_state::<serde_json::Value>(&work(bob)?)?.is_some())
}
#[tokio::test]
async fn confirming_a_reset_does_not_remove_its_persistent_minimum_interval() -> Result<(), SdkError>
{
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let stale = gap(&alice, &bob, "stale-gap")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale, false).await.is_err());
    let (mut ae, acks) = Wire::engine(&alice, &bob)?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &last(&sent)?, false).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&acks)?, false).await?;
    assert!(!has_work(&bob)?);
    let current = active(&bob, "alice")?;
    let previous = archive(&bob, "alice")?;
    for _ in 0..10 {
        assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale, false).await.is_err());
    }
    assert_eq!(sent.lock().map_err(|_| invalid("mutex"))?.len(), 1);
    assert_eq!(active(&bob, "alice")?, current);
    assert_eq!(archive(&bob, "alice")?, previous);
    assert!(!has_work(&bob)?);
    Ok(())
}
#[tokio::test]
async fn reset_attempts_never_exceed_ten_in_a_rolling_day() -> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let at = now_unix_timestamp();
    for n in 0..10 {
        assert!(bob.client.begin_pair_recovery(
            &bob.client.local_device_identity("bob")?,
            &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
            at + n * 301
        )?);
    }
    assert!(!bob.client.begin_pair_recovery(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        at + 3010
    )?);
    let events = bob.client.account_db()?.journal_after(0, 128)?;
    assert!(events.iter().any(|event| event.body["reason"] == "daily_budget"));
    assert!(bob.client.begin_pair_recovery(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        at + 86400
    )?);
    Ok(())
}
#[tokio::test]
async fn seven_day_reset_expiry_erases_states_and_persists_manual_recovery_without_sending()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let stale = gap(&alice, &bob, "expiry-gap")?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale, false).await.is_err());
    let now = now_unix_timestamp();
    let mut pending = bob
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&work(&bob)?)?
        .ok_or_else(|| invalid("work"))?;
    pending["first_at"] = serde_json::json!(now - 7 * 86400);
    pending["next_at"] = serde_json::json!(now + 86400);
    bob.client.account_db()?.persist_actor_state(&work(&bob)?, &pending)?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    bob.client.retry_pair_resets(&mut be, now).await?;
    assert!(!has_work(&bob)?);
    assert!(
        bob.client
            .active_pair(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
            )?
            .is_none()
    );
    assert_eq!(
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/session/")?.len(),
        0
    );
    let marker = bob
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&format!("{}/manual", pair(&bob)?))?
        .ok_or_else(|| invalid("manual recovery marker missing"))?;
    assert_eq!(marker["state"], "needs_manual_recovery");
    assert!(
        bob.client
            .account_db()?
            .journal_after(0, 128)?
            .iter()
            .any(|event| event.topic == "session.reset"
                && event.body["state"] == "needs_manual_recovery")
    );
    assert!(!bob.client.begin_pair_recovery(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        now + 8 * 86400
    )?);
    assert!(sent.lock().map_err(|_| invalid("mutex"))?.is_empty());
    Ok(())
}
async fn relationship_end(block: bool) -> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let stale = gap(&alice, &bob, "relationship-gap")?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale, false).await.is_err());
    let link = bob
        .client
        .account_db()?
        .friend_link_for_peer(alice.client.owned_device_identity()?.root_commitment())?
        .ok_or_else(|| invalid("friend"))?;
    if block {
        bob.client.block_friend_link(&link.link_id)?;
    } else {
        bob.client.remove_friend_link(&link.link_id, "both")?;
    }
    assert!(!has_work(&bob)?);
    assert!(
        bob.client
            .active_pair(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?
            )?
            .is_none()
    );
    assert_eq!(
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/session/")?.len(),
        0
    );
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    bob.client.retry_pair_resets(&mut be, now_unix_timestamp() + 3600).await?;
    assert!(sent.lock().map_err(|_| invalid("mutex"))?.is_empty());
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale, false).await.is_err());
    assert!(!has_work(&bob)?);
    Ok(())
}
#[tokio::test]
async fn removing_a_contact_ends_reset_work_through_the_production_path() -> Result<(), SdkError> {
    Box::pin(relationship_end(false)).await
}
#[tokio::test]
async fn blocking_a_contact_ends_reset_work_through_the_production_path() -> Result<(), SdkError> {
    Box::pin(relationship_end(true)).await
}
#[tokio::test]
async fn a_partial_or_stale_manifest_preserves_omitted_device_pairs_and_reset_work()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let stale = gap(&alice, &bob, "manifest-gap")?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale, false).await.is_err());
    let root = ramflux_crypto::create_identity_root("alice", [41; 32]);
    let public = ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let commitment = crate::prekey::identity_root_public_key_commitment(&public)?;
    let branch = ramflux_crypto::create_device_branch("alice", "alice-new", 1, [43; 32]);
    let now = now_unix_timestamp();
    let proof = ramflux_crypto::authorize_device_branch(
        &root,
        &branch,
        "ramflux-node",
        vec!["device.delivery.bind".to_owned()],
        now,
        now + 3600,
    )?;
    let identity = ramflux_crypto::X25519KeyPair::from_seed([44; 32]);
    let prekey = ramflux_crypto::X25519KeyPair::from_seed([45; 32]);
    let bundle = ramflux_crypto::create_prekey_bundle(
        &branch,
        &identity,
        "alice-new:prekey",
        &prekey,
        None,
        None,
    )?;
    let mut manifest = crate::prekey::SdkDeviceManifestResponse {
        signed_device_set: None,
        principal_id: "alice".into(),
        principal_commitment: commitment.clone(),
        root_public_key: public,
        devices: vec![crate::prekey::SdkDeviceManifestEntry {
            principal_id: "alice".into(),
            principal_commitment: commitment.clone(),
            device_id: "alice-new".into(),
            device_epoch: 1,
            branch_public_key: ramflux_protocol::encode_base64url(
                branch.signing_key.verifying_key().to_bytes(),
            ),
            target_delivery_id: "alice-new-target".into(),
            branch_proof: proof,
            prekey_bundle: bundle,
            branch_authorized_event_id: "alice-new:authorized".into(),
        }],
    };
    crate::client::identity_authority::test_support::sign_manifest(&root, &mut manifest, 1)?;
    let mut complete = manifest.clone();
    complete
        .devices
        .extend(crate::client::identity_authority::test_support::manifest(&alice.client)?.devices);
    crate::client::identity_authority::test_support::sign_manifest(&root, &mut complete, 2)?;
    manifest.signed_device_set = complete.signed_device_set;
    RamfluxClient::verify_device_manifest_json(serde_json::to_value(&manifest)?, &commitment)?;
    let before =
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/session/")?;
    let pending = bob.client.account_db()?.load_actor_state::<serde_json::Value>(&work(&bob)?)?;
    for _ in 0..2 {
        bob.client.persist_identity_directory(&manifest)?;
        assert!(has_work(&bob)?);
        assert_eq!(
            bob.client.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/session/")?,
            before
        );
        assert_eq!(
            bob.client.account_db()?.load_actor_state::<serde_json::Value>(&work(&bob)?)?,
            pending
        );
        assert!(bob.client.account_db()?.client_record("device", "alice")?.is_some());
    }
    Ok(())
}
#[tokio::test]
async fn a_reset_and_a_plain_bootstrap_select_the_same_current_at_both_ends() -> Result<(), SdkError>
{
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    assert!(alice.client.begin_pair_recovery(
        &alice.client.local_device_identity("alice")?,
        &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        now_unix_timestamp()
    )?);
    let (reset, plain) = {
        let mut chosen = None;
        for n in 0..64 {
            let _initial = fresh(&alice, &bob, &format!("reset-bootstrap-{n}"))?;
            let reset = seal_as(
                &alice,
                &bob,
                outgoing(&alice, &bob, &format!("reset-control-{n}")),
                br#"{"type":"pair.session.reset.v1"}"#,
                Route::control(),
            )?;
            let plain = fresh(&bob, &alice, &format!("plain-mixed-{n}"))?;
            if decode(&plain.envelope)?.ciphertext.session_id
                < decode(&reset.envelope)?.ciphertext.session_id
            {
                chosen = Some((reset, plain));
                break;
            }
        }
        chosen.ok_or_else(|| invalid("could not select mixed bootstrap order"))?
    };
    let (mut ae, _) = Wire::engine(&alice, &bob)?;
    let plain_id = decode(&plain.envelope)?.ciphertext.session_id;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &plain, false).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &reset, false).await?;
    assert_eq!(active(&alice, "bob")?, plain_id);
    assert_eq!(active(&bob, "alice")?, plain_id);
    Ok(())
}
#[tokio::test]
async fn session_replacements_prune_nonsecret_flags_and_tombstones_to_the_archive_bound()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let mut be = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    for n in 0..40 {
        let next = fresh(&alice, &bob, &format!("bounded-{n}"))?;
        bob.client.apply_routed_entry(&mut be, &pool()?, &next, false).await?;
    }
    let db = bob.client.account_db()?;
    assert!(db.list_actor_states::<serde_json::Value>("dm-pair/retired/")?.len() <= 8);
    for kind in ["confirmed", "local", "settled", "reset"] {
        assert!(db.list_actor_states::<serde_json::Value>(&format!("dm-pair/{kind}/"))?.len() <= 9);
    }
    Ok(())
}

#[tokio::test]
async fn evicted_packets_older_than_a_confirmed_successor_are_dropped_without_resetting()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    settle(&mut alice, &mut bob).await?;
    let late = seal(&alice, &bob, outgoing(&alice, &bob, "old-evicted-packet"), b"old")?;
    let mut replacement = None;
    for n in 0..10 {
        replacement = Some(fresh(&bob, &alice, &format!("successor-{n}"))?);
    }
    let (mut ae, _) = Wire::engine(&alice, &bob)?;
    alice
        .client
        .apply_routed_entry(
            &mut ae,
            &pool()?,
            &replacement.ok_or_else(|| invalid("replacement"))?,
            false,
        )
        .await?;
    let confirm = seal(&alice, &bob, outgoing(&alice, &bob, "confirm-successor"), b"confirmed")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &confirm, false).await?;
    let current = active(&bob, "alice")?;
    let previous = archive(&bob, "alice")?;
    for _ in 0..10 {
        assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &late, false).await.is_err());
    }
    assert!(sent.lock().map_err(|_| invalid("mutex"))?.is_empty());
    assert_eq!(active(&bob, "alice")?, current);
    assert_eq!(archive(&bob, "alice")?, previous);
    Ok(())
}

#[tokio::test]
async fn upgrading_legacy_work_uses_its_original_attempt_instead_of_renewing_from_the_last_retry()
-> Result<(), SdkError> {
    for retained_start in [true, false] {
        let mut alice = Fixture::new("alice", 41)?;
        let mut bob = Fixture::new("bob", 61)?;
        settle(&mut alice, &mut bob).await?;
        let now = now_unix_timestamp();
        assert!(bob.client.begin_pair_recovery(
            &bob.client.local_device_identity("bob")?,
            &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
            now
        )?);
        let db = bob.client.account_db()?;
        let mut legacy = db
            .load_actor_state::<serde_json::Value>(&work(&bob)?)?
            .ok_or_else(|| invalid("work"))?;
        let _ = legacy.as_object_mut().ok_or_else(|| invalid("work object"))?.remove("first_at");
        legacy["next_at"] = serde_json::json!(now + 300);
        db.persist_actor_state(&work(&bob)?, &legacy)?;
        let first = now - 7 * 86400;
        if retained_start {
            db.append_journal(
                &format!("pair-reset-attempt:{}:{first}", work(&bob)?),
                "session.reset",
                &serde_json::json!({"device_id":"alice","attempt":1}),
                first,
                None,
            )?;
        }
        let (mut be, sent) = Wire::engine(&bob, &alice)?;
        bob.client.retry_pair_resets(&mut be, now).await?;
        assert!(!has_work(&bob)?);
        assert!(
            bob.client
                .account_db()?
                .load_actor_state::<serde_json::Value>(&format!("{}/manual", pair(&bob)?))?
                .is_some()
        );
        assert!(sent.lock().map_err(|_| invalid("mutex"))?.is_empty());
    }
    Ok(())
}
