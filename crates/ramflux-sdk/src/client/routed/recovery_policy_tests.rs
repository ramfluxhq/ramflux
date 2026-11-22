// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reset budget, relationship lifecycle, manual-recovery and mixed-bootstrap regressions.
use super::r5::{fresh, native_outgoing as outgoing, seal, settle};
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
    crate::client::native_test_support::watchdog::within(
        confirming_a_reset_does_not_remove_its_persistent_minimum_interval_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn confirming_a_reset_does_not_remove_its_persistent_minimum_interval_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let stale = gap(&alice, &bob, "stale-gap")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale).await.is_err());
    let (mut ae, acks) = Wire::engine(&alice, &bob)?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &last(&sent)?).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&acks)?).await?;
    assert!(!has_work(&bob)?);
    let current = active(&bob, "alice")?;
    let previous = archive(&bob, "alice")?;
    for _ in 0..10 {
        assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale).await.is_err());
    }
    assert_eq!(sent.lock().map_err(|_| invalid("mutex"))?.len(), 1);
    assert_eq!(active(&bob, "alice")?, current);
    assert_eq!(archive(&bob, "alice")?, previous);
    assert!(!has_work(&bob)?);
    Ok(())
}
#[tokio::test]
async fn reset_attempts_never_exceed_ten_in_a_rolling_day() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        reset_attempts_never_exceed_ten_in_a_rolling_day_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn reset_attempts_never_exceed_ten_in_a_rolling_day_body() -> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
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
    crate::client::native_test_support::watchdog::within(
        seven_day_reset_expiry_erases_states_and_persists_manual_recovery_without_sending_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn seven_day_reset_expiry_erases_states_and_persists_manual_recovery_without_sending_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let stale = gap(&alice, &bob, "expiry-gap")?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale).await.is_err());
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
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let stale = gap(&alice, &bob, "relationship-gap")?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale).await.is_err());
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
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale).await.is_err());
    assert!(!has_work(&bob)?);
    Ok(())
}
#[tokio::test]
async fn removing_a_contact_ends_reset_work_through_the_production_path() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        removing_a_contact_ends_reset_work_through_the_production_path_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn removing_a_contact_ends_reset_work_through_the_production_path_body()
-> Result<(), SdkError> {
    Box::pin(relationship_end(false)).await
}
#[tokio::test]
async fn blocking_a_contact_ends_reset_work_through_the_production_path() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        blocking_a_contact_ends_reset_work_through_the_production_path_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn blocking_a_contact_ends_reset_work_through_the_production_path_body()
-> Result<(), SdkError> {
    Box::pin(relationship_end(true)).await
}
#[tokio::test]
async fn a_partial_or_stale_manifest_preserves_omitted_device_pairs_and_reset_work()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        a_partial_or_stale_manifest_preserves_omitted_device_pairs_and_reset_work_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn a_partial_or_stale_manifest_preserves_omitted_device_pairs_and_reset_work_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let stale = gap(&alice, &bob, "manifest-gap")?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &stale).await.is_err());
    let native = alice.native.as_ref().ok_or_else(|| invalid("test: source native vault"))?;
    let old = alice.manifest()?;
    let record = old
        .custody
        .as_ref()
        .ok_or_else(|| invalid("test: native publication"))?
        .publication
        .record
        .clone();
    let primary = native
        .vault
        .primary_for_public_key(&record.body.master_certificate.body.self_signing_public_key)?;
    let mut next = record.body.clone();
    next.device_set_epoch += 1;
    next.previous_record_hash = Some(ramflux_protocol::custody::object_hash(&record)?);
    next.profile.display_name = "current complete authority".into();
    let mut current = old.clone();
    current
        .custody
        .as_mut()
        .ok_or_else(|| invalid("test: native publication"))?
        .publication
        .record = primary.sign_record(next)?;
    bob.client.persist_observed_identity_directory_now(&current)?;
    let mut partial = current;
    partial.devices.clear();
    partial.custody.as_mut().ok_or_else(|| invalid("test: native descriptor"))?.devices.clear();
    let before =
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/session/")?;
    let pending = bob.client.account_db()?.load_actor_state::<serde_json::Value>(&work(&bob)?)?;
    for (manifest, stale) in [(&partial, false), (&old, true)] {
        let result = bob.client.persist_observed_identity_directory_now(manifest);
        if stale {
            assert!(result.is_err(), "a genuinely older native head must be refused");
        } else {
            result?;
        }
        assert!(has_work(&bob)?);
        assert_eq!(
            bob.client.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/session/")?,
            before,
            "omitted or stale descriptors must preserve the live pair",
        );
        assert_eq!(
            bob.client.account_db()?.load_actor_state::<serde_json::Value>(&work(&bob)?)?,
            pending,
            "omitted or stale descriptors must preserve reset work",
        );
        assert!(
            bob.client.account_db()?.client_record("device", &alice.reference()?)?.is_some(),
            "partial descriptors must not invent a device revocation",
        );
    }
    Ok(())
}
#[tokio::test]
async fn a_reset_and_a_plain_bootstrap_select_the_same_current_at_both_ends() -> Result<(), SdkError>
{
    crate::client::native_test_support::watchdog::within(
        a_reset_and_a_plain_bootstrap_select_the_same_current_at_both_ends_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn a_reset_and_a_plain_bootstrap_select_the_same_current_at_both_ends_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
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
            let (mut message, sealed) = seal_native_fixture(
                &alice,
                &bob,
                outgoing(&alice, &bob, &format!("reset-control-{n}"))?,
                &candidate_report::reset_inner(&alice, &bob)?,
                Route::control(),
            )?;
            let reset = GatewayInboxEntry {
                forwarded: false,
                inbox_seq: 1,
                target_delivery_id: bob.config()?.target_delivery_id,
                envelope: crate::dm::gateway_generated_envelope_from_sealed(
                    &crate::bus::connection_manager::SessionMetadata::sealing_config_for(
                        &alice.config()?,
                    )?,
                    &mut message,
                    sealed,
                )?,
            };
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
    alice.client.apply_routed_entry(&mut ae, &pool()?, &plain).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &reset).await?;
    assert_eq!(active(&alice, "bob")?, plain_id);
    assert_eq!(active(&bob, "alice")?, plain_id);
    Ok(())
}
#[tokio::test]
async fn session_replacements_prune_nonsecret_flags_and_tombstones_to_the_archive_bound()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        session_replacements_prune_nonsecret_flags_and_tombstones_to_the_archive_bound_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn session_replacements_prune_nonsecret_flags_and_tombstones_to_the_archive_bound_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let mut be = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    for n in 0..40 {
        let next = fresh(&alice, &bob, &format!("bounded-{n}"))?;
        bob.client.apply_routed_entry(&mut be, &pool()?, &next).await?;
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
    crate::client::native_test_support::watchdog::within(
        evicted_packets_older_than_a_confirmed_successor_are_dropped_without_resetting_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn evicted_packets_older_than_a_confirmed_successor_are_dropped_without_resetting_body()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    settle(&mut alice, &mut bob).await?;
    let late = seal(&alice, &bob, outgoing(&alice, &bob, "old-evicted-packet")?, b"old")?;
    let mut replacement = None;
    for n in 0..10 {
        replacement = Some(fresh(&bob, &alice, &format!("successor-{n}"))?);
    }
    let (mut ae, _) = Wire::engine(&alice, &bob)?;
    alice
        .client
        .apply_routed_entry(&mut ae, &pool()?, &replacement.ok_or_else(|| invalid("replacement"))?)
        .await?;
    let confirm = seal(&alice, &bob, outgoing(&alice, &bob, "confirm-successor")?, b"confirmed")?;
    let (mut be, sent) = Wire::engine(&bob, &alice)?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &confirm).await?;
    let current = active(&bob, "alice")?;
    let previous = archive(&bob, "alice")?;
    for _ in 0..10 {
        assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &late).await.is_err());
    }
    assert!(sent.lock().map_err(|_| invalid("mutex"))?.is_empty());
    assert_eq!(active(&bob, "alice")?, current);
    assert_eq!(archive(&bob, "alice")?, previous);
    Ok(())
}
