// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Accepted inbound contacts expose symmetric authenticated safety digits without another lookup.
use super::super::born_headless_bus;
use super::*;

fn link_headless(state: &LocalBusDaemonState, directory: &Directory) -> Result<(), SdkError> {
    // A headless account does not hold the group primary, so it cannot sign contact
    // consent. The accepted-link observation is the live property.
    let manifests = directory.records.lock().map_err(|_| invalid("records"))?.clone();
    let alice_manifest = manifests.first().cloned().ok_or_else(|| invalid("alice manifest"))?;
    let bob_manifest = manifests.get(1).cloned().ok_or_else(|| invalid("bob manifest"))?;
    let alice = account(state, "alice")?;
    let bob = account(state, "bob")?;
    alice.persist_fetched_identity_directory(&bob_manifest)?;
    bob.persist_fetched_identity_directory(&alice_manifest)?;
    let alice_root = alice.owned_device_identity()?.root_commitment().to_owned();
    let bob_root = bob.owned_device_identity()?.root_commitment().to_owned();
    alice.establish_friend_link("headless-link", &alice_root, &bob_root)?;
    bob.establish_friend_link("headless-link", &alice_root, &bob_root)?;
    alice.persist_native_accepted_contact_safety("bob", &bob_root)?;
    bob.persist_native_accepted_contact_safety("alice", &alice_root)?;
    Ok(())
}

fn peer_row(client: &RamfluxClient, peer: &str) -> Result<Value, SdkError> {
    let account = client.account_db()?.local_account_id.clone();
    let directory =
        crate::bus::read_model::read(client, &request(&account, "identity.directory", json!({})))?;
    directory["identities"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["principal_id"] == peer))
        .cloned()
        .ok_or_else(|| invalid("identity"))
}

#[tokio::test]
async fn inbound_acceptance_exposes_verified_kind_routes_and_symmetric_safety_digits_after_refresh()
-> Result<(), SdkError> {
    for automatic in [false, true] {
        let (directory, state) = born_headless_bus(&["alice", "bob"]).await?;
        if automatic {
            account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
        }
        link_headless(&state, &directory)?;
        for refresh in [false, true] {
            if refresh {
                let bob = state.accounts.get("bob").ok_or_else(|| invalid("bob"))?;
                for root in [
                    bob.client.owned_device_identity()?.root_commitment().to_owned(),
                    account(&state, "alice")?.owned_device_identity()?.root_commitment().to_owned(),
                ] {
                    bob.client
                        .cache_verified_device_manifest(
                            &bob.gateway_config,
                            &root,
                            "own-contact-backfill",
                        )
                        .await?;
                }
            }
            let a = peer_row(account(&state, "alice")?, "bob")?;
            let b = peer_row(account(&state, "bob")?, "alice")?;
            for row in [&a, &b] {
                assert_eq!(row["kind"], "headless_ai");
                assert_eq!(row["kind_verified"], true);
                assert_eq!(row["reachable"], true);
                assert_eq!(row["verified"], false);
                assert_eq!(row["safety_number_available"], true);
                assert_eq!(row["safety_number"].as_array().map(Vec::len), Some(12));
            }
            assert_eq!(a["safety_number"], b["safety_number"]);
        }
    }
    Ok(())
}

#[tokio::test]
async fn missing_forged_or_stale_cached_authority_cannot_synthesize_uncached_safety_digits()
-> Result<(), SdkError> {
    let (directory, state) = born_headless_bus(&["alice", "bob"]).await?;
    link_headless(&state, &directory)?;
    let receiver = account(&state, "bob")?;
    let root = account(&state, "alice")?.owned_device_identity()?.root_commitment().to_owned();
    let key = format!("identity/manifest-root/{root}");
    let db = receiver.account_db()?;
    let original = db
        .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&key)?
        .ok_or_else(|| invalid("manifest"))?;
    for case in ["missing", "forged", "stale"] {
        let mut manifest = original.clone();
        if case == "missing" {
            db.remove_actor_state(&key)?;
        } else if case == "forged" {
            manifest
                .custody
                .as_mut()
                .ok_or_else(|| invalid("custody"))?
                .publication
                .record
                .signature = ramflux_protocol::encode_base64url([0; 64]);
            db.persist_actor_state(&key, &manifest)?;
        } else {
            let alice_state = state.accounts.get("alice").ok_or_else(|| invalid("alice"))?;
            let born = alice_state
                .client
                .born_v3_account
                .as_ref()
                .ok_or(SdkError::CustodyModeDowngrade)?;
            let vault =
                alice_state.gateway_config.custody.as_ref().ok_or(SdkError::NetworkingPending)?;
            let primary = vault.vault.load_primary(born.primary_vault_ref())?;
            let publication =
                manifest.custody.as_ref().ok_or_else(|| invalid("custody"))?.publication.clone();
            let mut body = publication.record.body.clone();
            body.device_set_epoch = body.device_set_epoch.saturating_add(1);
            body.previous_record_hash =
                Some(ramflux_protocol::custody::object_hash(&publication.record)?);
            body.profile.display_name = "Renamed Human".into();
            body.issued_at = body.issued_at.saturating_add(1);
            let renamed = primary.sign_record(body).map_err(|_| invalid("resign"))?;
            let mut current = manifest.clone();
            current.custody.as_mut().ok_or_else(|| invalid("custody"))?.publication.record =
                renamed;
            receiver.persist_identity_directory(&current)?;
            // The previous signed cache remains valid cryptographically, but is no longer current.
            db.persist_actor_state(&key, &original)?;
        }
        // Explicit acceptance caches digits on current accounts. Directory polling must not
        // synthesize an absent cache from any of these incomplete authority snapshots.
        let mut identity =
            db.client_record("identity", "alice")?.ok_or_else(|| invalid("identity"))?;
        identity.as_object_mut().ok_or_else(|| invalid("identity object"))?.remove("safety_number");
        identity
            .as_object_mut()
            .ok_or_else(|| invalid("identity object"))?
            .remove("safety_number_algorithm_version");
        db.persist_client_record("identity", "alice", &identity)?;
        let row = peer_row(receiver, "alice")?;
        assert_eq!(
            row["kind_verified"], true,
            "{case}: born kind follows the custody publication, not the manifest cache"
        );
        assert_eq!(row["reachable"], true);
        assert_eq!(row["verified"], false);
        assert_eq!(row["safety_number_available"], false, "{case}");
        assert!(row["safety_number"].is_null(), "{case}");
    }
    Ok(())
}
