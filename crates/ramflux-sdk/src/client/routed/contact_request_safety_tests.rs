// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Accepted inbound contacts expose symmetric authenticated safety digits without another lookup.
use super::*;

fn signed_profiles(directory: &Directory, alice: &Fixture, bob: &Fixture) -> Result<(), SdkError> {
    for (manifest, owner) in
        directory.records.lock().map_err(|_| invalid("records"))?.iter_mut().zip([alice, bob])
    {
        let root = owner.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        for device in &mut manifest.devices {
            device
                .branch_proof
                .key_binding
                .as_mut()
                .ok_or_else(|| invalid("binding"))?
                .principal_kind = ramflux_protocol::PrincipalKind::HeadlessAi;
        }
        manifest.signed_device_set.as_mut().ok_or_else(|| invalid("set"))?.profile =
            Some(Box::new(ramflux_crypto::sign_identity_profile(
                root,
                ramflux_protocol::PrincipalKind::HeadlessAi,
                &owner.id,
                1,
            )?));
        crate::client::identity_authority::test_support::sign_manifest(root, manifest, 1)?;
    }
    Ok(())
}

fn peer_row(client: &RamfluxClient, peer: &str) -> Result<Value, SdkError> {
    let mut reader = RamfluxClient::new();
    reader.active_account_db = Some(client.account_db()?.open_reader()?);
    reader.reader_device_identity = Some(client.owned_device_identity()?);
    let directory =
        crate::bus::read_model::read(&reader, &request("bob", "identity.directory", json!({})))?;
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
        let mut alice = Fixture::new("alice", 91)?;
        let mut bob = Fixture::new("bob", 101)?;
        let directory = Directory::new(&alice, &bob).await?;
        signed_profiles(&directory, &alice, &bob)?;
        let mut state = state(&mut alice, &mut bob, &directory)?;
        if automatic {
            account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
        }
        pending(&mut state, &directory).await?;
        contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
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
async fn missing_forged_or_stale_cached_authority_cannot_supply_contact_safety_digits()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 111)?;
    let mut bob = Fixture::new("bob", 121)?;
    let directory = Directory::new(&alice, &bob).await?;
    signed_profiles(&directory, &alice, &bob)?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    pending(&mut state, &directory).await?;
    contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
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
            manifest.signed_device_set.as_mut().ok_or_else(|| invalid("set"))?.signature =
                ramflux_protocol::encode_base64url([0; 64]);
            db.persist_actor_state(&key, &manifest)?;
        } else {
            let root = account(&state, "alice")?
                .identity_root
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?;
            crate::client::identity_authority::test_support::sign_manifest(root, &mut manifest, 2)?;
            receiver.persist_identity_directory(&manifest)?;
            // The old signed cache remains valid cryptographically, but is no longer current.
            db.persist_actor_state(&key, &original)?;
        }
        let row = peer_row(receiver, "alice")?;
        assert_eq!(
            row["kind_verified"],
            case != "missing",
            "{case}: verification requires the cached root key"
        );
        assert_eq!(row["reachable"], true);
        assert_eq!(row["verified"], false);
        assert_eq!(row["safety_number_available"], false, "{case}");
        assert!(row["safety_number"].is_null(), "{case}");
    }
    Ok(())
}
