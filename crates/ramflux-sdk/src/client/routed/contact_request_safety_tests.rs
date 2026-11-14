// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Accepted inbound contacts expose symmetric authenticated safety digits without another lookup.
use super::*;

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
    crate::client::native_test_support::watchdog::within(inbound_acceptance_exposes_verified_kind_routes_and_symmetric_safety_digits_after_refresh_body())
        .await.map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn inbound_acceptance_exposes_verified_kind_routes_and_symmetric_safety_digits_after_refresh_body()
-> Result<(), SdkError> {
    for automatic in [false, true] {
        let mut alice = Box::pin(Fixture::native_named("alice", 91)).await?;
        let mut bob = Box::pin(Fixture::native_named("bob", 101)).await?;
        let directory = Directory::new(&alice, &bob).await?;
        let mut state = state(&mut alice, &mut bob, &directory)?;
        if automatic {
            account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
        }
        pending(&mut state, &directory).await?;
        contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
        contact(&mut state, "alice", "contact.accept", json!({"principal_id":"bob"})).await?;
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
                assert_eq!(row["kind"], "human");
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
    crate::client::native_test_support::watchdog::within(
        missing_forged_or_stale_cached_authority_cannot_synthesize_uncached_safety_digits_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn missing_forged_or_stale_cached_authority_cannot_synthesize_uncached_safety_digits_body()
-> Result<(), SdkError> {
    let mut alice = Box::pin(Fixture::native_named("alice", 111)).await?;
    let mut bob = Box::pin(Fixture::native_named("bob", 121)).await?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    pending(&mut state, &directory).await?;
    contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
    let receiver = account(&state, "bob")?;
    let root = account(&state, "alice")?.owned_device_identity()?.root_commitment().to_owned();
    let key = format!("identity/custody/{root}");
    let db = receiver.account_db()?;
    let original: Value = db.load_actor_state(&key)?.ok_or_else(|| invalid("native authority"))?;
    let native = alice.native.as_ref().ok_or_else(|| invalid("native source"))?;
    let record = native
        .manifest
        .custody
        .as_ref()
        .ok_or_else(|| invalid("native record"))?
        .publication
        .record
        .clone();
    let primary = native
        .vault
        .primary_for_public_key(&record.body.master_certificate.body.self_signing_public_key)?;
    for case in ["missing", "forged", "stale"] {
        let mut damaged = original.clone();
        if case == "missing" {
            damaged["publication"] = Value::Null;
        } else if case == "forged" {
            damaged["publication"]["record"]["signature"] =
                json!(ramflux_protocol::encode_base64url([0; 64]));
        } else {
            db.persist_actor_state(&key, &original)?;
            let mut newer = native.manifest.clone();
            let mut next = record.body.clone();
            next.device_set_epoch += 1;
            next.previous_record_hash = Some(ramflux_protocol::custody::object_hash(&record)?);
            next.profile.display_name = "newer native profile".into();
            newer
                .custody
                .as_mut()
                .ok_or_else(|| invalid("native publication"))?
                .publication
                .record = primary.sign_record(next)?;
            receiver.persist_fetched_identity_directory(&newer)?;
            assert_eq!(
                receiver
                    .current_custody_authority(&root, crate::custody::network_now()?)?
                    .ok_or_else(|| invalid("new current authority"))?
                    .envelope()
                    .body
                    .device_set_epoch,
                record.body.device_set_epoch + 1,
                "the newer native head must calibrate successfully before rollback"
            );
            damaged =
                db.load_actor_state::<Value>(&key)?.ok_or_else(|| invalid("new native pins"))?;
            damaged["publication"] = original["publication"].clone();
        }
        db.persist_actor_state(&key, &damaged)?;
        // The real native authority is now absent, forged, or below retained pins.
        // A public directory read may neither repair absent safety nor verify a kind.
        let mut identity =
            db.client_record("identity", "alice")?.ok_or_else(|| invalid("identity"))?;
        let fields = identity.as_object_mut().ok_or_else(|| invalid("identity object"))?;
        fields.remove("safety_number");
        fields.remove("safety_number_algorithm_version");
        db.persist_client_record("identity", "alice", &identity)?;
        let row = peer_row(receiver, "alice")?;
        assert_eq!(row["kind_verified"], false, "{case}: current native evidence is required");
        assert_eq!(row["reachable"], true, "the accepted local relationship is retained");
        assert_eq!(row["verified"], false);
        assert_eq!(row["safety_number_available"], false, "{case}");
        assert!(row["safety_number"].is_null(), "{case}");
    }
    Ok(())
}
