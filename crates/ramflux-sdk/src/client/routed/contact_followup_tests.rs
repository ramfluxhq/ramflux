// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact retry and consent-boundary regressions through the public local bus.
use super::*;
fn card(principal: &str, seed: [u8; 32]) -> Result<String, SdkError> {
    let public = ramflux_crypto::public_key_base64url_from_seed(seed);
    let now = now_unix_timestamp();
    let body = crate::ContactCardBody {
        native_authority: None,
        version: 1,
        principal_id: principal.into(),
        root_commitment: crate::identity_root_public_key_commitment(&public)?,
        root_public_key: public,
        node: crate::ContactNode {
            url: "https://node.example".into(),
            key_fingerprint: crate::contact_node_fingerprint(
                &ramflux_crypto::public_key_base64url_from_seed([91; 32]),
            )?,
        },
        display_name: None,
        kind_asserted: None,
        issued_at: now,
        expires_at: now + 3600,
    };
    Ok(crate::contact_card::encode_contact_card(body, seed, now)?.0)
}
#[tokio::test]
async fn auto_accepted_card_retry_exposes_safety_number_without_a_network_fetch()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 31)?;
    let mut b = Fixture::new("bob", 41)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
    pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    assert!(account(&state, "bob")?.friend_link_peer_is_accepted(&root)?);
    let seed = account(&state, "alice")?
        .identity_root
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?
        .signing_key
        .to_bytes();
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    let receiver = account(&state, "bob")?;
    assert!(receiver.observed_device_set(&root)?.is_some());
    assert!(receiver.observed_device_set(&receiver.contact_own_commitment()?)?.is_some());
    let row = crate::bus::read_model::row(receiver, "identity", "alice")?;
    assert_eq!(row["safety_number_available"], false);
    assert!(row["safety_number"].is_null(), "automatic acceptance has not computed it");
    let started = std::time::Instant::now();
    for retry in 0..2 {
        let accepted =
            contact(&mut state, "bob", "contact.accept", json!({"card":card("alice", seed)?}))
                .await?;
        assert_eq!(accepted["contact"]["root_source"], "card");
        let receiver = account(&state, "bob")?;
        let row = crate::bus::read_model::row(receiver, "identity", "alice")?;
        assert_eq!(row["safety_number_available"], true);
        assert_eq!(row["safety_number_algorithm_version"], 1);
        assert_eq!(row["safety_number"].as_array().map(Vec::len), Some(12));
        assert_eq!(
            row["safety_number"],
            json!(receiver.contact_safety_number(&root)?.safety_number)
        );
        assert_eq!(row["verified"], false, "deriving a number cannot mark it verified");
        eprintln!(
            "contact acceptance readiness retry={retry} elapsed_us={} safety_number_available=true remote_fetches={}",
            started.elapsed().as_micros(),
            directory.manifest_fetches.load(Ordering::SeqCst) - before,
        );
    }
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before);
    Ok(())
}

#[tokio::test]
async fn accepted_retry_without_a_verified_manifest_preserves_success_without_caching()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 32)?;
    let mut b = Fixture::new("bob", 42)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
    pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    let (expected, request_id) = {
        let receiver = account(&state, "bob")?;
        let db = receiver.account_db()?;
        let request = db.contact_request(&root, "inbound")?.ok_or_else(|| invalid("request"))?;
        db.remove_actor_state("identity/manifest/alice")?;
        (receiver.contact_entry("alice")?, request.request_id)
    };
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    for selector in [json!({"principal_id":"alice"}), json!({"request_id":request_id})] {
        let accepted = contact(&mut state, "bob", "contact.accept", selector).await?;
        assert_eq!(accepted["contact"], expected);
        let row = crate::bus::read_model::row(account(&state, "bob")?, "identity", "alice")?;
        assert_eq!(row["safety_number_available"], false);
        assert!(row["safety_number"].is_null());
    }
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before);
    Ok(())
}

#[tokio::test]
async fn accepted_legacy_retry_without_a_signed_device_set_does_not_cache_a_number()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 33)?;
    let mut b = Fixture::new("bob", 43)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
    pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    account(&state, "bob")?
        .account_db()?
        .remove_actor_state(&crate::client::identity_authority::record_key(&root))?;
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    let accepted =
        contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
    assert_eq!(accepted["contact"]["principal_id"], "alice");
    let row = crate::bus::read_model::row(account(&state, "bob")?, "identity", "alice")?;
    assert_eq!(row["safety_number_available"], false);
    assert!(row["safety_number"].is_null());
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before);
    Ok(())
}

#[tokio::test]
async fn lookup_accept_and_accepted_retry_cache_safety_without_changing_verification()
-> Result<(), SdkError> {
    for automatic in [false, true] {
        let mut a = Fixture::new("alice", 31)?;
        let mut b = Fixture::new("bob", 41)?;
        let directory = Directory::new(&a, &b).await?;
        let mut state = state(&mut a, &mut b, &directory)?;
        if automatic {
            account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
        }
        pending(&mut state, &directory).await?;
        let root = r2::root(&state, "alice")?;
        let receiver = account(&state, "bob")?;
        assert_eq!(
            crate::bus::read_model::row(receiver, "identity", "alice")?["safety_number_available"],
            false
        );
        let verification = receiver.account_db()?.contact_verification(&root)?;
        let mut fetches = directory.manifest_fetches.load(Ordering::SeqCst);
        for retry in 0..2 {
            contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
            let receiver = account(&state, "bob")?;
            let row = crate::bus::read_model::row(receiver, "identity", "alice")?;
            assert_eq!(row["safety_number_available"], true);
            assert_eq!(row["safety_number_algorithm_version"], 1);
            assert_eq!(row["root_source"], "lookup");
            assert_eq!(row["verified"], false);
            assert_eq!(receiver.account_db()?.contact_verification(&root)?, verification);
            if retry == 0 {
                directory.unavailable.store(true, Ordering::SeqCst);
                fetches = directory.manifest_fetches.load(Ordering::SeqCst);
            } else {
                assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), fetches);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn contact_accept_retries_return_the_auto_accepted_contact_and_refuse_conflicting_keys()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 31)?;
    let mut b = Fixture::new("bob", 41)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    contact(
        &mut state,
        "bob",
        "contact.requests.policy.set",
        json!({"contact_requests":"auto_accept"}),
    )
    .await?;
    pending(&mut state, &directory).await?;
    let client = account(&state, "alice")?;
    let seed =
        client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?.signing_key.to_bytes();
    let valid = card("alice", seed)?;
    let original = account(&state, "bob")?.contact_entry("alice")?;
    assert_eq!(original["root_source"], "lookup");
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    let mut upgraded = original.clone();
    upgraded["root_source"] = json!("card");
    upgraded["node"] = json!({
        "url":"https://node.example",
        "key_fingerprint": crate::contact_node_fingerprint(
            &ramflux_crypto::public_key_base64url_from_seed([91; 32]))?
    });
    for _ in 0..2 {
        let retry = contact(&mut state, "bob", "contact.accept", json!({"card":valid})).await?;
        assert_eq!(retry["contact"]["root_source"], "card");
        assert_eq!(retry["contact"], upgraded);
    }
    let conflicting = card("alice", [211; 32])?;
    assert!(matches!(
        contact(&mut state, "bob", "contact.accept", json!({"card":conflicting})).await,
        Err(SdkError::ContactInput(crate::ContactReason::RootConflict))
    ));
    assert_eq!(account(&state, "bob")?.contact_entry("alice")?, upgraded);
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before);
    let root = original["root_commitment"].as_str().ok_or_else(|| invalid("root"))?;
    let db = account(&state, "bob")?.account_db()?;
    let request = db.contact_request(root, "inbound")?.ok_or_else(|| invalid("request"))?;
    db.remove_contact_request(root, "inbound", &request.request_id)?;
    let retry =
        contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
    assert_eq!(retry["contact"], upgraded, "retry also survives request retirement");
    let client = account(&state, "bob")?;
    let db = client.account_db()?;
    let mut identity = db.client_record("identity", "alice")?.ok_or_else(|| invalid("identity"))?;
    identity["root_source"] = json!("verified");
    db.persist_client_record("identity", "alice", &identity)?;
    let verified = contact(&mut state, "bob", "contact.accept", json!({"card":valid})).await?;
    assert_eq!(verified["contact"]["root_source"], "verified");
    assert_eq!(verified["contact"]["root_commitment"], original["root_commitment"]);
    Ok(())
}

#[tokio::test]
async fn peer_unblock_preserves_local_fences_and_local_unblock_lifts_them() -> Result<(), SdkError>
{
    let mut a = Fixture::new("alice", 51)?;
    let mut b = Fixture::new("bob", 61)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    contact(&mut state, "bob", "contact.accept", json!({"root_commitment":root})).await?;
    let link = account(&state, "bob")?
        .account_db()?
        .contact_request(&root, "inbound")?
        .ok_or_else(|| invalid("request"))?
        .link_id;
    for kind in ["declined", "blocked"] {
        let client = account(&state, "bob")?;
        let db = client.account_db()?;
        db.fence_contact_request(
            &root,
            kind,
            if kind == "blocked" { 0 } else { now_unix_timestamp() + 3600 },
        )?;
        let before = db.retained_contact_request_fence(&root)?;
        // Exercise the shared peer path even in a future accepted-link/fence combination.
        client.project_contact_control(
            &entry,
            &json!({"type":"friend.unblocked","link_id":link,"requester":"alice","target":"bob"}),
        )?;
        assert_eq!(db.retained_contact_request_fence(&root)?, before);
        contact(&mut state, "bob", "contact.unblock", json!({"link_id":link})).await?;
        assert!(
            account(&state, "bob")?.account_db()?.retained_contact_request_fence(&root)?.is_none()
        );
    }
    Ok(())
}

#[tokio::test]
async fn declining_a_crossed_request_preserves_the_pending_outbound_acceptance()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 71)?;
    let mut b = Fixture::new("bob", 81)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    let client = account(&state, "bob")?;
    let db = client.account_db()?;
    let inbound = db.contact_request(&root, "inbound")?.ok_or_else(|| invalid("inbound"))?;
    let manifest = db
        .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
            "identity/manifest-root/{root}"
        ))?
        .ok_or_else(|| invalid("manifest"))?;
    // Model the crossed outbound intent before the inbound decision is applied.
    client.stage_contact_request(&manifest, &inbound.link_id, None)?;
    contact(&mut state, "bob", "contact.decline", json!({"request_id":inbound.request_id})).await?;
    let client = account(&state, "bob")?;
    assert_eq!(
        client.account_db()?.retained_contact_request_fence(&root)?.map(|f| f.0),
        Some("declined".into())
    );
    assert!(client.friend_rejection_reason(&root)?.is_none());
    assert_eq!(
        client
            .account_db()?
            .contact_request(&root, "outbound")?
            .ok_or_else(|| invalid("outbound"))?
            .state,
        "pending"
    );
    flush(&mut state, "bob").await?;
    let mut outbound = frames(&directory)?;
    // The peer sees the decline before accepting the independent crossed request.
    outbound.sort_by_key(|frame| {
        crate::client::routed::decode(&frame.envelope)
            .is_ok_and(|packet| packet.schema == contact_requests::ENVELOPE_SCHEMA)
    });
    for frame in outbound {
        deliver(&mut state, "alice", &frame)
            .await
            .map_err(|e| invalid(&format!("crossed request at alice: {e}")))?;
    }
    flush(&mut state, "alice").await?;
    let responses = frames(&directory)?;
    assert!(!responses.is_empty(), "peer must accept the independent crossed outbound request");
    for frame in responses {
        deliver(&mut state, "bob", &frame)
            .await
            .map_err(|e| invalid(&format!("crossed accept at bob: {e}")))?;
    }
    let client = account(&state, "bob")?;
    assert_eq!(
        client
            .account_db()?
            .contact_request(&root, "outbound")?
            .ok_or_else(|| invalid("outbound"))?
            .state,
        "accepted"
    );
    assert!(client.friend_link_peer_is_accepted(&root)?);
    assert_eq!(
        client
            .account_db()?
            .contact_request(&root, "inbound")?
            .ok_or_else(|| invalid("inbound"))?
            .state,
        "declined"
    );
    Ok(())
}
#[tokio::test]
async fn crossed_decline_still_fences_new_requests_after_outbound_expires() -> Result<(), SdkError>
{
    let mut a = Fixture::new("alice", 111)?;
    let mut b = Fixture::new("bob", 121)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    let client = account(&state, "bob")?;
    let db = client.account_db()?;
    let inbound = db.contact_request(&root, "inbound")?.ok_or_else(|| invalid("inbound"))?;
    let manifest = db
        .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
            "identity/manifest-root/{root}"
        ))?
        .ok_or_else(|| invalid("manifest"))?;
    client.stage_contact_request(&manifest, &inbound.link_id, None)?;
    contact(&mut state, "bob", "contact.decline", json!({"request_id":inbound.request_id})).await?;
    let client = account(&state, "bob")?;
    let db = client.account_db()?;
    let fence = db.retained_contact_request_fence(&root)?;
    assert_eq!(fence.as_ref().map(|f| f.0.as_str()), Some("declined"));
    // Move just the persisted outbound deadline into the past, without waiting out the cooldown.
    let mut outbound = db.contact_request(&root, "outbound")?.ok_or_else(|| invalid("outbound"))?;
    db.remove_contact_request(&root, "outbound", &outbound.request_id)?;
    outbound.expires_at = now_unix_timestamp() - 1;
    assert!(db.persist_contact_request(&outbound)?);
    db.expire_contact_requests(now_unix_timestamp())?;
    assert_eq!(db.contact_request(&root, "outbound")?.map(|r| r.state), Some("expired".into()));
    assert_eq!(db.retained_contact_request_fence(&root)?, fence);
    assert!(client.contact_request_admission(&entry).is_err());
    // Remove the old inbound decision: the retained fence alone must refuse a fresh request.
    db.remove_contact_request(&root, "inbound", &inbound.request_id)?;
    let peer = r2::root(&state, "bob")?;
    let sender = account(&state, "alice")?;
    let sender_db = sender.account_db()?;
    let old =
        sender_db.contact_request(&peer, "outbound")?.ok_or_else(|| invalid("sender request"))?;
    sender_db.remove_contact_request(&peer, "outbound", &old.request_id)?;
    let manifest = sender_db
        .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
            "identity/manifest-root/{peer}"
        ))?
        .ok_or_else(|| invalid("sender manifest"))?;
    sender.stage_contact_request(&manifest, &old.link_id, None)?;
    let fresh =
        sender_db.contact_request(&peer, "outbound")?.ok_or_else(|| invalid("fresh request"))?;
    assert_ne!(fresh.request_id, inbound.request_id);
    flush(&mut state, "alice").await?;
    let entries = frames(&directory)?;
    assert!(!entries.is_empty(), "fresh outbound request must produce a carrier");
    let client = account(&state, "bob")?;
    let gateway = state.accounts["bob"].gateway_config.clone();
    for entry in entries {
        assert!(client.contact_request_candidate(&gateway, &entry).await.is_err());
    }
    assert_eq!(client.account_db()?.retained_contact_request_fence(&root)?, fence);
    Ok(())
}

#[tokio::test]
async fn failed_outbound_staging_keeps_the_decline_fence_and_rolls_back_new_intent()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 91)?;
    let mut b = Fixture::new("bob", 101)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    let client = account(&state, "bob")?;
    let db = client.account_db()?;
    for i in 0..128 {
        let record = ramflux_storage::ContactRequestRecord {
            contact_identity_commitment: format!("full-{i}"),
            direction: "outbound".into(),
            request_id: format!("full-{i}"),
            principal_id: format!("full-{i}"),
            link_id: format!("full-{i}"),
            state: "pending".into(),
            request_json: b"{}".to_vec(),
            expires_at: now_unix_timestamp() + 3600,
            updated_at: now_unix_timestamp(),
        };
        match db.persist_contact_request(&record) {
            Ok(true) => {}
            Err(StorageError::AuthorizationRejected) => break,
            other => return Err(invalid(&format!("unexpected capacity result: {other:?}"))),
        }
    }
    db.fence_contact_request(&root, "declined", now_unix_timestamp() + 3600)?;
    let fence = db.retained_contact_request_fence(&root)?;
    let manifest = db
        .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
            "identity/manifest-root/{root}"
        ))?
        .ok_or_else(|| invalid("manifest"))?;
    assert!(client.stage_contact_request(&manifest, "failed-add", None).is_err());
    assert_eq!(db.retained_contact_request_fence(&root)?, fence);
    assert!(db.contact_request(&root, "outbound")?.is_none());
    assert!(db.client_record("contact_request_status", &root)?.is_none());
    Ok(())
}

#[path = "contact_capacity_followup_tests.rs"]
mod capacity;

#[tokio::test]
async fn accepted_retry_preserves_the_requested_legacy_link_when_root_has_aliases()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 171)?;
    let mut b = Fixture::new("bob", 181)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    let peer = r2::root(&state, "alice")?;
    let own = r2::root(&state, "bob")?;
    contact(&mut state, "bob", "contact.accept", json!({"root_commitment":peer})).await?;
    let client = account(&state, "bob")?;
    let db = client.account_db()?;
    let old = db.contact_request(&peer, "inbound")?.ok_or_else(|| invalid("request"))?;
    db.remove_contact_request(&peer, "inbound", &old.request_id)?;
    client.establish_friend_link("zzz-new-alias", &peer, &own)?;
    assert_eq!(
        db.friend_link_for_peer(&peer)?.ok_or_else(|| invalid("alias"))?.link_id,
        "zzz-new-alias"
    );
    let response =
        contact(&mut state, "bob", "contact.accept", json!({"link_id":old.link_id})).await?;
    assert_eq!(response["link_id"], old.link_id, "legacy link selectors remain stable");
    assert_eq!(response["contact"]["root_commitment"], peer);
    account(&state, "bob")?.establish_friend_link("wrong-link", &own, "unrelated")?;
    assert!(matches!(
        contact(
            &mut state,
            "bob",
            "contact.accept",
            json!({
                "link_id":"wrong-link","requester_id":own,"target_id":peer
            })
        )
        .await,
        Err(SdkError::ContactInput(crate::ContactReason::RootConflict))
    ));
    Ok(())
}
