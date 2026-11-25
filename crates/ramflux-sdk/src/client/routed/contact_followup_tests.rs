// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact retry and consent-boundary regressions through the public local bus.
use super::*;
fn card(fixture: &Fixture) -> Result<String, SdkError> {
    let account = fixture.client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
    let vault = &fixture.native.as_ref().ok_or(SdkError::CustodySetupInvalid)?.vault;
    let record = account.record();
    let now = crate::custody::network_now()?;
    let signed = account.sign_contact_card(
        vault.as_ref(),
        ramflux_protocol::custody::ContactCardV3 {
            reach: None,
            version: 3,
            principal_id: record.body.principal_id.clone(),
            account_anchor: record.body.account_anchor.clone(),
            master_public_key: record.body.master_certificate.body.master_public_key.clone(),
            master_certificate: record.body.master_certificate.clone(),
            authority_head_hash: ramflux_protocol::custody::object_hash(record)?,
            authority_epoch: record.body.device_set_epoch,
            devices: record.body.devices.clone(),
            node_url: "https://node.example".into(),
            node_key_fingerprint: crate::contact_node_fingerprint(
                &ramflux_crypto::public_key_base64url_from_seed(&[91; 32]),
            )?,
            display_name: record.body.profile.display_name.clone(),
            issued_at: now,
            expires_at: now + 3600,
        },
        now,
    )?;
    Ok(crate::contact_card_native::encode(
        &signed,
        i64::try_from(now).map_err(|_| invalid("native card time"))?,
    )?
    .0)
}
fn clear_cached_safety(client: &RamfluxClient) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let mut row = db.client_record("identity", "alice")?.ok_or_else(|| invalid("identity"))?;
    let fields = row.as_object_mut().ok_or_else(|| invalid("identity object"))?;
    fields.remove("safety_number");
    fields.remove("safety_number_algorithm_version");
    db.persist_client_record("identity", "alice", &row)?;
    Ok(())
}
#[tokio::test]
async fn auto_accepted_card_retry_exposes_safety_number_without_a_network_fetch()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        auto_accepted_card_retry_exposes_safety_number_without_a_network_fetch_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn auto_accepted_card_retry_exposes_safety_number_without_a_network_fetch_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 31)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 41)).await?;
    let valid = card(&a)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
    pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    assert!(account(&state, "bob")?.friend_link_peer_is_accepted(&root)?);
    clear_cached_safety(account(&state, "bob")?)?;
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    let receiver = account(&state, "bob")?;
    let now = crate::custody::network_now()?;
    assert!(receiver.current_custody_authority(&root, now)?.is_some());
    assert!(
        receiver.current_custody_authority(&receiver.contact_own_commitment()?, now)?.is_some()
    );
    let row = crate::bus::read_model::row(receiver, "identity", "alice")?;
    assert_eq!(row["safety_number_available"], false);
    assert!(row["safety_number"].is_null(), "the derived cache was deliberately removed");
    let started = std::time::Instant::now();
    for retry in 0..2 {
        let accepted = contact(&mut state, "bob", "contact.accept", json!({"card":valid})).await?;
        assert_eq!(
            accepted["contact"]["root_source"], "lookup",
            "a card retry without a fetch must not change provenance (lookup -> card needs the full authority checks)"
        );
        let receiver = account(&state, "bob")?;
        let row = crate::bus::read_model::row(receiver, "identity", "alice")?;
        assert_eq!(row["safety_number_available"], true);
        assert_eq!(row["safety_number_algorithm_version"], 2);
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
async fn accepted_retry_uses_native_authority_when_manifest_payload_is_absent()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        accepted_retry_uses_native_authority_when_manifest_payload_is_absent_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn accepted_retry_uses_native_authority_when_manifest_payload_is_absent_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 32)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 42)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
    pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    let (expected, request_id) = {
        let receiver = account(&state, "bob")?;
        clear_cached_safety(receiver)?;
        let db = receiver.account_db()?;
        let request = db.contact_request(&root, "inbound")?.ok_or_else(|| invalid("request"))?;
        db.remove_actor_state("identity/manifest/alice")?;
        (receiver.contact_entry("alice")?, request.request_id)
    };
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    for selector in [json!({"principal_id":"alice"}), json!({"request_id":request_id})] {
        let accepted = contact(&mut state, "bob", "contact.accept", selector).await?;
        assert_eq!(accepted["contact"]["root_commitment"], expected["root_commitment"]);
        assert_eq!(accepted["contact"]["root_source"], expected["root_source"]);
        assert_eq!(accepted["contact"]["verified"], expected["verified"]);
        let row = crate::bus::read_model::row(account(&state, "bob")?, "identity", "alice")?;
        assert_eq!(row["safety_number_available"], true);
        assert_eq!(row["safety_number_algorithm_version"], 2);
    }
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before);
    Ok(())
}

#[tokio::test]
async fn accepted_native_retry_without_a_stored_record_still_derives_the_number()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        accepted_native_retry_without_a_stored_record_still_derives_the_number_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn accepted_native_retry_without_a_stored_record_still_derives_the_number_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 33)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 43)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
    pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    let client = account(&state, "bob")?;
    client
        .account_db()?
        .remove_actor_state(&crate::client::identity_authority::record_key(&root))?;
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    let accepted =
        contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
    assert_eq!(accepted["contact"]["principal_id"], "alice");
    let row = crate::bus::read_model::row(account(&state, "bob")?, "identity", "alice")?;
    assert_eq!(row["safety_number_available"], true);
    assert_eq!(row["safety_number"].as_array().map(Vec::len), Some(12));
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before);
    Ok(())
}

#[tokio::test]
async fn lookup_accept_and_accepted_retry_cache_safety_without_changing_verification()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        lookup_accept_and_accepted_retry_cache_safety_without_changing_verification_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn lookup_accept_and_accepted_retry_cache_safety_without_changing_verification_body()
-> Result<(), SdkError> {
    for automatic in [false, true] {
        let mut a = Box::pin(Fixture::native_named("alice", 31)).await?;
        let mut b = Box::pin(Fixture::native_named("bob", 41)).await?;
        let directory = Directory::new(&a, &b).await?;
        let mut state = state(&mut a, &mut b, &directory)?;
        if automatic {
            account(&state, "bob")?.set_contact_request_policy("auto_accept")?;
        }
        pending(&mut state, &directory).await?;
        let root = r2::root(&state, "alice")?;
        let receiver = account(&state, "bob")?;
        clear_cached_safety(receiver)?;
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
            assert_eq!(row["safety_number_algorithm_version"], 2);
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
    crate::client::native_test_support::watchdog::within(
        contact_accept_retries_return_the_auto_accepted_contact_and_refuse_conflicting_keys_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact_accept_retries_return_the_auto_accepted_contact_and_refuse_conflicting_keys_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 31)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 41)).await?;
    let valid = card(&a)?;
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
    let original = account(&state, "bob")?.contact_entry("alice")?;
    assert_eq!(original["root_source"], "lookup");
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    // A retry carrying a card returns the existing state unchanged: provenance moves from
    // lookup to card only through a resolution that fetched and checked the authority.
    let upgraded = original.clone();
    for _ in 0..2 {
        let retry = contact(&mut state, "bob", "contact.accept", json!({"card":valid})).await?;
        assert_eq!(
            retry["contact"]["root_source"], "lookup",
            "a card retry must not promote lookup provenance without the authority checks"
        );
        assert_eq!(
            retry["contact"], upgraded,
            "a card retry must return the existing contact unchanged"
        );
    }
    let impostor = Box::pin(Fixture::native_named("alice", 211)).await?;
    let conflicting = card(&impostor)?;
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
    crate::client::native_test_support::watchdog::within(
        peer_unblock_preserves_local_fences_and_local_unblock_lifts_them_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn peer_unblock_preserves_local_fences_and_local_unblock_lifts_them_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 51)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 61)).await?;
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
    crate::client::native_test_support::watchdog::within(
        declining_a_crossed_request_preserves_the_pending_outbound_acceptance_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn declining_a_crossed_request_preserves_the_pending_outbound_acceptance_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 71)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 81)).await?;
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
    let receiver = account(&state, "alice")?;
    let mut outbound = frames(&directory)?
        .into_iter()
        .map(|frame| {
            let opened = receiver.open_routed(&frame, "alice")?;
            let control = receiver.verify_contact_control(&frame, &opened.routing, &opened.body)?;
            Ok::<_, SdkError>((control.body.kind == contact_requests::Decision::Request, frame))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Order the authenticated typed controls, without a plaintext routing discriminator.
    outbound.sort_by_key(|(request, _)| *request);
    for (_, frame) in outbound {
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
    crate::client::native_test_support::watchdog::within(
        crossed_decline_still_fences_new_requests_after_outbound_expires_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn crossed_decline_still_fences_new_requests_after_outbound_expires_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 111)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 121)).await?;
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
    crate::client::native_test_support::watchdog::within(
        failed_outbound_staging_keeps_the_decline_fence_and_rolls_back_new_intent_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn failed_outbound_staging_keeps_the_decline_fence_and_rolls_back_new_intent_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 91)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 101)).await?;
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
    crate::client::native_test_support::watchdog::within(
        accepted_retry_preserves_the_requested_legacy_link_when_root_has_aliases_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn accepted_retry_preserves_the_requested_legacy_link_when_root_has_aliases_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 171)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 181)).await?;
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
