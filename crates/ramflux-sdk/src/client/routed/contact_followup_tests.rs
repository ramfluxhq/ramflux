// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact retry and consent-boundary regressions through the public local bus.
use super::*;
fn card(principal: &str, seed: [u8; 32]) -> Result<String, SdkError> {
    let public = ramflux_crypto::public_key_base64url_from_seed(seed);
    let now = now_unix_timestamp();
    let body = crate::ContactCardBody {
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
    directory.unavailable.store(true, Ordering::SeqCst);
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    for _ in 0..2 {
        let retry = contact(&mut state, "bob", "contact.accept", json!({"card":valid})).await?;
        assert_eq!(retry["contact"], original);
    }
    let conflicting = card("alice", [211; 32])?;
    assert!(matches!(
        contact(&mut state, "bob", "contact.accept", json!({"card":conflicting})).await,
        Err(SdkError::ContactInput(crate::ContactReason::RootConflict))
    ));
    assert_eq!(account(&state, "bob")?.contact_entry("alice")?, original);
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before);
    let root = original["root_commitment"].as_str().ok_or_else(|| invalid("root"))?;
    let db = account(&state, "bob")?.account_db()?;
    let request = db.contact_request(root, "inbound")?.ok_or_else(|| invalid("request"))?;
    db.remove_contact_request(root, "inbound", &request.request_id)?;
    let retry =
        contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
    assert_eq!(retry["contact"], original, "retry also survives request retirement");
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
    assert!(client.account_db()?.retained_contact_request_fence(&root)?.is_none());
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
