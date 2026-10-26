// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Floor saturation, cold duplicate receipts and slot-less overflow admission.
use super::*;
#[tokio::test]
async fn floor_capacity_is_typed_visible_and_explicitly_clearable_without_lifting_blocks()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 111)?;
    let mut b = Fixture::new("bob", 121)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = r2::outbound(&mut state, &directory).await?;
    let client = account(&state, "bob")?;
    let db = client.account_db()?;
    let now = now_unix_timestamp();
    db.write_transaction(|| -> Result<(), SdkError> {
        for i in 0..4096 {
            assert!(db.retain_contact_request_authority_floor(
                &format!("floor-{i}"),
                1,
                "hash",
                now + 3600,
                now
            )?);
        }
        Ok(())
    })?;
    db.fence_contact_request("floor-0", "blocked", 0)?;
    let fence = db.retained_contact_request_fence("floor-0")?;
    assert!(
        matches!(client.contact_request_candidate(&state.accounts["bob"].gateway_config,&entry).await,
        Err(SdkError::ContactRequestCapacity(reason)) if reason == "contact_authority_floors_exhausted")
    );
    let status = contact(&mut state, "bob", "contact.requests.policy.get", json!({})).await?;
    assert_eq!(status["authority_floors"]["retained"], 4096);
    assert_eq!(status["authority_floors"]["saturated"], true);
    assert_eq!(status["authority_floors"]["clearable"], 4096);
    let cleared = contact(
        &mut state,
        "bob",
        "contact.requests.policy.set",
        json!({"contact_requests":"manual","clear_retired_authority_floors":true}),
    )
    .await?;
    assert_eq!(cleared["cleared_authority_floors"], 4096);
    assert_eq!(cleared["authority_floors"]["retained"], 0);
    let db = account(&state, "bob")?.account_db()?;
    assert_eq!(db.retained_contact_request_fence("floor-0")?, fence);
    assert_eq!(
        db.client_record("settings", "contact_requests")?,
        Some(json!({"contact_requests":"manual"}))
    );
    deliver(&mut state, "bob", &entry).await?;
    assert_eq!(
        contact(&mut state, "bob", "contact.requests.list", json!({})).await?["requests"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}
#[tokio::test]
async fn committed_redelivery_after_request_retirement_cannot_resurrect_identity_cache()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 131)?;
    let mut b = Fixture::new("bob", 141)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = pending(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    let db = account(&state, "bob")?.account_db()?;
    let request = db.contact_request(&root, "inbound")?.ok_or_else(|| invalid("request"))?;
    db.purge_contact_request_identity_metadata(&root, "alice", &request.link_id)?;
    db.remove_actor_state(&format!("contact-request/cache/{root}"))?;
    db.release_contact_request_authority_floor(&root)?;
    db.remove_contact_request(&root, "inbound", &request.request_id)?;
    for _ in 0..2 {
        deliver(&mut state, "bob", &entry).await?;
        let db = account(&state, "bob")?.account_db()?;
        assert!(db.client_record("identity", "alice")?.is_none());
        assert!(!db.actor_state_exists(&format!("contact-request/cache/{root}"))?);
        assert!(!db.actor_state_exists(&format!("identity/manifest-root/{root}"))?);
        assert!(db.contact_request_authority_floor(&root, now_unix_timestamp())?.is_none());
        assert!(db.contact_request(&root, "inbound")?.is_none());
    }
    Ok(())
}
#[tokio::test]
async fn overflow_roots_are_deduplicated_within_a_drain_without_changing_saved_format()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 151)?;
    let mut b = Fixture::new("bob", 161)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let mut entries = Vec::new();
    for seq in 1..=3 {
        let mut entry = r2::outbound(&mut state, &directory).await?;
        entry.inbox_seq = seq;
        entries.push(entry);
    }
    let now = now_unix_timestamp();
    let roots: serde_json::Map<String, Value> = (0..1024)
        .map(|i| (format!("held-{i}"), json!({"sequence":100+i,"expires_at":now+3600})))
        .collect();
    let db = account(&state, "bob")?.account_db()?;
    db.persist_actor_state(
        "contact-admission/backpressure",
        &json!({
        "floor":1,"next_at":now+3600,"expires_at":now+3600,"scan":null,"roots":roots}),
    )?;
    db.write_transaction(|| -> Result<(), SdkError> {
        for _ in 0..64 {
            assert!(db.charge_contact_request("inbound-account", 64, 3600, now)?);
        }
        Ok(())
    })?;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = entries;
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    crate::bus::sync_driver::run(state.accounts.get_mut("bob").ok_or_else(|| invalid("bob"))?)
        .await?;
    assert_eq!(directory.manifest_fetches.load(Ordering::SeqCst), before + 1);
    assert_eq!(directory.incoming.lock().map_err(|_| invalid("inbox"))?.len(), 1);
    let saved = account(&state, "bob")?
        .account_db()?
        .load_actor_state::<Value>("contact-admission/backpressure")?
        .ok_or_else(|| invalid("pressure"))?;
    assert_eq!(saved["roots"].as_object().map(serde_json::Map::len), Some(1024));
    assert!(saved.get("overflow").is_none());
    assert_eq!(saved.as_object().map(serde_json::Map::len), Some(5));
    Ok(())
}
