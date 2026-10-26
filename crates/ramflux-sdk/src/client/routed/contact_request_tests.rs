// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public contact bus commands across real encrypted pairs and a cold receiver trust cache.
use super::*;
use crate::client::contact_requests;
async fn contact(
    state: &mut LocalBusDaemonState,
    who: &str,
    method: &str,
    body: Value,
) -> Result<Value, SdkError> {
    Ok(crate::bus::dispatch::contact::dispatch_contact_bus_request(
        &request(who, method, body),
        state,
    )
    .await?
    .response_body)
}
fn frames(directory: &Directory) -> Result<Vec<GatewayInboxEntry>, SdkError> {
    Ok(std::mem::take(&mut *directory.captured.lock().map_err(|_| invalid("capture lock"))?)
        .into_iter()
        .enumerate()
        .map(|(index, envelope)| GatewayInboxEntry {
            inbox_seq: u64::try_from(index + 1).unwrap_or(u64::MAX),
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        })
        .collect())
}
async fn flush(state: &mut LocalBusDaemonState, who: &str) -> Result<usize, SdkError> {
    contact_requests::flush(state.accounts.get_mut(who).ok_or_else(|| invalid("account"))?).await
}
async fn deliver(
    state: &mut LocalBusDaemonState,
    who: &str,
    entry: &GatewayInboxEntry,
) -> Result<Delivery, SdkError> {
    let account = state.accounts.get_mut(who).ok_or_else(|| invalid("account"))?;
    let mut engine = account.take_live_engine().await?;
    let result = account
        .client
        .apply_routed_entry(&mut engine, &super::super::review::pool()?, entry, false)
        .await;
    account.put_engine(engine);
    result
}
async fn message(state: &mut LocalBusDaemonState, text: &str) -> Result<(), SdkError> {
    let request = request(
        "alice",
        "message.submit",
        json!({"conversation_id":"request-thread",
        "message_id":text,"envelope_id":text,"source_principal_id":"alice","sender_id":"alice",
        "recipient_device_id":"bob","target_delivery_id":"bob","encrypted_body_base64":"",
        "plaintext_body_base64":ramflux_protocol::encode_base64url(text),"created_at":now_unix_timestamp().saturating_sub(120),"ttl":3600}),
    );
    let (outbound, _receiver) = tokio::sync::mpsc::channel(8);
    let connection = crate::bus::state::LocalBusConnectionState::new(1, outbound);
    Box::pin(crate::bus::dispatch::message::dispatch_message_bus_request(
        &request,
        state,
        &connection,
    ))
    .await?;
    Ok(())
}
fn account<'a>(state: &'a LocalBusDaemonState, who: &str) -> Result<&'a RamfluxClient, SdkError> {
    Ok(&state.accounts.get(who).ok_or_else(|| invalid("account"))?.client)
}
async fn pending(
    state: &mut LocalBusDaemonState,
    directory: &Directory,
) -> Result<GatewayInboxEntry, SdkError> {
    contact(
        state,
        "alice",
        "contact.add",
        json!({"principal_id":"bob","note":"PRIVATE_REQUEST_NOTE"}),
    )
    .await?;
    assert!(
        account(state, "bob")?.account_db()?.client_record("identity", "alice")?.is_none(),
        "receiver is genuinely cold"
    );
    assert_eq!(flush(state, "alice").await?, 0, "contact.add already submitted the request");
    let entries = frames(directory)?;
    assert_eq!(entries.len(), 1);
    let entry = entries.into_iter().next().ok_or_else(|| invalid("request frame"))?;
    let raw = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|error| invalid(&error.to_string()))?;
    assert!(!String::from_utf8_lossy(&raw).contains("PRIVATE_REQUEST_NOTE"));
    deliver(state, "bob", &entry).await?;
    Ok(entry)
}

#[tokio::test]
async fn contact02_request_auto_accept_then_first_message_crosses_the_cold_receiver_boundary()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 51)?;
    let mut bob = Fixture::new("bob", 61)?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    contact(
        &mut state,
        "bob",
        "contact.requests.policy.set",
        json!({"contact_requests":"auto_accept"}),
    )
    .await?;
    pending(&mut state, &directory).await?;
    let root = account(&state, "alice")?.owned_device_identity()?.root_commitment().to_owned();
    assert!(account(&state, "bob")?.friend_link_peer_is_accepted(&root)?);
    assert_eq!(flush(&mut state, "bob").await?, 1);
    for entry in frames(&directory)? {
        deliver(&mut state, "alice", &entry).await?;
    }
    let target = account(&state, "bob")?.owned_device_identity()?.root_commitment().to_owned();
    assert_eq!(
        account(&state, "alice")?
            .account_db()?
            .contact_request(&target, "outbound")?
            .ok_or_else(|| invalid("outbound"))?
            .state,
        "accepted"
    );
    message(&mut state, "first-after-auto-accept").await?;
    for entry in frames(&directory)? {
        assert!(deliver(&mut state, "bob", &entry).await?.plaintext.is_some());
    }
    assert_eq!(account(&state, "bob")?.direct_messages("request-thread")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn contact02_manual_request_holds_content_without_a_thread_then_accept_releases_it_once()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 71)?;
    let mut bob = Fixture::new("bob", 81)?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    let original = pending(&mut state, &directory).await?;
    deliver(&mut state, "bob", &original).await?;
    message(&mut state, "held-before-consent").await?;
    let entries = frames(&directory)?;
    assert_eq!(entries.len(), 1);
    for entry in &entries {
        assert!(deliver(&mut state, "bob", entry).await?.plaintext.is_none());
    }
    let bob = account(&state, "bob")?;
    assert_eq!(bob.direct_messages("request-thread")?.len(), 0);
    assert!(bob.account_db()?.client_record("conversation", "request-thread")?.is_none());
    let list = contact(&mut state, "bob", "contact.requests.list", json!({})).await?;
    assert_eq!(list["requests"].as_array().map(Vec::len), Some(1));
    assert_eq!(list["requests"][0]["message_count"], 1);
    assert_eq!(list["requests"][0]["safety_number"].as_array().map(Vec::len), Some(12), "{list}");
    let id = list["requests"][0]["request_id"].clone();
    contact(&mut state, "bob", "contact.accept", json!({"request_id":id})).await?;
    assert_eq!(account(&state, "bob")?.direct_messages("request-thread")?.len(), 1);
    assert_eq!(
        account(&state, "bob")?.direct_messages("request-thread")?[0].created_at,
        entries[0].envelope.created_at
    );
    assert_eq!(
        account(&state, "bob")?
            .account_db()?
            .message_content(
                &account(&state, "bob")?.direct_messages("request-thread")?[0].message_id
            )?
            .as_deref(),
        Some(b"held-before-consent".as_slice())
    );
    for entry in &entries {
        deliver(&mut state, "bob", entry).await?;
    }
    assert_eq!(
        account(&state, "bob")?.direct_messages("request-thread")?.len(),
        1,
        "consent replay must not duplicate content"
    );
    assert_eq!(
        contact(&mut state, "bob", "contact.requests.list", json!({})).await?["requests"],
        json!([])
    );
    Ok(())
}

#[tokio::test]
async fn contact02_decline_and_block_discard_held_messages_and_refuse_later_sender_frames()
-> Result<(), SdkError> {
    for (action, seeds) in [("contact.decline", (91, 101)), ("contact.block", (111, 121))] {
        let mut alice = Fixture::new("alice", seeds.0)?;
        let mut bob = Fixture::new("bob", seeds.1)?;
        let directory = Directory::new(&alice, &bob).await?;
        let mut state = state(&mut alice, &mut bob, &directory)?;
        let original = pending(&mut state, &directory).await?;
        message(&mut state, "unaccepted-first-message").await?;
        for entry in frames(&directory)? {
            deliver(&mut state, "bob", &entry).await?;
        }
        let list = contact(&mut state, "bob", "contact.requests.list", json!({})).await?;
        contact(&mut state, "bob", action, json!({"request_id":list["requests"][0]["request_id"]}))
            .await?;
        assert!(deliver(&mut state, "bob", &original).await.is_err());
        let root = account(&state, "alice")?.owned_device_identity()?.root_commitment().to_owned();
        assert_eq!(account(&state, "bob")?.account_db()?.held_contact_messages(&root)?.len(), 0);
        assert_eq!(account(&state, "bob")?.direct_messages("request-thread")?.len(), 0);
        message(&mut state, "new-message-after-refusal").await?;
        for entry in frames(&directory)? {
            assert!(deliver(&mut state, "bob", &entry).await.is_err());
        }
        assert_eq!(account(&state, "bob")?.direct_messages("request-thread")?.len(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn contact02_a_stranger_cannot_relabel_a_direct_packet_to_poison_the_trust_cache()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 131)?;
    let mut bob = Fixture::new("bob", 141)?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    contact(&mut state, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    message(&mut state, "stranger-without-the-request").await?;
    let mut entry = frames(&directory)?
        .into_iter()
        .find(|entry| {
            decode(&entry.envelope)
                .is_ok_and(|packet| packet.schema != contact_requests::ENVELOPE_SCHEMA)
        })
        .ok_or_else(|| invalid("direct frame"))?;
    assert!(
        deliver(&mut state, "bob", &entry).await.is_err(),
        "unrequested strangers stay rejected"
    );
    let raw = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut packet: SdkDmEncryptedEnvelope = serde_json::from_slice(&raw)?;
    packet.schema = contact_requests::ENVELOPE_SCHEMA.into();
    entry.envelope.encrypted_payload =
        ramflux_protocol::encode_base64url(serde_json::to_vec(&packet)?);
    entry.envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        entry.envelope.encrypted_payload.as_bytes(),
    );
    entry.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        account(&state, "alice")?.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &entry.envelope,
    )?;
    assert!(deliver(&mut state, "bob", &entry).await.is_err());
    assert!(account(&state, "bob")?.account_db()?.client_record("identity", "alice")?.is_none());
    assert_eq!(
        contact(&mut state, "bob", "contact.requests.list", json!({})).await?["requests"],
        json!([])
    );
    assert_eq!(account(&state, "bob")?.direct_messages("request-thread")?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn contact02_first_message_drains_its_request_before_loading_the_ordinary_send_ratchet()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 151)?;
    let mut bob = Fixture::new("bob", 161)?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    {
        let source = state.accounts.get_mut("alice").ok_or_else(|| invalid("source"))?;
        let mut engine = source.take_live_engine().await?;
        let config = engine.config.clone();
        source
            .client
            .resolve_contact(
                &config,
                &config,
                crate::client::contact_resolution::ContactResolution {
                    send_request: true,
                    request_note: None,
                    selector: "bob",
                    expected_root: None,
                    card: None,
                    link_id: "deferred-contact-request".into(),
                    allow_commitment: false,
                    requester_is_peer: false,
                    replace_provisional_root: None,
                    verification: None,
                },
                &mut engine,
            )
            .await?;
        source.put_engine(engine);
    }
    assert!(
        frames(&directory)?.is_empty(),
        "the SDK resolution has staged but not submitted its control"
    );
    message(&mut state, "immediate-first-message").await?;
    let entries = frames(&directory)?;
    assert_eq!(entries.len(), 2, "request and message must both use normal gateway submission");
    assert_eq!(decode(&entries[0].envelope)?.schema, contact_requests::ENVELOPE_SCHEMA);
    assert_eq!(decode(&entries[1].envelope)?.schema, "ramflux.sdk.dm_x3dh_envelope.v2");
    for entry in entries {
        deliver(&mut state, "bob", &entry).await?;
    }
    let list = contact(&mut state, "bob", "contact.requests.list", json!({})).await?;
    assert_eq!(list["requests"][0]["message_count"], 1);
    assert_eq!(account(&state, "bob")?.direct_messages("request-thread")?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn contact02_fresh_request_after_decline_cooldown_does_not_clear_a_block()
-> Result<(), SdkError> {
    for action in ["contact.decline", "contact.block"] {
        let mut alice = Fixture::new("alice", 171)?;
        let mut bob = Fixture::new("bob", 181)?;
        let directory = Directory::new(&alice, &bob).await?;
        let mut state = state(&mut alice, &mut bob, &directory)?;
        let original = pending(&mut state, &directory).await?;
        let list = contact(&mut state, "bob", "contact.requests.list", json!({})).await?;
        let old_id = list["requests"][0]["request_id"]
            .as_str()
            .ok_or_else(|| invalid("request id"))?
            .to_owned();
        contact(&mut state, "bob", action, json!({"request_id":old_id})).await?;
        let a_root =
            account(&state, "alice")?.owned_device_identity()?.root_commitment().to_owned();
        let b_root = account(&state, "bob")?.owned_device_identity()?.root_commitment().to_owned();
        // Advance the persisted decision age, without sleeping or changing the signed request clock.
        let past = now_unix_timestamp().saturating_sub(2 * 24 * 3600);
        let decision = if action == "contact.block" { "blocked" } else { "declined" };
        account(&state, "bob")?
            .account_db()?
            .decide_contact_request(&a_root, "inbound", &old_id, decision, past)?;
        account(&state, "alice")?
            .account_db()?
            .decide_contact_request(&b_root, "outbound", &old_id, "declined", past)?;
        if action == "contact.decline" {
            account(&state, "bob")?.account_db()?.fence_contact_request(
                &a_root,
                "declined",
                past + 24 * 3600,
            )?;
        }
        let _ = flush(&mut state, "bob").await?;
        let _ = frames(&directory)?;
        contact(&mut state, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
        let entries = frames(&directory)?;
        assert_eq!(entries.len(), 1);
        let _ = deliver(&mut state, "bob", &original).await;
        assert_eq!(
            contact(&mut state, "bob", "contact.requests.list", json!({})).await?["requests"],
            json!([]),
            "old wire replay cannot reopen consent"
        );
        if action == "contact.block" {
            assert!(deliver(&mut state, "bob", &entries[0]).await.is_err());
            assert_eq!(
                contact(&mut state, "bob", "contact.requests.list", json!({})).await?["requests"],
                json!([])
            );
        } else {
            deliver(&mut state, "bob", &entries[0]).await?;
            let next = contact(&mut state, "bob", "contact.requests.list", json!({})).await?;
            assert_ne!(next["requests"][0]["request_id"], old_id);
            contact(
                &mut state,
                "bob",
                "contact.accept",
                json!({"request_id":next["requests"][0]["request_id"]}),
            )
            .await?;
            message(&mut state, "fresh-consent-message").await?;
            for entry in frames(&directory)? {
                if entry.envelope.source_principal_id == "alice" {
                    deliver(&mut state, "bob", &entry).await?;
                }
            }
            assert_eq!(account(&state, "bob")?.direct_messages("request-thread")?.len(), 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn contact02_authenticated_own_contact_acceptance_releases_a_siblings_pending_messages()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 191)?;
    let mut bob = Fixture::new("bob", 201)?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    pending(&mut state, &directory).await?;
    message(&mut state, "sibling-consent").await?;
    for entry in frames(&directory)? {
        deliver(&mut state, "bob", &entry).await?;
    }
    let list = contact(&mut state, "bob", "contact.requests.list", json!({})).await?;
    let client = account(&state, "bob")?;
    let root = list["requests"][0]["root_commitment"].as_str().ok_or_else(|| invalid("root"))?;
    let id = list["requests"][0]["link_id"].as_str().ok_or_else(|| invalid("link"))?;
    let mut link = client.account_db()?.friend_link(id)?;
    link.state = "accepted".into();
    let manifest: Value = client
        .account_db()?
        .load_actor_state(&format!("identity/manifest-root/{root}"))?
        .ok_or_else(|| invalid("manifest"))?;
    // This decoder's caller already authenticated the owned-root packet. The existing
    // own-device transport tests cover that boundary; this tests its consent projection.
    let mut bytes = b"ramflux.own_contact.v1\n".to_vec();
    bytes.extend(serde_json::to_vec(&json!({"manifest":manifest,"link":link}))?);
    assert!(client.receive_own_contact(&bytes)?);
    assert_eq!(client.direct_messages("request-thread")?.len(), 1);
    assert_eq!(client.account_db()?.held_contact_messages(root)?.len(), 0);
    assert_eq!(
        contact(&mut state, "bob", "contact.requests.list", json!({})).await?["requests"],
        json!([])
    );
    Ok(())
}

#[tokio::test]
async fn contact02_desktop_contract_exposes_outgoing_states_and_idempotent_decision_codes()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 211)?;
    let mut bob = Fixture::new("bob", 221)?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    pending(&mut state, &directory).await?;
    let outgoing = contact(&mut state, "alice", "contact.requests.list", json!({})).await?;
    let row = &outgoing["requests"][0];
    assert_eq!(row["direction"], "outbound");
    assert_eq!(row["state"], "pending");
    assert_eq!(row["message_count"], 0);
    let id = row["request_id"].clone();
    let contacts = contact(&mut state, "alice", "contact.list", json!({})).await?;
    assert_eq!(contacts["contacts"][0]["request_id"], id, "{contacts}");
    assert!(
        account(&state, "bob")?.account_db()?.client_record("identity", "alice")?.is_some(),
        "pending peers have directory metadata"
    );
    let response =
        contact(&mut state, "bob", "contact.request.decline", json!({"request_id":id})).await?;
    assert_eq!(response["principal_id"], "alice");
    assert_eq!(response["direction"], "inbound");
    assert_eq!(
        contact(&mut state, "bob", "contact.request.decline", json!({"request_id":id})).await?,
        response
    );
    let error = contact(&mut state, "bob", "contact.request.accept", json!({"request_id":id}))
        .await
        .err()
        .ok_or_else(|| invalid("expected closed request"))?;
    assert!(matches!(error, SdkError::ContactInput(crate::ContactReason::RequestClosed)));
    let error = contact(&mut state, "bob", "contact.request.accept", json!({"request_id":"gone"}))
        .await
        .err()
        .ok_or_else(|| invalid("expected missing request"))?;
    assert!(matches!(error, SdkError::ContactInput(crate::ContactReason::RequestNotFound)));
    flush(&mut state, "bob").await?;
    for entry in frames(&directory)? {
        deliver(&mut state, "alice", &entry).await?;
    }
    let outgoing = contact(&mut state, "alice", "contact.requests.list", json!({})).await?;
    assert_eq!(outgoing["requests"][0]["state"], "declined");
    Ok(())
}

#[tokio::test]
async fn contact02_note_character_limit_and_persistent_outbound_rate_refusal()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 31)?;
    let mut bob = Fixture::new("bob", 41)?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    for note in ["é".repeat(141), "unsafe\nnote".into()] {
        let error =
            contact(&mut state, "alice", "contact.add", json!({"principal_id":"bob","note":note}))
                .await
                .err()
                .ok_or_else(|| invalid("invalid note admitted"))?;
        assert!(matches!(error, SdkError::ContactInput(crate::ContactReason::InvalidRequestNote)));
    }
    let db = account(&state, "alice")?.account_db()?;
    for _ in 0..64 {
        assert!(db.charge_contact_request("outbound-account", 64, 3600, now_unix_timestamp())?);
    }
    let error = contact(
        &mut state,
        "alice",
        "contact.add",
        json!({"principal_id":"bob","note":"é".repeat(140)}),
    )
    .await
    .err()
    .ok_or_else(|| invalid("rate limit bypassed"))?;
    assert!(matches!(error, SdkError::ContactInput(crate::ContactReason::LookupRateLimited)));
    assert_eq!(
        contact(&mut state, "alice", "contact.requests.list", json!({})).await?["requests"],
        json!([])
    );
    assert!(!account(&state, "alice")?.friend_link_peer_is_accepted("bob")?);
    Ok(())
}

#[tokio::test]
async fn contact02_expired_request_can_recover_a_lost_acceptance_without_reopening_consent()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 231)?;
    let mut bob = Fixture::new("bob", 241)?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    pending(&mut state, &directory).await?;
    let incoming = contact(&mut state, "bob", "contact.requests.list", json!({})).await?;
    let id =
        incoming["requests"][0]["request_id"].as_str().ok_or_else(|| invalid("id"))?.to_owned();
    contact(&mut state, "bob", "contact.accept", json!({"request_id":id})).await?;
    flush(&mut state, "bob").await?;
    let _ = frames(&directory)?; // Lost acceptance: the source request eventually expires.
    let root = account(&state, "bob")?.owned_device_identity()?.root_commitment().to_owned();
    account(&state, "alice")?.account_db()?.decide_contact_request(
        &root,
        "outbound",
        &id,
        "expired",
        now_unix_timestamp(),
    )?;
    contact(&mut state, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    for entry in frames(&directory)? {
        deliver(&mut state, "bob", &entry).await?;
    }
    assert_eq!(
        contact(&mut state, "bob", "contact.requests.list", json!({})).await?["requests"],
        json!([])
    );
    flush(&mut state, "bob").await?;
    for entry in frames(&directory)? {
        deliver(&mut state, "alice", &entry).await?;
    }
    let outgoing = contact(&mut state, "alice", "contact.requests.list", json!({})).await?;
    assert_eq!(outgoing["requests"][0]["state"], "accepted");
    assert_ne!(outgoing["requests"][0]["request_id"], id);
    Ok(())
}

#[path = "contact_request_r2_tests.rs"]
mod r2;

#[path = "contact_request_r3_tests.rs"]
mod r3;

#[path = "contact_request_r4_tests.rs"]
mod r4;

#[tokio::test]
async fn contact02_accepting_a_received_lookup_request_keeps_stable_lookup_provenance()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 71)?;
    let mut bob = Fixture::new("bob", 81)?;
    let directory = Directory::new(&alice, &bob).await?;
    let mut state = state(&mut alice, &mut bob, &directory)?;
    // The request reaches the cold receiver before it accepts by principal name.
    let entry = pending(&mut state, &directory).await?;
    let source = |state: &LocalBusDaemonState, who: &str, peer: &str| -> Result<Value, SdkError> {
        let db = account(state, who)?.account_db()?;
        let row = db.client_record("identity", peer)?.ok_or_else(|| invalid("identity"))?;
        Ok(row["root_source"].clone())
    };
    assert_eq!(source(&state, "bob", "alice")?, "lookup", "a requester root is never a card");
    // Retry delivery and republish the peer manifest after contact.add decorated the row.
    deliver(&mut state, "bob", &entry).await?;
    let manifest = directory
        .records
        .lock()
        .map_err(|_| invalid("directory"))?
        .iter()
        .find(|record| record.principal_id == "bob")
        .cloned()
        .ok_or_else(|| invalid("bob manifest"))?;
    account(&state, "alice")?.persist_root_verified_directory(&manifest)?;
    assert_eq!(source(&state, "alice", "bob")?, "lookup");
    let accepted =
        contact(&mut state, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
    assert_eq!(accepted["direction"], "inbound");
    assert_eq!(accepted["contact"]["root_source"], "lookup");
    assert_eq!(account(&state, "alice")?.contact_entry("bob")?["root_source"], "lookup");
    Ok(())
}
