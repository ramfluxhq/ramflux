// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adversarial contact admission, retention, selectors and consent races.
use super::*;
pub(super) fn root(state: &LocalBusDaemonState, who: &str) -> Result<String, SdkError> {
    Ok(account(state, who)?.owned_device_identity()?.root_commitment().into())
}
pub(super) async fn outbound(
    state: &mut LocalBusDaemonState,
    directory: &Directory,
) -> Result<GatewayInboxEntry, SdkError> {
    contact(state, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    frames(directory)?.into_iter().next().ok_or_else(|| invalid("request"))
}
#[tokio::test]
async fn contact02_r2_unsigned_junk_cannot_spend_the_genuine_request_budget() -> Result<(), SdkError>
{
    let mut a = Fixture::new("alice", 31)?;
    let mut b = Fixture::new("bob", 41)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let valid = outbound(&mut state, &directory).await?;
    let mut junk = valid.clone();
    junk.envelope.signed.signature = "invalid".into();
    let receiver = state.accounts.get("bob").ok_or_else(|| invalid("bob"))?;
    for _ in 0..120 {
        assert!(
            receiver
                .client
                .contact_request_candidate(&receiver.gateway_config, &junk)
                .await
                .is_err()
        );
    }
    deliver(&mut state, "bob", &valid).await?;
    assert_eq!(
        contact(&mut state, "bob", "contact.requests.list", json!({})).await?["requests"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}
#[tokio::test]
async fn contact02_r2_short_expiry_and_chosen_request_ids_are_not_valid_wire_controls()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 51)?;
    let mut b = Fixture::new("bob", 61)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = outbound(&mut state, &directory).await?;
    let manifest = directory.records.lock().map_err(|_| invalid("directory lock"))?[0].clone();
    account(&state, "bob")?.persist_identity_directory(&manifest)?;
    let opened = account(&state, "bob")?.open_routed(&entry, "bob")?;
    let original: contact_requests::Control = serde_json::from_slice(&opened.body)?;
    for short_lifetime in [true, false] {
        let mut control = original.clone();
        if short_lifetime {
            control.body.expires_at = control.body.issued_at + 60;
        } else {
            control.body.request_id = ramflux_protocol::encode_base64url([9; 32]);
        }
        control.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::canonical_json_bytes(
                &json!({"domain":"ramflux.contact_request.v1","body":control.body}),
            )?,
            account(&state, "alice")?
                .identity_root
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .signing_key
                .to_bytes(),
        );
        assert!(
            account(&state, "bob")?
                .verify_contact_control(&entry, &opened.routing, &serde_json::to_vec(&control)?)
                .is_err(),
            "a root signer cannot choose expiry or another selector as its request ID"
        );
    }
    Ok(())
}
#[tokio::test]
async fn contact02_r2_persists_a_compact_request_and_prunes_closed_requester_authority()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 71)?;
    let mut b = Fixture::new("bob", 81)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let source = root(&state, "alice")?;
    account(&state, "bob")?.account_db()?.append_journal(
        "legacy-preview",
        "contact.requested",
        &json!({"preview":"old private body","note":"old note","safety_number":["1"]}),
        now_unix_timestamp(),
        Some(&source),
    )?;
    pending(&mut state, &directory).await?;
    let source = root(&state, "alice")?;
    let row = account(&state, "bob")?
        .account_db()?
        .contact_request(&source, "inbound")?
        .ok_or_else(|| invalid("row"))?;
    assert!(
        row.request_json.len() < 1024,
        "the request must not retain the signed manifest/control"
    );
    contact(&mut state, "bob", "contact.decline", json!({"request_id":row.request_id})).await?;
    account(&state, "bob")?.account_db()?.decide_contact_request(
        &source,
        "inbound",
        &row.request_id,
        "declined",
        now_unix_timestamp() - 7200,
    )?;
    account(&state, "bob")?.account_db()?.remove_actor_state("contact-request/maintenance-next")?;
    contact(&mut state, "bob", "contact.requests.list", json!({})).await?;
    for event in account(&state, "bob")?.account_db()?.journal_after(0, 128)? {
        if event.topic == "contact.requested" {
            assert!(event.body.get("preview").is_none());
            assert!(event.body.get("note").is_none());
            assert!(event.body.get("safety_number").is_none());
        }
    }
    assert!(account(&state, "bob")?.account_db()?.contact_request(&source, "inbound")?.is_none());
    assert!(account(&state, "bob")?.account_db()?.client_record("identity", "alice")?.is_none());
    assert!(
        account(&state, "bob")?
            .account_db()?
            .load_actor_state::<Value>(&format!("identity/manifest-root/{source}"))?
            .is_none()
    );
    Ok(())
}
#[tokio::test]
async fn contact02_r2_exhausted_reply_items_cannot_roll_back_a_new_auto_accept_receipt()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 91)?;
    let mut b = Fixture::new("bob", 101)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let a_root = root(&state, "alice")?;
    let b_root = root(&state, "bob")?;
    let receiver = account(&state, "bob")?;
    receiver.set_contact_request_policy("auto_accept")?;
    let now = now_unix_timestamp();
    for i in 0_u8..128 {
        let id = ramflux_protocol::encode_base64url([i; 32]);
        let key = format!(
            "contact-request/send/{}",
            ramflux_protocol::hash_base64url(
                "ramflux.contact_request.delivery.v1",
                format!("{a_root}:{id}:Accept").as_bytes()
            )
        );
        receiver.account_db()?.persist_actor_state(&key,&json!({"kind":"accept","request_id":id,"requester_root":a_root,"target_root":b_root,"peer_root":a_root,"note":null,"expires_at":now+604_800,"issued_at":now,"nonce":ramflux_protocol::encode_base64url([i;32]),"attempts":8,"next_at":now+60,"delivered":[]}))?;
    }
    let entry = outbound(&mut state, &directory).await?;
    deliver(&mut state, "bob", &entry).await?;
    assert!(account(&state, "bob")?.friend_link_peer_is_accepted(&a_root)?);
    assert!(
        account(&state, "bob")?
            .account_db()?
            .list_actor_states::<Value>("contact-request/send/")?
            .len()
            <= 4
    );
    Ok(())
}
#[tokio::test]
async fn contact02_r2_readding_a_pending_request_retries_delivery() -> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 111)?;
    let mut b = Fixture::new("bob", 121)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let first = outbound(&mut state, &directory).await?;
    let target = root(&state, "bob")?;
    let source = root(&state, "alice")?;
    let row = account(&state, "alice")?
        .account_db()?
        .contact_request(&target, "outbound")?
        .ok_or_else(|| invalid("request"))?;
    let metadata: Value = serde_json::from_slice(&row.request_json)?;
    let key = format!(
        "contact-request/send/{}",
        ramflux_protocol::hash_base64url(
            "ramflux.contact_request.delivery.v1",
            format!("{target}:{}:Request", row.request_id).as_bytes()
        )
    );
    account(&state,"alice")?.account_db()?.persist_actor_state(&key,&json!({"kind":"request","request_id":row.request_id,"requester_root":source,"target_root":target,"peer_root":target,"note":metadata["note"],"expires_at":row.expires_at,"issued_at":metadata["issued_at"],"nonce":metadata["nonce"],"attempts":8,"next_at":now_unix_timestamp()+3600,"delivered":[]}))?;
    contact(&mut state, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    let entries = frames(&directory)?;
    assert_eq!(entries.len(), 1);
    assert_ne!(entries[0].envelope.envelope_id, first.envelope.envelope_id);
    Ok(())
}
#[tokio::test]
async fn contact02_r2_root_selector_cannot_match_an_attackers_request_id() -> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 131)?;
    let mut b = Fixture::new("bob", 141)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let victim = root(&state, "alice")?;
    let own = root(&state, "bob")?;
    let attacker = ramflux_protocol::encode_base64url([42; 32]);
    for (root, id, name) in
        [(&victim, "victim-request", "victim"), (&attacker, victim.as_str(), "attacker")]
    {
        account(&state,"bob")?.account_db()?.persist_contact_request(&ramflux_storage::ContactRequestRecord {contact_identity_commitment:root.clone(),direction:"inbound".into(),request_id:id.into(),principal_id:name.into(),link_id:format!("link-{name}"),state:"pending".into(),request_json:serde_json::to_vec(&json!({"note":null,"nonce":ramflux_protocol::encode_base64url([1;32]),"issued_at":now_unix_timestamp()}))?,expires_at:now_unix_timestamp()+604_800,updated_at:now_unix_timestamp()})?;
        account(&state, "bob")?.record_pending_friend_link(&format!("link-{name}"), root, &own)?;
    }
    let response =
        contact(&mut state, "bob", "contact.decline", json!({"root_commitment":victim})).await?;
    assert_eq!(response["principal_id"], "victim");
    assert_eq!(
        account(&state, "bob")?
            .account_db()?
            .contact_request(&attacker, "inbound")?
            .ok_or_else(|| invalid("attacker"))?
            .state,
        "pending"
    );
    Ok(())
}
#[tokio::test]
async fn contact02_r2_expiry_between_admission_and_projection_cannot_publish_content()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 151)?;
    let mut b = Fixture::new("bob", 161)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    message(&mut state, "expiry-race").await?;
    let entry = frames(&directory)?.into_iter().next().ok_or_else(|| invalid("message"))?;
    let client = account(&state, "bob")?;
    let mut opened = client.open_routed(&entry, "bob")?;
    opened.routing.message_id = client.projection_id(&entry, &opened.routing)?;
    client.contact_route_gate(&entry, &opened.routing, &opened.body)?;
    let source = root(&state, "alice")?;
    let row = client
        .account_db()?
        .contact_request(&source, "inbound")?
        .ok_or_else(|| invalid("request"))?;
    client.account_db()?.decide_contact_request(
        &source,
        "inbound",
        &row.request_id,
        "expired",
        now_unix_timestamp(),
    )?;
    assert!(
        client
            .project_accepted_contact_message(&opened.routing, &entry, &opened.body, None)
            .is_err()
    );
    assert_eq!(client.direct_messages("request-thread")?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn contact02_r2_budget_backpressure_keeps_gateway_ciphertext_and_redrives_without_blocking_dm()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 171)?;
    let mut b = Fixture::new("bob", 181)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = outbound(&mut state, &directory).await?;
    let source = root(&state, "alice")?;
    let target = root(&state, "bob")?;
    {
        let receiver = account(&state, "bob")?;
        let manifest = directory.records.lock().map_err(|_| invalid("directory"))?[0].clone();
        receiver.persist_identity_directory(&manifest)?;
        receiver.establish_friend_link("known-root", &source, &target)?;
        for _ in 0..120 {
            assert!(receiver.account_db()?.charge_contact_request(
                "bootstrap-attempts",
                120,
                3600,
                now_unix_timestamp()
            )?);
        }
    }
    message(&mut state, "ordinary-traffic-behind-backpressure").await?;
    let mut dm = frames(&directory)?.into_iter().next().ok_or_else(|| invalid("dm"))?;
    dm.inbox_seq = 2;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = vec![entry.clone(), dm];
    crate::bus::sync_driver::run(state.accounts.get_mut("bob").ok_or_else(|| invalid("bob"))?)
        .await?;
    assert_eq!(account(&state, "bob")?.direct_messages("request-thread")?.len(), 1);
    assert_eq!(
        directory.incoming.lock().map_err(|_| invalid("inbox"))?.len(),
        1,
        "quota refusal must not ACK/discard the contact control"
    );
    let db = account(&state, "bob")?.account_db()?;
    let key = account(&state, "bob")?.inbox_admission_key(&entry)?;
    assert!(
        !db.has_inbox_retry(&key)?,
        "30-second generic retries cannot wait out an hourly quota"
    );
    let mut pressure = db
        .load_actor_state::<Value>("contact-admission/backpressure")?
        .ok_or_else(|| invalid("backpressure metadata"))?;
    pressure["next_at"] = json!(now_unix_timestamp() - 1);
    db.persist_actor_state("contact-admission/backpressure", &pressure)?;
    assert!(db.charge_contact_request(
        "bootstrap-attempts",
        120,
        3600,
        now_unix_timestamp() + 3601
    )?);
    crate::bus::sync_driver::run(state.accounts.get_mut("bob").ok_or_else(|| invalid("bob"))?)
        .await?;
    assert_eq!(directory.incoming.lock().map_err(|_| invalid("inbox"))?.len(), 0);
    assert_eq!(
        account(&state, "bob")?
            .account_db()?
            .contact_request(&source, "inbound")?
            .ok_or_else(|| invalid("accepted request"))?
            .state,
        "accepted"
    );
    assert_eq!(account(&state, "bob")?.direct_messages("request-thread")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn contact02_r2_full_active_queue_defers_the_reply_without_rolling_back_consent()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 191)?;
    let mut b = Fixture::new("bob", 201)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let source = root(&state, "alice")?;
    let target = root(&state, "bob")?;
    let now = now_unix_timestamp();
    {
        let receiver = account(&state, "bob")?;
        receiver.set_contact_request_policy("auto_accept")?;
        for n in 0_u8..128 {
            let peer = ramflux_protocol::encode_base64url([n; 32]);
            let id = format!("queued-{n}");
            receiver.account_db()?.persist_contact_request(
                &ramflux_storage::ContactRequestRecord {
                    contact_identity_commitment: peer.clone(),
                    direction: "inbound".into(),
                    request_id: id.clone(),
                    principal_id: format!("peer-{n}"),
                    link_id: id.clone(),
                    state: "accepted".into(),
                    request_json: b"{}".to_vec(),
                    expires_at: now + 604_800,
                    updated_at: now,
                },
            )?;
            let key = format!(
                "contact-request/send/{}",
                ramflux_protocol::hash_base64url(
                    "ramflux.contact_request.delivery.v1",
                    format!("{peer}:{id}:Accept").as_bytes()
                )
            );
            receiver.account_db()?.persist_actor_state(&key,&json!({"kind":"accept","request_id":id,"requester_root":peer,"target_root":target,"peer_root":peer,"note":null,"expires_at":now+604_800,"issued_at":now,"nonce":"nonce","attempts":0,"next_at":now+3600,"delivered":[]}))?;
        }
    }
    let entry = outbound(&mut state, &directory).await?;
    deliver(&mut state, "bob", &entry).await?;
    let receiver = account(&state, "bob")?;
    assert!(receiver.friend_link_peer_is_accepted(&source)?);
    let db = receiver.account_db()?;
    let row = db.contact_request(&source, "inbound")?.ok_or_else(|| invalid("request"))?;
    assert_eq!(serde_json::from_slice::<Value>(&row.request_json)?["needs_reply"], "accept");
    assert!(db.actor_state_exists(&receiver.authenticated_committed_key(&entry)?)?);
    let peer = ramflux_protocol::encode_base64url([0; 32]);
    let key = format!(
        "contact-request/send/{}",
        ramflux_protocol::hash_base64url(
            "ramflux.contact_request.delivery.v1",
            format!("{peer}:queued-0:Accept").as_bytes()
        )
    );
    db.remove_actor_state(&key)?;
    flush(&mut state, "bob").await?;
    let row = account(&state, "bob")?
        .account_db()?
        .contact_request(&source, "inbound")?
        .ok_or_else(|| invalid("request"))?;
    assert!(serde_json::from_slice::<Value>(&row.request_json)?.get("needs_reply").is_none());
    assert_eq!(
        account(&state, "bob")?
            .account_db()?
            .list_actor_states::<Value>("contact-request/send/")?
            .len(),
        127
    );
    assert_eq!(frames(&directory)?.len(), 1, "deferred acceptance was submitted");
    Ok(())
}

#[tokio::test]
async fn contact02_r2_retired_authority_floors_are_bounded_and_reject_rollback()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 211)?;
    let mut b = Fixture::new("bob", 221)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    let receiver = account(&state, "bob")?;
    let source = root(&state, "alice")?;
    let mut set = receiver.observed_device_set(&source)?.ok_or_else(|| invalid("authority"))?;
    let now = now_unix_timestamp();
    let db = receiver.account_db()?;
    assert!(db.retain_contact_request_authority_floor(
        &source,
        set.device_set_epoch + 1,
        "newer-record",
        now + 604_800,
        now
    )?);
    assert!(receiver.check_observed_set(&set).is_err());
    set.device_set_epoch += 1;
    assert!(receiver.check_observed_set(&set).is_err(), "same-epoch fork must also fail");
    db.write_transaction(|| -> Result<(), SdkError> {
        for n in 0..4095 {
            assert!(db.retain_contact_request_authority_floor(
                &format!("floor-{n}"),
                1,
                "hash",
                now + 60,
                now
            )?);
        }
        assert!(!db.retain_contact_request_authority_floor(
            "overflow",
            1,
            "hash",
            now + 60,
            now
        )?);
        Ok(())
    })?;
    assert!(db.retain_contact_request_authority_floor(
        "overflow",
        1,
        "hash",
        now + 120,
        now + 61
    )?);
    Ok(())
}

#[tokio::test]
async fn contact02_r2_held_surface_expiry_starts_at_release_and_creates_its_thread()
-> Result<(), SdkError> {
    use crate::client::surface::{Carrier, PayloadKind, SnapshotProof};
    use ramflux_protocol::{
        A2uiConversationCommand as C, A2uiConversationEvent as E, CreateSurfaceCommand,
        StreamAppendCommand, SurfaceState, SurfaceType,
    };
    let mut a = Fixture::new("alice", 231)?;
    let mut b = Fixture::new("bob", 241)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    let create = C::CreateSurface(CreateSurfaceCommand {
        surface_id: "held".into(),
        surface_type: SurfaceType::StatusPanel,
        catalog: "basic".into(),
        catalog_version: "1".into(),
        fallback_text: "Working".into(),
        fallback_markdown: None,
        components: vec![json!({"id":"stream","text":""})],
        data_model: serde_json::Map::default(),
        allowed_actions: vec![],
    });
    let create = ramflux_protocol::encode_a2ui_conversation_event("request-thread", 1, &create)?;
    let append = ramflux_protocol::encode_a2ui_conversation_event(
        "request-thread",
        2,
        &C::StreamAppend(StreamAppendCommand {
            surface_id: "held".into(),
            component_id: "stream".into(),
            text_delta: "hello".into(),
            final_: false,
        }),
    )?;
    let expected = SurfaceState::default()
        .apply(&E::from_wire_bytes(&create)?)
        .map_err(|_| invalid("create"))?
        .apply(&E::from_wire_bytes(&append)?)
        .map_err(|_| invalid("append"))?;
    let carrier = account(&state, "alice")?.sign_surface_carrier(Carrier {
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        posted_at: None,
        updated_at: None,
        payload_kind: PayloadKind::Event,
        conversation_id: "request-thread".into(),
        surface_id: "held".into(),
        message_id: "held-v2".into(),
        sender_principal_id: "alice".into(),
        sender_device_id: "alice".into(),
        author_principal_id: "alice".into(),
        wire_base64: ramflux_protocol::encode_base64url(append),
        signature: String::new(),
        snapshot: Some(SnapshotProof {
            wire_base64: String::new(),
            checkpoint_base64: String::new(),
            surface_hash: expected.hash().map(str::to_owned),
            metadata: None,
            author_device_id: "alice".into(),
        }),
    })?;
    let request = request(
        "alice",
        "message.submit",
        json!({"conversation_id":"request-thread","message_id":"held-surface","envelope_id":"held-surface","source_principal_id":"alice","sender_id":"alice","recipient_device_id":"bob","target_delivery_id":"bob","encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(carrier.bytes()?),"created_at":now_unix_timestamp()-120,"ttl":3600}),
    );
    let (outbound, _) = tokio::sync::mpsc::channel(8);
    let connection = crate::bus::state::LocalBusConnectionState::new(1, outbound);
    crate::bus::dispatch::message::dispatch_message_bus_request(&request, &mut state, &connection)
        .await?;
    let entry = frames(&directory)?.into_iter().next().ok_or_else(|| invalid("surface"))?;
    deliver(&mut state, "bob", &entry).await?;
    let source = root(&state, "alice")?;
    let at = now_unix_timestamp();
    contact(&mut state, "bob", "contact.accept", json!({"root_commitment":source})).await?;
    let receiver = account(&state, "bob")?;
    let pending = receiver.account_db()?.list_actor_states::<Value>("surface/pending/")?;
    assert_eq!(pending.len(), 1, "future surface is held for its missing create");
    assert!(pending[0]["wire_expires_at"].as_i64().is_some_and(|expiry| expiry >= at + 3600));
    assert!(receiver.account_db()?.client_record("conversation", "request-thread")?.is_some());
    assert_eq!(receiver.direct_messages("request-thread")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn contact02_r2_requester_cache_cannot_supply_the_pin_for_legacy_name_consent()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 23)?;
    let mut b = Fixture::new("bob", 33)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    account(&state, "bob")?.account_db()?.establish_friend_link("legacy-name", "bob", "alice")?;
    pending(&mut state, &directory).await?;
    message(&mut state, "requires-root-consent").await?;
    let entry = frames(&directory)?.into_iter().next().ok_or_else(|| invalid("message"))?;
    assert!(deliver(&mut state, "bob", &entry).await?.plaintext.is_none());
    let receiver = account(&state, "bob")?;
    assert_eq!(receiver.direct_messages("request-thread")?.len(), 0);
    assert!(receiver.pending_contact_root(&root(&state, "alice")?)?);
    assert_eq!(receiver.account_db()?.contact_message_count(&root(&state, "alice")?)?, 1);
    Ok(())
}
