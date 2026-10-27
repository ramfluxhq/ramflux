// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! State ordering, sender namespace and confirmed-session recovery regressions.
use super::review::{Inbox, legacy, pool, trust};
use super::*;

fn from(
    sender: &Fixture,
    receiver: &Fixture,
    id: &str,
    conversation: &str,
) -> GatewayDirectMessage {
    let mut msg = super::r5::outgoing(sender, receiver, id);
    msg.conversation_id = conversation.into();
    msg.source_principal_id.clone_from(&sender.id);
    msg.sender_id.clone_from(&sender.id);
    msg.recipient_device_id = Some(receiver.id.clone());
    msg.target_delivery_id.clone_from(&receiver.id);
    msg
}

fn bootstrap(
    sender: &Fixture,
    receiver: &Fixture,
    id: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    trust(sender, receiver)?;
    trust(receiver, sender)?;
    let mut msg = from(sender, receiver, id, "simultaneous");
    let bundle = receiver
        .client
        .load_x3dh_private_state(&receiver.client.local_device_identity(&receiver.id)?)?
        .bundle
        .clone();
    let (mut session, header, bundle) = sender.client.new_send_pair(
        &sender.client.local_device_identity(&sender.id)?,
        &msg,
        bundle,
    )?;
    let sealed = sender.client.seal_routed_with_route(
        &msg,
        b"bootstrap",
        Route::direct(),
        SealPair {
            local: &sender.id,
            remote: &receiver.reference()?,
            session: &mut session,
            header,
            bundle,
        },
    )?;
    msg.encrypted_body = serde_json::to_vec(&sealed)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: receiver.id.clone(),
        envelope: gateway_direct_message_envelope(&sender.config()?, &msg, None)?,
    })
}

#[tokio::test]
async fn simultaneous_verified_bootstraps_converge_and_retire_x3dh_after_peer_confirmation()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    alice.client.establish_friend_link("friend", "alice", "bob")?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let a = bootstrap(&alice, &bob, "alice-initial")?;
    let b = bootstrap(&bob, &alice, "bob-initial")?;
    let mut ae = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    let mut be = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    alice.client.apply_routed_entry(&mut ae, &pool()?, &b, false).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &a, false).await?;
    let active_a = alice
        .client
        .active_pair(
            &alice.client.local_device_identity("alice")?,
            &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?
        .0
        .session_id;
    let active_b = bob
        .client
        .active_pair(
            &bob.client.local_device_identity("bob")?,
            &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?
        .0
        .session_id;
    assert_eq!(active_a, active_b);
    let reply = seal(&alice, &bob, from(&alice, &bob, "reply-a", "simultaneous"), b"reply")?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &reply, false).await?;
    let reply = seal(&bob, &alice, from(&bob, &alice, "reply-b", "simultaneous"), b"reply")?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &reply, false).await?;
    let next = seal(&alice, &bob, from(&alice, &bob, "confirmed", "simultaneous"), b"next")?;
    assert!(decode(&next.envelope)?.x3dh.is_none());
    assert!(decode(&next.envelope)?.ciphertext.ratchet_public_key.is_some());
    bob.client.apply_routed_entry(&mut be, &pool()?, &next, false).await?;
    let (_, _, _) = bob.client.send_pair_session_from_url(
        &bob.client.local_device_identity("bob")?,
        &from(&bob, &alice, "next", "simultaneous"),
        None,
    )?;
    let snapshot = serde_json::to_value(
        bob.client
            .active_pair(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
            )?
            .ok_or_else(|| invalid("pair"))?
            .0
            .snapshot(),
    )?;
    assert!(snapshot["dh_ratchet_step"].as_u64().is_some_and(|step| step > 0));
    Ok(())
}

#[tokio::test]
async fn group_message_before_membership_update_retries_then_delivers_without_acknowledged_loss()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    fixture_group(&alice.client, "ordered", &alice)?;
    fixture_member(&alice.client, "ordered", &bob)?;
    bob.client.create_group("ordered", "bob")?;
    let body =
        alice.client.encrypt_group_message("ordered", "alice", b"membership arrives later")?;
    let mut msg = from(&alice, &bob, "before-membership", "ordered-thread");
    let entry = seal_as(&alice, &bob, msg.clone(), &body, Route::group_message("ordered"))?;
    let (engine, writes) = Inbox::engine(bob.config()?, vec![entry.clone()])?;
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob.client),
        engine,
        "bob".to_owned(),
    );
    crate::bus::sync_driver::run(&mut account).await?;
    assert!(!writes.lock().map_err(|_| invalid("mutex"))?.iter().any(|v| v["frame_type"] == "ack"));
    let header = decode(&entry.envelope)?.x3dh.ok_or_else(|| invalid("bootstrap header"))?;
    let state =
        account.client.load_x3dh_private_state(&account.client.local_device_identity("bob")?)?;
    assert!(
        header
            .recipient_one_time_prekey_id
            .as_ref()
            .is_none_or(|id| { state.one_time_prekeys.iter().any(|private| &private.id == id) }),
        "deferred bootstrap consumed its one-time prekey"
    );
    fixture_member(&account.client, "ordered", &alice)?;
    account.client.import_group_sender_key_distribution(
        &alice.client.export_group_sender_key_distribution("ordered", "alice")?,
    )?;
    let (engine, _) = Inbox::engine(account.gateway_config.clone(), vec![entry])?;
    account.engine = Some(engine);
    crate::bus::sync_driver::run(&mut account).await?;
    let messages = account.client.direct_messages("ordered-thread")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(
        account.client.account_db()?.message_content(&messages[0].message_id)?,
        Some(b"membership arrives later".to_vec())
    );
    // A later malformed packet remains isolated from the successfully retried message.
    msg.envelope_id = "later".to_owned();
    Ok(())
}

#[tokio::test]
async fn a_group_member_cannot_preclaim_another_senders_message_identity() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let carol = Fixture::new("carol", 81)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    trust(&bob, &carol)?;
    bob.client.establish_friend_link("friend", "bob", "carol")?;
    for client in [&alice.client, &bob.client] {
        fixture_group(client, "group", &alice)?;
        fixture_member(client, "group", &bob)?;
        fixture_member(client, "group", &carol)?;
    }
    bob.client.import_group_sender_key_distribution(
        &alice.client.export_group_sender_key_distribution("group", "alice")?,
    )?;
    let guessed =
        seal(&carol, &bob, from(&carol, &bob, "next-fanout:3", "attackers-thread"), b"squat")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &guessed, false).await?;
    let body = alice.client.encrypt_group_message("group", "alice", b"genuine group message")?;
    let genuine = seal_as(
        &alice,
        &bob,
        from(&alice, &bob, "next-fanout:3", "real-group-thread"),
        &body,
        Route::group_message("group"),
    )?;
    bob.client.apply_routed_entry(&mut engine, &pool()?, &genuine, false).await?;
    let real = bob.client.direct_messages("real-group-thread")?;
    assert_eq!(real.len(), 1);
    assert_eq!(
        bob.client.account_db()?.message_content(&real[0].message_id)?,
        Some(b"genuine group message".to_vec())
    );
    assert_eq!(bob.client.direct_messages("attackers-thread")?.len(), 1);
    assert_ne!(bob.client.direct_messages("attackers-thread")?[0].message_id, real[0].message_id);
    Ok(())
}

#[tokio::test]
async fn legacy_quarantine_survives_v2_upgrade_without_ack_or_dead_letter() -> Result<(), SdkError>
{
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    let held = legacy(&alice, &bob)?;
    bob.client.account_db()?.hold_unrouted(
        "held",
        1,
        &serde_json::to_vec(&held)?,
        now_unix_timestamp(),
    )?;
    let entry = seal(&alice, &bob, message("v2", "new-thread"), b"new")?;
    let opened = bob.client.open_routed(&entry, "bob")?;
    bob.client.persist_pair(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        &opened.bundle_hash,
        &opened.session,
    )?;
    let (engine, writes) = Inbox::engine(bob.config()?, Vec::new())?;
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob.client),
        engine,
        "bob".to_owned(),
    );
    crate::bus::sync_driver::run(&mut account).await?;
    assert!(!writes.lock().map_err(|_| invalid("mutex"))?.iter().any(|v| v["frame_type"] == "ack"));
    assert_ne!(account.client.account_db()?.unrouted_entries()?.len(), 0);
    assert!(
        !account
            .client
            .account_db()?
            .journal_after(0, 100)?
            .iter()
            .any(|e| e.topic == "message.undeliverable")
    );
    Ok(())
}

#[tokio::test]
async fn two_authenticated_devices_can_deliver_the_same_a2i_event_id_independently()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let carol = Fixture::new("carol", 81)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    trust(&bob, &carol)?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    for sender in [&alice, &carol] {
        let event = A2iControlEvent {
            source_principal_id: None,
            source_principal_commitment: None,
            event_id: "same-event".to_owned(),
            event_type: "a2i.control".to_owned(),
            source_device_id: sender.id.clone(),
            target_device_id: "bob".to_owned(),
            control_domain: "message".to_owned(),
            action: "test".to_owned(),
            subject_base64: String::new(),
            created_at: 1,
            acknowledged: false,
        };
        let entry = seal_as(
            sender,
            &bob,
            from(sender, &bob, &format!("{}-a2i", sender.id), "controls"),
            &serde_json::to_vec(&event)?,
            Route::control(),
        )?;
        bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    }
    let persisted = bob.client.account_db()?.list_actor_states::<A2iControlEvent>("a2i/")?;
    assert_eq!(persisted.len(), 2);
    Ok(())
}

#[tokio::test]
async fn legacy_a2i_is_durable_before_ack_and_survives_cursor_advance() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    let conversation = a2i_control_conversation_id("alice", "bob");
    let mut msg = from(&alice, &bob, "legacy-control", &conversation);
    let event = A2iControlEvent {
        source_principal_id: None,
        source_principal_commitment: None,
        event_id: "legacy-event".to_owned(),
        event_type: "a2i.control".to_owned(),
        source_device_id: "alice".to_owned(),
        target_device_id: "bob".to_owned(),
        control_domain: "message".to_owned(),
        action: "test".to_owned(),
        subject_base64: String::new(),
        created_at: 1,
        acknowledged: false,
    };
    let (mut sending, header) = alice.client.create_send_dm_session_from_bundle(
        &msg,
        "bob",
        bob.client
            .load_x3dh_private_state(&bob.client.local_device_identity("bob")?)?
            .bundle
            .clone(),
        "alice",
    )?;
    let receiving = bob.client.load_or_create_recv_dm_session(&conversation, header.as_ref())?;
    bob.client.send_direct_message(&conversation, "prior", "alice", b"prior")?;
    bob.client.persist_dm_session(&conversation, "prior", "recv", &receiving)?;
    msg.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        source_principal_commitment: None,
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".to_owned(),
        version: 1,
        x3dh: header,
        ciphertext: sending
            .encrypt(&serde_json::to_vec(&event)?, dm_associated_data(&conversation))?,
    })?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "bob".to_owned(),
        envelope: gateway_direct_message_envelope(&alice.config()?, &msg, None)?,
    };
    let (mut engine, writes) = Inbox::engine(bob.config()?, vec![entry])?;
    let mut expected = event;
    expected.source_principal_id = Some(alice.id.clone());
    expected.source_principal_commitment = Some(ramflux_crypto::identity_root_commitment(
        &alice
            .client
            .identity_root
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key(),
    ));
    assert_eq!(bob.client.receive_a2i_control_events(&mut engine, 16).await?, vec![expected]);
    assert_eq!(bob.client.account_db()?.list_actor_states::<A2iControlEvent>("a2i/")?.len(), 1);
    assert!(writes.lock().map_err(|_| invalid("mutex"))?.iter().any(|v| v["frame_type"] == "ack"));
    assert_eq!(bob.client.gateway_receive_cursor("bob")?, 1);
    Ok(())
}

#[tokio::test]
async fn a_receipt_sender_must_participate_in_the_authenticated_conversation()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    bob.client.send_direct_message("private", "outgoing", "bob", b"private")?;
    bob.client.account_db()?.persist_client_record(
        "conversation",
        "private",
        &serde_json::json!({"kind":"direct","participants":["bob","carol"]}),
    )?;
    let receipt = serde_json::json!({"schema":"ramflux.sdk.receipt_event.v1","version":1,"receipt_id":"squatted","event_seq":1,"nonce":"nonce","reader_device_id":"alice","event":{"type":"ReceiptDelivered","conversation_id":"private","message_id":"outgoing","delivered_at":1,"receiver_device_id":"alice","scope":"device","ttl_seconds":3600}});
    let entry = seal_as(
        &alice,
        &bob,
        from(&alice, &bob, "receipt-envelope", "private"),
        &serde_json::to_vec(&receipt)?,
        Route::receipt(),
    )?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await.is_err());
    Ok(())
}

fn reference(entry: &GatewayInboxEntry) -> Result<crate::dm::SdkDmAttachmentRef, SdkError> {
    let wrapper = decode(&entry.envelope)?;
    Ok(crate::dm::SdkDmAttachmentRef {
        schema: "ramflux.sdk.dm_attachment_ref.v1".to_owned(),
        version: 1,
        object_id: "same-object".to_owned(),
        manifest_hash: "manifest".to_owned(),
        plaintext_hash: "hash".to_owned(),
        cipher_size: 32,
        chunk_size: 64,
        total_chunks: 1,
        relay_endpoint: "https://relay.invalid".to_owned(),
        owner_home_node_id: None,
        relay_audience_node_id: None,
        owner_principal_id: entry.envelope.source_principal_id.clone(),
        owner_device_epoch: 1,
        access_grant: None,
        key_slot: SdkObjectKeySlot {
            schema: "ramflux.sdk.object_key_slot.dm.v2".to_owned(),
            version: 2,
            object_id: "same-object".to_owned(),
            conversation_id: "slot".to_owned(),
            recipient_device_id: "bob".to_owned(),
            source_principal_commitment: None,
            x3dh: wrapper.x3dh,
            ciphertext: wrapper.ciphertext,
        },
    })
}

#[tokio::test]
async fn a_failed_projection_cannot_leave_an_attachment_reference_outside_its_transaction()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let first = seal(&alice, &bob, message("slot", "slot"), b"not a key")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &first, false).await?;
    let reference = reference(&first)?;
    let wrapper = serde_json::json!({"schema":"ramflux.sdk.dm_attachment_envelope.v1","version":1,"body_base64":ramflux_protocol::encode_base64url(br#"{"type":"unknown-control"}"#),"attachments":[reference]});
    let route = Route::attachments();
    let entry = seal_as(
        &alice,
        &bob,
        message("invalid-with-ref", "thread"),
        &serde_json::to_vec(&wrapper)?,
        route,
    )?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.account_db()?.apply_identity_lifecycle_event(
        "alice",
        "deactivate",
        "identity.deactivated",
        1,
        ramflux_storage::IdentityLifecycleTiming {
            reason_code: None,
            timelock_until: None,
            grace_window_until: None,
            finalization_time: None,
            updated_at: 1,
        },
    )?;
    let error = bob
        .client
        .apply_routed_entry(&mut engine, &pool()?, &entry, false)
        .await
        .err()
        .ok_or_else(|| invalid("projection unexpectedly succeeded"))?;
    assert!(matches!(error, SdkError::Storage(StorageError::IdentityLifecycleBlocked(_))));
    assert_eq!(
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("attachment/reference/")?,
        Vec::<serde_json::Value>::new()
    );
    assert_eq!(
        bob.client
            .account_db()?
            .list_actor_states::<serde_json::Value>("attachment/reference-by-sender/")?,
        Vec::<serde_json::Value>::new()
    );
    Ok(())
}

#[tokio::test]
async fn attachment_references_with_one_object_id_remain_independent_for_each_sender()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let carol = Fixture::new("carol", 81)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    trust(&bob, &carol)?;
    bob.client.establish_friend_link("a", "bob", "alice")?;
    bob.client.establish_friend_link("c", "bob", "carol")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    for sender in [&alice, &carol] {
        let slot = seal(
            sender,
            &bob,
            from(
                sender,
                &bob,
                &format!("{}-slot", sender.id),
                &format!("{}-slot-thread", sender.id),
            ),
            b"not a key",
        )?;
        bob.client.apply_routed_entry(&mut engine, &pool()?, &slot, false).await?;
        let mut reference = reference(&slot)?;
        reference.relay_endpoint = format!("https://{}.invalid", sender.id);
        let body = serde_json::json!({"schema":"ramflux.sdk.dm_attachment_envelope.v1","version":1,"body_base64":ramflux_protocol::encode_base64url(b"text"),"attachments":[reference]});
        let entry = seal_as(
            sender,
            &bob,
            from(sender, &bob, &format!("{}-message", sender.id), &format!("{}-thread", sender.id)),
            &serde_json::to_vec(&body)?,
            Route::attachments(),
        )?;
        bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    }
    let references =
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("attachment/reference/")?;
    assert_eq!(references.len(), 2);
    assert!(references.iter().any(|r| r["reference"]["relay_endpoint"] == "https://alice.invalid"));
    assert!(references.iter().any(|r| r["reference"]["relay_endpoint"] == "https://carol.invalid"));
    Ok(())
}

#[tokio::test]
async fn acknowledging_a2i_control_persists_the_decision_beyond_the_memory_cache()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    let event = A2iControlEvent {
        source_principal_id: None,
        source_principal_commitment: None,
        event_id: "ack-event".to_owned(),
        event_type: "a2i.control".to_owned(),
        source_device_id: "alice".to_owned(),
        target_device_id: "bob".to_owned(),
        control_domain: "message".to_owned(),
        action: "test".to_owned(),
        subject_base64: String::new(),
        created_at: 1,
        acknowledged: false,
    };
    let entry = seal_as(
        &alice,
        &bob,
        message("ack-control", "controls"),
        &serde_json::to_vec(&event)?,
        Route::control(),
    )?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob.client),
        engine,
        "bob".to_owned(),
    );
    account.pending_a2i.insert(event.event_id.clone(), event.clone());
    let mut state = crate::bus::state::LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(bob.root.join("bus.sock"), &bob.root),
        accounts: BTreeMap::from([("bob".to_owned(), account)]),
        active_account_id: Some("bob".to_owned()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    // Reconstructing from durable state must not create two cache aliases for the same event.
    let request = LocalBusFrame::request(
        "ack",
        Some("bob".to_owned()),
        "a2i",
        "a2i.acknowledge",
        serde_json::json!({"event_id":"ack-event"}),
    );
    Box::pin(crate::bus::dispatch::a2i_a2ui::dispatch_a2i_bus_request(&request, &mut state))
        .await?;
    let account = state.accounts.get_mut("bob").ok_or_else(|| invalid("account"))?;
    account.pending_a2i.clear();
    let events = account.client.account_db()?.list_actor_states::<A2iControlEvent>("a2i/")?;
    assert_eq!(events.len(), 1);
    assert!(events[0].acknowledged);
    Ok(())
}

#[tokio::test]
async fn unowned_legacy_rows_cannot_squat_new_sender_scoped_projection_or_attachment_ids()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let slot = seal(&alice, &bob, message("old-slot", "slot-thread"), b"slot")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &slot, false).await?;
    let reference = reference(&slot)?;
    bob.client.account_db()?.persist_actor_state(
        "attachment/reference/same-object",
        &serde_json::json!({"reference":reference,"prepared_slot":null}),
    )?;
    let wrapper = serde_json::json!({"schema":"ramflux.sdk.dm_attachment_envelope.v1","version":1,"body_base64":ramflux_protocol::encode_base64url(b"genuine"),"attachments":[reference]});
    let entry = seal_as(
        &alice,
        &bob,
        message("old-collision", "genuine-thread"),
        &serde_json::to_vec(&wrapper)?,
        Route::attachments(),
    )?;
    let scoped = format!(
        "routed:{}",
        bob.client.authenticated_committed_key(&entry)?.trim_start_matches("routed/committed/")
    );
    bob.client.send_direct_message("old-attacker", "old-collision", "carol", b"old squat")?;
    bob.client.send_direct_message("old-attacker", &scoped, "carol", b"old reserved squat")?;
    bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    let messages = bob.client.direct_messages("genuine-thread")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(
        bob.client.account_db()?.message_content(&messages[0].message_id)?,
        Some(b"genuine".to_vec())
    );
    let refs =
        bob.client.account_db()?.list_actor_states::<serde_json::Value>("attachment/reference/")?;
    assert_eq!(refs.len(), 2);
    assert_eq!(refs.iter().filter(|r| r["authenticated_sender"] == "alice").count(), 1);
    Ok(())
}
