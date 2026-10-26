// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adversarial device authentication, attribution, routing and ratchet ownership regressions.
use super::*;

pub(super) fn trust(receiver: &Fixture, sender: &Fixture) -> Result<(), SdkError> {
    let mut manifest = crate::client::identity_authority::test_support::manifest(&sender.client)?;
    if let Some(target) = receiver
        .client
        .account_db()?
        .client_record("device", &sender.id)?
        .and_then(|v| v["target_delivery_id"].as_str().map(str::to_owned))
    {
        manifest.devices[0].target_delivery_id = target;
    }
    if receiver.client.identity_root.as_ref().is_some_and(|r| {
        ramflux_crypto::identity_root_commitment(&r.signing_key.verifying_key())
            == manifest.principal_commitment
    }) && receiver.id != sender.id
    {
        manifest.devices.extend(
            crate::client::identity_authority::test_support::manifest(&receiver.client)?.devices,
        );
        crate::client::identity_authority::test_support::sign_manifest(
            sender.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &mut manifest,
            1,
        )?;
    }
    if let Some(alias) =
        receiver.client.account_db()?.client_record("identity", &manifest.principal_id)?.and_then(
            |v| {
                v["devices"]
                    .as_array()
                    .and_then(|d| d.iter().find(|d| d["device_id"] == sender.id))
                    .and_then(|d| d["target_delivery_id"].as_str())
                    .map(str::to_owned)
            },
        )
        && let Some(device) = manifest.devices.iter_mut().find(|d| d.device_id == sender.id)
    {
        device.target_delivery_id = alias;
    }
    receiver.client.persist_identity_directory(&manifest)?;
    Ok(())
}
pub(super) fn pool() -> Result<ramflux_transport::RelayQuicPool, SdkError> {
    Ok(ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()
            .map_err(|e| invalid(&e.to_string()))?,
    ))
}
pub(super) fn legacy(sender: &Fixture, receiver: &Fixture) -> Result<GatewayInboxEntry, SdkError> {
    let mut msg = message("legacy-unbound", "thread");
    let bundle = receiver
        .client
        .load_x3dh_private_state(&receiver.client.local_device_identity(&receiver.id)?)?
        .bundle;
    let (mut session, header) =
        sender.client.create_send_dm_session_from_bundle(&msg, &receiver.id, bundle, &sender.id)?;
    let ciphertext = session.encrypt(b"old message", dm_associated_data("thread"))?;
    msg.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        source_principal_commitment: None,
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".to_owned(),
        version: 1,
        x3dh: header,
        ciphertext,
    })?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: receiver.id.clone(),
        envelope: gateway_direct_message_envelope(&sender.config()?, &msg, None)?,
    })
}

#[test]
fn unverified_initiator_cannot_replace_a_known_devices_pair_session() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 10)?;
    let impostor = Fixture::new("alice", 20)?;
    let bob = Fixture::new("bob", 30)?;
    trust(&bob, &alice)?;
    let staging = Fixture::new("bob", 30)?;
    let mut forged = seal(&impostor, &staging, message("forged-bootstrap", "thread"), b"attack")?;
    forged.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        alice.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &forged.envelope,
    )?;
    assert!(bob.client.open_routed(&forged, "bob").is_err());
    Ok(())
}

#[tokio::test]
async fn a_friend_cannot_inject_into_another_principals_direct_thread() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 40)?;
    let mut bob = Fixture::new("bob", 50)?;
    trust(&bob, &alice)?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    bob.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &serde_json::json!({"kind":"direct","participants":["bob","carol"]}),
    )?;
    let entry = seal(&alice, &bob, message("injection", "thread"), b"injected")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await.is_err());
    assert_eq!(bob.client.direct_messages("thread")?.len(), 0);
    Ok(())
}

#[test]
fn json_text_in_a_direct_message_cannot_select_a_control_route() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 60)?;
    let bob = Fixture::new("bob", 70)?;
    trust(&bob, &alice)?;
    let text = br#"{"schema":"ramflux.sdk.group_sender_key.message.v1","group_id":"victim"}"#;
    let entry = seal(&alice, &bob, message("json-text", "thread"), text)?;
    let opened = bob.client.open_routed(&entry, "bob")?;
    assert_eq!(opened.routing.kind, Kind::Direct);
    assert_eq!(opened.body.as_slice(), text);
    Ok(())
}

#[tokio::test]
async fn an_unbound_legacy_entry_cannot_be_released_by_a_callers_thread_id() -> Result<(), SdkError>
{
    let alice = Fixture::new("alice", 80)?;
    let mut bob = Fixture::new("bob", 90)?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let entry = legacy(&alice, &bob)?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    assert!(
        bob.client
            .receive_legacy_entry(
                &mut engine,
                &pool()?,
                entry,
                crate::client::dm::LegacyReceive {
                    conversation_id: "thread",
                    auto_fetch_attachments: false,
                    relay_service_key_base64: None
                }
            )
            .await
            .is_err()
    );
    assert_eq!(bob.client.direct_messages("thread")?.len(), 0);
    Ok(())
}

#[test]
fn pair_encryption_does_not_fork_a_legacy_conversation_ratchet() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 100)?;
    let bob = Fixture::new("bob", 110)?;
    seal(&alice, &bob, message("pair-only", "thread"), b"text")?;
    assert!(alice.client.load_dm_session("thread", "send").is_err());
    Ok(())
}

#[tokio::test]
async fn a_duplicate_cannot_replace_the_original_authenticated_attribution() -> Result<(), SdkError>
{
    let alice = Fixture::new("alice", 120)?;
    let mut bob = Fixture::new("bob", 130)?;
    trust(&bob, &alice)?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let entry = seal(&alice, &bob, message("duplicate", "thread"), b"text")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    let carol = Fixture::new("carol", 141)?;
    trust(&bob, &carol)?;
    let mut msg = message("duplicate", "carol-thread");
    msg.source_principal_id = "carol".to_owned();
    msg.sender_id = "carol".to_owned();
    let collision = seal(&carol, &bob, msg, b"replace Alice's text")?;
    if let Ok(delivery) =
        bob.client.apply_routed_entry(&mut engine, &pool()?, &collision, false).await
    {
        assert_eq!(
            delivery
                .plaintext
                .ok_or_else(|| invalid("missing independently scoped content"))?
                .sender_id,
            "carol"
        );
    }
    let mut forged = entry.clone();
    forged.envelope.source_principal_id = "carol".to_owned();
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &forged, false).await.is_err());
    let original = bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    assert_eq!(
        original.plaintext.ok_or_else(|| invalid("missing original content"))?.sender_id,
        "alice"
    );
    assert_eq!(
        bob.client.account_db()?.message_content("duplicate")?.as_deref(),
        Some(b"text".as_slice())
    );
    Ok(())
}

#[tokio::test]
async fn group_delivery_preserves_existing_titles_and_all_conversation_links()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 140)?;
    let mut bob = Fixture::new("bob", 150)?;
    trust(&bob, &alice)?;
    for client in [&alice.client, &bob.client] {
        fixture_group(client, "group", &alice)?;
        fixture_member(client, "group", &bob)?;
    }
    bob.client.account_db()?.persist_client_record("group","group",&serde_json::json!({"conversation_id":null,"conversation_ids":["thread","other"],"custom":"keep"}))?;
    bob.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &serde_json::json!({"kind":"group","group_id":"group","title":"Existing title"}),
    )?;
    let body = alice.client.encrypt_group_message("group", "alice", b"text")?;
    let entry = seal_group(&alice, &bob, message("group-message", "thread"), &body)?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    let db = bob.client.account_db()?;
    let group = db.client_record("group", "group")?.ok_or_else(|| invalid("group missing"))?;
    assert_eq!(group["conversation_ids"].as_array().map(Vec::len), Some(2));
    assert_eq!(group["custom"], "keep");
    assert_eq!(
        db.client_record("conversation", "thread")?.ok_or_else(|| invalid("thread missing"))?["title"],
        "Existing title"
    );
    Ok(())
}

#[test]
fn a_v2_device_pair_rejects_a_bound_legacy_downgrade() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 160)?;
    let bob = Fixture::new("bob", 170)?;
    trust(&bob, &alice)?;
    let old = legacy(&alice, &bob)?;
    let wrapped: SdkDmEncryptedEnvelope = serde_json::from_slice(
        &ramflux_protocol::decode_base64url(&old.envelope.encrypted_payload)
            .map_err(|_| invalid("payload"))?,
    )?;
    let recv = bob.client.load_or_create_recv_dm_session("thread", wrapped.x3dh.as_ref())?;
    bob.client.send_direct_message("thread", "history", "alice", b"history")?;
    bob.client.persist_dm_session("thread", "history", "recv", &recv)?;
    assert_eq!(bob.client.legacy_routing_binding("bob", &old)?, Some("thread".to_owned()));
    let entry = seal(&alice, &bob, message("v2", "thread"), b"v2")?;
    let opened = bob.client.open_routed(&entry, "bob")?;
    bob.client.persist_pair(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        &opened.bundle_hash,
        &opened.session,
    )?;
    assert_eq!(bob.client.legacy_routing_binding("bob", &old)?, None);
    Ok(())
}

#[test]
fn decrypted_payload_debug_output_never_discloses_plaintext_or_franking_keys() {
    let output = ramflux_crypto::DmDecryptionOutput {
        plaintext: b"PRIVATE_PLAINTEXT".to_vec(),
        opening_key: [45; 32],
        commitment_key: [99; 32],
    };
    let debug = format!("{output:?}");
    assert!(!debug.contains("45"));
    assert!(!debug.contains("99"));
    assert!(!debug.contains("80"));
}

#[test]
fn a_valid_device_cannot_claim_another_principal_before_friend_checks() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 180)?;
    let bob = Fixture::new("bob", 190)?;
    trust(&bob, &alice)?;
    let mut msg = message("principal-spoof", "thread");
    msg.source_principal_id = "carol".to_owned();
    let entry = seal(&alice, &bob, msg, b"spoof")?;
    assert!(bob.client.open_routed(&entry, "bob").is_err());
    Ok(())
}

type Writes = std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>;
pub(super) struct Inbox {
    responses: VecDeque<Vec<u8>>,
    writes: Writes,
}
impl Inbox {
    pub(super) fn engine(
        config: GatewaySessionConfig,
        entries: Vec<GatewayInboxEntry>,
    ) -> Result<(GatewaySessionEngine, Writes), SdkError> {
        let acknowledgements = entries.len();
        Self::engine_with_acknowledgements(config, entries, acknowledgements)
    }
    pub(super) fn engine_with_acknowledgements(
        config: GatewaySessionConfig,
        entries: Vec<GatewayInboxEntry>,
        acknowledgements: usize,
    ) -> Result<(GatewaySessionEngine, Writes), SdkError> {
        let cursor = GatewayCursor {
            target_delivery_id: config.target_delivery_id.clone(),
            inbox_seq: entries.last().map_or(0, |entry| entry.inbox_seq),
            last_envelope_id: None,
            acked_envelope_ids: Vec::new(),
            nacked_envelope_ids: BTreeMap::new(),
        };
        let mut responses =
            VecDeque::from([serde_json::to_vec(&GatewayServerFrame::Resume { entries })?]);
        for _ in 0..acknowledgements {
            responses.push_back(serde_json::to_vec(&GatewayServerFrame::Ack {
                cursor: cursor.clone(),
            })?);
            responses.push_back(serde_json::to_vec(&GatewayServerFrame::Cursor {
                cursor: Some(cursor.clone()),
            })?);
        }
        let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        Ok((
            GatewaySessionEngine::with_test_transport(
                config,
                Box::new(Self { responses, writes: writes.clone() }),
            ),
            writes,
        ))
    }
}
impl ramflux_transport::GatewaySessionFrameSink for Inbox {
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let value: serde_json::Value = serde_json::from_slice(body)?;
            if value["frame_type"] == "heartbeat" {
                self.responses.push_front(serde_json::to_vec(&GatewayServerFrame::Heartbeat {
                    now: value["now"].as_u64().unwrap_or(0),
                })?);
            }
            self.writes
                .lock()
                .map_err(|_| ramflux_transport::TransportError::Quic("test mutex".to_owned()))?
                .push(value);
            Ok(())
        })
    }
}
impl ramflux_transport::GatewaySessionFrameSource for Inbox {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        Box::pin(async move {
            self.responses
                .pop_front()
                .ok_or_else(|| ramflux_transport::TransportError::Quic("no test frame".to_owned()))
        })
    }
}

#[tokio::test]
async fn mixed_a2i_batch_commits_and_acks_control_without_losing_direct_messages()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 200)?;
    let mut bob = Fixture::new("bob", 210)?;
    trust(&bob, &alice)?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let first = seal(&alice, &bob, message("dm-before-control", "thread"), b"direct message")?;
    let event = A2iControlEvent {
        source_principal_id: None,
        source_principal_commitment: None,
        event_id: "control-event".to_owned(),
        event_type: "a2i.control".to_owned(),
        source_device_id: "alice".to_owned(),
        target_device_id: "bob".to_owned(),
        control_domain: "message".to_owned(),
        action: "test".to_owned(),
        subject_base64: String::new(),
        created_at: 1,
        acknowledged: false,
    };
    let mut control = seal_as(
        &alice,
        &bob,
        message("control-envelope", "control-thread"),
        &serde_json::to_vec(&event)?,
        Route::control(),
    )?;
    control.inbox_seq = 2;
    let (mut engine, writes) = Inbox::engine(bob.config()?, vec![first, control.clone()])?;
    let events = bob.client.receive_a2i_control_events(&mut engine, 10).await?;
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
    assert_eq!(events, vec![expected]);
    assert_eq!(bob.client.direct_messages("thread")?.len(), 1);
    assert_eq!(bob.client.gateway_receive_cursor("bob")?, 2);
    assert_eq!(
        writes
            .lock()
            .map_err(|_| invalid("mutex"))?
            .iter()
            .filter(|value| value["frame_type"] == "ack")
            .count(),
        2
    );
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &control, false).await.is_ok());
    Ok(())
}

#[tokio::test]
async fn a_poison_entry_is_dead_lettered_without_stalling_the_next_message() -> Result<(), SdkError>
{
    let alice = Fixture::new("alice", 220)?;
    let mut bob = Fixture::new("bob", 230)?;
    trust(&bob, &alice)?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let mut good = seal(&alice, &bob, message("healthy", "thread"), b"healthy message")?;
    good.inbox_seq = 2;
    let mut poison = good.clone();
    poison.inbox_seq = 1;
    poison.envelope.envelope_id = "poison".to_owned();
    poison.envelope.encrypted_payload = "malformed".to_owned();
    let (engine, _) = Inbox::engine(bob.config()?, vec![poison, good])?;
    let client = std::mem::take(&mut bob.client);
    let mut account =
        crate::bus::state::LocalBusAccountState::new(client, engine, "bob".to_owned());
    crate::bus::sync_driver::run(&mut account).await?;
    assert_eq!(account.client.direct_messages("thread")?.len(), 1);
    assert_eq!(account.client.gateway_receive_cursor("bob")?, 2);
    assert!(
        account
            .client
            .account_db()?
            .journal_after(0, 100)?
            .iter()
            .any(|event| event.topic == "message.undeliverable")
    );
    Ok(())
}

#[test]
fn quarantine_overflow_evicts_oldest_instead_of_stopping_receive() -> Result<(), SdkError> {
    let bob = Fixture::new("bob", 240)?;
    let db = bob.client.account_db()?;
    for n in 0..65 {
        db.hold_unrouted(&format!("e{n:02}"), n, format!("ciphertext{n:02}").as_bytes(), 1)?;
    }
    assert_eq!(db.unrouted_count()?, 64);
    let entries = db.unrouted_entries()?;
    assert_eq!(entries.len(), 64);
    assert!(!entries.iter().any(|entry| entry == b"ciphertext00"));
    assert!(entries.iter().any(|entry| entry == b"ciphertext64"));
    Ok(())
}

#[test]
fn a_lower_peer_session_id_cannot_displace_a_locally_initiated_session() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 11)?;
    let bob = Fixture::new("bob", 31)?;
    trust(&bob, &alice)?;
    let mut outbound = super::r5::outgoing(&bob, &alice, "local-first");
    outbound.source_principal_id = "bob".to_owned();
    outbound.sender_id = "bob".to_owned();
    outbound.recipient_device_id = Some("alice".to_owned());
    outbound.target_delivery_id = "alice".to_owned();
    let local_id = install_high_local_pair(&bob, &alice, &outbound)?;
    let bundle =
        bob.client.load_x3dh_private_state(&bob.client.local_device_identity("bob")?)?.bundle;
    let hash = prekey_bundle_hash(&bundle)?;
    let mut inbound = None;
    for attempt in 0..256 {
        let mut msg = message(&format!("peer-{attempt}"), "thread");
        let aad = associated_data(&msg.envelope_id, "alice", "bob", &hash)?;
        let (mut session, header) = alice.client.create_send_dm_session_with_aad(
            &msg,
            "bob",
            bundle.clone(),
            "alice",
            Some(&aad),
        )?;
        if session.session_id >= local_id {
            continue;
        }
        let plaintext = serde_json::to_vec(
            &serde_json::json!({"routing":{"kind":"direct","conversation_id":"thread","group_id":null,"message_id":msg.envelope_id},"body_base64":ramflux_protocol::encode_base64url(b"peer")}),
        )?;
        let ciphertext = session.encrypt(&plaintext, &aad)?;
        msg.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
            source_principal_commitment: None,
            schema: "ramflux.sdk.dm_x3dh_envelope.v2".to_owned(),
            version: 2,
            x3dh: header,
            ciphertext,
        })?;
        inbound = Some(GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: "bob".to_owned(),
            envelope: gateway_direct_message_envelope(&alice.config()?, &msg, None)?,
        });
        break;
    }
    let entry = inbound.ok_or_else(|| invalid("could not construct a lower peer session id"))?;
    let opened = bob.client.open_routed(&entry, "bob")?;
    bob.client.persist_pair(
        &bob.client.local_device_identity("bob")?,
        &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        &opened.bundle_hash,
        &opened.session,
    )?;
    let (active, _, _) = bob.client.send_pair_session_from_url(
        &bob.client.local_device_identity("bob")?,
        &outbound,
        None,
    )?;
    assert_eq!(active.session_id, local_id);
    Ok(())
}

#[test]
fn an_invalid_envelope_signature_is_rejected_before_any_delivery_is_appended()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 51)?;
    let bob = Fixture::new("bob", 71)?;
    trust(&bob, &alice)?;
    let mut entry = seal(&alice, &bob, message("bad-signature", "thread"), b"text")?;
    entry.envelope.signed.signature = "invalid".to_owned();
    assert!(bob.client.open_routed(&entry, "bob").is_err());
    assert!(bob.client.event_body("bad-signature")?.is_none());
    Ok(())
}

#[tokio::test]
async fn an_object_share_and_later_messages_keep_one_device_pair_ratchet() -> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 91)?;
    let mut bob = Fixture::new("bob", 111)?;
    trust(&bob, &alice)?;
    trust(&alice, &bob)?;
    alice.client.put_encrypted_object("shared", b"object bytes")?;
    let bundle =
        bob.client.load_x3dh_private_state(&bob.client.local_device_identity("bob")?)?.bundle;
    let response = crate::prekey::SdkPrekeyResponse {
        device_id: "bob".to_owned(),
        bundle: Some(bundle),
        principal_commitment: "bob".to_owned(),
        target_delivery_id: Some("bob".to_owned()),
    };
    let inbox = Inbox {
        responses: VecDeque::from([serde_json::to_vec(&GatewayServerFrame::Prekey { response })?]),
        writes: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let mut engine = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(inbox));
    let recipient = bob.client.local_device_reference("bob")?;
    let request = serde_json::from_value(
        serde_json::json!({"object_id":"shared","conversation_id":"thread","recipient_device_id":recipient,"target_delivery_id":"bob"}),
    )?;
    let package = alice.client.share_object_key_with_dm_recipient(&mut engine, request).await?;
    let entry = seal(&alice, &bob, message("after-share", "thread"), b"after share")?;
    assert_eq!(
        package.key_slot.ciphertext.session_id,
        decode(&entry.envelope)?.ciphertext.session_id
    );
    let deferred = bob
        .client
        .decrypt_object_key_slot(&package.key_slot)
        .map_err(|e| invalid(&format!("initial slot: {e}")))?;
    bob.client.establish_friend_link("friend", "bob", "alice")?;
    let mut incoming =
        GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client
        .apply_routed_entry(&mut incoming, &pool()?, &entry, false)
        .await
        .map_err(|e| invalid(&format!("after-share message: {e}")))?;
    let mut reply = message("reply-after-share", "thread");
    reply.source_principal_id = "bob".to_owned();
    reply.sender_id = "bob".to_owned();
    reply.recipient_device_id = Some("alice".to_owned());
    reply.target_delivery_id = "alice".to_owned();
    let reply = seal(&bob, &alice, reply, b"reply")?;
    let opened =
        alice.client.open_routed(&reply, "alice").map_err(|e| invalid(&format!("reply: {e}")))?;
    alice.client.persist_pair(
        &alice.client.local_device_identity("alice")?,
        &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        &opened.bundle_hash,
        &opened.session,
    )?;
    bob.client
        .commit_object_key_slot_session(&deferred)
        .map_err(|e| invalid(&format!("delayed slot commit: {e}")))?;
    let next = seal(&alice, &bob, message("after-download", "thread"), b"still works")?;
    assert_eq!(
        bob.client
            .open_routed(&next, "bob")
            .map_err(|e| invalid(&format!("next message: {e}")))?
            .body
            .as_slice(),
        b"still works"
    );
    assert!(alice.client.load_dm_session("thread", "send").is_err());
    assert!(bob.client.load_dm_session("thread", "recv").is_err());
    Ok(())
}

#[test]
fn gateway_franking_receipts_preserve_sender_signatures_without_unbinding_sender_fields()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 12)?;
    let bob = Fixture::new("bob", 32)?;
    trust(&bob, &alice)?;
    let mut entry = seal(&alice, &bob, message("gateway-franking", "thread"), b"text")?;
    let ciphertext = decode(&entry.envelope)?.ciphertext;
    entry.envelope.ext.ext.insert(
        "franking".to_owned(),
        serde_json::to_value(crate::dm::SdkDmFrankingMetadata::from_ciphertext(&ciphertext))?,
    );
    entry.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        alice.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &entry.envelope,
    )?;
    let franking = entry.envelope.ext.ext.get_mut("franking").ok_or_else(|| invalid("franking"))?;
    franking["franking_tag"] = serde_json::json!("node receipt");
    franking["node_id"] = serde_json::json!("node");
    franking["accepted_at"] = serde_json::json!(1);
    assert!(bob.client.open_routed(&entry, "bob").is_ok());
    entry.envelope.ext.ext.get_mut("franking").ok_or_else(|| invalid("franking"))?["commitment"] =
        serde_json::json!("tampered");
    assert!(bob.client.open_routed(&entry, "bob").is_err());
    Ok(())
}

#[tokio::test]
async fn transient_sender_lookup_retries_with_backoff_while_later_messages_progress()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 52)?;
    let carol = Fixture::new("carol", 72)?;
    let mut bob = Fixture::new("bob", 92)?;
    let mut remote = message("transient", "carol-thread");
    remote.source_principal_id = "carol".to_owned();
    remote.sender_id = "carol".to_owned();
    let pending = seal(&carol, &bob, remote, b"retry me")?;
    let carol_root = ramflux_crypto::identity_root_commitment(
        &carol
            .client
            .identity_root
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key(),
    );
    let carol_address = ramflux_protocol::qualified_device_id(&carol_root, "carol")?;
    bob.client.account_db()?.remove_actor_state(&format!("directory/device/{carol_address}"))?;
    bob.client.establish_friend_link("carol-friend", "bob", &carol_root)?;
    bob.client.establish_friend_link(
        "alice-friend",
        "bob",
        alice.client.owned_device_identity()?.root_commitment(),
    )?;
    let mut good = seal(&alice, &bob, message("later-good", "thread"), b"works")?;
    good.inbox_seq = 2;
    let (engine, _) = Inbox::engine(bob.config()?, vec![pending.clone(), good])?;
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob.client),
        engine,
        "bob".to_owned(),
    );
    // Admission and observations share a clock even if later work is descheduled.
    let now = now_unix_timestamp();
    crate::bus::sync_driver::run_at(&mut account, now).await?;
    assert_eq!(account.client.direct_messages("thread")?.len(), 1);
    assert_eq!(account.client.gateway_receive_cursor("bob")?, 2);
    let db = account.client.account_db()?;
    assert_eq!(db.due_inbox_retries(now)?.len(), 0);
    assert_eq!(db.due_inbox_retries(now + 1)?.len(), 0);
    assert_eq!(db.due_inbox_retries(now + 2)?.len(), 1);
    assert_eq!(db.due_inbox_retries(now + 3)?.len(), 1);
    assert!(!db.journal_after(0, 100)?.iter().any(|event| event.topic == "message.undeliverable"));
    let key = account.client.inbox_admission_key(&pending)?;
    assert_eq!(db.defer_inbox_entry(&key, &serde_json::to_vec(&pending)?, now + 3)?, 2);
    let (engine, _) = Inbox::engine(account.gateway_config.clone(), vec![pending])?;
    account.engine = Some(engine);
    crate::bus::sync_driver::run_at(&mut account, now + 3).await?;
    assert_eq!(account.client.account_db()?.due_inbox_retries(now + 6)?.len(), 0);
    assert_eq!(account.client.account_db()?.due_inbox_retries(now + 7)?.len(), 1);
    assert_eq!(account.client.account_db()?.due_inbox_retries(now + 8)?.len(), 1);

    Ok(())
}

#[tokio::test]
async fn direct_message_json_cannot_apply_a_friend_control_side_effect() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 13)?;
    let mut bob = Fixture::new("bob", 33)?;
    let body =
        br#"{"type":"friend.accepted","link_id":"text-only","requester":"bob","target":"carol"}"#;
    bob.client.establish_friend_link(
        "consented",
        "bob",
        alice.client.owned_device_identity()?.root_commitment(),
    )?;
    let before = bob.client.friend_links()?;
    let entry = seal(&alice, &bob, message("json-friend-text", "thread"), body)?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    assert_eq!(bob.client.friend_links()?, before);
    assert_eq!(
        bob.client.account_db()?.message_content("json-friend-text")?.as_deref(),
        Some(body.as_slice())
    );
    Ok(())
}

#[tokio::test]
async fn typed_friend_control_commits_only_for_its_authenticated_endpoints() -> Result<(), SdkError>
{
    let alice = Fixture::new("alice", 53)?;
    let mut bob = Fixture::new("bob", 73)?;
    let body=br#"{"type":"friend.accepted","link_id":"typed-control","requester":"bob","target":"alice"}"#;
    let entry =
        seal_as(&alice, &bob, message("typed-friend", "control-thread"), body, Route::control())?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    assert_eq!(bob.client.friend_links()?.len(), 1);
    let invalid =
        br#"{"type":"friend.accepted","link_id":"unrelated","requester":"bob","target":"carol"}"#;
    let entry = seal_as(
        &alice,
        &bob,
        message("unrelated-friend", "control-thread"),
        invalid,
        Route::control(),
    )?;
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await.is_err());
    assert_eq!(bob.client.friend_links()?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_stranger_cannot_create_group_conversations_with_pending_ciphertext()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 93)?;
    let mut bob = Fixture::new("bob", 113)?;
    fixture_group(&alice.client, "untrusted-group", &alice)?;
    let body = alice.client.encrypt_group_message("untrusted-group", "alice", b"message")?;
    let entry = seal_group(&alice, &bob, message("stranger-group", "untrusted-thread"), &body)?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await.is_err());
    assert!(bob.client.account_db()?.client_record("group", "untrusted-group")?.is_none());
    assert!(bob.client.account_db()?.client_record("conversation", "untrusted-thread")?.is_none());
    Ok(())
}

#[test]
fn a_substituted_recipient_prekey_cannot_bootstrap_a_known_device() -> Result<(), SdkError> {
    use std::io::{BufRead, BufReader, Write};
    let alice = Fixture::new("alice", 133)?;
    let bob = Fixture::new("bob", 153)?;
    let impostor = Fixture::new("bob", 173)?;
    trust(&alice, &bob)?;
    let bundle = impostor
        .client
        .load_x3dh_private_state(&impostor.client.local_device_identity("bob")?)?
        .bundle;
    let reply = serde_json::to_vec(&crate::prekey::SdkPrekeyResponse {
        device_id: "bob".to_owned(),
        bundle: Some(bundle),
        principal_commitment: "bob".to_owned(),
        target_delivery_id: Some("bob".to_owned()),
    })?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}", listener.local_addr()?);
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut reader = BufReader::new(socket.try_clone()?);
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 || line == "\r\n" {
                break;
            }
        }
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reply.len()
        )?;
        socket.write_all(&reply)
    });
    let result = alice.client.send_pair_session_from_url(
        &alice.client.local_device_identity("alice")?,
        &super::r5::outgoing(&alice, &bob, "substitution"),
        Some(&url),
    );
    server.join().map_err(|_| invalid("prekey test server stopped"))??;
    assert!(result.is_err());
    Ok(())
}

fn install_high_local_pair(
    sender: &Fixture,
    recipient: &Fixture,
    message: &GatewayDirectMessage,
) -> Result<String, SdkError> {
    let bundle = recipient
        .client
        .load_x3dh_private_state(&recipient.client.local_device_identity(&recipient.id)?)?
        .bundle;
    let hash = prekey_bundle_hash(&bundle)?;
    let aad = associated_data(&message.envelope_id, &sender.id, &recipient.id, &hash)?;
    let mut selected: Option<ramflux_crypto::DmSession> = None;
    for _ in 0..32 {
        let (session, _) = sender.client.create_send_dm_session_with_aad(
            message,
            &recipient.id,
            bundle.clone(),
            &sender.id,
            Some(&aad),
        )?;
        if selected.as_ref().is_none_or(|old| session.session_id > old.session_id) {
            selected = Some(session);
        }
    }
    let session = selected.ok_or_else(|| invalid("local session missing"))?;
    sender
        .client
        .account_db()?
        .persist_actor_state(&format!("dm-pair/local/{}", session.session_id), &true)?;
    sender.client.persist_pair(
        &sender.client.local_device_identity(&sender.id)?,
        &sender.client.device_identity(&recipient.reference()?)?,
        &hash,
        &session,
    )?;
    Ok(session.session_id.clone())
}

#[test]
fn a_legacy_group_envelope_cannot_be_released_under_a_different_group_id() -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 14)?;
    let bob = Fixture::new("bob", 34)?;
    for client in [&alice.client, &bob.client] {
        fixture_group(client, "actual-group", &alice)?;
        fixture_member(client, "actual-group", &bob)?;
    }
    let mut msg = message("legacy-group-conflict", "requested-thread");
    msg.encrypted_body = alice.client.encrypt_group_message("actual-group", "alice", b"text")?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "bob".to_owned(),
        envelope: gateway_direct_message_envelope(&alice.config()?, &msg, None)?,
    };
    assert!(
        bob.client
            .append_group_gateway_delivery_for_recipient(
                "requested-thread",
                "wrong-group",
                "legacy-group-conflict",
                &entry,
                "bob"
            )
            .is_err()
    );
    assert_eq!(bob.client.direct_messages("requested-thread")?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn existing_threads_without_participant_metadata_are_never_claimed_by_a_new_sender()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 15)?;
    let mut bob = Fixture::new("bob", 35)?;
    bob.client.send_direct_message("thread", "old-history", "carol", b"prior history")?;
    let entry = seal(&alice, &bob, message("claim-old-thread", "thread"), b"injection")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await.is_err());
    assert_eq!(bob.client.direct_messages("thread")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn attachment_shaped_json_text_is_not_interpreted_as_an_attachment_wrapper()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 16)?;
    let mut bob = Fixture::new("bob", 36)?;
    let body = serde_json::to_vec(
        &serde_json::json!({"schema":"ramflux.sdk.dm_attachment_envelope.v1","version":1,"body_base64":ramflux_protocol::encode_base64url(b"different bytes"),"attachments":[]}),
    )?;
    bob.client.establish_friend_link(
        "consented",
        "bob",
        alice.client.owned_device_identity()?.root_commitment(),
    )?;
    let plain = seal(&alice, &bob, message("attachment-looking-text", "thread"), &body)?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    bob.client.apply_routed_entry(&mut engine, &pool()?, &plain, false).await?;
    assert_eq!(
        bob.client.account_db()?.message_content("attachment-looking-text")?.as_deref(),
        Some(body.as_slice())
    );
    let wrapped = seal_as(
        &alice,
        &bob,
        message("real-attachment-wrapper", "thread"),
        &body,
        Route::attachments(),
    )?;
    bob.client.apply_routed_entry(&mut engine, &pool()?, &wrapped, false).await?;
    assert_eq!(
        bob.client.account_db()?.message_content("real-attachment-wrapper")?.as_deref(),
        Some(b"different bytes".as_slice())
    );
    Ok(())
}

#[tokio::test]
async fn an_authenticated_alias_still_honors_a_block_on_its_root_commitment() -> Result<(), SdkError>
{
    let alice = Fixture::new("alice", 17)?;
    let mut bob = Fixture::new("bob", 37)?;
    trust(&bob, &alice)?;
    let commitment = crate::client::identity_authority::test_support::manifest(&alice.client)?
        .principal_commitment;
    bob.client.establish_friend_link("blocked-root", "bob", &commitment)?;
    bob.client.block_friend_link("blocked-root")?;
    let entry = seal(&alice, &bob, message("blocked-alias", "thread"), b"blocked message")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    let result = bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    assert!(result.plaintext.is_none());
    assert!(bob.client.account_db()?.message_content("blocked-alias")?.is_none());
    assert_eq!(bob.client.rejected_inbox("thread")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn root_commitment_submit_remains_readable_after_autonomous_receive_ack()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    bob.client.establish_friend_link("s48-friend", "bob", "alice")?;
    let mut outgoing = message("s48-history", "conv_s48_bob_alice");
    let mut entry = seal(&alice, &bob, outgoing.clone(), b"s48 historical dm")?;
    outgoing.source_principal_id =
        crate::identity_root_public_key_commitment_for_seed("alice", [41; 32]);
    outgoing.encrypted_body = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    entry.envelope = gateway_direct_message_envelope(&alice.config()?, &outgoing, None)?;
    let (engine, writes) = Inbox::engine(bob.config()?, vec![entry])?;
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob.client),
        engine,
        "bob".to_owned(),
    );
    crate::bus::sync_driver::run(&mut account).await?;
    assert_eq!(account.client.direct_messages("conv_s48_bob_alice")?.len(), 1);
    assert_eq!(account.pending_deliveries.len(), 1);
    assert!(writes.lock().map_err(|_| invalid("mutex"))?.iter().any(|v| v["frame_type"] == "ack"));
    let (engine, _) = Inbox::engine(account.gateway_config.clone(), Vec::new())?;
    account.engine = Some(engine);
    let mut state = crate::bus::state::LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(bob.root.join("bus.sock"), &bob.root),
        accounts: BTreeMap::from([("bob".to_owned(), account)]),
        active_account_id: Some("bob".to_owned()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let (outbound, _) = tokio::sync::mpsc::channel(4);
    let connection = crate::bus::state::LocalBusConnectionState::new(1, outbound);
    let request = LocalBusFrame::request(
        "s48-receive",
        Some("bob".to_owned()),
        "message",
        "message.receive",
        serde_json::json!({"conversation_id":"conv_s48_bob_alice","limit":16,"auto_fetch_attachments":false}),
    );
    let result = crate::bus::dispatch::message::dispatch_message_receive_request(
        &request,
        &mut state,
        &connection,
    )
    .await?;
    assert_eq!(result.response_body["decrypted_messages"][0]["sender_id"], "alice");
    assert_eq!(
        result.response_body["decrypted_messages"][0]["plaintext_body_base64"],
        ramflux_protocol::encode_base64url(b"s48 historical dm")
    );
    assert_eq!(result.response_body["entries"].as_array().map(Vec::len), Some(1));
    Ok(())
}

#[tokio::test]
async fn unfiltered_receive_decrypts_own_device_delivery_after_background_ack()
-> Result<(), SdkError> {
    let bob_a = Fixture::owned("bob-a", "bob", 41, 42)?;
    let mut bob_b = Fixture::owned("bob-b", "bob", 41, 62)?;
    trust(&bob_b, &bob_a)?;
    let mut device = bob_b
        .client
        .account_db()?
        .client_record("device", "bob-a")?
        .ok_or_else(|| invalid("device"))?;
    device["principal_id"] = serde_json::json!("bob");
    bob_b.client.account_db()?.persist_client_record("device", "bob-a", &device)?;
    let mut outgoing = message("own-device-message", "own-device-thread");
    outgoing.source_principal_id = "bob".to_owned();
    outgoing.sender_id = "bob-a".to_owned();
    outgoing.recipient_device_id = Some("bob-b".to_owned());
    outgoing.target_delivery_id = "bob-b".to_owned();
    let mut valid = seal(&bob_a, &bob_b, outgoing, b"s35 encrypted own-device sync")?;
    valid.inbox_seq = 2;
    let mut poison = valid.clone();
    poison.inbox_seq = 1;
    poison.envelope.envelope_id = "opaque-placeholder".to_owned();
    poison.envelope.encrypted_payload = ramflux_protocol::encode_base64url(b"not an E2EE envelope");
    let (engine, writes) = Inbox::engine(bob_b.config()?, vec![poison, valid])?;
    let mut account = crate::bus::state::LocalBusAccountState::new(
        std::mem::take(&mut bob_b.client),
        engine,
        "bob".to_owned(),
    );
    crate::bus::sync_driver::run(&mut account).await?;
    assert_eq!(account.pending_deliveries.len(), 1);
    assert_eq!(
        writes
            .lock()
            .map_err(|_| invalid("mutex"))?
            .iter()
            .filter(|v| v["frame_type"] == "ack")
            .count(),
        2
    );
    let (engine, _) = Inbox::engine(account.gateway_config.clone(), Vec::new())?;
    account.engine = Some(engine);
    let mut state = crate::bus::state::LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(bob_b.root.join("bus.sock"), &bob_b.root),
        accounts: BTreeMap::from([("bob".to_owned(), account)]),
        active_account_id: Some("bob".to_owned()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let (outbound, _) = tokio::sync::mpsc::channel(4);
    let connection = crate::bus::state::LocalBusConnectionState::new(1, outbound);
    let request = LocalBusFrame::request(
        "s35-receive",
        Some("bob".to_owned()),
        "message",
        "message.receive",
        serde_json::json!({"conversation_id":null,"limit":16,"auto_fetch_attachments":false}),
    );
    let result = crate::bus::dispatch::message::dispatch_message_receive_request(
        &request,
        &mut state,
        &connection,
    )
    .await?;
    assert_eq!(result.response_body["decrypted_messages"].as_array().map(Vec::len), Some(1));
    assert_eq!(result.response_body["decrypted_messages"][0]["sender_id"], "bob");
    assert_eq!(
        result.response_body["decrypted_messages"][0]["entry"]["envelope"]["source_device_id"],
        "bob-a"
    );
    assert_eq!(
        result.response_body["decrypted_messages"][0]["plaintext_body_base64"],
        ramflux_protocol::encode_base64url(b"s35 encrypted own-device sync")
    );
    assert_eq!(result.response_body["entries"].as_array().map(Vec::len), Some(1));
    Ok(())
}

#[test]
fn live_pair_bootstrap_rejects_a_signed_prekey_from_an_older_device_epoch() -> Result<(), SdkError>
{
    let old = Fixture::new("bob", 61)?;
    let current = Fixture::owned_epoch("bob", "bob", 61, 62, 2)?;
    let sender = Fixture::new("alice", 41)?;
    trust(&sender, &current)?;
    let bundle =
        old.client.load_x3dh_private_state(&old.client.local_device_identity("bob")?)?.bundle;
    ramflux_crypto::verify_prekey_bundle(
        &current
            .client
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key(),
        &bundle,
    )?;
    assert!(
        sender
            .client
            .new_send_pair(
                &sender.client.local_device_identity("alice")?,
                &super::r5::outgoing(&sender, &current, "old-device-epoch"),
                bundle
            )
            .is_err()
    );
    Ok(())
}
