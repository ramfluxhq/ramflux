// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adversarial device authentication, attribution, routing and ratchet ownership regressions.
use super::*;

pub(super) fn trust(receiver: &Fixture, sender: &Fixture) -> Result<(), SdkError> {
    if let Some(native) = &sender.native {
        receiver.client.persist_observed_identity_directory_now(&native.manifest)?;
        return Ok(());
    }
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
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &entry).await.is_err());
    assert_eq!(bob.client.direct_messages("thread")?.len(), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn json_text_in_a_direct_message_cannot_select_a_control_route() -> Result<(), SdkError> {
    native_text::roundtrip(
        br#"{"schema":"ramflux.sdk.group_sender_key.message.v1","group_id":"victim"}"#,
        false,
    )
    .await
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
    crate::client::native_test_support::watchdog::within(native_delivery::duplicate_attribution())
        .await
        .map_err(|_| invalid("test: native attribution watchdog"))?
        .map_err(|error| invalid(&format!("native attribution: {error}")))
}

#[tokio::test]
async fn group_delivery_preserves_existing_titles_and_all_conversation_links()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(native_delivery::group_metadata())
        .await
        .map_err(|_| invalid("test: native group metadata watchdog"))?
        .map_err(|error| invalid(&format!("native group metadata: {error}")))
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
    fn recv_idle_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        // This fixture emits solicited replies only; an idle reader waits for a request.
        Box::pin(std::future::pending())
    }

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
async fn closed_a2i_api_preserves_mixed_inbox_for_supported_receive() -> Result<(), SdkError> {
    let alice = Fixture::native_named("alice", 200).await?;
    let mut bob = Fixture::native_named("bob", 210).await?;
    bob.client.establish_friend_link(
        "friend",
        &bob.client.own_account_anchor()?,
        &alice.client.own_account_anchor()?,
    )?;
    let sent = generated_delivery(&alice, &bob, "dm-before-control", "direct message")?;
    let mut poison = sent.entry.clone();
    poison.inbox_seq = 2;
    poison.envelope.envelope_id = "unsupported-control".into();
    let (mut engine, writes) = Inbox::engine(bob.config()?, vec![sent.entry.clone(), poison])?;
    assert_a2i_authority_refused(bob.client.receive_a2i_control_events(&mut engine, 10).await);
    assert_eq!(writes.lock().map_err(|_| invalid("mutex"))?.len(), 0, "closed API consumed inbox");
    assert_eq!(bob.client.direct_messages(&sent.conversation)?.len(), 0);
    assert_eq!(bob.client.gateway_receive_cursor(&engine.config.target_delivery_id)?, 0);
    bob.client.apply_routed_entry(&mut engine, &pool()?, &sent.entry).await?;
    assert_eq!(bob.client.direct_messages(&sent.conversation)?.len(), 1);
    assert_eq!(bob.client.account_db()?.list_actor_states::<A2iControlEvent>("a2i/")?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_poison_entry_is_dead_lettered_without_stalling_the_next_message() -> Result<(), SdkError>
{
    let alice = Fixture::native_named("alice", 220).await?;
    let mut bob = Fixture::native_named("bob", 230).await?;
    trust(&bob, &alice)?;
    bob.client.establish_friend_link(
        "friend",
        &bob.client.own_account_anchor()?,
        &alice.client.own_account_anchor()?,
    )?;
    let sent = generated_delivery(&alice, &bob, "healthy", "healthy message")?;
    let mut good = sent.entry;
    good.inbox_seq = 2;
    let mut poison = good.clone();
    poison.inbox_seq = 1;
    poison.envelope.envelope_id = "poison".into();
    poison.envelope.encrypted_payload = "malformed".into();
    let config = bob.config()?;
    let mailbox = config.target_delivery_id.clone();
    let root = bob.client.own_account_anchor()?;
    let (engine, _) = Inbox::engine(config, vec![poison, good])?;
    let mut account =
        crate::bus::state::LocalBusAccountState::new(std::mem::take(&mut bob.client), engine, root);
    crate::bus::sync_driver::run(&mut account).await?;
    assert_eq!(account.client.direct_messages(&sent.conversation)?.len(), 1);
    assert_eq!(account.client.gateway_receive_cursor(&mailbox)?, 2);
    assert!(
        account
            .client
            .account_db()?
            .journal_after(0, 100)?
            .iter()
            .any(|event| event.topic == "message.undeliverable")
    );
    assert_eq!(
        account
            .client
            .generated_message_detail(&sent.conversation, &sent.message)?
            .message
            .text
            .as_deref(),
        Some("healthy message")
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

#[tokio::test(flavor = "current_thread")]
async fn gateway_franking_receipts_preserve_sender_signatures_without_unbinding_sender_fields()
-> Result<(), SdkError> {
    let alice = Fixture::native_named("alice", 12).await?;
    let bob = Fixture::native_named("bob", 32).await?;
    let mut entry = generated_delivery(&alice, &bob, "gateway-franking", "text")?.entry;
    let packet = decode(&entry.envelope)?;
    entry.envelope.ext.ext.insert(
        "franking".into(),
        serde_json::to_value(crate::dm::SdkDmFrankingMetadata::from_ciphertext(
            &packet.ciphertext,
        ))?,
    );
    entry.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        alice.config()?.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &entry.envelope,
    )?;
    assert!(bob.client.open_routed(&entry, "bob").is_ok(), "signed sender fields must verify");
    let signature = entry.envelope.signed.signature.clone();
    let franking = entry.envelope.ext.ext.get_mut("franking").ok_or_else(|| invalid("franking"))?;
    franking["franking_tag"] = serde_json::json!("node receipt");
    franking["node_id"] = serde_json::json!("node");
    franking["accepted_at"] = serde_json::json!(1);
    assert_eq!(entry.envelope.signed.signature, signature);
    assert!(
        bob.client.open_routed(&entry, "bob").is_ok(),
        "node fields cannot break sender binding"
    );
    entry.envelope.ext.ext.get_mut("franking").ok_or_else(|| invalid("franking"))?["commitment"] =
        serde_json::json!("tampered");
    assert!(bob.client.open_routed(&entry, "bob").is_err(), "sender commitment must remain bound");
    Ok(())
}

#[tokio::test]
async fn transient_sender_lookup_retries_with_backoff_while_later_messages_progress()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(native_delivery::transient_lookup())
        .await
        .map_err(|_| invalid("test: native backoff watchdog"))?
        .map_err(|error| invalid(&format!("native backoff: {error}")))
}

#[tokio::test(flavor = "current_thread")]
async fn direct_message_json_cannot_apply_a_friend_control_side_effect() -> Result<(), SdkError> {
    native_text::roundtrip(
        br#"{"type":"friend.accepted","link_id":"text-only","requester":"bob","target":"carol"}"#,
        false,
    )
    .await
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

#[tokio::test]
async fn existing_threads_without_participant_metadata_are_never_claimed_by_a_new_sender()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 15)?;
    let mut bob = Fixture::new("bob", 35)?;
    bob.client.send_direct_message("thread", "old-history", "carol", b"prior history")?;
    let entry = seal(&alice, &bob, message("claim-old-thread", "thread"), b"injection")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    assert!(bob.client.apply_routed_entry(&mut engine, &pool()?, &entry).await.is_err());
    assert_eq!(bob.client.direct_messages("thread")?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn attachment_shaped_json_text_is_not_interpreted_as_an_attachment_wrapper()
-> Result<(), SdkError> {
    let body = serde_json::to_vec(&serde_json::json!({
        "schema":"ramflux.sdk.dm_attachment_envelope.v1","version":1,
        "body_base64":ramflux_protocol::encode_base64url(b"different bytes"),"attachments":[],
    }))?;
    native_text::roundtrip(&body, true).await
}

#[tokio::test]
async fn an_authenticated_alias_still_honors_a_block_on_its_root_commitment() -> Result<(), SdkError>
{
    let alice = Fixture::native_named("alice", 17).await?;
    let mut bob = Fixture::native_named("bob", 37).await?;
    trust(&bob, &alice)?;
    let commitment = alice.client.own_account_anchor()?;
    bob.client.establish_friend_link(
        "blocked-root",
        &bob.client.own_account_anchor()?,
        &commitment,
    )?;
    bob.client.block_friend_link("blocked-root")?;
    let sent = generated_delivery(&alice, &bob, "blocked-alias", "blocked message")?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    let result = bob.client.apply_routed_entry(&mut engine, &pool()?, &sent.entry).await?;
    assert!(result.plaintext.is_none());
    assert!(bob.client.account_db()?.message_content(&sent.message)?.is_none());
    assert_eq!(bob.client.rejected_inbox(&sent.conversation)?.len(), 1);
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

#[path = "review_native_text.rs"]
pub(super) mod native_text;

#[path = "review_native_delivery.rs"]
mod native_delivery;
