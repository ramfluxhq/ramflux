// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
struct Fixture {
    root: PathBuf,
    client: RamfluxClient,
    id: String,
}
impl Fixture {
    fn new(id: &str, seed: u8) -> Result<Self, SdkError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_nanos());
        let root = PathBuf::from(format!(
            "/tmp/ramflux-routed-{id}-{}-{sequence}-{now}",
            std::process::id()
        ));
        let mut client = RamfluxClient::new();
        client.create_identity_root(id, [seed; 32]);
        client.create_device_branch(id, id, 1, [seed + 1; 32]);
        client.open_account_index(&root)?;
        client.create_account(id, id)?;
        client.unlock_account(id, b"routed-test")?;
        client.initialize_and_publish_prekey_bundle(id, id, id, [seed + 1; 32], None)?;
        Ok(Self { root, client, id: id.to_owned() })
    }
    fn config(&self) -> Result<GatewaySessionConfig, SdkError> {
        Ok(GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().map_err(|_| invalid("address"))?,
            gateway_addr: "127.0.0.1:1".parse().map_err(|_| invalid("address"))?,
            server_name: "test".to_owned(),
            ca_cert: self.root.join("ca.pem"),
            principal_id: self.id.clone(),
            device_id: self.id.clone(),
            target_delivery_id: self.id.clone(),
            prekey_http_url: None,
        })
        .with_device_branch(
            self.client.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?,
        ))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn message(id: &str, conversation: &str) -> GatewayDirectMessage {
    GatewayDirectMessage {
        conversation_id: conversation.to_owned(),
        message_id: id.to_owned(),
        envelope_id: id.to_owned(),
        source_principal_id: "alice".to_owned(),
        sender_id: "alice".to_owned(),
        recipient_device_id: Some("bob".to_owned()),
        target_delivery_id: "bob".to_owned(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    }
}
fn seal(
    sender: &Fixture,
    receiver: &Fixture,
    message: GatewayDirectMessage,
    body: &[u8],
) -> Result<GatewayInboxEntry, SdkError> {
    seal_as(sender, receiver, message, body, Route::direct())
}
fn seal_as(
    sender: &Fixture,
    receiver: &Fixture,
    mut message: GatewayDirectMessage,
    body: &[u8],
    route: Route,
) -> Result<GatewayInboxEntry, SdkError> {
    if receiver.client.account_db()?.client_record("device", &sender.id)?.is_none() {
        review::trust(receiver, sender)?;
    }
    let bundle = receiver.client.load_x3dh_private_state(&receiver.id)?.bundle;
    let hash = prekey_bundle_hash(&bundle)?;
    let existing = sender.client.send_pair_session_from_url(&sender.id, &message, None);
    let (mut session, header, hash) = if let Ok(value) = existing {
        value
    } else {
        let aad = associated_data(&message.envelope_id, &sender.id, &receiver.id, &hash)?;
        let (session, header) = sender.client.create_send_dm_session_with_aad(
            &message,
            &receiver.id,
            bundle,
            &sender.id,
            Some(&aad),
        )?;
        (session, header, hash)
    };
    let sealed = sender.client.seal_routed_with_route(
        &message,
        body,
        route,
        SealPair {
            local: &sender.id,
            remote: &receiver.id,
            session: &mut session,
            header,
            bundle: hash,
        },
    )?;
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    let mut envelope = gateway_direct_message_envelope(&sender.config()?, &message, None)?;
    // Adversarial fixtures can deliberately claim an owner the production sender cannot emit.
    envelope.source_principal_id.clone_from(&message.source_principal_id);
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &envelope,
    )?;
    Ok(GatewayInboxEntry { inbox_seq: 1, target_delivery_id: receiver.id.clone(), envelope })
}

#[test]
fn first_unknown_conversation_decrypts_and_outer_frame_has_no_route() -> Result<(), SdkError> {
    let a = Fixture::new("alice", 21)?;
    let b = Fixture::new("bob", 31)?;
    let conversation = "private-first-conversation-never-known-to-the-receiver";
    let entry = seal(&a, &b, message("envelope", conversation), b"hello first message")?;
    let opened = b.client.open_routed(&entry, "bob")?;
    assert_eq!(opened.routing.conversation_id, conversation);
    assert_eq!(opened.body.as_slice(), b"hello first message");
    let outer = serde_json::to_string(&entry.envelope)?;
    assert!(!outer.contains(conversation));
    let wrapper = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|_| invalid("payload"))?;
    assert!(!String::from_utf8_lossy(&wrapper).contains(conversation));
    assert!(!String::from_utf8_lossy(&wrapper).contains("hello first message"));
    Ok(())
}

#[test]
fn device_pair_session_spans_conversations_and_rejects_replay_and_tampering() -> Result<(), SdkError>
{
    let a = Fixture::new("alice", 41)?;
    let b = Fixture::new("bob", 51)?;
    let first = seal(&a, &b, message("first", "conversation-one"), b"one")?;
    let opened = b.client.open_routed(&first, "bob")?;
    let session_id = opened.session.session_id.clone();
    b.client.persist_pair("bob", "alice", &opened.bundle_hash, &opened.session)?;
    assert!(b.client.open_routed(&first, "bob").is_err());
    let second = seal(&a, &b, message("second", "different-conversation"), b"two")?;
    let opened = b.client.open_routed(&second, "bob")?;
    assert_eq!(opened.session.session_id, session_id);
    assert_eq!(opened.body.as_slice(), b"two");
    let mut tampered = second.clone();
    tampered.envelope.envelope_id = "different-envelope".to_owned();
    assert!(b.client.open_routed(&tampered, "bob").is_err());
    let mut tampered = second;
    let mut wrapper = decode(&tampered.envelope)?;
    wrapper.ciphertext.ciphertext[0] ^= 1;
    tampered.envelope.encrypted_payload =
        ramflux_protocol::encode_base64url(serde_json::to_vec(&wrapper)?);
    assert!(b.client.open_routed(&tampered, "bob").is_err());
    Ok(())
}

#[test]
fn device_pair_session_supports_reply_direction() -> Result<(), SdkError> {
    let a = Fixture::new("alice", 61)?;
    let b = Fixture::new("bob", 71)?;
    let first = seal(&a, &b, message("first", "c"), b"hello")?;
    let opened = b.client.open_routed(&first, "bob")?;
    b.client.persist_pair("bob", "alice", &opened.bundle_hash, &opened.session)?;
    let mut reply = message("reply", "another-private-conversation");
    reply.source_principal_id = "bob".to_owned();
    reply.sender_id = "bob".to_owned();
    reply.recipient_device_id = Some("alice".to_owned());
    reply.target_delivery_id = "alice".to_owned();
    let entry = seal(&b, &a, reply, b"reply body")?;
    let received = a.client.open_routed(&entry, "alice")?;
    assert_eq!(received.body.as_slice(), b"reply body");
    assert_eq!(received.session.session_id, opened.session.session_id);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn fresh_receiver_commits_first_dm_and_replays_without_ratchet_advance()
-> Result<(), SdkError> {
    let a = Fixture::new("alice", 81)?;
    let mut b = Fixture::new("bob", 91)?;
    b.client.account_db()?.establish_friend_link("link", "bob", "alice")?;
    let entry =
        seal(&a, &b, message("first-committed", "unseen-conversation"), b"private message body")?;
    assert_eq!(b.client.conversation_list()?.len(), 0);
    let mut engine = GatewaySessionEngine::with_test_transport(b.config()?, Box::new(NoNetwork));
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()
            .map_err(|e| invalid(&e.to_string()))?,
    );
    let first = b.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
    assert!(first.plaintext.is_some());
    assert_eq!(b.client.direct_messages("unseen-conversation")?.len(), 1);
    let duplicate = b.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
    assert!(duplicate.plaintext.is_some());
    assert_eq!(b.client.direct_messages("unseen-conversation")?.len(), 1);
    Ok(())
}
struct NoNetwork;
impl ramflux_transport::GatewaySessionFrameSink for NoNetwork {
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>,
    > {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic("unexpected network".to_owned()))
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for NoNetwork {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        Box::pin(async {
            Err(ramflux_transport::TransportError::Quic("unexpected network".to_owned()))
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn group_control_and_message_route_without_conversation_hint_and_reject_conflicting_link()
-> Result<(), SdkError> {
    let a = Fixture::new("alice", 101)?;
    let mut b = Fixture::new("bob", 111)?;
    let group = "private-group";
    let conversation = "private-group-conversation";
    for client in [&a.client, &b.client] {
        client.create_group(group, "alice")?;
        client.add_group_member(group, "bob", "member")?;
        let key = ramflux_protocol::encode_base64url(
            a.client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .signing_key
                .verifying_key()
                .to_bytes(),
        );
        client.account_db()?.persist_group_member_device_key(group, "alice", &key)?;
    }
    let distribution = a.client.export_group_sender_key_distribution(group, "alice")?;
    let wrapper = SdkGroupSenderKeyDistributionEnvelope {
        schema: "ramflux.sdk.group_sender_key.distribution_envelope.v1".to_owned(),
        version: 1,
        membership_event_base64: None,
        actor_manifest_url: None,
        distribution_base64: ramflux_protocol::encode_base64url(distribution),
    };
    let entry =
        seal_group(&a, &b, message("group-control", conversation), &serde_json::to_vec(&wrapper)?)?;
    let outer = serde_json::to_string(&entry)?;
    assert!(!outer.contains(conversation));
    assert!(!outer.contains(group));
    let mut engine = GatewaySessionEngine::with_test_transport(b.config()?, Box::new(NoNetwork));
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()
            .map_err(|e| invalid(&e.to_string()))?,
    );
    let delivered = b.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
    assert_eq!(delivered.routing.kind, Kind::GroupControl);
    let inner = a.client.encrypt_group_message(group, "alice", b"private group text")?;
    let message = seal_group(&a, &b, message("group-message", conversation), &inner)?;
    let delivered = b.client.apply_routed_entry(&mut engine, &pool, &message, false).await?;
    assert_eq!(delivered.routing.kind, Kind::GroupMessage);
    let plaintext = delivered.plaintext.ok_or_else(|| invalid("missing group plaintext"))?;
    assert_eq!(
        ramflux_protocol::decode_base64url(&plaintext.plaintext_body_base64)
            .map_err(|_| invalid("body"))?,
        b"private group text"
    );
    b.client.account_db()?.persist_client_record(
        "group",
        group,
        &serde_json::json!({"conversation_id":"conflicting-conversation"}),
    )?;
    let inner = a.client.encrypt_group_message(group, "alice", b"second group message")?;
    let next = seal_group(&a, &b, super::tests::message("group-next", conversation), &inner)?;
    assert!(b.client.apply_routed_entry(&mut engine, &pool, &next, false).await.is_err());
    let direct = seal(
        &a,
        &b,
        super::tests::message("direct-kind-conflict", conversation),
        b"not a group ciphertext",
    )?;
    assert!(b.client.apply_routed_entry(&mut engine, &pool, &direct, false).await.is_err());
    Ok(())
}

#[test]
fn legacy_requires_exact_existing_device_pair_conversation_binding() -> Result<(), SdkError> {
    let a = Fixture::new("alice", 121)?;
    let b = Fixture::new("bob", 131)?;
    let mut message = message("legacy-envelope", "legacy-conversation");
    let bundle = b.client.load_x3dh_private_state("bob")?.bundle;
    let (mut sending, header) =
        a.client.create_send_dm_session_from_bundle(&message, "bob", bundle, "alice")?;
    let ciphertext = sending.encrypt(b"legacy body", dm_associated_data("legacy-conversation"))?;
    message.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".to_owned(),
        version: 1,
        x3dh: header.clone(),
        ciphertext,
    })?;
    let entry = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: "bob".to_owned(),
        envelope: gateway_direct_message_envelope(&a.config()?, &message, None)?,
    };
    assert_eq!(b.client.legacy_routing_binding("bob", &entry)?, None);
    b.client.account_db()?.hold_unrouted("legacy-envelope", 1, &serde_json::to_vec(&entry)?, 1)?;
    assert_eq!(b.client.account_db()?.unrouted_count()?, 1);
    assert!(!b.client.account_db()?.has_gateway_ack("legacy-envelope")?);
    // Explicit prior session state, rather than a caller/driver guessing from local conversations.
    let receiving =
        b.client.load_or_create_recv_dm_session("legacy-conversation", header.as_ref())?;
    b.client.send_direct_message(
        "legacy-conversation",
        "bound-history",
        "alice",
        b"prior history",
    )?;
    b.client.persist_dm_session("legacy-conversation", "bound-history", "recv", &receiving)?;
    assert_eq!(
        b.client.legacy_routing_binding("bob", &entry)?,
        Some("legacy-conversation".to_owned())
    );
    assert_eq!(b.client.legacy_routing_binding("different-device", &entry)?, None);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn group_message_before_distribution_keeps_content_retryable() -> Result<(), SdkError> {
    let a = Fixture::new("alice", 141)?;
    let mut b = Fixture::new("bob", 151)?;
    for client in [&a.client, &b.client] {
        client.create_group("pending-group", "alice")?;
        client.add_group_member("pending-group", "bob", "member")?;
        let key = ramflux_protocol::encode_base64url(
            a.client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .signing_key
                .verifying_key()
                .to_bytes(),
        );
        client.account_db()?.persist_group_member_device_key("pending-group", "alice", &key)?;
    }
    let distribution = a.client.export_group_sender_key_distribution("pending-group", "alice")?;
    let inner =
        a.client.encrypt_group_message("pending-group", "alice", b"delayed-key plaintext")?;
    let entry = seal_group(&a, &b, message("pending-message", "pending-conversation"), &inner)?;
    let mut engine = GatewaySessionEngine::with_test_transport(b.config()?, Box::new(NoNetwork));
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()
            .map_err(|e| invalid(&e.to_string()))?,
    );
    let pending = b.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
    assert!(pending.plaintext.is_none());
    assert_eq!(b.client.account_db()?.message_content("pending-message")?, None);
    let wrapper = SdkGroupSenderKeyDistributionEnvelope {
        schema: "ramflux.sdk.group_sender_key.distribution_envelope.v1".to_owned(),
        version: 1,
        membership_event_base64: None,
        actor_manifest_url: None,
        distribution_base64: ramflux_protocol::encode_base64url(distribution),
    };
    let control = seal_group(
        &a,
        &b,
        message("pending-control", "pending-conversation"),
        &serde_json::to_vec(&wrapper)?,
    )?;
    b.client.apply_routed_entry(&mut engine, &pool, &control, false).await?;
    assert_eq!(
        b.client.account_db()?.message_content("pending-message")?,
        Some(b"delayed-key plaintext".to_vec())
    );
    assert_eq!(b.client.account_db()?.group_pending_undecrypted_count("pending-group")?, 0);
    Ok(())
}

struct ReceivingGateway {
    queued: VecDeque<GatewayServerFrame>,
    entry: Option<GatewayInboxEntry>,
    last: Option<GatewayClientFrame>,
    reader: AccountDb,
    receipt_key: String,
    acks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl ramflux_transport::GatewaySessionFrameSink for ReceivingGateway {
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let frame: GatewayClientFrame = serde_json::from_slice(bytes)
                .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()))?;
            if let GatewayClientFrame::Ack { .. } = &frame {
                assert!(
                    self.reader
                        .load_actor_state::<super::committed::Committed>(&self.receipt_key)
                        .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()))?
                        .is_some(),
                    "ACK preceded the durable receive commit"
                );
                self.acks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.last = Some(frame);
            Ok(())
        })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for ReceivingGateway {
    fn recv_frame(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>,
    > {
        Box::pin(async move {
            if let Some(frame) = self.queued.pop_front() {
                return serde_json::to_vec(&frame)
                    .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()));
            }
            let frame = match self.last.take() {
                Some(GatewayClientFrame::Heartbeat { now }) => {
                    GatewayServerFrame::Heartbeat { now }
                }
                Some(GatewayClientFrame::Resume { .. }) => {
                    GatewayServerFrame::Resume { entries: self.entry.take().into_iter().collect() }
                }
                Some(GatewayClientFrame::Ack { ack }) => {
                    self.queued.push_back(GatewayServerFrame::Cursor { cursor: None });
                    GatewayServerFrame::Ack {
                        cursor: GatewayCursor {
                            target_delivery_id: "bob".to_owned(),
                            inbox_seq: 1,
                            last_envelope_id: Some(ack.envelope_id.clone()),
                            acked_envelope_ids: vec![ack.envelope_id],
                            nacked_envelope_ids: BTreeMap::new(),
                        },
                    }
                }
                _ => GatewayServerFrame::Nack { reason: "unexpected frame".to_owned() },
            };
            serde_json::to_vec(&frame)
                .map_err(|e| ramflux_transport::TransportError::Quic(e.to_string()))
        })
    }
}
#[tokio::test(flavor = "current_thread")]
async fn compatibility_receive_acks_after_commit_and_returns_cached_plaintext()
-> Result<(), SdkError> {
    let a = Fixture::new("alice", 161)?;
    let mut b = Fixture::new("bob", 171)?;
    b.client.account_db()?.establish_friend_link("link", "bob", "alice")?;
    let entry =
        seal(&a, &b, message("compat-first", "compat-conversation"), b"compatibility plaintext")?;
    let acks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let engine = GatewaySessionEngine::with_test_transport(
        b.config()?,
        Box::new(ReceivingGateway {
            queued: VecDeque::new(),
            receipt_key: super::committed_key(&entry)?,
            entry: Some(entry),
            last: None,
            reader: b.client.account_db()?.open_reader()?,
            acks: std::sync::Arc::clone(&acks),
        }),
    );
    let client = std::mem::replace(&mut b.client, RamfluxClient::new());
    let mut state = LocalBusDaemonState {
        config: LocalBusConfig::new(b.root.join("bus.sock"), &b.root),
        nodes: crate::node::NodeStore::default(),
        account_index: None,
        accounts: BTreeMap::from([(
            "bob".to_owned(),
            LocalBusAccountState::new(client, engine, "commitment".to_owned()),
        )]),
        active_account_id: Some("bob".to_owned()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let (tx, _rx) = mpsc::channel(8);
    let connection = LocalBusConnectionState::new(1, tx);
    let request = LocalBusFrame::request(
        "receive",
        Some("bob".to_owned()),
        "message",
        "message.receive",
        serde_json::json!({"conversation_id":"compat-conversation","limit":10}),
    );
    for _ in 0..2 {
        let reply = crate::bus::dispatch::message::dispatch_message_receive_request(
            &request,
            &mut state,
            &connection,
        )
        .await?;
        assert_eq!(
            reply.response_body["decrypted_messages"][0]["plaintext_body_base64"],
            ramflux_protocol::encode_base64url(b"compatibility plaintext")
        );
        assert_eq!(acks.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    Ok(())
}

#[path = "review_tests.rs"]
mod review;

fn seal_group(
    sender: &Fixture,
    receiver: &Fixture,
    message: GatewayDirectMessage,
    body: &[u8],
) -> Result<GatewayInboxEntry, SdkError> {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    let route = if value["schema"] == "ramflux.sdk.group_sender_key.message.v1" {
        Route::group_message(value["group_id"].as_str().ok_or_else(|| invalid("group id"))?)
    } else {
        let decoded = ramflux_protocol::decode_base64url(
            value["distribution_base64"].as_str().ok_or_else(|| invalid("distribution"))?,
        )
        .map_err(|_| invalid("distribution"))?;
        let distribution: SdkGroupSenderKeyDistribution = serde_json::from_slice(&decoded)?;
        Route::group_control(&distribution.group_id)
    };
    seal_as(sender, receiver, message, body, route)
}

#[path = "r4_tests.rs"]
mod r4;

#[path = "r5_tests.rs"]
mod r5;

#[path = "session_record_tests.rs"]
mod session_record;
