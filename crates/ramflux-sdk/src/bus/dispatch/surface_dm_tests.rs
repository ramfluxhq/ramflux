// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared DM transport journals one logical surface across peer devices and retries.
use super::*;
use crate::bus::runtime_tests;
use ramflux_protocol::{A2uiConversationCommand, CreateSurfaceCommand, SurfaceType};
use std::sync::{Arc, Mutex, atomic::AtomicBool};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn conversation_send_derives_routes_and_seals_for_every_verified_peer_device() -> TestResult {
    Box::pin(tokio::time::timeout(Duration::from_secs(30), async {
        let root = tempfile::tempdir()?;
        let mut source = runtime_tests::account(
            &root.path().join("source"),
            "sender",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let PeerFixture { peers, config, directory, .. } =
            peer_fixture(root.path(), &mut source).await?;
        let captured = Arc::new(Mutex::new(Vec::new()));
        source.install_test_session(GatewaySessionEngine::with_test_transport(
            config,
            Box::new(super::fixture::RecordingGateway::new(captured.clone())),
        ));
        let mut request = LocalBusFrame::request(
            "send",
            Some("sender".into()),
            "conversation",
            "conversation.send",
            json!({"conversation_id":conversation(&source.client)?,"text":"Native text"}),
        );
        request.operation_id = Some("host-send-1".into());
        // Admission number 1,025 must recycle terminal metadata and reach the real send path.
        let now = now_unix_timestamp();
        source.client.account_db()?.write_transaction(|| {
            for n in 0..super::conversation_journal::LIMIT {
                source.client.account_db()?.persist_actor_state(
                    &format!("conversation-send/seed-{n:04}"),
                    &json!({"fingerprint":n.to_string(),"expires_at":now+3600,
                        "completed":n != 1023,"completed_at":now-1024+i64::from(n)}),
                )?;
            }
            Ok::<_, SdkError>(())
        })?;

        let response =
            crate::bus::dispatch::conversation_send::send_account(&request, &mut source).await?;
        assert_eq!(
            response.response_body["delivery_state"], "submitted",
            "SDK fan-out must submit all peers"
        );
        let db = source.client.account_db()?;
        assert!(!db.actor_state_exists("conversation-send/seed-0000")?, "oldest terminal makes room for send 1,025");
        assert!(db.actor_state_exists("conversation-send/seed-1023")?, "pending receipt survives actual send");
        assert_eq!(db.actor_state_usage("conversation-send/")?.0, 1024, "actual send preserves receipt cap");
        let key = format!("conversation-send/{}", ramflux_crypto::blake3_256_base64url(
            "ramflux.conversation.send.operation.v1", b"host-send-1"));
        let receipt = db.load_actor_state::<Value>(&key)?.ok_or("test: sent receipt")?;
        assert_eq!(receipt["completed"], true, "real all-device submission marks receipt terminal");
        let envelopes = captured.lock().map_err(|_| "capture poisoned")?.clone();
        assert_eq!(envelopes.len(), 2, "verified two-device directory must determine fan-out");
        assert_ne!(
            envelopes.first().ok_or("first envelope")?.encrypted_payload,
            ramflux_protocol::encode_base64url(b"Native text"),
            "SDK must seal native plaintext"
        );
        assert_eq!(
            source.client.direct_messages(&conversation(&source.client)?)?.len(),
            1,
            "fan-out must retain one logical local message"
        );
        let retry = crate::bus::dispatch::conversation_send::send_account(&request, &mut source).await?;
        assert_eq!(retry.response_body["message_id"], response.response_body["message_id"], "exact retry keeps its logical identity");
        assert_eq!(retry.response_body["delivery_state"], "submitted", "exact intent retry remains valid");
        let baseline = captured.lock().map_err(|_| "capture poisoned")?.len();
        let original = request.body.clone();
        source.client.account_db()?.persist_client_record("conversation", "other-thread", &json!({"kind":"direct","participants":["sender","peer"]}))?;
        for changed in [
            json!({"conversation_id":conversation(&source.client)?,"text":"Changed text"}),
            json!({"conversation_id":"other-thread","text":"Native text"}),
            json!({"conversation_id":conversation(&source.client)?,"text":"Native text","attachments":[{"object_id":"changed","plaintext_base64":"eA","chunk_size":1024,"relay_endpoint":"https://relay.example.invalid"}]}),
        ] {
            request.body = changed;
            let error = crate::bus::dispatch::conversation_send::send_account(&request,&mut source).await.err().ok_or("changed intent was accepted")?;
            if request.body.get("attachments").is_some() {
                assert!(matches!(error, SdkError::GeneratedRefused { code: crate::GeneratedRefusalCode::Content, .. }), "retired attachment metadata requires a typed Content refusal");
            } else {
                assert_eq!(crate::bindings::AdapterError::from_sdk(&error).code,crate::bindings::GeneratedErrorCode::InvalidArgument as i32,"different intent has a typed refusal");
            }
            assert_eq!(captured.lock().map_err(|_| "capture poisoned")?.len(),baseline,"rejected retry must never reach transport");
        }
        request.body = original;
        request.body["sender_id"] = json!("host-forged");
        assert!(
            crate::bus::dispatch::conversation_send::send_account(&request, &mut source)
                .await
                .is_err(),
            "native callers cannot override authenticated sender routing"
        );
        directory.abort();
        drop(peers);
        Ok::<_, Box<dyn std::error::Error>>(())
    }))
    .await?
}

#[tokio::test]
async fn two_device_peer_retries_keep_one_logical_timeline_and_safe_failed_fallback() -> TestResult
{
    let root = runtime_tests::root("surface-dm");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let PeerFixture { mut peers, config, address, directory } =
        peer_fixture(&root, &mut source).await?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut gateway = super::fixture::RecordingGateway::new(captured.clone());
    gateway.fail_after = Some(1);
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(gateway),
    ));
    let carrier = create_carrier(&source.client)?;
    let failed = send(&mut source, &carrier).await;
    eprintln!("injected failure result: {failed:?}");
    assert!(failed.is_err());
    assert_eq!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 1);
    let timeline = source.client.surface_generated_message_id(&carrier)?;
    let first_cipher =
        source.client.account_db()?.message_content(&timeline)?.ok_or("logical message")?;
    assert_ne!(first_cipher, [] as [u8; 0]);
    assert_eq!(source.client.surface_get("surface", 0, None)?["delivery_state"], "failed");
    let fallback = source.client.account_db()?.message_content(&timeline)?.ok_or("fallback")?;
    let (_, content) = RamfluxClient::decode_generated_inner(&fallback)?;
    assert!(
        matches!(content.value, Some(ramflux_protocol::message::content::Value::Surface(_))),
        "retained projection must be a typed Surface"
    );
    assert!(
        source.client.surface_get("surface", 0, None)?["fallback_text"]
            .as_str()
            .is_some_and(|text| text.contains("Safe fallback")),
        "failed transport preserves the public safe fallback"
    );
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config,
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    assert_eq!(send(&mut source, &carrier).await?["delivery_state"], "submitted");
    assert_eq!(
        source.client.account_db()?.message_content(&timeline)?.ok_or("logical message")?,
        first_cipher
    );
    assert_eq!(source.client.direct_messages(&conversation(&source.client)?)?.len(), 1);
    let envelopes = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(envelopes.len(), 3, "one failed fanout plus two successful targets");
    assert_eq!(
        envelopes.first(),
        envelopes.get(1),
        "retry must reuse the exact already sealed target envelope"
    );
    Box::pin(assert_deliveries(&root, address, &source.client, &mut peers, envelopes, &timeline))
        .await?;
    directory.abort();
    drop(peers);
    drop(source);
    Ok(())
}

pub(super) struct PeerFixture {
    pub(super) peers: Vec<LocalBusAccountState>,
    pub(super) config: GatewaySessionConfig,
    pub(super) address: SocketAddr,
    pub(super) directory: tokio::task::JoinHandle<()>,
}
pub(super) async fn peer_fixture(
    root: &Path,
    source: &mut LocalBusAccountState,
) -> Result<PeerFixture, Box<dyn std::error::Error>> {
    peer_fixture_devices(root, source, &["device-peer-one", "device-peer-two"]).await
}
pub(super) async fn peer_fixture_devices(
    root: &Path,
    source: &mut LocalBusAccountState,
    devices: &[&str],
) -> Result<PeerFixture, Box<dyn std::error::Error>> {
    use crate::client::native_test_support::{
        Fixture as Native, activation_send::tests::publish_layer_four, bus,
    };
    assert!(!devices.is_empty() && devices.len() <= 8, "bounded peer fixture device inventory");
    let mut native = Box::pin(Native::with_principal("sender", "device-sender", "sender")).await?;
    Box::pin(publish_layer_four(&mut native)).await?;
    let mut peer =
        Box::pin(Native::with_principal("peer", devices.first().ok_or("peer device")?, "peer"))
            .await?;
    Box::pin(publish_layer_four(&mut peer)).await?;
    let mut first = peer.into_bus();
    let mut peers = Vec::new();
    for device in devices.iter().skip(1) {
        peers.push(Box::pin(bus::sibling(&mut first, device, device)).await?);
    }
    peers.insert(0, first);
    let peer_manifest = super::fixture::manifest(&peers.first().ok_or("peer")?.client)?;
    let own = native.manifest.clone();
    *source = native.into_bus();
    source.client.persist_fetched_identity_directory(&peer_manifest)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &own.principal_commitment,
        &peer_manifest.principal_commitment,
    )?;
    for account in std::iter::once(&*source).chain(peers.iter()) {
        account.client.persist_fetched_identity_directory(&own)?;
        account.client.persist_fetched_identity_directory(&peer_manifest)?;
        account.client.establish_friend_link(
            "surface-peer",
            &own.principal_commitment,
            &peer_manifest.principal_commitment,
        )?;
        account.client.account_db()?.persist_client_record("conversation", &conversation, &json!({"kind":"direct","group_id":null,"participants":["sender","peer"],"participant_roots":[own.principal_commitment,peer_manifest.principal_commitment]}))?;
        account
            .client
            .account_db()?
            .persist_actor_state("fixture/direct-conversation", &conversation)?;
        account.client.account_db()?.persist_client_record(
            "identity",
            "peer",
            &json!({"contact_identity_commitment":peer_manifest.principal_commitment}),
        )?;
        account.client.account_db()?.persist_client_record(
            "identity",
            "sender",
            &json!({"contact_identity_commitment":own.principal_commitment}),
        )?;
    }
    for peer in &peers {
        bus::seed_pair(&source.client, &peer.client)?;
    }
    let manifests = BTreeMap::from([
        (own.principal_commitment.clone(), serde_json::to_value(own)?),
        (peer_manifest.principal_commitment.clone(), serde_json::to_value(peer_manifest)?),
    ]);
    let (address, directory) = super::fixture::directory(root, manifests).await?;
    let mut config = source.gateway_config.clone();
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "test-gateway".into();
    config.ca_cert = root.join("ca.pem");
    source.gateway_config = config.clone();
    Ok(PeerFixture { peers, config, address, directory })
}

pub(super) fn conversation(client: &RamfluxClient) -> Result<String, SdkError> {
    client
        .account_db()?
        .load_actor_state("fixture/direct-conversation")?
        .ok_or_else(|| invalid("test: canonical conversation missing"))
}
pub(super) fn create_carrier(source: &RamfluxClient) -> Result<Carrier, SdkError> {
    create_carrier_in(source, &conversation(source)?)
}
pub(super) fn create_carrier_in(
    source: &RamfluxClient,
    conversation: &str,
) -> Result<Carrier, SdkError> {
    let request = crate::SurfaceSendRequest::event(
        conversation,
        1,
        &A2uiConversationCommand::CreateSurface(CreateSurfaceCommand {
            surface_id: "surface".into(),
            surface_type: SurfaceType::StatusPanel,
            catalog: "basic".into(),
            catalog_version: "1".into(),
            fallback_text: "Safe fallback".into(),
            fallback_markdown: None,
            components: vec![json!({"id":"result","text":""})],
            data_model: serde_json::Map::default(),
            allowed_actions: Vec::new(),
        }),
    )?;
    let mut carrier = Carrier {
        typed: None,
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        posted_at: None,
        updated_at: None,
        payload_kind: PayloadKind::Event,
        conversation_id: conversation.to_owned(),
        surface_id: "surface".into(),
        message_id: request.message_id,
        sender_principal_id: "sender".into(),
        sender_device_id: "device-sender".into(),
        author_principal_id: "sender".into(),
        wire_base64: request.wire_base64,
        signature: String::new(),
        snapshot: None,
    };
    source.attach_surface_snapshot(&mut carrier)?;
    let carrier = source.sign_surface_carrier(carrier)?;
    Ok(carrier)
}
async fn assert_deliveries(
    root: &Path,
    address: SocketAddr,
    source: &RamfluxClient,
    peers: &mut [LocalBusAccountState],
    envelopes: Vec<ramflux_protocol::Envelope>,
    timeline: &str,
) -> TestResult {
    let mut counts = [0; 2];
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    for (seq, envelope) in envelopes.into_iter().enumerate() {
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: u64::try_from(seq + 1)?,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        };
        for (index, peer) in peers.iter_mut().enumerate() {
            if entry.target_delivery_id == peer.target_delivery_id {
                let mut config = peer.gateway_config.clone();
                config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
                config.gateway_addr = address;
                config.tcp_gateway_addr = Some(address);
                config.server_name = "test-gateway".into();
                config.ca_cert = root.join("ca.pem");
                // Already authenticated directory records isolate this receive from prekey discovery.
                let own_manifest = super::fixture::manifest(source)?;
                peer.client.persist_fetched_identity_directory(&own_manifest)?;
                let mut engine = GatewaySessionEngine::with_test_transport(
                    config,
                    Box::new(super::fixture::RecordingGateway::new(Arc::default())),
                );
                let result = peer.client.apply_routed_entry(&mut engine, &pool, &entry).await?;
                assert_eq!(result.routing.map(|route| route.message_id), Some(timeline.to_owned()));
                assert_eq!(peer.client.surface_get("surface", 0, None)?["version"], 1);
                assert_eq!(peer.client.direct_messages(&conversation(source)?)?.len(), 1);
                // Exact-envelope retry also retains the committed logical projection.
                assert_eq!(
                    peer.client
                        .apply_routed_entry(&mut engine, &pool, &entry)
                        .await?
                        .routing
                        .map(|route| route.message_id),
                    Some(timeline.to_owned())
                );
                counts[index] += 1;
            }
        }
    }
    assert_eq!(counts, [2, 1]);
    Ok(())
}
