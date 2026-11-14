// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared DM transport journals one logical surface across peer devices and retries.
use super::*;
use crate::bus::runtime_tests;
use crate::client::surface::test_support::{create_frame, text_snapshot};
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
            json!({"conversation_id":"thread","text":"Native text"}),
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
            source.client.direct_messages("thread")?.len(),
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
            json!({"conversation_id":"thread","text":"Changed text"}),
            json!({"conversation_id":"other-thread","text":"Native text"}),
            json!({"conversation_id":"thread","text":"Native text","attachments":[{"object_id":"changed","plaintext_base64":"eA","chunk_size":1024,"relay_endpoint":"https://relay.example.invalid"}]}),
        ] {
            request.body = changed;
            let error = crate::bus::dispatch::conversation_send::send_account(&request,&mut source).await.err().ok_or("changed intent was accepted")?;
            assert_eq!(crate::bindings::AdapterError::from_sdk(&error).code,crate::bindings::GeneratedErrorCode::InvalidArgument as i32,"different intent has a typed refusal");
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
    let timeline = RamfluxClient::surface_timeline_id(&carrier)?;
    let first_cipher =
        source.client.direct_message_by_id(&timeline)?.ok_or("logical message")?.encrypted_body;
    assert_ne!(first_cipher, [] as [u8; 0]);
    assert_eq!(source.client.surface_get("surface", 0, None)?["delivery_state"], "failed");
    let fallback = source.client.account_db()?.message_content(&timeline)?.ok_or("fallback")?;
    assert!(String::from_utf8(fallback)?.contains("Safe fallback"));
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config,
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    assert_eq!(send(&mut source, &carrier).await?["delivery_state"], "submitted");
    assert_eq!(
        source.client.direct_message_by_id(&timeline)?.ok_or("logical message")?.encrypted_body,
        first_cipher
    );
    assert_eq!(source.client.direct_messages("thread")?.len(), 1);
    let envelopes = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(envelopes.len(), 3);
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
    let mut peers = Vec::new();
    let mut peer_manifest = None;
    for (index, device) in devices.iter().enumerate() {
        let mut peer = runtime_tests::account(
            &root.join(device),
            "peer",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        peer.client.create_identity_root("peer", [91; 32]);
        peer.client.create_device_branch("peer", device, 1, [92 + u8::try_from(index)?; 32]);
        let mut manifest = super::fixture::manifest(&peer.client)?;
        manifest.devices[0].target_delivery_id = device.to_string();
        if let Some(existing) = peer_manifest.as_mut() {
            let existing: &mut crate::prekey::SdkDeviceManifestResponse = existing;
            existing.devices.extend(manifest.devices);
        } else {
            peer_manifest = Some(manifest);
        }
        let send = ramflux_crypto::DmSession::initiator(
            [50 + u8::try_from(index)?; 32],
            dm_device_id_hash("device-sender"),
            dm_device_id_hash(device),
            [3; 32],
        )?;
        let recv = ramflux_crypto::DmSession::recipient(
            [50 + u8::try_from(index)?; 32],
            dm_device_id_hash(device),
            dm_device_id_hash("device-sender"),
            [3; 32],
        )?;
        source.client.persist_pair(
            &source.client.owned_device_identity()?,
            &peer.client.owned_device_identity()?,
            &[4; 32],
            &send,
        )?;
        peer.client.persist_pair(
            &peer.client.owned_device_identity()?,
            &source.client.owned_device_identity()?,
            &[4; 32],
            &recv,
        )?;
        peer.client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"direct","participants":["sender","peer"]}),
        )?;
        peer.client.account_db()?.persist_client_record("device","device-sender",&json!({"principal_id":"sender","signing_public_key":ramflux_protocol::encode_base64url(source.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.signing_key.verifying_key().to_bytes())}))?;
        peers.push(peer);
    }
    if let Some(manifest) = peer_manifest.as_mut() {
        crate::client::identity_authority::test_support::sign_manifest(
            peers[0].client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            manifest,
            2,
        )?;
        source.client.persist_root_verified_directory(manifest)?;
        for peer in &peers {
            configure_receiver(&peer.client, &source.client, manifest)?;
        }
    }
    let peer_manifest = peer_manifest.ok_or("peer manifest")?;
    source.client.account_db()?.establish_friend_link("surface-peer", "sender", "peer")?;
    let own = super::fixture::manifest(&source.client)?;
    source.principal_commitment = own.principal_commitment.clone();
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"direct","participants":["sender","peer"]}),
    )?;
    source.client.account_db()?.persist_client_record(
        "identity",
        "peer",
        &json!({"contact_identity_commitment":peer_manifest.principal_commitment}),
    )?;
    let manifests = BTreeMap::from([
        (own.principal_commitment.clone(), serde_json::to_value(own)?),
        (peer_manifest.principal_commitment.clone(), serde_json::to_value(peer_manifest)?),
    ]);
    let (address, directory) = super::fixture::directory(root, manifests).await?;
    let config = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: address,
        server_name: "test-gateway".into(),
        ca_cert: root.join("ca.pem"),
        principal_id: "sender".into(),
        device_id: "device-sender".into(),
        target_delivery_id: "sender".into(),
        prekey_http_url: None,
    })
    .with_account_identity(&source.client)?;
    Ok(PeerFixture { peers, config, address, directory })
}
fn configure_receiver(
    peer: &RamfluxClient,
    source: &RamfluxClient,
    manifest: &crate::prekey::SdkDeviceManifestResponse,
) -> Result<(), SdkError> {
    peer.persist_root_verified_directory(manifest)?;
    peer.persist_root_verified_directory(&super::fixture::manifest(source)?)?;
    peer.establish_friend_link(
        "surface-receiver-consent",
        source.owned_device_identity()?.root_commitment(),
        peer.owned_device_identity()?.root_commitment(),
    )?;
    Ok(())
}
pub(super) fn create_carrier(source: &RamfluxClient) -> Result<Carrier, SdkError> {
    let request = crate::SurfaceSendRequest::event(&create_frame(
        "thread",
        &text_snapshot("surface", "Safe fallback", &("")),
    )?)?;
    let carrier = Carrier {
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        posted_at: None,
        updated_at: None,
        payload_kind: PayloadKind::Event,
        conversation_id: "thread".into(),
        surface_id: "surface".into(),
        message_id: request.message_id,
        sender_principal_id: "sender".into(),
        sender_device_id: "device-sender".into(),
        author_principal_id: "sender".into(),
        wire_base64: request.wire_base64,
        signature: String::new(),
        snapshot: None,
    };

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
            let device = peer
                .client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .device_id
                .clone();
            if peer.client.open_routed(&entry, &device).is_ok() {
                let config = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
                    bind_addr: "127.0.0.1:0".parse()?,
                    gateway_addr: address,
                    server_name: "test-gateway".into(),
                    ca_cert: root.join("ca.pem"),
                    principal_id: "peer".into(),
                    device_id: device,
                    target_delivery_id: "peer".into(),
                    prekey_http_url: None,
                })
                .with_account_identity(&peer.client)?;
                // Already authenticated directory records isolate this receive from prekey discovery.
                let own_manifest = super::fixture::manifest(source)?;
                peer.client.persist_identity_directory(&own_manifest)?;
                let mut engine = GatewaySessionEngine::with_test_transport(
                    config,
                    Box::new(super::fixture::RecordingGateway::new(Arc::default())),
                );
                let result =
                    peer.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
                assert_eq!(result.routing.map(|route| route.message_id), Some(timeline.to_owned()));
                assert!(
                    peer.client.surface_get("surface", 0, None)?.is_null(),
                    "human-authored peer cards remain fallback-only"
                );
                assert_eq!(peer.client.direct_messages("thread")?.len(), 1);
                // Exact-envelope retry also retains the committed logical projection.
                assert_eq!(
                    peer.client
                        .apply_routed_entry(&mut engine, &pool, &entry, false)
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
