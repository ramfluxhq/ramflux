// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SDK bootstrap and replenishment over production gateway and router dispatchers and mTLS.
#![allow(clippy::wildcard_imports)]
use super::*;
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_gateway::inprocess::Gateway;
use ramflux_router::inprocess::Router;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;

struct Wire {
    gateway: Gateway,
    identity: RootQualifiedDeviceRef,
    replies: VecDeque<Vec<u8>>,
}
impl GatewaySessionFrameSink for Wire {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(&'a mut self, body: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            let frames = self
                .gateway
                .frame(self.identity.clone(), body.to_vec())
                .await
                .map_err(|e| TransportError::Quic(e.to_string()))?;
            self.replies.extend(frames);
            Ok(())
        })
    }
}
impl GatewaySessionFrameSource for Wire {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.replies
                .pop_front()
                .ok_or_else(|| TransportError::Quic("missing real gateway reply".into()))
        })
    }
}
struct Harness {
    root: tempfile::TempDir,
    gateway: Gateway,
    router: Arc<RwLock<Option<Arc<Router>>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    endpoint: std::net::SocketAddr,
}
impl Harness {
    fn new() -> TestResult<Self> {
        use rcgen::{
            CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir()?;
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca.self_signed(&ca_key)?;
        let pem = ca_cert.pem();
        std::fs::write(root.path().join("ca.pem"), &pem)?;
        let issuer = Issuer::new(ca, ca_key);
        let cert = |service: &str| -> TestResult<ramflux_transport::MeshTlsConfig> {
            let mut leaf = CertificateParams::new(vec![
                service.into(),
                "localhost".into(),
                "127.0.0.1".into(),
            ])?;
            leaf.subject_alt_names
                .push(rcgen::SanType::URI(format!("spiffe://test-node/{service}").try_into()?));
            leaf.extended_key_usages =
                vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
            let key = KeyPair::generate()?;
            let cert = leaf.signed_by(&key, &issuer)?;
            let tls = ramflux_transport::MeshTlsConfig {
                ca_cert: root.path().join("ca.pem"),
                service_cert: root.path().join(format!("{service}.pem")),
                service_key: root.path().join(format!("{service}.key")),
            };
            std::fs::write(&tls.service_cert, cert.pem())?;
            std::fs::write(&tls.service_key, key.serialize_pem())?;
            Ok(tls)
        };
        let gateway_tls = cert("ramflux-gateway")?;
        let router_tls = cert("ramflux-router")?;
        let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &router_tls)?;
        let endpoint = server.local_addr()?;
        let router =
            Arc::new(RwLock::new(Some(Arc::new(Router::open(root.path().join("router.redb"))?))));
        let serving = Arc::clone(&router);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let mut workers = Vec::new();
            while !stopping.load(std::sync::atomic::Ordering::Relaxed) {
                let Ok(accepted) = server
                    .accept_authenticated_with_pem_roots(&router_tls, std::slice::from_ref(&pem))
                else {
                    continue;
                };
                let current = serving.read().ok().and_then(|r| r.clone());
                workers.push(std::thread::spawn(move || {
                    let Some(router) = current else { return };
                    let mut stream = accepted.stream;
                    if let Ok(Some(request)) =
                        ramflux_transport::read_mesh_http_request(&mut stream)
                    {
                        let Ok((status, body)) = router.dispatch(request, "ramflux-gateway") else {
                            return;
                        };
                        let status = if status == 200 { "200 OK" } else { "409 Conflict" };
                        if ramflux_transport::write_mesh_json_response(&mut stream, status, &body)
                            .is_err()
                        {
                            return;
                        }
                        let _ = ramflux_transport::close_mesh_server_stream(&mut stream);
                    }
                }));
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        let config = ramflux_node_core::NodeServiceConfig {
            node_id: "test-node".into(),
            service_id: "ramflux-gateway".into(),
            redb_path: root.path().join("gateway.redb").to_string_lossy().into_owned(),
            node_service_signing_seed_b64url: None,
            mesh: ramflux_node_core::MeshConfig {
                listen_addr: "127.0.0.1:0".into(),
                ca_cert: gateway_tls.ca_cert.to_string_lossy().into_owned(),
                service_cert: gateway_tls.service_cert.to_string_lossy().into_owned(),
                service_key: gateway_tls.service_key.to_string_lossy().into_owned(),
                allowed_service_ids: std::collections::BTreeSet::default(),
                endpoints: [("router".into(), endpoint.to_string())].into_iter().collect(),
            },
            gateway: None,
            signaling: None,
            relay: None,
        };
        let gateway = Gateway::open(&config)?;
        Ok(Self { root, gateway, router, stop, worker: Some(worker), endpoint })
    }
    fn client(&self, label: &str, seed: u8) -> TestResult<RamfluxClient> {
        let mut client = RamfluxClient::new();
        client.create_identity_root(label, [seed; 32]);
        client.create_device_branch(label, label, 1, [seed + 1; 32]);
        client.open_account_index(self.root.path().join(label))?;
        client.create_account(label, label)?;
        client.unlock_account(label, b"prekey-test")?;
        client.initialize_and_publish_prekey_bundle(label, label, label, [seed + 1; 32], None)?;
        Ok(client)
    }
    fn engine(&self, client: &RamfluxClient) -> TestResult<GatewaySessionEngine> {
        let branch = client.device_branch.as_ref().ok_or("branch")?;
        let config = GatewaySessionConfig::quic(crate::GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse()?,
            gateway_addr: "127.0.0.1:443".parse()?,
            server_name: "localhost".into(),
            ca_cert: self.root.path().join("ca.pem"),
            principal_id: branch.principal_id.clone(),
            device_id: branch.device_id.clone(),
            target_delivery_id: branch.device_id.clone(),
            prekey_http_url: None,
        })
        .with_owned_device(client.identity_root.as_ref().ok_or("root")?, branch.clone())?;
        Ok(GatewaySessionEngine::with_test_transport(
            config,
            Box::new(Wire {
                gateway: self.gateway.clone(),
                identity: client.owned_device_identity()?,
                replies: VecDeque::new(),
            }),
        ))
    }
    async fn restart(&self) -> TestResult {
        let old = self.router.write().map_err(|_| "router lock")?.take().ok_or("router")?;
        while Arc::strong_count(&old) > 1 {
            tokio::task::yield_now().await;
        }
        drop(old);
        *self.router.write().map_err(|_| "router lock")? =
            Some(Arc::new(Router::open(self.root.path().join("router.redb"))?));
        Ok(())
    }
    async fn publish(&self, client: &RamfluxClient) -> TestResult<SdkPrekeyResponse> {
        let own = client.owned_device_identity()?;
        let response = self
            .gateway
            .anonymous(ramflux_transport::GatewayQuicRequest {
                method: "GET".into(),
                path: format!("/mvp1/device-manifest/{}", own.root_commitment()),
                body: serde_json::Value::Null,
            })
            .await?;
        let manifest: Option<SdkDeviceManifestResponse> = serde_json::from_value(response.body)?;
        let record = client.prepare_owned_authority(manifest.as_ref())?;
        client.account_db()?.persist_actor_state("identity/registration_set", &record)?;
        let request = client.mvp1_identity_registration_request(
            own.device_id(),
            own.device_id(),
            "test-session",
            own.root_commitment(),
        )?;
        let mut engine = self.engine(client)?;
        engine.register_identity(request).await?;
        Ok(engine
            .publish_prekey_bundle(own.device_id(), &client.load_x3dh_private_state(&own)?.bundle)
            .await?)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = std::net::TcpStream::connect(self.endpoint);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn assert_public(bundle: &ramflux_crypto::PrekeyBundle) {
    assert!(bundle.one_time_prekey_id.is_none());
    assert!(bundle.one_time_prekey.is_none());
    assert!(bundle.one_time_prekey_signature.is_none());
    assert_eq!(bundle.one_time_prekey_ids, Vec::<String>::new());
    assert_eq!(bundle.one_time_prekey_x25519_public, Vec::<[u8; 32]>::new());
    assert_eq!(bundle.one_time_prekey_signatures, Vec::<String>::new());
}

async fn queue_bootstrap(
    h: &Harness,
    sender: &RamfluxClient,
    bundle: ramflux_crypto::PrekeyBundle,
    i: u8,
    own: &RootQualifiedDeviceRef,
) -> TestResult {
    let mut message = crate::GatewayDirectMessage {
        conversation_id: format!("queued-{i}"),
        message_id: format!("message-{i}"),
        envelope_id: format!("envelope-{i}"),
        source_principal_id: format!("sender-{i}"),
        sender_id: format!("sender-{i}"),
        recipient_device_id: Some("bob".into()),
        recipient_principal_commitment: Some(own.root_commitment().into()),
        target_delivery_id: "bob".into(),
        encrypted_body: vec![],
        created_at: crate::time::now_unix_timestamp(),
        ttl: 3600,
    };
    let (mut session, header) = sender.create_send_dm_session_from_bundle(
        &message,
        "bob",
        bundle,
        &format!("sender-{i}"),
    )?;
    let aad = crate::dm::dm_associated_data(&message.conversation_id);
    message.encrypted_body = serde_json::to_vec(&(
        message.conversation_id.clone(),
        header.ok_or("header")?,
        session.encrypt(b"queued first message", aad)?,
    ))?;
    let envelope =
        crate::dm::gateway_direct_message_envelope(&h.engine(sender)?.config, &message, None)?;
    let accepted = h
        .gateway
        .anonymous(ramflux_transport::GatewayQuicRequest {
            method: "POST".into(),
            path: "/mvp0/envelope".into(),
            body: serde_json::to_value(envelope)?,
        })
        .await?;
    assert_eq!(accepted.status, 200);
    assert!(accepted.body["inbox_seq"].as_u64().is_some());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_gateway_router_preserve_seven_queued_bootstraps_across_replenishment_and_restart()
-> TestResult {
    let h = Harness::new()?;
    let bob = h.client("bob", 10)?;
    let own = bob.owned_device_identity()?;
    let response = h.publish(&bob).await?;
    assert_public(response.bundle.as_ref().ok_or("published bundle")?);
    let anonymous = h
        .gateway
        .anonymous(ramflux_transport::GatewayQuicRequest {
            method: "GET".into(),
            path: format!("/mvp1/prekey/{}", own.storage_key()),
            body: serde_json::Value::Null,
        })
        .await?;
    let anonymous: SdkPrekeyResponse = serde_json::from_value(anonymous.body)?;
    assert_public(anonymous.bundle.as_ref().ok_or("anonymous bundle")?);
    let initial = bob
        .load_x3dh_private_state(&own)?
        .one_time_prekeys
        .iter()
        .map(|k| k.id.clone())
        .collect::<Vec<_>>();
    let mut senders = Vec::new();

    let mut ids = std::collections::BTreeSet::new();
    for i in 0..7u8 {
        // A restart after the first hourly allowance permits the seventh lease and verifies recovery.
        if i == 6 {
            h.restart().await?;
        }
        let sender = h.client(&format!("sender-{i}"), 30 + 2 * i)?;
        h.publish(&sender).await?;
        let response = h.engine(&sender)?.fetch_prekey_bundle(own.storage_key()).await?;
        let bundle = response.bundle.ok_or("leased bundle")?;
        assert!(ids.insert(bundle.one_time_prekey_id.clone().ok_or("leased OPK")?));
        queue_bootstrap(&h, &sender, bundle, i, &own).await?;
        senders.push(sender);
    }
    // Real publish reports the directory low water mark; the SDK adds fresh ids and republishes.
    let mut engine = h.engine(&bob)?;
    let response = h
        .engine(&bob)?
        .publish_prekey_bundle("bob", &bob.load_x3dh_private_state(&own)?.bundle)
        .await?;
    assert_eq!(response.available_one_time_prekeys, 1);
    assert!(bob.directory_requests_prekey_replenishment("bob", &response)?);
    let fresh =
        bob.replenish_one_time_prekeys("bob", [11; 32], response.available_one_time_prekeys)?;
    assert!(initial.iter().all(|id| fresh.one_time_prekey_ids.contains(id)));
    assert_eq!(fresh.one_time_prekey_ids.len(), 15);
    let response = engine.publish_prekey_bundle("bob", &fresh).await?;
    assert_eq!(response.available_one_time_prekeys, 8);
    assert_public(response.bundle.as_ref().ok_or("published bundle")?);
    let anonymous = h
        .gateway
        .anonymous(ramflux_transport::GatewayQuicRequest {
            method: "GET".into(),
            path: format!("/mvp1/device-manifest/{}", own.root_commitment()),
            body: serde_json::Value::Null,
        })
        .await?;
    let manifest: SdkDeviceManifestResponse = serde_json::from_value(anonymous.body)?;
    assert_public(&manifest.devices[0].prekey_bundle);
    let mut cached = manifest;
    cached.devices[0].prekey_bundle = fresh;
    let serialized = serde_json::to_value(cached)?;
    let cached: SdkDeviceManifestResponse = serde_json::from_value(serialized)?;
    assert_public(&cached.devices[0].prekey_bundle);
    let inbox = engine.resume_after(0, 16).await?;
    assert_eq!(inbox.len(), 7);
    for entry in inbox {
        let payload = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)?;
        let (conversation, header, ciphertext): (
            String,
            crate::dm::SdkDmX3dhHeader,
            ramflux_crypto::DmCiphertext,
        ) = serde_json::from_slice(&payload)?;
        let aad = crate::dm::dm_associated_data(&conversation);
        let mut receiving = bob.create_recv_dm_session_with_aad(&header, aad)?;
        assert_eq!(receiving.decrypt(&ciphertext, aad)?, b"queued first message");
        bob.persist_dm_session(&conversation, &conversation, "recv", &receiving)?;
    }
    let remaining = bob.load_x3dh_private_state(&own)?;
    assert_eq!(remaining.one_time_prekeys.len(), 8);
    assert!(remaining.one_time_prekeys.iter().all(|k| !ids.contains(&k.id)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_gateway_router_account_and_target_limits_return_working_fallbacks() -> TestResult {
    let h = Harness::new()?;
    let bob = h.client("bob", 10)?;
    h.publish(&bob).await?;
    let own = bob.owned_device_identity()?;
    let alice = h.client("alice", 20)?;
    h.publish(&alice).await?;
    let mut engine = h.engine(&alice)?;
    assert!(
        engine
            .fetch_prekey_bundle(own.storage_key())
            .await?
            .bundle
            .ok_or("bundle")?
            .one_time_prekey_id
            .is_some()
    );
    for index in 0..2u8 {
        let mut device = h.client(&format!("alice-{index}"), 22 + index * 2)?;
        device.create_identity_root("alice", [20; 32]);
        device.create_device_branch("alice", &format!("alice-{index}"), 1, [23 + index * 2; 32]);
        // The branch agreement identity is retained from its independently opened account.
        let identity = device.owned_device_identity()?;
        device.initialize_and_publish_prekey_bundle(
            "alice",
            identity.device_id(),
            identity.device_id(),
            [23 + index * 2; 32],
            None,
        )?;
        h.publish(&device).await?;
        let fallback = h
            .engine(&device)?
            .fetch_prekey_bundle(own.storage_key())
            .await?
            .bundle
            .ok_or("fallback")?;
        assert_public(&fallback);
        let message = crate::GatewayDirectMessage {
            conversation_id: format!("fallback-{index}"),
            message_id: "fallback".into(),
            envelope_id: "fallback".into(),
            source_principal_id: "alice".into(),
            sender_id: identity.device_id().into(),
            recipient_device_id: Some("bob".into()),
            recipient_principal_commitment: Some(own.root_commitment().into()),
            target_delivery_id: "bob".into(),
            encrypted_body: vec![],
            created_at: crate::time::now_unix_timestamp(),
            ttl: 3600,
        };
        let (mut sender, header) = device.create_send_dm_session_from_bundle(
            &message,
            "bob",
            fallback,
            identity.device_id(),
        )?;
        let aad = crate::dm::dm_associated_data(&message.conversation_id);
        let ciphertext = sender.encrypt(b"fallback works", aad)?;
        let mut receiver = bob.create_recv_dm_session_with_aad(&header.ok_or("header")?, aad)?;
        assert_eq!(receiver.decrypt(&ciphertext, aad)?, b"fallback works");
    }
    let mut engines = Vec::new();
    for i in 0..8u8 {
        let client = h.client(&format!("other-{i}"), 60 + i * 2)?;
        h.publish(&client).await?;
        engines.push(h.engine(&client)?);
    }
    let mut pending = tokio::task::JoinSet::new();
    let lookup = own.storage_key().to_owned();
    for mut engine in engines {
        let lookup = lookup.clone();
        pending.spawn(async move { engine.fetch_prekey_bundle(&lookup).await });
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut fallbacks = 0;
    while let Some(response) = pending.join_next().await {
        let bundle = response??.bundle.ok_or("bundle")?;
        if let Some(id) = bundle.one_time_prekey_id {
            assert!(ids.insert(id));
        } else {
            assert_public(&bundle);
            fallbacks += 1;
        }
    }
    assert_eq!(ids.len(), 5);
    assert_eq!(fallbacks, 3);
    h.restart().await?;
    let after = h
        .engine(&alice)?
        .fetch_prekey_bundle(own.storage_key())
        .await?
        .bundle
        .ok_or("restart bundle")?;
    assert!(!ids.contains(after.one_time_prekey_id.as_ref().ok_or("restart OPK")?));
    let response = h
        .engine(&bob)?
        .publish_prekey_bundle("bob", &bob.load_x3dh_private_state(&own)?.bundle)
        .await?;
    assert_eq!(response.available_one_time_prekeys, 1);
    Ok(())
}
