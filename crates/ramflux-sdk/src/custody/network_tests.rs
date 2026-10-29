// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual TLS, bus ceremony, native admission and account-isolated sessions.
use super::*;
use ramflux_protocol::custody::*;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) struct Root(pub(crate) PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Shutdown(tokio::sync::watch::Sender<bool>);
impl Drop for Shutdown {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}
async fn create(socket: &Path, id: &str, principal: &str) -> Result<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut bus = loop {
        match CustodyBusClient::connect(socket).await {
            Ok(c) => break c,
            Err(crate::SdkError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(e) => return Err(e.into()),
        }
    };
    let anchor = bus
        .begin(&CreateInput {
            local_account_id: id.into(),
            principal_id: principal.into(),
            device_id: "primary".into(),
            display_name: principal.into(),
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            custodian_account_id: None,
        })
        .await?;
    let phrase = bus.show_once().await?;
    let words: Vec<_> =
        phrase.split_whitespace().map(|word| Zeroizing::new(word.to_string())).collect();
    drop(phrase);
    let positions = bus.hidden_challenge().await?;
    let confirm = std::array::from_fn(|i| words[usize::from(positions[i] - 1)].clone());
    let confirmed = bus.confirm(&confirm).await?;
    assert_eq!(confirmed.state, CreationState::NetworkingPending);
    Ok(anchor)
}
pub(super) fn node(
    now: u64,
    certificate_hash: String,
) -> Result<ramflux_crypto::custody::VerifiedNodeRecord> {
    let key = ramflux_crypto::fixture_signing_key();
    let body = NodeIdentityRecord {
        schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
        version: 1,
        node_id: "node".into(),
        node_signing_public_key: ramflux_protocol::encode_base64url(key.verifying_key().to_bytes()),
        client_tls_certificate_sha256: Some(certificate_hash),
        epoch: 1,
        previous_record_hash: None,
        issued_at: now,
        receipt_keys: vec![],
        revoked_receipt_key_ids: vec![],
        proxy_keys: vec![],
        revoked_proxy_key_ids: vec![],
        channel_binding_modes: vec![BindingMode::DirectExporter],
    };
    let record = ramflux_crypto::custody::sign_node_identity_record(&key, body)?;
    Ok(ramflux_crypto::custody::verify_node_identity_record(
        &record,
        "node",
        &ramflux_crypto::fixture_public_key_base64url(),
        now,
    )?)
}
async fn tls_server(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    router: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
    service: Arc<ramflux_node_core::CustodyService>,
    corrupt_recovery_ack: Arc<std::sync::atomic::AtomicBool>,
) -> Result {
    let mut stream = ramflux_transport::GatewayTcpTlsStream::Server(stream);
    let connection = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    loop {
        let bytes = match ramflux_transport::read_custody_tcp_frame(&mut stream).await {
            Ok(v) => v,
            Err(ramflux_transport::TransportError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        let frame: CustodyClientFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
        let exporter = if let CustodyClientFrame::Prove { proof, .. } = &frame {
            let nonce = ramflux_protocol::decode_base64url(&proof.body.challenge_nonce)?
                .try_into()
                .map_err(|_| "nonce")?;
            Some(ramflux_transport::custody_tcp_exporter(&stream, &nonce)?)
        } else {
            None
        };
        let replacement = matches!(&frame, CustodyClientFrame::Prove { action: CustodyProofAction::Publish { publication }, .. }
            if decode_epoch(publication.record.body.device_set_epoch)?.0 > 1);
        let mut response = service.tls(
            &router,
            &store,
            frame,
            ramflux_node_core::CustodyTlsContext {
                connection_id: &connection,
                remote_ip: "127.0.0.1",
                mode: BindingMode::DirectExporter,
                exporter,
            },
            super::network::now()?,
        );
        if replacement
            && matches!(response, CustodyServerFrame::Published { .. })
            && corrupt_recovery_ack.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            response = CustodyServerFrame::Published {
                record_hash: ramflux_protocol::encode_base64url([99; 32]),
            };
        }
        ramflux_transport::write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?)
            .await?;
    }
}
async fn start_server(
    root: &Root,
) -> Result<(std::net::SocketAddr, PathBuf, tokio::task::JoinHandle<Result>)> {
    start_server_with_ack_fault(root, false).await
}
pub(crate) async fn start_server_with_ack_fault(
    root: &Root,
    corrupt_ack: bool,
) -> Result<(std::net::SocketAddr, PathBuf, tokio::task::JoinHandle<Result>)> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let ca = root.0.join("ca.pem");
    let cert = root.0.join("tls.pem");
    let key = root.0.join("tls.key");
    std::fs::write(&ca, certificate.cert.pem())?;
    std::fs::write(&cert, certificate.cert.pem())?;
    std::fs::write(&key, certificate.signing_key.serialize_pem())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        ramflux_transport::tcp_gateway_server_config(&ramflux_transport::MeshTlsConfig {
            ca_cert: ca.clone(),
            service_cert: cert.clone(),
            service_key: key,
        })?,
    ));
    let router = Arc::new(ramflux_node_core::RouterCore::new());
    let store = Arc::new(ramflux_node_core::RouterRedbStore::open(root.0.join("router.redb"))?);
    store.save_router(&router)?;
    let service = Arc::new(ramflux_node_core::CustodyService::new(
        node(super::network::now()?, ramflux_transport::custody_certificate_file_hash(&cert)?)?,
        false,
        &store,
        super::network::now()?,
    )?);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let mut clients = Vec::new();
        let fault = Arc::new(std::sync::atomic::AtomicBool::new(corrupt_ack));
        for _ in 0..if corrupt_ack { 4 } else { 3 } {
            let (stream, _) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let router = Arc::clone(&router);
            let store = Arc::clone(&store);
            let service = Arc::clone(&service);
            let fault = fault.clone();
            clients.push(tokio::spawn(async move {
                tls_server(acceptor.accept(stream).await?, router, store, service, fault).await
            }));
        }
        for client in clients {
            client.await??;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    Ok((address, ca, server))
}
async fn submit_invalid_dm_page(sender: &mut CustodyConnection, target: &DeviceRef) -> Result {
    let peer = sender.lookup(target).await?;
    for sequence in 0..100_u8 {
        let bytes = [sequence];
        let mut envelope = ramflux_protocol::Envelope {
            schema: ramflux_protocol::domain::ENVELOPE.into(),
            version: 1,
            domain: ramflux_protocol::domain::ENVELOPE.into(),
            ext: ramflux_protocol::Ext::default(),
            signed: super::network::fields(),
            envelope_id: ramflux_protocol::encode_base64url([sequence; 32]),
            source_principal_id: sender.account.record().body.principal_id.clone(),
            source_device_id: sender.device.device_id.clone(),
            target_delivery_id: peer.target_delivery_id.clone(),
            routing_set_id: None,
            delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
            priority: ramflux_protocol::Priority::Normal,
            ttl: 300,
            created_at: i64::try_from(super::network::now()?)?,
            encrypted_payload: ramflux_protocol::encode_base64url(bytes),
            payload_hash: ramflux_crypto::blake3_256_base64url(
                "ramflux.identity.custody_dm_payload.v1",
                &bytes,
            ),
        };
        envelope
            .ext
            .ext
            .insert("source_root_commitment".into(), sender.device.account_anchor.clone().into());
        envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
            &sender.credentials.signing,
        );
        assert!(matches!(
            sender.request(CustodySessionAction::Submit { envelope: Box::new(envelope) }).await?,
            CustodyServerFrame::Submitted { .. }
        ));
    }
    Ok(())
}
#[tokio::test]
async fn custody_live_bus_creation_tls_registration_sessions_and_name_conflict() -> Result {
    let root = Root(std::env::temp_dir().join(format!(
        "cv-{}",
        ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
    )));
    std::fs::create_dir(&root.0)?;
    let (address, ca, server) = start_server(&root).await?;
    let socket = root.0.join("bus.sock");
    let vault = Arc::new(super::memory_vault::MemoryPrimaryVault::default());
    let mut config = crate::LocalBusConfig::new(&socket, &root.0);

    config.custody_vault = Some(vault.clone());
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let flow = async {
        let _stop = Shutdown(stop);
        let _alice_anchor = create(&socket, "alice", "Alice").await?;
        let _bob_anchor = create(&socket, "bob", "Bob").await?;
        create(&socket, "impostor", "Alice").await?;
        let network = |id: &str| CustodyNetworkConfig {
            account_root: root.0.clone(),
            account_id: id.into(),
            device_id: "primary".into(),
            gateway_address: address,
            server_name: "localhost".into(),
            ca_certificate: ca.clone(),
            node_id: "node".into(),
            node_public_key: ramflux_crypto::fixture_public_key_base64url(),
            audience: "node".into(),
            binding_mode: BindingMode::DirectExporter,
            allow_no_channel_binding: false,
            timeout: Duration::from_secs(15),
        };
        let alice = CustodyConnection::connect(network("alice"), vault.clone()).await?;
        let bob = CustodyConnection::connect(network("bob"), vault.clone()).await?;
        assert_eq!(alice.account().state(), CreationState::Live);
        assert_eq!(bob.account().state(), CreationState::Live);
        assert_ne!(
            alice.session().map(|session| &session.session_id),
            bob.session().map(|session| &session.session_id)
        );
        let conflict = CustodyConnection::connect(network("impostor"), vault.clone()).await;
        assert!(matches!(
            conflict,
            Err(crate::SdkError::CustodyNetwork(CustodyRefusal::PrincipalIdTaken))
        ));
        assert_eq!(
            load_account(&root.0, "impostor", super::network::now()?)?.state(),
            CreationState::NetworkingPending
        );
        assert_eq!(
            load_account(&root.0, "alice", super::network::now()?)?.state(),
            CreationState::Live
        );
        drop(alice);
        drop(bob);
        server.await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (daemon, result) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    daemon?;
    result?;
    Ok(())
}
