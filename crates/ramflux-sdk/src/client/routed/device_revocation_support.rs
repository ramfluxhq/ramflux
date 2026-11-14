// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native TLS revocation fixture and real pair setup for denial regressions.
use super::*;
#[path = "device_revocation_native.rs"]
mod native;
use crate::bus::protocol::LocalBusFrame;
use crate::bus::state::{LocalBusAccountState, LocalBusDaemonState};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server(tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn revoke(owner: &mut Fixture, target: &str) -> TestResult {
    let (address, ca, server) = directory(owner).await?;
    let _server = Server(server);
    let mut config = owner.config.clone();
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.transport_kind = crate::gateway::GatewaySessionTransportKind::TcpTls;
    config.server_name = "localhost".into();
    config.ca_cert = ca;
    let selected = config.custody.as_mut().ok_or("test: native config")?;
    selected.node_id = "node".into();
    selected.node_public_key = ramflux_crypto::fixture_public_key_base64url();
    let account_id = owner.client.account_db()?.local_account_id.clone();
    let account = LocalBusAccountState::disconnected(
        std::mem::take(&mut owner.client),
        config,
        owner.manifest.principal_commitment.clone(),
    );
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: crate::bus::LocalBusConfig::new(owner.root.0.join("rfd.sock"), &owner.root.0),
        accounts: BTreeMap::from([(account_id.clone(), account)]),
        active_account_id: Some(account_id.clone()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let request = LocalBusFrame::request(
        "revoke",
        Some(account_id.clone()),
        "device",
        "device.revoke",
        serde_json::json!({"device_id":target}),
    );
    let response =
        crate::bus::dispatch::device::dispatch_device_bus_request(&request, &mut state).await?;
    assert_eq!(response.response_body["revoked"], true, "test: native revoke was not acknowledged");
    owner.client = std::mem::take(
        &mut state.accounts.get_mut(&account_id).ok_or("test: publisher account")?.client,
    );
    Ok(())
}

async fn directory(
    owner: &Fixture,
) -> TestResult<(
    std::net::SocketAddr,
    std::path::PathBuf,
    tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
)> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let manifest = owner.manifest.clone();
    let tls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(certificate.signing_key.serialize_der().into()),
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    std::fs::write(owner.root.0.join("directory-ca.pem"), certificate.cert.pem())?;
    let ca = owner.root.0.join("directory-ca.pem");
    let router = Arc::new(ramflux_node_core::RouterCore::new());
    let store = Arc::new(ramflux_node_core::RouterRedbStore::open(
        owner.root.0.join("revoke-router.redb"),
    )?);
    store.save_router(&router)?;
    let now = crate::custody::network_now()?;
    let node = native::node(now)?;
    let service =
        Arc::new(ramflux_node_core::CustodyService::new(node.clone(), false, &store, now)?);
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut stream =
            tokio_rustls::TlsAcceptor::from(Arc::new(tls.clone())).accept(socket).await?;
        let length = stream.read_u32().await?;
        if length > 65536 {
            return Err("test: directory request exceeds bound".into());
        }
        let mut bytes = vec![0; 65536];
        let body = bytes.get_mut(..usize::try_from(length)?).ok_or("test: request length")?;
        stream.read_exact(body).await?;
        let request: ramflux_transport::GatewayQuicRequest = serde_json::from_slice(body)?;
        assert_eq!(request.method, "GET", "test: revoke did not fetch native authority");
        assert_eq!(
            request.path,
            format!("/mvp1/device-manifest/{}", manifest.principal_commitment),
            "test: fetched another account"
        );
        let response = serde_json::to_vec(&ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::to_value(manifest)?,
        })?;
        stream.write_u32(u32::try_from(response.len())?).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
        drop(stream);
        let (socket, _) = listener.accept().await?;
        let stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls)).accept(socket).await?;
        native::serve(stream, router, store, service, node).await
    });
    Ok((address, ca, server))
}

pub(super) fn outgoing(source: &Fixture, target: &Fixture, id: &str) -> GatewayDirectMessage {
    GatewayDirectMessage {
        conversation_id: "native-revocation".into(),
        message_id: id.into(),
        envelope_id: id.into(),
        source_principal_id: source.manifest.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(target.manifest.principal_commitment.clone()),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    }
}

pub(super) fn packet(
    source: &Fixture,
    target: &Fixture,
    id: &str,
) -> TestResult<GatewayInboxEntry> {
    let mut message = outgoing(source, target, id);
    let remote = target.client.owned_device_identity()?;
    let bundle = target.client.load_x3dh_private_state(&remote)?.bundle;
    let (mut session, header, bundle) =
        source.client.new_send_pair(&source.client.owned_device_identity()?, &message, bundle)?;
    let encrypted = source.client.seal_routed_with_route(
        &message,
        b"old traffic",
        Route::direct(),
        SealPair {
            local: &source.config.device_id,
            remote: remote.storage_key(),
            session: &mut session,
            header,
            bundle,
        },
    )?;
    message.encrypted_body = serde_json::to_vec(&encrypted)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: target.config.target_delivery_id.clone(),
        envelope: gateway_direct_message_envelope(&source.config, &message, None)?,
    })
}

pub(super) fn seed_pair(local: &Fixture, remote: &Fixture) -> TestResult {
    let local_ref = local.client.owned_device_identity()?;
    let remote_ref = remote.client.owned_device_identity()?;
    let message = outgoing(local, remote, "initial");
    let bundle = remote.client.load_x3dh_private_state(&remote_ref)?.bundle;
    let hash = crate::dm::prekey_bundle_hash(&bundle)?;
    let (session, _) = local.client.create_send_dm_session_from_bundle(
        &message,
        &remote.config.device_id,
        bundle,
        &local.config.device_id,
    )?;
    local.client.persist_pair(&local_ref, &remote_ref, &hash, &session)?;
    assert!(
        local.client.active_pair(&local_ref, &remote_ref)?.is_some(),
        "test: private pair oracle was vacuous"
    );
    assert!(
        local.client.begin_pair_recovery(&local_ref, &remote_ref, now_unix_timestamp())?,
        "test: reset work was never created"
    );
    assert!(
        !local
            .client
            .account_db()?
            .list_actor_states::<serde_json::Value>("dm-pair/session/")?
            .is_empty(),
        "test: recovery did not retain a private session to retire"
    );
    Ok(())
}

struct NoSend(Arc<AtomicUsize>);
impl ramflux_transport::GatewaySessionFrameSink for NoSend {
    fn send_frame<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> ramflux_transport::GatewaySessionFrameFuture<'a, ()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(ramflux_transport::TransportError::ShutdownDraining) })
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        Ok(())
    }
}
impl ramflux_transport::GatewaySessionFrameSource for NoSend {
    fn recv_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async { Err(ramflux_transport::TransportError::ShutdownDraining) })
    }
}
pub(super) fn engine(local: &Fixture) -> (GatewaySessionEngine, Arc<AtomicUsize>) {
    let sent = Arc::new(AtomicUsize::new(0));
    (
        GatewaySessionEngine::with_test_transport(
            local.config.clone(),
            Box::new(NoSend(sent.clone())),
        ),
        sent,
    )
}
