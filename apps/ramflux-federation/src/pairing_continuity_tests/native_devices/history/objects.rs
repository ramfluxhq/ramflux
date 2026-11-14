// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual v3 relay authorization and durable object route over owned QUIC connections.
use super::*;
use ramflux_node_core::{self as core, RelayTrustSnapshotCache};
use std::sync::atomic::AtomicUsize;

pub(super) struct Objects {
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
    pub puts: Arc<AtomicUsize>,
    pub gets: Arc<AtomicUsize>,
    _root: tempfile::TempDir,
}
impl Drop for Objects {
    fn drop(&mut self) {
        self.endpoint.close(0_u32.into(), b"history fixture complete");
        self.task.abort();
    }
}
pub(super) fn issuer(root: &std::path::Path) -> TestResult<(String, String)> {
    let now = wall()?;
    let seed = random_32()?;
    let root_seed = ramflux_crypto::blake3_256("ramflux.cli.e2e.node.v1", b"localhost");
    let mut certificate = core::GatewayIssuerCertificate {
        schema: core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.into(),
        version: core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "pairing-history-gateway".into(),
        node_id: "localhost".into(),
        gateway_instance_id: "pairing-history-gateway".into(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(seed),
        attestation_key_id: "pairing-history-issuer".into(),
        not_before: now - 60,
        not_after: now + 3600,
        issued_at: now,
        node_root_signing_key_id: "localhost#root".into(),
        node_root_signature: String::new(),
        revoked_at: None,
    };
    certificate.node_root_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &core::gateway_issuer_certificate_signing_bytes(&certificate)?,
        root_seed,
    );
    let path = root.join("gateway-issuer.json");
    std::fs::write(&path, ramflux_protocol::canonical_json_bytes(&certificate)?)?;
    Ok((encode_base64url(seed), path.to_str().ok_or("test: issuer path")?.into()))
}
impl Objects {
    pub(super) async fn stop(&mut self) -> TestResult {
        self.endpoint.close(0_u32.into(), b"history fixture complete");
        (&mut self.task).await.map_err(|_| "test: ordinary object listener did not drain")?;
        Ok(())
    }
    pub(super) fn open(
        stack: &process_stack::Stack,
        socket: std::net::UdpSocket,
    ) -> TestResult<Self> {
        let now = wall()?;
        let mut trust = RelayTrustSnapshotCache::new();
        let seed = ramflux_crypto::blake3_256("ramflux.cli.e2e.node.v1", b"localhost");
        trust.update(
            core::FederatedIssuerTrustSnapshot {
                schema: core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.into(),
                version: core::OBJECT_RELAY_V3_PROOF_VERSION,
                node_id: "localhost".into(),
                generation: 1,
                pin_epoch: 1,
                trust_status: core::FederatedIssuerTrustStatus::Active,
                roots: vec![core::TrustedNodeRootKey {
                    node_id: "localhost".into(),
                    key_id: "localhost#root".into(),
                    public_key: ramflux_crypto::public_key_base64url_from_seed(seed),
                    not_before: now - 60,
                    not_after: now + 3600,
                    pin_epoch: 1,
                    retired_at: None,
                }],
                revoked_cert_ids: std::collections::BTreeSet::default(),
                hard_stale_at: now + 3600,
            },
            "localhost",
            now,
        )?;
        process_stack::issue_service_cert(&stack.root, "ramflux-relay", &stack.node_id)?;
        let certs = stack.root.join("certs");
        let config =
            ramflux_transport::quic_gateway_server_config(&ramflux_transport::MeshTlsConfig {
                ca_cert: certs.join("ca.pem"),
                service_cert: certs.join("ramflux-relay.pem"),
                service_key: certs.join("ramflux-relay.key"),
            })?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let root = tempfile::tempdir()?;
        let service = ramflux_relay::RelayObjectService::new(
            "localhost".into(),
            Arc::new(Mutex::new(trust)),
            Arc::new(core::RelayRedbStore::open(root.path().join("objects.redb"))?),
            Arc::new(Mutex::new(core::RelayCacheState::with_max_bytes(8 * 1024 * 1024))),
        );
        let puts = Arc::new(AtomicUsize::new(0));
        let gets = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve(endpoint.clone(), service, puts.clone(), gets.clone()));
        Ok(Self { endpoint, task, puts, gets, _root: root })
    }
}
async fn serve(
    endpoint: quinn::Endpoint,
    service: ramflux_relay::RelayObjectService,
    puts: Arc<AtomicUsize>,
    gets: Arc<AtomicUsize>,
) {
    let mut jobs = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept(), if jobs.len() < 4 => {
                let Some(incoming) = incoming else { break };
                let service = service.clone();
                let puts = puts.clone(); let gets = gets.clone();
                jobs.spawn(async move {
                    if let Ok(connection) = incoming.await {
                        let _ = connection_requests(connection, service, puts, gets).await;
                    }
                });
            }
            _ = jobs.join_next(), if !jobs.is_empty() => {}
        }
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
}
async fn connection_requests(
    connection: quinn::Connection,
    service: ramflux_relay::RelayObjectService,
    puts: Arc<AtomicUsize>,
    gets: Arc<AtomicUsize>,
) -> TestResult {
    for _ in 0..128 {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let request: ramflux_transport::GatewayQuicRequest =
            ramflux_transport::read_quic_json_frame(&mut recv).await?;
        let response = service.handle(&request, wall()?);
        if (200..300).contains(&response.status) {
            if request.path == "/relay/v1/object/put_chunk" {
                puts.fetch_add(1, Ordering::SeqCst);
            }
            if request.path == "/relay/v1/object/get_chunk" {
                gets.fetch_add(1, Ordering::SeqCst);
            }
        }
        ramflux_transport::write_quic_json_frame(&mut send, &response).await?;
    }
    Ok(())
}
