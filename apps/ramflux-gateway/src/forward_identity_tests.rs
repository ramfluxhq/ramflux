// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real-mTLS gateway forward listener identity bind (GW-INSTANCE-IDENTITY-01 Part B).

use super::{GatewaySessionHub, gateway_forward_mesh_connection_loop};
use crate::ephemeral_forward::{GatewayForwardEphemeralRequest, PATH as EPHEMERAL_FORWARD_PATH};
use crate::session_push::tests::support::{ID, sink};
use crate::{GatewayForwardDeliverRequest, GatewayPeerDirectory, GatewaySendHandle};
use ramflux_protocol::ephemeral::DELIVERY_MODE_EXTENSION;
use ramflux_protocol::{Envelope, Ext};
use ramflux_transport::{MeshQuicServer, MeshTlsConfig, TransportError};
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;

const NODE: &str = "node-a";
const TARGET: &str = "target-forward-identity";
const EXPIRES_AT_MS: u64 = 1_760_000_005_000;
const NOW_LIVE_MS: u64 = 1_760_000_004_999;

struct TestCa {
    pem: String,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

struct TestPeerCerts {
    tls: MeshTlsConfig,
    ca_pem: String,
}

struct ForwardServer {
    endpoint: String,
    hub: Arc<GatewaySessionHub>,
    _root: ramflux_test_support::TestPath,
}

fn temp_cert_root(
    name: &str,
) -> Result<ramflux_test_support::TestPath, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!("ramflux_gw_forward_id_{name}_{}_{}", std::process::id(), nanos));
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| format!("non-UTF-8 path {}", path.display()).into())
}

fn run_openssl(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("openssl").args(args).status()?;
    if !status.success() {
        return Err(format!("openssl failed with status {status}: {}", args.join(" ")).into());
    }
    Ok(())
}

fn issue_test_ca(root: &Path) -> Result<TestCa, Box<dyn std::error::Error>> {
    let ca_key = root.join("ca-key.pem");
    let ca_cert = root.join("ca.pem");
    run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&ca_key)?])?;
    run_openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        path_str(&ca_key)?,
        "-out",
        path_str(&ca_cert)?,
        "-days",
        "30",
        "-subj",
        "/CN=Ramflux Gateway Forward Identity Test CA",
    ])?;
    Ok(TestCa { pem: std::fs::read_to_string(&ca_cert)?, cert: ca_cert, key: ca_key })
}

fn issue_test_service_cert(
    ca: &TestCa,
    node_id: &str,
    service_id: &str,
    instance_id: Option<&str>,
) -> Result<TestPeerCerts, Box<dyn std::error::Error>> {
    let dir_name = match instance_id {
        Some(instance) => format!("{service_id}-{instance}"),
        None => service_id.to_owned(),
    };
    let service_dir = ca.cert.parent().ok_or("CA cert has no parent")?.join(dir_name);
    std::fs::create_dir_all(&service_dir)?;
    let service_key = service_dir.join(format!("{service_id}-key.pem"));
    let service_csr = service_dir.join(format!("{service_id}.csr"));
    let service_cert = service_dir.join(format!("{service_id}.pem"));
    let ext = service_dir.join(format!("{service_id}.ext"));
    run_openssl(&["genpkey", "-algorithm", "ED25519", "-out", path_str(&service_key)?])?;
    run_openssl(&[
        "req",
        "-new",
        "-key",
        path_str(&service_key)?,
        "-out",
        path_str(&service_csr)?,
        "-subj",
        &format!("/CN={service_id}"),
    ])?;
    let spiffe_uri = match instance_id {
        Some(instance) => format!("spiffe://{node_id}/{service_id}/{instance}"),
        None => format!("spiffe://{node_id}/{service_id}"),
    };
    std::fs::write(
        &ext,
        format!(
            "subjectAltName = DNS:{service_id}, DNS:localhost, URI:{spiffe_uri}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
        ),
    )?;
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        path_str(&service_csr)?,
        "-CA",
        path_str(&ca.cert)?,
        "-CAkey",
        path_str(&ca.key)?,
        "-CAcreateserial",
        "-out",
        path_str(&service_cert)?,
        "-days",
        "30",
        "-extfile",
        path_str(&ext)?,
    ])?;
    Ok(TestPeerCerts {
        tls: MeshTlsConfig { ca_cert: ca.cert.clone(), service_cert, service_key },
        ca_pem: ca.pem.clone(),
    })
}

fn spawn_forward_listener(
    server_tls: MeshTlsConfig,
    trusted_client_ca: String,
    hub: Arc<GatewaySessionHub>,
) -> Result<String, Box<dyn std::error::Error>> {
    let (endpoint_tx, endpoint_rx) = mpsc::channel::<Result<String, String>>();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = endpoint_tx.send(Err(error.to_string()));
                return;
            }
        };
        let result: Result<(), String> = runtime.block_on(async move {
            let roots = Arc::new(move || Ok(vec![trusted_client_ca.clone()]));
            let server =
                MeshQuicServer::bind_with_pem_roots_provider("127.0.0.1:0", &server_tls, roots)
                    .map_err(|error| error.to_string())?;
            endpoint_tx
                .send(
                    server
                        .local_addr()
                        .map(|addr| addr.to_string())
                        .map_err(|error| error.to_string()),
                )
                .map_err(|error| error.to_string())?;
            loop {
                let connection =
                    server.accept_connection().await.map_err(|error| error.to_string())?;
                let hub = Arc::clone(&hub);
                tokio::spawn(async move {
                    let _ = gateway_forward_mesh_connection_loop(connection, hub).await;
                });
            }
        });
        if let Err(error) = result {
            tracing::debug!(%error, "gateway forward identity test server stopped");
        }
    });
    endpoint_rx.recv()?.map_err(Into::into)
}

fn start_gw_b_listener()
-> Result<(ForwardServer, TestCa, TestPeerCerts), Box<dyn std::error::Error>> {
    let root = temp_cert_root("listener")?;
    let ca = issue_test_ca(&root)?;
    let gw_b = issue_test_service_cert(&ca, NODE, "ramflux-gateway", Some("gw-b"))?;
    let hub = Arc::new(GatewaySessionHub::default());
    let endpoint = spawn_forward_listener(gw_b.tls.clone(), ca.pem.clone(), Arc::clone(&hub))?;
    Ok((ForwardServer { endpoint, hub, _root: root }, ca, gw_b))
}

fn post_json<T: serde::Serialize>(
    endpoint: &str,
    path: &str,
    client: &TestPeerCerts,
    server: &TestPeerCerts,
    body: &T,
) -> Result<Value, TransportError> {
    ramflux_transport::mesh_quic_post_json_with_peer_ca_pems::<_, Value>(
        endpoint,
        path,
        &client.tls,
        "ramflux-gateway",
        std::slice::from_ref(&server.ca_pem),
        body,
    )
}

fn identity_reason(error: TransportError) -> Result<(u16, String), Box<dyn std::error::Error>> {
    match error {
        TransportError::HttpStatus { status, body } => {
            let value: Value = serde_json::from_str(&body)?;
            let reason =
                value.get("reason").and_then(Value::as_str).ok_or("missing reason")?.to_owned();
            Ok((status, reason))
        }
        other => Err(format!("expected HTTP status, got {other}").into()),
    }
}

fn recording_send_handle(frames: Arc<Mutex<Vec<Vec<u8>>>>) -> GatewaySendHandle {
    Arc::new(AsyncMutex::new(Box::new(RecordingSink { frames })))
}

struct RecordingSink {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ramflux_transport::GatewaySessionFrameSink for RecordingSink {
    fn send_frame<'a>(
        &'a mut self,
        frame: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let mut frames =
                self.frames.lock().map_err(|error| TransportError::Quic(error.to_string()))?;
            frames.push(frame.to_vec());
            Ok(())
        })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

fn deliver_frame(
    envelope_id: &str,
    target_delivery_id: &str,
) -> ramflux_node_core::GatewayServerFrame {
    ramflux_node_core::GatewayServerFrame::Deliver {
        entry: ramflux_node_core::InboxEntry {
            inbox_seq: 1,
            target_delivery_id: target_delivery_id.to_owned(),
            envelope: test_envelope(envelope_id, target_delivery_id),
        },
    }
}

fn test_envelope(envelope_id: &str, target_delivery_id: &str) -> Envelope {
    Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "test-envelope-key".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "test-envelope-signature".to_owned(),
        },
        envelope_id: envelope_id.to_owned(),
        source_principal_id: "principal_gateway_forward".to_owned(),
        source_device_id: "device_gateway_forward".to_owned(),
        target_delivery_id: target_delivery_id.to_owned(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Normal,
        ttl: 86_400,
        created_at: 1_760_000_000,
        encrypted_payload: "encrypted_payload".to_owned(),
        payload_hash: "payload_hash".to_owned(),
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
    }
}

fn ephemeral_envelope(target: &str, envelope_id: &str) -> Envelope {
    let mut ext = BTreeMap::new();
    ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("ephemeral".to_owned()));
    Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: Ext { ext },
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "test-c4-key".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "test-c4-signature".to_owned(),
        },
        envelope_id: envelope_id.to_owned(),
        source_principal_id: "principal-c4".to_owned(),
        source_device_id: "device-c4".to_owned(),
        target_delivery_id: target.to_owned(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Low,
        ttl: 5,
        created_at: 1_760_000_000,
        encrypted_payload: "encrypted_payload".to_owned(),
        payload_hash: "payload_hash".to_owned(),
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
    }
}

#[test]
fn forward_deliver_accepts_matching_gateway_instance() -> Result<(), Box<dyn std::error::Error>> {
    let (server, ca, gw_b) = start_gw_b_listener()?;
    let gw_a = issue_test_service_cert(&ca, NODE, "ramflux-gateway", Some("gw-a"))?;
    let frames = Arc::new(Mutex::new(Vec::new()));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(server.hub.register(
        TARGET.to_owned(),
        "session-bob".to_owned(),
        recording_send_handle(Arc::clone(&frames)),
    ))?;
    let request = GatewayForwardDeliverRequest {
        source_gateway_id: "gw-a".to_owned(),
        target_delivery_id: TARGET.to_owned(),
        forwarded: true,
        incarnation_id: None,
        retain_until: None,
        frame: deliver_frame("env-forward-a", TARGET),
    };
    let response =
        post_json(&server.endpoint, GatewayPeerDirectory::forward_path(), &gw_a, &gw_b, &request)?;
    assert_eq!(response["delivered"], true);
    runtime.block_on(server.hub.flushed(TARGET))?;
    let recorded = frames.lock().map_err(|error| error.to_string())?;
    assert_eq!(recorded.len(), 1);
    Ok(())
}

#[test]
fn forward_ephemeral_accepts_matching_gateway_instance() -> Result<(), Box<dyn std::error::Error>> {
    let (server, ca, gw_b) = start_gw_b_listener()?;
    let gw_a = issue_test_service_cert(&ca, NODE, "ramflux-gateway", Some("gw-a"))?;
    let (recipient, _received) = sink();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        server
            .hub
            .register_ephemeral(TARGET.into(), "session-c4".into(), recipient, Some(ID.into()), 32)
            .await?;
        server.hub.set_ephemeral_clock_ms(NOW_LIVE_MS);
        server.hub.set_queue_clock(TARGET, NOW_LIVE_MS).await;
        Ok::<(), anyhow::Error>(())
    })?;
    let request = GatewayForwardEphemeralRequest {
        source_gateway_id: "gw-a".to_owned(),
        target_delivery_id: TARGET.to_owned(),
        forwarded: true,
        envelope: ephemeral_envelope(TARGET, "env-ephemeral-a"),
        expires_at_ms: EXPIRES_AT_MS,
    };
    let response = post_json(&server.endpoint, EPHEMERAL_FORWARD_PATH, &gw_a, &gw_b, &request)?;
    assert_eq!(response["delivered"], true);
    assert_eq!(runtime.block_on(server.hub.ephemeral_queued(TARGET)), 1);
    Ok(())
}

#[test]
fn forward_deliver_refuses_federation_peer() -> Result<(), Box<dyn std::error::Error>> {
    let (server, ca, gw_b) = start_gw_b_listener()?;
    let federation = issue_test_service_cert(&ca, NODE, "ramflux-federation", None)?;
    let request = GatewayForwardDeliverRequest {
        source_gateway_id: "gw-a".to_owned(),
        target_delivery_id: TARGET.to_owned(),
        forwarded: true,
        incarnation_id: None,
        retain_until: None,
        frame: deliver_frame("env-federation", TARGET),
    };
    let Err(error) = post_json(
        &server.endpoint,
        GatewayPeerDirectory::forward_path(),
        &federation,
        &gw_b,
        &request,
    ) else {
        return Err("federation peer must be refused".into());
    };
    let (status, reason) = identity_reason(error)?;
    assert_eq!(status, 403);
    assert_eq!(reason, "gateway_role_required");
    Ok(())
}

#[test]
fn forward_deliver_refuses_gateway_claiming_another_instance()
-> Result<(), Box<dyn std::error::Error>> {
    let (server, ca, gw_b) = start_gw_b_listener()?;
    let gw_b_client = issue_test_service_cert(&ca, NODE, "ramflux-gateway", Some("gw-b"))?;
    let request = GatewayForwardDeliverRequest {
        source_gateway_id: "gw-c".to_owned(),
        target_delivery_id: TARGET.to_owned(),
        forwarded: true,
        incarnation_id: None,
        retain_until: None,
        frame: deliver_frame("env-claim-c", TARGET),
    };
    let Err(error) = post_json(
        &server.endpoint,
        GatewayPeerDirectory::forward_path(),
        &gw_b_client,
        &gw_b,
        &request,
    ) else {
        return Err("gw-b cannot claim source gw-c".into());
    };
    let (status, reason) = identity_reason(error)?;
    assert_eq!(status, 403);
    assert_eq!(reason, "gateway_instance_mismatch");
    Ok(())
}

fn ephemeral_forward_request(
    source_gateway_id: &str,
    envelope_id: &str,
) -> GatewayForwardEphemeralRequest {
    GatewayForwardEphemeralRequest {
        source_gateway_id: source_gateway_id.to_owned(),
        target_delivery_id: TARGET.to_owned(),
        forwarded: true,
        envelope: ephemeral_envelope(TARGET, envelope_id),
        expires_at_ms: EXPIRES_AT_MS,
    }
}

#[test]
fn forward_ephemeral_refuses_federation_peer() -> Result<(), Box<dyn std::error::Error>> {
    let (server, ca, gw_b) = start_gw_b_listener()?;
    let federation = issue_test_service_cert(&ca, NODE, "ramflux-federation", None)?;
    let Err(error) = post_json(
        &server.endpoint,
        EPHEMERAL_FORWARD_PATH,
        &federation,
        &gw_b,
        &ephemeral_forward_request("gw-a", "env-ephemeral-federation"),
    ) else {
        return Err("federation peer must be refused on ephemeral forward".into());
    };
    let (status, reason) = identity_reason(error)?;
    assert_eq!(status, 403);
    assert_eq!(reason, "gateway_role_required");
    Ok(())
}

#[test]
fn forward_ephemeral_refuses_gateway_claiming_another_instance()
-> Result<(), Box<dyn std::error::Error>> {
    let (server, ca, gw_b) = start_gw_b_listener()?;
    let gw_b_client = issue_test_service_cert(&ca, NODE, "ramflux-gateway", Some("gw-b"))?;
    let Err(error) = post_json(
        &server.endpoint,
        EPHEMERAL_FORWARD_PATH,
        &gw_b_client,
        &gw_b,
        &ephemeral_forward_request("gw-c", "env-ephemeral-claim-c"),
    ) else {
        return Err("gw-b cannot claim source gw-c on ephemeral forward".into());
    };
    let (status, reason) = identity_reason(error)?;
    assert_eq!(status, 403);
    assert_eq!(reason, "gateway_instance_mismatch");
    Ok(())
}

#[test]
fn forward_deliver_refuses_legacy_gateway_without_instance()
-> Result<(), Box<dyn std::error::Error>> {
    let (server, ca, gw_b) = start_gw_b_listener()?;
    let legacy = issue_test_service_cert(&ca, NODE, "ramflux-gateway", None)?;
    let request = GatewayForwardDeliverRequest {
        source_gateway_id: "gw-a".to_owned(),
        target_delivery_id: TARGET.to_owned(),
        forwarded: true,
        incarnation_id: None,
        retain_until: None,
        frame: deliver_frame("env-legacy", TARGET),
    };
    let Err(error) =
        post_json(&server.endpoint, GatewayPeerDirectory::forward_path(), &legacy, &gw_b, &request)
    else {
        return Err("legacy gateway cert without instance must be refused".into());
    };
    let (status, reason) = identity_reason(error)?;
    assert_eq!(status, 403);
    assert_eq!(reason, "gateway_instance_missing");
    Ok(())
}

/// Real authenticated receiving gateway for the originating-submit regression.
pub(crate) fn ephemeral_pair()
-> Result<(GatewayPeerDirectory, Arc<GatewaySessionHub>), Box<dyn std::error::Error>> {
    let (server, ca, _gw_b) = start_gw_b_listener()?;
    let gw_a = issue_test_service_cert(&ca, NODE, "ramflux-gateway", Some("gw-a"))?;
    Ok((GatewayPeerDirectory::test_peer(gw_a.tls, ca.pem, "gw-b", server.endpoint), server.hub))
}

pub(crate) struct EphemeralPair {
    pub peers: GatewayPeerDirectory,
    pub hub: Arc<GatewaySessionHub>,
    pub receiver_tls: MeshTlsConfig,
    pub ca_pem: String,
}

/// Two instance-bound gateways under a CA trusted by the same real test node.
pub(crate) fn ephemeral_pair_for_node(
    node: &str,
) -> Result<EphemeralPair, Box<dyn std::error::Error>> {
    let root = temp_cert_root("same-node-pair")?;
    let ca = issue_test_ca(&root)?;
    let gw_a = issue_test_service_cert(&ca, node, "ramflux-gateway", Some("gw-a"))?;
    let gw_b = issue_test_service_cert(&ca, node, "ramflux-gateway", Some("gw-b"))?;
    let hub = Arc::new(GatewaySessionHub::default());
    let endpoint = spawn_forward_listener(gw_b.tls.clone(), ca.pem.clone(), hub.clone())?;
    Ok(EphemeralPair {
        peers: GatewayPeerDirectory::test_peer(gw_a.tls, ca.pem.clone(), "gw-b", endpoint),
        hub,
        receiver_tls: gw_b.tls,
        ca_pem: ca.pem,
    })
}
