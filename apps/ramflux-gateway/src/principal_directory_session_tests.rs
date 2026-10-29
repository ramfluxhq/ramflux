// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-authentication directory rejection at the actual gateway dispatch boundaries.
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::sync::{Arc, Mutex};
type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;
struct Sink(Arc<Mutex<Vec<Vec<u8>>>>);
impl GatewaySessionFrameSink for Sink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(&'a mut self, body: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .lock()
                .map_err(|_| TransportError::Quic("test sink mutex".into()))?
                .push(body.to_vec());
            Ok(())
        })
    }
}
struct NoReceive;
impl GatewaySessionFrameSource for NoReceive {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        Box::pin(async {
            Err(TransportError::Quic(
                "directory must reject before reading authentication or using the router".into(),
            ))
        })
    }
}
#[tokio::test]
async fn an_unauthenticated_directory_frame_is_rejected_before_reading_or_contacting_the_router()
-> anyhow::Result<()> {
    let frames = Arc::new(Mutex::new(Vec::new()));
    super::handle_gateway_session_transport(
        Box::new(Sink(frames.clone())),
        Box::new(NoReceive),
        super::tests::test_gateway_context()?,
        ramflux_node_core::GatewayClientFrame::PrincipalManifestFetch {
            principal_id: "alice".into(),
        },
    )
    .await?;
    let output = frames.lock().map_err(|_| anyhow::anyhow!("test sink mutex"))?;
    assert_eq!(output.len(), 1);
    let response: ramflux_node_core::GatewayServerFrame = serde_json::from_slice(&output[0])?;
    assert_eq!(
        response,
        ramflux_node_core::GatewayServerFrame::Nack {
            reason: ramflux_protocol::GATEWAY_FIRST_FRAME_NACK_REASON.into()
        }
    );
    Ok(())
}
#[tokio::test]
async fn raw_name_lookup_rejects_known_and_unknown_queries_before_router_io() -> anyhow::Result<()>
{
    let context = super::tests::test_gateway_context()?;
    let mut bodies = Vec::new();
    for name in ["alice", "unknown"] {
        let response = crate::dispatch_quic_json_request(
            &context.router,
            ramflux_transport::GatewayQuicRequest {
                method: "GET".into(),
                path: format!("/mvp1/principal-manifest/{name}"),
                body: serde_json::Value::Null,
            },
            context.remote_addr.ip(),
        )
        .await?;
        assert_eq!(response.status, 401);
        assert_eq!(response.body["reason_code"], "authentication_required");
        bodies.push(response.body);
    }
    assert_eq!(bodies[0], bodies[1]);
    Ok(())
}

struct LookupFrame(Option<Vec<u8>>);
impl GatewaySessionFrameSource for LookupFrame {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        let frame = self.0.take();
        Box::pin(
            async move { frame.ok_or_else(|| TransportError::Quic("test session ended".into())) },
        )
    }
}

#[tokio::test]
async fn authenticated_principal_lookup_uses_router_json_ingress_and_returns_a_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
    let root = temp_cert_root("principal-lookup-ingress")?;
    let gateway = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-gateway")?;
    let router = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-router")?;
    let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &router.tls,
        Arc::new(move || Ok(vec![gateway.ca_pem.clone()])),
    )?;
    let endpoint = server.local_addr()?.to_string();
    let expected = ramflux_node_core::DeviceManifestResponse {
        signed_device_set: None,
        principal_id: "bob".into(),
        principal_commitment: "bob-root".into(),
        root_public_key: "fixture-public-key".into(),
        devices: Vec::new(),
    };
    let (done, finished) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(serve_lookup_router(server, expected.clone(), finished));
    let mut context = super::tests::test_gateway_context()?;
    context.router = crate::RouterMeshClient {
        endpoint: "127.0.0.1:0".into(),
        server_name: "ramflux-router".into(),
        tls: gateway.tls.clone(),
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: Some(crate::RouterAsyncMeshClient {
            endpoint,
            server_name: "ramflux-router".into(),
            tls: gateway.tls,
            peer_ca_pems: vec![router.ca_pem],
        }),
    };
    let runtime = crate::GatewaySessionRuntime {
        source_identity: ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
            &ramflux_crypto::create_identity_root("alice", [1; 32]),
            &ramflux_crypto::create_device_branch("alice", "alice-device", 1, [2; 32]),
        )?,
        session_id: "session".into(),
        resume_token: "resume".into(),
        principal_id: "alice".into(),
        device_id: "alice-device".into(),
        target_delivery_id: "alice-target".into(),
        device_epoch: 1,
        branch_public_key: "fixture-branch-key".into(),
        supports_forward_ack: false,
    };
    let frames = Arc::new(Mutex::new(Vec::new()));
    let send: crate::GatewaySendHandle =
        Arc::new(tokio::sync::Mutex::new(Box::new(Sink(Arc::clone(&frames)))));
    let result = super::run_gateway_session_loop(
        send,
        Box::new(LookupFrame(Some(serde_json::to_vec(
            &ramflux_node_core::GatewayClientFrame::PrincipalManifestFetch {
                principal_id: "bob".into(),
            },
        )?))),
        context,
        runtime,
    )
    .await;
    let _ = done.send(());
    let observed = serving.await??;
    result?;
    let observed = observed.ok_or("lookup used unsupported postcard ingress")?;
    assert_eq!(observed.principal_id, "bob");
    assert_eq!(observed.session_id, "session");
    assert_eq!(observed.requester_device_id, "alice-device");
    assert_eq!(observed.target_delivery_id, "alice-target");
    let frames = frames.lock().map_err(|_| anyhow::anyhow!("frame mutex"))?;
    assert_eq!(frames.len(), 1);
    let response: ramflux_node_core::GatewayServerFrame = serde_json::from_slice(&frames[0])?;
    assert_eq!(
        response,
        ramflux_node_core::GatewayServerFrame::PrincipalManifest {
            response: ramflux_protocol::PrincipalLookupResponse {
                manifest: Some(expected),
                reason_code: None
            }
        }
    );
    drop(frames);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn authenticated_prekey_fetch_forwards_fetcher_and_real_source_prefix_to_router()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
    let root = temp_cert_root("prekey-lease-ingress")?;
    let gateway = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-gateway")?;
    let router = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-router")?;
    let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &router.tls,
        Arc::new(move || Ok(vec![gateway.ca_pem.clone()])),
    )?;
    let endpoint = server.local_addr()?.to_string();
    let expected = ramflux_node_core::PrekeyResponse {
        device_id: "bob-device".into(),
        bundle: None,
        principal_commitment: "bob-root".into(),
        target_delivery_id: Some("bob-target".into()),
        one_time_prekey_exhausted: false,
        prekey_exhaustion_warning: false,
        available_one_time_prekeys: 7,
        one_time_prekey_leases: std::collections::BTreeMap::new(),
    };
    let (done, finished) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(serve_prekey_router(server, expected.clone(), finished));
    let mut context = super::tests::test_gateway_context()?;
    context.router = crate::RouterMeshClient {
        endpoint: "127.0.0.1:0".into(),
        server_name: "ramflux-router".into(),
        tls: gateway.tls.clone(),
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: Some(crate::RouterAsyncMeshClient {
            endpoint,
            server_name: "ramflux-router".into(),
            tls: gateway.tls,
            peer_ca_pems: vec![router.ca_pem],
        }),
    };
    let owned_root = ramflux_crypto::create_identity_root("alice", [1; 32]);
    let owned_branch = ramflux_crypto::create_device_branch("alice", "alice-device", 1, [2; 32]);
    let runtime = crate::GatewaySessionRuntime {
        supports_forward_ack: true,
        source_identity: ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
            &owned_root,
            &owned_branch,
        )?,
        session_id: "session".into(),
        resume_token: "resume".into(),
        principal_id: "alice".into(),
        device_id: "alice-device".into(),
        target_delivery_id: "alice-target".into(),
        device_epoch: 1,
        branch_public_key: "fixture-branch-key".into(),
    };
    let frames = Arc::new(Mutex::new(Vec::new()));
    let send: crate::GatewaySendHandle =
        Arc::new(tokio::sync::Mutex::new(Box::new(Sink(Arc::clone(&frames)))));
    let result = super::run_gateway_session_loop(
        send,
        Box::new(LookupFrame(Some(serde_json::to_vec(
            &ramflux_node_core::GatewayClientFrame::PrekeyFetch {
                device_id: "bob-root::bob-device".into(),
            },
        )?))),
        context,
        runtime,
    )
    .await;
    let _ = done.send(());
    let observed = serving.await??;
    result?;
    assert_eq!(observed.device_id, "bob-root::bob-device");
    assert_eq!(
        observed.fetcher_root_commitment,
        ramflux_crypto::identity_root_commitment(&owned_root.signing_key.verifying_key())
    );
    assert_eq!(observed.fetcher_device_id, "alice-device");
    assert_eq!(observed.source_prefix, "127.0.0.0/24");
    let frames = frames.lock().map_err(|_| anyhow::anyhow!("frame mutex"))?;
    assert_eq!(frames.len(), 1);
    let response: ramflux_node_core::GatewayServerFrame = serde_json::from_slice(&frames[0])?;
    assert_eq!(response, ramflux_node_core::GatewayServerFrame::Prekey { response: expected });
    drop(frames);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn serve_prekey_router(
    server: ramflux_transport::MeshQuicServer,
    response: ramflux_node_core::PrekeyResponse,
    finished: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<ramflux_node_core::PrekeyLeaseRequest> {
    let connection = server.accept_connection().await?;
    let accepted =
        ramflux_transport::MeshQuicServer::accept_json_or_postcard_request_on_connection(
            &connection,
        )
        .await?;
    let ramflux_transport::MeshQuicAcceptedWireRequest::Json(accepted) = accepted else {
        anyhow::bail!("prekey lease used unsupported postcard ingress");
    };
    anyhow::ensure!(
        accepted.request.method == "POST" && accepted.request.path == "/mvp1/prekey/lease",
        "unexpected prekey lease request"
    );
    let request = serde_json::from_value(accepted.request.body.clone())?;
    accepted.write_json_response(200, &response).await?;
    let _ = finished.await;
    Ok(request)
}

async fn serve_lookup_router(
    server: ramflux_transport::MeshQuicServer,
    manifest: ramflux_node_core::DeviceManifestResponse,
    finished: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<Option<ramflux_node_core::PrincipalLookupRequest>> {
    let connection = server.accept_connection().await?;
    let accepted =
        ramflux_transport::MeshQuicServer::accept_json_or_postcard_request_on_connection(
            &connection,
        )
        .await?;
    let request = match accepted {
        ramflux_transport::MeshQuicAcceptedWireRequest::Json(accepted) => {
            anyhow::ensure!(
                accepted.request.method == "POST"
                    && accepted.request.path == "/mvp1/principal-lookup",
                "unexpected directory request"
            );
            let request: ramflux_node_core::PrincipalLookupRequest =
                serde_json::from_value(accepted.request.body.clone())?;
            let response = ramflux_protocol::PrincipalLookupResponse {
                manifest: Some(manifest),
                reason_code: None,
            };
            accepted.write_json_response(200, &response).await?;
            Some(request)
        }
        ramflux_transport::MeshQuicAcceptedWireRequest::Postcard(accepted) => {
            // The production router's postcard ingress accepts only /mvp0/envelope.
            accepted.write_text_response(404, "not found").await?;
            None
        }
    };
    let _ = finished.await;
    Ok(request)
}
