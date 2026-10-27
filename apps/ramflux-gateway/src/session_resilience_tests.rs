// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Request failures preserve the authenticated client stream; client transport failures end it.
use super::*;
use crate::state::GatewaySessionHub;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
type Future<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;
struct Source(VecDeque<Vec<u8>>);
impl GatewaySessionFrameSource for Source {
    fn recv_frame(&mut self) -> Future<'_, Vec<u8>> {
        let next = self.0.pop_front();
        Box::pin(async move {
            next.ok_or_else(|| {
                TransportError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            })
        })
    }
}
struct Sink(Arc<Mutex<Vec<Vec<u8>>>>);
impl GatewaySessionFrameSink for Sink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(&'a mut self, body: &'a [u8]) -> Future<'a, ()> {
        Box::pin(async move {
            self.0.lock().map_err(|_| TransportError::LockPoisoned)?.push(body.to_vec());
            Ok(())
        })
    }
}
fn runtime() -> anyhow::Result<GatewaySessionRuntime> {
    Ok(GatewaySessionRuntime {
        source_identity: ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
            &ramflux_crypto::create_identity_root("alice", [1; 32]),
            &ramflux_crypto::create_device_branch("alice", "device", 1, [2; 32]),
        )?,
        session_id: "session".into(),
        resume_token: "resume".into(),
        principal_id: "alice".into(),
        device_id: "device".into(),
        target_delivery_id: "target".into(),
        branch_public_key: ramflux_crypto::public_key_base64url_from_seed([2; 32]),
        device_epoch: 1,
        supports_forward_ack: false,
    })
}
#[tokio::test]
async fn router_500_is_a_nack_and_the_next_lookup_and_heartbeat_use_the_same_session()
-> anyhow::Result<()> {
    survives_router_failure(false).await
}
#[tokio::test]
async fn router_timeout_is_a_nack_and_the_next_lookup_and_heartbeat_use_the_same_session()
-> anyhow::Result<()> {
    survives_router_failure(true).await
}
async fn survives_router_failure(timeout: bool) -> anyhow::Result<()> {
    use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
    let root = temp_cert_root(if timeout { "session-timeout" } else { "session-500" })
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let gateway = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-gateway")
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let router = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-router")
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &router.tls,
        Arc::new(move || Ok(vec![gateway.ca_pem.clone()])),
    )?;
    let endpoint = server.local_addr()?.to_string();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(serve_router(server, timeout, stopped));
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
    let frames = Arc::new(Mutex::new(Vec::new()));
    let lookup = ramflux_node_core::GatewayClientFrame::PrincipalManifestFetch {
        principal_id: "peer".into(),
    };
    let source = Source(VecDeque::from([
        serde_json::to_vec(&lookup)?,
        serde_json::to_vec(&lookup)?,
        serde_json::to_vec(&ramflux_node_core::GatewayClientFrame::Heartbeat { now: 7 })?,
    ]));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(70),
        super::run_gateway_session_loop(
            Arc::new(AsyncMutex::new(Box::new(Sink(frames.clone())))),
            Box::new(source),
            context,
            runtime()?,
        ),
    )
    .await;
    let _ = stop.send(());
    serving.await??;
    result??;
    let frames = frames.lock().map_err(|_| anyhow::anyhow!("frame mutex"))?;
    assert_eq!(frames.len(), 3);
    let output = frames
        .iter()
        .map(|bytes| serde_json::from_slice::<ramflux_node_core::GatewayServerFrame>(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        output[0],
        ramflux_node_core::GatewayServerFrame::Nack {
            reason: "gateway_request_failed:principal_manifest_fetch".into()
        }
    );
    assert!(
        matches!(&output[1],ramflux_node_core::GatewayServerFrame::PrincipalManifest{response} if response.manifest.as_ref().is_some_and(|m|m.principal_id=="peer"))
    );
    assert_eq!(output[2], ramflux_node_core::GatewayServerFrame::Heartbeat { now: 7 });
    drop(frames);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn serve_router(
    server: ramflux_transport::MeshQuicServer,
    timeout: bool,
    mut stopped: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let requests = Arc::new(AtomicUsize::new(0));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _=&mut stopped=>break,
            connection=server.accept_connection()=>{
                let connection=connection?;let requests=Arc::clone(&requests);
                connections.spawn(async move {
                    let mut streams=tokio::task::JoinSet::new();
                    while let Ok(request)=ramflux_transport::MeshQuicServer::accept_json_or_postcard_request_on_connection(&connection).await {
                        let first=requests.fetch_add(1,Ordering::SeqCst)==0;
                        streams.spawn(async move {
                            let ramflux_transport::MeshQuicAcceptedWireRequest::Json(request)=request else {return Err(anyhow::anyhow!("expected JSON lookup"));};
                            anyhow::ensure!(request.request.path=="/mvp1/principal-lookup","unexpected router path");
                            if first && timeout {std::future::pending::<()>().await;}
                            if first {request.write_json_response(500,&serde_json::json!({"error":"injected router error"})).await?;} else {
                                request.write_json_response(200,&ramflux_protocol::PrincipalLookupResponse {manifest:Some(ramflux_node_core::DeviceManifestResponse{custody:None,signed_device_set:None,principal_id:"peer".into(),principal_commitment:"peer-root".into(),root_public_key:"peer-key".into(),devices:Vec::new()}),reason_code:None}).await?;
                            }
                            Ok::<(),anyhow::Error>(())
                        });
                    }
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}
struct BrokenSink(Arc<AtomicUsize>);
impl GatewaySessionFrameSink for BrokenSink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(&'a mut self, _: &'a [u8]) -> Future<'a, ()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(TransportError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        })
    }
}
#[tokio::test]
async fn client_write_failure_ends_the_session_without_attempting_a_second_reply()
-> anyhow::Result<()> {
    let writes = Arc::new(AtomicUsize::new(0));
    let source = Source(VecDeque::from([serde_json::to_vec(
        &ramflux_node_core::GatewayClientFrame::Heartbeat { now: 1 },
    )?]));
    let error = super::run_gateway_session_loop(
        Arc::new(AsyncMutex::new(Box::new(BrokenSink(writes.clone())))),
        Box::new(source),
        super::tests::test_gateway_context()?,
        runtime()?,
    )
    .await
    .err()
    .ok_or_else(|| anyhow::anyhow!("write unexpectedly succeeded"))?;
    assert!(error.downcast_ref::<crate::session_response::ClientWriteFailure>().is_some());
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_missing_auth_root_gets_an_explicit_rejection_before_router_io() -> anyhow::Result<()> {
    let open: ramflux_node_core::GatewayOpenFrame = serde_json::from_value(serde_json::json!({
        "protocol_version":ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION,"transport_kind":"quic_quinn","client_instance_id":"client","device_id":"device","target_delivery_id":"target","stream_nonce":"nonce","previous_session_id":null,"resume_token_hash":null,"last_seen_inbox_seq":null,"max_inflight_downstream":4,"max_inflight_upstream":4,"pre_auth_cookie":null,"pre_auth_now":null,"source_ip_hash":null
    }))?;
    let auth = serde_json::json!({"frame_type":"auth","auth":{
        "signed_request":{"schema":"ramflux.signed_request.v1","version":1,"domain":"ramflux.signed_request.v1","ext":{},"signing_key_id":"device","signature_alg":"ed25519","signature":"unused","source_device_id":"device","request_id":"auth","method":"POST","path":"/gateway/session/auth","device_proof_hash":"unused","body_hash":"unused","nonce":"nonce","created_at":1,"expires_at":2},
        "device_proof":{"schema":"ramflux.device_proof.v1","version":1,"domain":"ramflux.device_proof.v1","ext":{},"signing_key_id":"device","signature_alg":"ed25519","signature":"unused","principal_id":"alice","device_id":"device","device_epoch":1,"branch_proof_hash":"unused","capability_scope":["gateway.session"],"nonce":"nonce","expires_at":2}
    }});
    let frames = Arc::new(Mutex::new(Vec::new()));
    super::handle_gateway_session_transport(
        Box::new(Sink(frames.clone())),
        Box::new(Source(VecDeque::from([serde_json::to_vec(&auth)?]))),
        super::tests::test_gateway_context()?,
        ramflux_node_core::GatewayClientFrame::Open { open },
    )
    .await?;
    let frames = frames.lock().map_err(|_| anyhow::anyhow!("frame mutex"))?;
    assert_eq!(frames.len(), 1);
    assert_eq!(
        serde_json::from_slice::<ramflux_node_core::GatewayServerFrame>(&frames[0])?,
        ramflux_node_core::GatewayServerFrame::Nack {
            reason: "gateway_auth_source_rejected".into()
        }
    );
    Ok(())
}

#[tokio::test]
async fn broken_recipient_is_unregistered_without_an_extra_sender_reply_and_reconnect_delivers()
-> anyhow::Result<()> {
    let context = super::tests::test_gateway_context()?;
    let writes = Arc::new(AtomicUsize::new(0));
    context
        .hub
        .register(
            "peer".into(),
            "broken".into(),
            Arc::new(AsyncMutex::new(Box::new(BrokenSink(writes.clone())))),
        )
        .await?;
    let frames = Arc::new(Mutex::new(Vec::new()));
    let send: GatewaySendHandle = Arc::new(AsyncMutex::new(Box::new(Sink(frames.clone()))));
    let envelope = super::tests::test_envelope();
    let frame = ramflux_node_core::GatewayServerFrame::Deliver {
        entry: ramflux_node_core::InboxEntry {
            target_delivery_id: "peer".into(),
            inbox_seq: 1,
            envelope: envelope.clone(),
        },
    };
    let response = ramflux_node_core::EnvelopeSubmitResponse {
        outcome: "online".into(),
        target_delivery_id: "peer".into(),
        inbox_seq: Some(1),
        cursor: None,
        nack: None,
    };
    super::reply_and_deliver_submitted(&send, &context, &runtime()?, &response, &frame, &envelope)
        .await?;
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert!(!context.hub.send_to("peer", &frame).await);
    assert_eq!(writes.load(Ordering::SeqCst), 1, "dead peer was removed, not retried");
    // The same sender sink and authenticated session still answer the next request exactly once.
    let source = Source(VecDeque::from([serde_json::to_vec(
        &ramflux_node_core::GatewayClientFrame::Heartbeat { now: 9 },
    )?]));
    super::run_gateway_session_loop(send.clone(), Box::new(source), context.clone(), runtime()?)
        .await?;
    assert_eq!(frames.lock().map_err(|_| anyhow::anyhow!("frames"))?.len(), 2);
    let received = Arc::new(Mutex::new(Vec::new()));
    context
        .hub
        .register(
            "peer".into(),
            "reconnected".into(),
            Arc::new(AsyncMutex::new(Box::new(Sink(received.clone())))),
        )
        .await?;
    // Re-delivery of the retained inbox entry now reaches the new recipient session.
    // This is delivery work, not another request or reply on A's stream.
    super::deliver_submitted_to_peer(&context, &runtime()?, &response, &frame, &envelope).await?;
    let received = received.lock().map_err(|_| anyhow::anyhow!("received"))?;
    assert_eq!(received.len(), 1);
    assert_eq!(
        serde_json::from_slice::<ramflux_node_core::GatewayServerFrame>(&received[0])?,
        frame
    );
    let output_frames = frames.lock().map_err(|_| anyhow::anyhow!("frames"))?;
    assert_eq!(output_frames.len(), 2);
    assert_eq!(
        serde_json::from_slice::<ramflux_node_core::GatewayServerFrame>(&output_frames[0])?,
        frame
    );
    assert_eq!(
        serde_json::from_slice::<ramflux_node_core::GatewayServerFrame>(&output_frames[1])?,
        ramflux_node_core::GatewayServerFrame::Heartbeat { now: 9 }
    );
    Ok(())
}

struct ReplacedSink {
    hub: Arc<GatewaySessionHub>,
    replacement: GatewaySendHandle,
}
impl GatewaySessionFrameSink for ReplacedSink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(&'a mut self, _: &'a [u8]) -> Future<'a, ()> {
        Box::pin(async move {
            self.hub
                .register("peer".into(), "same-session".into(), self.replacement.clone())
                .await
                .map_err(|error| TransportError::Quic(error.to_string()))?;
            Err(TransportError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
        })
    }
}
#[tokio::test]
async fn a_failed_old_sink_cannot_unregister_the_replacement_session() -> anyhow::Result<()> {
    let hub = Arc::new(GatewaySessionHub::default());
    let received = Arc::new(Mutex::new(Vec::new()));
    let replacement: GatewaySendHandle =
        Arc::new(AsyncMutex::new(Box::new(Sink(received.clone()))));
    hub.register(
        "peer".into(),
        "same-session".into(),
        Arc::new(AsyncMutex::new(Box::new(ReplacedSink { hub: hub.clone(), replacement }))),
    )
    .await?;
    let frame = ramflux_node_core::GatewayServerFrame::Heartbeat { now: 1 };
    assert!(!hub.send_to("peer", &frame).await);
    assert!(hub.send_to("peer", &frame).await);
    assert_eq!(received.lock().map_err(|_| anyhow::anyhow!("frames"))?.len(), 1);
    Ok(())
}

struct WaitingSource(Arc<tokio::sync::Notify>);
impl GatewaySessionFrameSource for WaitingSource {
    fn recv_frame(&mut self) -> Future<'_, Vec<u8>> {
        self.0.notify_one();
        Box::pin(std::future::pending())
    }
}
#[tokio::test]
async fn resuming_the_same_session_id_survives_the_old_loops_cleanup() -> anyhow::Result<()> {
    let context = super::tests::test_gateway_context()?;
    let mut old_runtime = runtime()?;
    old_runtime.target_delivery_id = "peer".into();
    old_runtime.session_id = "same-session".into();
    let waiting = Arc::new(tokio::sync::Notify::new());
    let old = tokio::spawn(super::run_registered_gateway_session(
        Box::new(Sink(Arc::default())),
        Box::new(WaitingSource(waiting.clone())),
        context.clone(),
        old_runtime,
        None,
    ));
    waiting.notified().await;
    let received = Arc::new(Mutex::new(Vec::new()));
    let _new = context
        .hub
        .register(
            "peer".into(),
            "same-session".into(),
            Arc::new(AsyncMutex::new(Box::new(Sink(received.clone())))),
        )
        .await?;
    old.await??;
    assert!(
        context
            .hub
            .send_to("peer", &ramflux_node_core::GatewayServerFrame::Heartbeat { now: 7 })
            .await
    );
    assert_eq!(received.lock().map_err(|_| anyhow::anyhow!("frames"))?.len(), 1);
    Ok(())
}

struct StalledSink(Arc<AtomicUsize>);
impl GatewaySessionFrameSink for StalledSink {
    fn finish(&mut self) -> Result<(), TransportError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn send_frame<'a>(&'a mut self, _: &'a [u8]) -> Future<'a, ()> {
        Box::pin(std::future::pending())
    }
}
#[tokio::test]
async fn a_stalled_peer_write_closes_only_that_registration_within_the_deadline()
-> anyhow::Result<()> {
    let hub = GatewaySessionHub::default();
    let finished = Arc::new(AtomicUsize::new(0));
    let registration = hub
        .register(
            "peer".into(),
            "session".into(),
            Arc::new(AsyncMutex::new(Box::new(StalledSink(finished.clone())))),
        )
        .await?;
    let frame = ramflux_node_core::GatewayServerFrame::Heartbeat { now: 1 };
    assert!(
        !tokio::time::timeout(std::time::Duration::from_secs(3), hub.send_to("peer", &frame))
            .await?
    );
    assert_eq!(finished.load(Ordering::SeqCst), 1);
    assert!(*registration.closed.borrow());
    assert!(!hub.send_to("peer", &frame).await);
    Ok(())
}
