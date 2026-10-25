// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A recipient ACK may precede the sender's submit confirmation.
use ramflux_node_core::{EnvelopeSubmitResponse, GatewayServerFrame, OpaqueDeviceInbox};
use ramflux_transport::{
    GatewaySessionFrameSink, MeshQuicAcceptedWireRequest, MeshQuicServer, TransportError,
};
use std::sync::{Arc, Mutex};

struct Sink(Arc<Mutex<Vec<GatewayServerFrame>>>);
impl GatewaySessionFrameSink for Sink {
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
    fn send_frame<'a>(
        &'a mut self,
        body: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.0
                .lock()
                .map_err(|_| TransportError::Quic("test sink mutex".into()))?
                .push(serde_json::from_slice(body)?);
            Ok(())
        })
    }
}
fn sink() -> (crate::GatewaySendHandle, Arc<Mutex<Vec<GatewayServerFrame>>>) {
    let frames = Arc::new(Mutex::new(Vec::new()));
    (Arc::new(tokio::sync::Mutex::new(Box::new(Sink(frames.clone())))), frames)
}

#[tokio::test]
async fn recipient_ack_before_submit_confirmation_succeeds_when_the_inbox_is_empty()
-> Result<(), Box<dyn std::error::Error>> {
    submit_after_recipient_ack(false).await
}

#[tokio::test]
async fn recipient_ack_before_submit_confirmation_never_confirms_a_later_envelope()
-> Result<(), Box<dyn std::error::Error>> {
    submit_after_recipient_ack(true).await
}

async fn submit_after_recipient_ack(later_message: bool) -> Result<(), Box<dyn std::error::Error>> {
    use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
    let root = temp_cert_root("submit-ack-race")?;
    let gateway = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-gateway")?;
    let router = issue_test_ca_and_service_cert(&root, "node-test", "ramflux-router")?;
    let server = MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &router.tls,
        Arc::new(move || Ok(vec![gateway.ca_pem.clone()])),
    )?;
    let mut context = super::tests::test_gateway_context()?;
    context.router = crate::RouterMeshClient {
        endpoint: "127.0.0.1:0".into(),
        server_name: "ramflux-router".into(),
        tls: gateway.tls.clone(),
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: Some(crate::RouterAsyncMeshClient {
            endpoint: server.local_addr()?.to_string(),
            server_name: "ramflux-router".into(),
            tls: gateway.tls,
            peer_ca_pems: vec![router.ca_pem],
        }),
    };
    let now = i64::try_from(ramflux_node_core::now_unix_seconds())?;
    let runtime = test_runtime()?;
    let mut envelope = test_envelope(now)?;
    envelope.ext.ext.insert(
        "source_root_commitment".into(),
        serde_json::json!(runtime.source_identity.root_commitment()),
    );
    envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
        [4; 32],
    );
    let mut signed_request: ramflux_protocol::SignedRequest = serde_json::from_value(
        serde_json::json!({
            "schema":"ramflux.signed_request.v1","version":1,"domain":"ramflux.signed_request.v1",
            "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
            "source_device_id":"agent-device","request_id":"submit-once","method":"POST","path":"/gateway/session/submit",
            "device_proof_hash":"already_authed","body_hash":"opaque-hash","nonce":"submit-nonce","created_at":now,"expires_at":now+60
        }),
    )?;
    signed_request.body_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        &ramflux_protocol::canonical_json_bytes(&envelope)?,
    );
    signed_request.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(&signed_request)?,
        [4; 32],
    );
    let (finished, done) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(ack_before_response(server, done, later_message));
    let (send, frames) = sink();
    let (recipient, received) = sink();
    context.hub.register("alice-target".into(), "alice-session".into(), recipient).await?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        super::handle_gateway_submit(
            &send,
            &context,
            &runtime,
            &ramflux_node_core::GatewaySubmitFrame { signed_request, envelope: envelope.clone() },
        ),
    )
    .await?;
    let _ = finished.send(());
    serving.await??;
    result?;
    let frames = frames.lock().map_err(|_| anyhow::anyhow!("sender mutex"))?;
    assert_eq!(frames.len(), 1);
    let GatewayServerFrame::Deliver { entry } = &frames[0] else {
        return Err("submit did not confirm acceptance".into());
    };
    assert_eq!(entry.inbox_seq, 1);
    assert_eq!(entry.envelope, envelope);
    assert_eq!(entry.target_delivery_id, "alice-target");
    assert_eq!(*received.lock().map_err(|_| anyhow::anyhow!("recipient mutex"))?, *frames);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn ack_before_response(
    server: MeshQuicServer,
    mut done: tokio::sync::oneshot::Receiver<()>,
    later_message: bool,
) -> anyhow::Result<()> {
    let inbox = Arc::new(Mutex::new(OpaqueDeviceInbox::new()));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            result = server.accept_connection() => {
                tasks.spawn(serve_connection(result?, inbox.clone(), later_message));
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result { result??; }
            }
            _ = &mut done => { tasks.abort_all(); return Ok(()); }
        }
    }
}

async fn serve_connection(
    connection: ramflux_transport::MeshQuicConnection,
    inbox: Arc<Mutex<OpaqueDeviceInbox>>,
    later_message: bool,
) -> anyhow::Result<()> {
    loop {
        let accepted =
            MeshQuicServer::accept_json_or_postcard_request_on_connection(&connection).await?;
        match accepted {
            MeshQuicAcceptedWireRequest::Postcard(accepted) => {
                anyhow::ensure!(
                    accepted.path == "/mvp0/envelope" && accepted.method == "POST",
                    "unexpected submit"
                );
                let envelope: ramflux_protocol::Envelope = serde_json::from_slice(&accepted.body)?;
                let entry = {
                    let mut pending = inbox.lock().map_err(|_| anyhow::anyhow!("inbox mutex"))?;
                    let entry = pending.append(envelope.clone());
                    let ack: ramflux_protocol::Ack = serde_json::from_value(serde_json::json!({
                        "schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1",
                        "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
                        "ack_id":"ack","envelope_id":envelope.envelope_id,"receiver_device_id":"alice-device","received_at":envelope.created_at
                    }))?;
                    pending.apply_ack(&ack)?;
                    assert_eq!(pending.pull_after("alice-target", 0, 1), []);
                    // A subsequent accepted envelope must never be mistaken for this confirmation.
                    if later_message {
                        let mut later = envelope.clone();
                        later.envelope_id = "later-message".into();
                        pending.append(later);
                    }
                    entry
                };
                accepted
                    .write_postcard_response(
                        200,
                        &EnvelopeSubmitResponse {
                            outcome: "online".into(),
                            target_delivery_id: entry.target_delivery_id,
                            inbox_seq: Some(entry.inbox_seq),
                            cursor: None,
                            nack: None,
                        },
                    )
                    .await?;
            }
            MeshQuicAcceptedWireRequest::Json(accepted) => {
                anyhow::ensure!(
                    accepted.request.path.starts_with("/mvp1/inbox/alice-target?"),
                    "unexpected inbox request"
                );
                // This is exactly what the old post-submit lookup sees after the ACK.
                let entries = inbox.lock().map_err(|_| anyhow::anyhow!("inbox mutex"))?.pull_after(
                    "alice-target",
                    0,
                    1,
                );
                accepted
                    .write_json_response(
                        200,
                        &serde_json::json!({"target_delivery_id":"alice-target","entries":entries}),
                    )
                    .await?;
            }
        }
    }
}

fn test_envelope(now: i64) -> anyhow::Result<ramflux_protocol::Envelope> {
    let envelope = serde_json::from_value(serde_json::json!({
        "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
        "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
        "envelope_id":"group-distribution","source_principal_id":"agent","source_device_id":"agent-device","target_delivery_id":"alice-target",
        "delivery_class":"opaque_event","priority":"normal","ttl":300,"created_at":now,"encrypted_payload":"opaque","payload_hash":"opaque-hash"
    }))?;
    Ok(envelope)
}

#[test]
fn submit_confirmation_requires_an_accepted_outcome_matching_target_and_committed_sequence()
-> anyhow::Result<()> {
    let envelope = test_envelope(100)?;
    let accepted = EnvelopeSubmitResponse {
        outcome: "online".into(),
        target_delivery_id: envelope.target_delivery_id.clone(),
        inbox_seq: Some(1),
        cursor: None,
        nack: None,
    };
    for outcome in ["online", "offline_queued"] {
        let mut response = accepted.clone();
        response.outcome = outcome.into();
        assert!(super::committed_submit_entry(&response, envelope.clone()).is_ok());
    }
    for seq in [None, Some(0)] {
        let mut response = accepted.clone();
        response.inbox_seq = seq;
        assert!(super::committed_submit_entry(&response, envelope.clone()).is_err());
    }
    let mut wrong_target = accepted.clone();
    wrong_target.target_delivery_id = "other-target".into();
    assert!(super::committed_submit_entry(&wrong_target, envelope.clone()).is_err());
    for outcome in ["rejected_security", "forwarded_home_node_migrated", "unknown"] {
        let mut response = accepted.clone();
        response.outcome = outcome.into();
        assert!(super::committed_submit_entry(&response, envelope.clone()).is_err());
    }
    Ok(())
}

fn test_runtime() -> anyhow::Result<crate::GatewaySessionRuntime> {
    let root = ramflux_crypto::create_identity_root("agent", [3; 32]);
    let branch = ramflux_crypto::create_device_branch("agent", "agent-device", 1, [4; 32]);
    Ok(crate::GatewaySessionRuntime {
        source_identity: ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?,
        session_id: "agent-session".into(),
        resume_token: "resume".into(),
        principal_id: "agent".into(),
        device_id: "agent-device".into(),
        target_delivery_id: "agent-target".into(),
        device_epoch: 1,
        branch_public_key: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
    })
}
#[tokio::test]
async fn fanout_confirmation_survives_recipient_ack_with_an_empty_or_later_inbox()
-> Result<(), Box<dyn std::error::Error>> {
    for later in [false, true] {
        let context = super::tests::test_gateway_context()?;
        let runtime = test_runtime()?;
        let submitted = test_envelope(i64::try_from(ramflux_node_core::now_unix_seconds())?)?;
        let mut expected = submitted.clone();
        expected.envelope_id =
            ramflux_node_core::mvp10_fanout_envelope_id(&submitted.envelope_id, "alice-device");
        let mut inbox = OpaqueDeviceInbox::new();
        let entry = inbox.append(expected.clone());
        let ack = serde_json::from_value(serde_json::json!({
            "schema":"ramflux.ack.v1","version":1,"domain":"ramflux.ack.v1",
            "signing_key_id":"test","signature_alg":"ed25519","signature":"fixture",
            "ack_id":"fanout-race-ack","envelope_id":expected.envelope_id,
            "receiver_device_id":"alice-device","received_at":submitted.created_at,
        }))?;
        inbox.apply_ack(&ack)?;
        assert_eq!(inbox.pull_after("alice-target", 0, 10).len(), 0);
        if later {
            let mut next = expected.clone();
            next.envelope_id = "later".into();
            inbox.append(next);
        }
        let (recipient, received) = sink();
        context.hub.register("alice-target".into(), "same-session".into(), recipient).await?;
        let delivery = ramflux_node_core::GatewayOwnDeviceFanoutDelivery {
            device_id: "alice-device".into(),
            target_delivery_id: "alice-target".into(),
            outcome: "online".into(),
            inbox_seq: Some(entry.inbox_seq),
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            super::deliver_own_device_fanout_entry(&context, &runtime, &delivery, &submitted),
        )
        .await??;
        assert_eq!(
            *received.lock().map_err(|_| anyhow::anyhow!("frames"))?,
            vec![GatewayServerFrame::Deliver { entry }]
        );
    }
    Ok(())
}
#[test]
fn fanout_confirmation_requires_a_positive_committed_sequence_for_an_accepted_delivery()
-> anyhow::Result<()> {
    let envelope = test_envelope(100)?;
    for sequence in [None, Some(0)] {
        let delivery = ramflux_node_core::GatewayOwnDeviceFanoutDelivery {
            device_id: "alice-device".into(),
            target_delivery_id: "alice-target".into(),
            outcome: "online".into(),
            inbox_seq: sequence,
        };
        assert!(super::committed_fanout_entry(&delivery, &envelope).is_err());
    }
    Ok(())
}
