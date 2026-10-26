// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Forwarded submit receipts remain successful across gateway-version skew and retries.

use super::*;
use crate::SdkError;
use crate::time::now_unix_timestamp;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;
type Submissions = Arc<Mutex<Vec<String>>>;

#[derive(Clone, Copy)]
enum Reply {
    ForwardAck,
    MismatchedEnvelopeAck,
    MismatchedTargetAck,
    LegacyForwardedNack,
    UnknownNack,
}

struct SubmitGateway {
    reply: Reply,
    responses: VecDeque<Vec<u8>>,
    submissions: Submissions,
}

impl GatewaySessionFrameSink for SubmitGateway {
    fn send_frame<'a>(&'a mut self, body: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async move {
            let frame: GatewayClientFrame = serde_json::from_slice(body)?;
            let GatewayClientFrame::Submit { submit } = frame else {
                return Err(TransportError::Quic("expected submit frame".into()));
            };
            let mut submissions =
                self.submissions.lock().map_err(|_| TransportError::LockPoisoned)?;
            let duplicate = submissions.iter().any(|id| id == &submit.envelope.envelope_id);
            submissions.push(submit.envelope.envelope_id.clone());
            drop(submissions);
            let response = match self.reply {
                Reply::ForwardAck | Reply::MismatchedEnvelopeAck | Reply::MismatchedTargetAck => {
                    ramflux_node_core::GatewayServerFrame::ForwardAck {
                        ack: ramflux_node_core::GatewayForwardAck {
                            envelope_id: if matches!(self.reply, Reply::MismatchedEnvelopeAck) {
                                "wrong-envelope".into()
                            } else {
                                submit.envelope.envelope_id
                            },
                            target_delivery_id: if matches!(self.reply, Reply::MismatchedTargetAck)
                            {
                                "wrong-target".into()
                            } else {
                                submit.envelope.target_delivery_id
                            },
                            inbox_seq: (!duplicate).then_some(41),
                        },
                    }
                }
                Reply::LegacyForwardedNack => ramflux_node_core::GatewayServerFrame::Nack {
                    reason: ramflux_protocol::GATEWAY_FORWARDED_HOME_NODE_MIGRATED_REASON.into(),
                },
                Reply::UnknownNack => ramflux_node_core::GatewayServerFrame::Nack {
                    reason: "rejected_security".into(),
                },
            };
            self.responses.push_back(serde_json::to_vec(&response)?);
            Ok(())
        })
    }

    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

impl GatewaySessionFrameSource for SubmitGateway {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        let response = self.responses.pop_front();
        Box::pin(async move {
            if let Some(response) = response { Ok(response) } else { std::future::pending().await }
        })
    }
}

fn engine(reply: Reply) -> Result<(GatewaySessionEngine, Submissions), SdkError> {
    let root = ramflux_crypto::create_identity_root("submit-forward", [0x31; 32]);
    let branch =
        ramflux_crypto::create_device_branch("submit-forward", "submit-device", 1, [0x32; 32]);
    let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse().map_err(|error| {
            SdkError::GatewaySessionRejected(format!("test bind address: {error}"))
        })?,
        gateway_addr: "127.0.0.1:443".parse().map_err(|error| {
            SdkError::GatewaySessionRejected(format!("test gateway address: {error}"))
        })?,
        server_name: "localhost".into(),
        ca_cert: "test-ca.pem".into(),
        principal_id: "submit-forward".into(),
        device_id: "submit-device".into(),
        target_delivery_id: "submit-source-target".into(),
        prekey_http_url: None,
    })
    .with_owned_device(&root, branch)?;
    let submissions = Arc::new(Mutex::new(Vec::new()));
    let gateway =
        SubmitGateway { reply, responses: VecDeque::new(), submissions: Arc::clone(&submissions) };
    Ok((GatewaySessionEngine::with_test_transport(config, Box::new(gateway)), submissions))
}

fn envelope() -> Result<ramflux_protocol::Envelope, SdkError> {
    Ok(serde_json::from_value(serde_json::json!({
        "schema":"ramflux.envelope.v1","version":1,"domain":"ramflux.envelope.v1",
        "signing_key_id":"submit-device","signature_alg":"ed25519","signature":"fixture",
        "envelope_id":"forwarded-envelope","source_principal_id":"submit-forward",
        "source_device_id":"submit-device","target_delivery_id":"remote-target",
        "delivery_class":"opaque_event","priority":"normal","ttl":600,
        "created_at":now_unix_timestamp(),"encrypted_payload":"opaque",
        "payload_hash":"opaque-hash"
    }))?)
}

#[test]
fn stored_inbox_entries_without_forwarded_marker_read_unchanged()
-> Result<(), Box<dyn std::error::Error>> {
    let legacy = serde_json::json!({
        "inbox_seq": 7,
        "target_delivery_id": "remote-target",
        "envelope": envelope()?,
    });
    let entry: GatewayInboxEntry = serde_json::from_value(legacy)?;
    assert!(!entry.forwarded);
    let encoded = serde_json::to_value(entry)?;
    assert!(encoded.get("forwarded").is_none());
    Ok(())
}

#[tokio::test]
async fn typed_forward_ack_is_submitted_and_retry_keeps_one_envelope_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut engine, submissions) = engine(Reply::ForwardAck)?;
    assert!(
        engine
            .config
            .capability_scope
            .iter()
            .any(|capability| capability == ramflux_protocol::GATEWAY_FORWARD_ACK_CAPABILITY)
    );
    let envelope = envelope()?;

    let first = engine.submit_envelope(envelope.clone()).await?;
    assert_eq!(first.inbox_seq, 41);
    assert!(first.forwarded);
    assert_eq!(first.envelope.envelope_id, envelope.envelope_id);

    let retry = engine.submit_envelope(envelope.clone()).await?;
    assert_eq!(retry.inbox_seq, 0, "deduplicated retry has no new committed sequence");
    assert!(retry.forwarded);
    let submitted = submissions.lock().map_err(|_| "submissions mutex")?;
    assert_eq!(submitted.as_slice(), [envelope.envelope_id.as_str(); 2]);
    assert_eq!(submitted.iter().collect::<std::collections::BTreeSet<_>>().len(), 1);
    Ok(())
}

#[tokio::test]
async fn legacy_forwarded_nack_is_submitted_but_unknown_nack_still_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut legacy, _submissions) = engine(Reply::LegacyForwardedNack)?;
    let submitted = legacy.submit_envelope(envelope()?).await?;
    assert_eq!(submitted.inbox_seq, 0);
    assert!(submitted.forwarded);

    let (mut rejected, _submissions) = engine(Reply::UnknownNack)?;
    let error = rejected.submit_envelope(envelope()?).await.err().ok_or("expected rejection")?;
    assert!(matches!(
        error,
        SdkError::GatewaySessionRejected(reason) if reason == "rejected_security"
    ));
    Ok(())
}

#[tokio::test]
async fn mismatched_forward_ack_ids_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    for reply in [Reply::MismatchedEnvelopeAck, Reply::MismatchedTargetAck] {
        let (mut engine, _) = engine(reply)?;
        let error = engine.submit_envelope(envelope()?).await.err().ok_or("expected mismatch")?;
        assert!(
            matches!(error, SdkError::GatewaySessionRejected(reason) if reason.contains("forward acknowledgement mismatch"))
        );
    }
    Ok(())
}
