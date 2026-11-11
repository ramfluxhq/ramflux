// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session transport integration and the single transient host consumer.

use super::{
    SessionMode,
    routing_tests::{scripted, scripted_raw},
};
use crate::ephemeral::session::{SessionInbox, wall_ms};
use crate::{
    GatewayServerFrame,
    ephemeral::{EphemeralSendOutcome, EphemeralSource, ReceiverClock},
};
use std::{future::Future, task::Poll};
use tokio::time::{Duration, timeout};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn source() -> Result<EphemeralSource, ramflux_crypto::CryptoError> {
    let root = ramflux_crypto::create_identity_root("session-source", [11; 32]);
    let branch = ramflux_crypto::create_device_branch("session-source", "device", 1, [12; 32]);
    Ok(EphemeralSource {
        principal_id: root.principal_id.clone(),
        device: ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?,
        signing_public_key: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
    })
}

fn envelope(
    created_at: i64,
    id: &str,
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error + Send + Sync>> {
    let authority = source()?;
    let mut envelope: ramflux_protocol::Envelope = serde_json::from_value(serde_json::json!({
        "schema":"ramflux.envelope.v1", "version":1, "domain":"ramflux.envelope.v1",
        "signing_key_id":"device", "signature_alg":"ed25519", "signature":"",
        "envelope_id":id, "source_principal_id":authority.principal_id,
        "source_device_id":"device", "target_delivery_id":"target-route",
        "delivery_class":"opaque_event", "priority":"low", "ttl":5,
        "created_at":created_at, "encrypted_payload":"presealed", "payload_hash":"hash",
        "ext":{"delivery_mode":"ephemeral", "source_root_commitment":authority.device.root_commitment()}
    }))?;
    let branch = ramflux_crypto::create_device_branch("session-source", "device", 1, [12; 32]);
    envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
        &branch,
    );
    Ok(envelope)
}

fn frame(envelope: ramflux_protocol::Envelope) -> Result<Vec<u8>, serde_json::Error> {
    let expires_at_ms =
        u64::try_from(envelope.created_at).unwrap_or(0).saturating_add(5).saturating_mul(1_000);
    // Preserve whitespace: transport occupancy and handoff must use original bytes.
    let mut bytes = serde_json::to_vec(&GatewayServerFrame::Ephemeral { envelope, expires_at_ms })?;
    bytes.extend_from_slice(b"   \n");
    Ok(bytes)
}

async fn poll_pending(future: std::pin::Pin<&mut impl Future>) {
    let mut future = future;
    std::future::poll_fn(|context| {
        assert!(future.as_mut().poll(context).is_pending(), "expected an idle consumer");
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn ephemeral_session_host_carries_raw_events_during_correlated_reply() -> TestResult {
    let now = i64::try_from(wall_ms() / 1_000)?;
    let incoming = frame(envelope(now, "received")?)?;
    let result = serde_json::to_vec(&GatewayServerFrame::EphemeralResult {
        envelope_id: "sent".into(),
        result: ramflux_protocol::ephemeral::EphemeralSubmitResult::accepted(),
    })?;
    let mut engine = scripted_raw(super::routing_tests::push(), vec![incoming.clone(), result]);
    engine.ephemeral_negotiated = true;
    engine.config = engine.config.clone().with_owned_device(
        &ramflux_crypto::create_identity_root("session-source", [11; 32]),
        ramflux_crypto::create_device_branch("session-source", "device", 1, [12; 32]),
    )?;
    let mut consumer = engine.take_ephemeral_consumer().ok_or("consumer missing")?;
    assert!(engine.take_ephemeral_consumer().is_none(), "consumer must be exclusive");
    assert_eq!(
        engine.submit_ephemeral(envelope(now, "sent")?).await?,
        EphemeralSendOutcome::Delivered
    );
    let authority = source()?;
    let mut authority = Some(authority);
    let received = timeout(Duration::from_secs(1), consumer.next(|_| authority.take())).await?;
    let (bytes, _) = received.ok_or("consumer closed")?;
    assert_eq!(bytes, incoming);
    assert_eq!(engine.ephemeral_inbox.observation().0, 1, "in-flight counts once");
    consumer.complete();
    assert_eq!(engine.ephemeral_inbox.observation().0, 0);
    assert!(engine.take_pending_deliveries().is_empty(), "no durable delivery buffer entry");
    Ok(())
}

#[tokio::test]
async fn ephemeral_session_host_refuses_foreign_result_and_unsupported_without_write() -> TestResult
{
    let now = i64::try_from(wall_ms() / 1_000)?;
    let mut engine = scripted(SessionMode::Legacy, Vec::new());
    assert_eq!(
        engine.submit_ephemeral(envelope(now, "sent")?).await?,
        EphemeralSendOutcome::Unsupported
    );
    assert_eq!(engine.wire_writes, 0);
    let wrong = GatewayServerFrame::EphemeralResult {
        envelope_id: "foreign".into(),
        result: ramflux_protocol::ephemeral::EphemeralSubmitResult::accepted(),
    };
    let wrong = serde_json::to_value(wrong)?;
    let mut engine = scripted(super::routing_tests::push(), vec![wrong]);
    engine.ephemeral_negotiated = true;
    engine.config = engine.config.clone().with_owned_device(
        &ramflux_crypto::create_identity_root("session-source", [11; 32]),
        ramflux_crypto::create_device_branch("session-source", "device", 1, [12; 32]),
    )?;
    assert!(engine.submit_ephemeral(envelope(now, "sent")?).await.is_err());
    assert_eq!(
        engine.terminal_reason,
        Some(crate::bus::connection_manager::DisconnectReason::UnexpectedReply),
        "foreign ephemeral reply must retire the owning session"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn ephemeral_session_consumer_promotes_idle_hold_and_preserves_generation_dedup() -> TestResult
{
    let inbox = SessionInbox::new();
    inbox.set_clock(ReceiverClock { local_now_ms: 1_000_000, monotonic_ms: 0 });
    let raw = frame(envelope(1_001, "held")?)?;
    let mut consumer = inbox.consumer().ok_or("consumer missing")?;
    inbox.push(&raw, 1_006_000);
    let mut authority = Some(source()?);
    let mut waiting = Box::pin(consumer.next(|_| authority.take()));
    poll_pending(waiting.as_mut()).await;
    assert_eq!(inbox.observation(), (1, raw.len(), 1, 0));
    inbox.set_clock(ReceiverClock { local_now_ms: 1_001_000, monotonic_ms: 1_000 });
    tokio::time::advance(Duration::from_millis(10)).await;
    let received = waiting.await.ok_or("held consumer closed")?;
    assert_eq!(received.0, raw, "idle timer must promote the original ciphertext");
    consumer.complete();
    drop(consumer);
    let mut consumer = inbox.consumer().ok_or("dropped consumer retained its exclusive lease")?;
    assert_eq!(inbox.observation().3, 1, "reattachment must preserve live dedup");
    inbox.disconnect(false);
    assert_eq!(inbox.observation(), (0, 0, 0, 1), "same-generation dedup survives disconnect");
    inbox.reconnect();
    inbox.push(&raw, 1_006_000);
    let mut authority = Some(source()?);
    let mut waiting = Box::pin(consumer.next(|_| authority.take()));
    poll_pending(waiting.as_mut()).await;
    inbox.disconnect(true);
    assert!(waiting.await.is_none(), "lock closes the consumer");
    assert_eq!(inbox.observation(), (0, 0, 0, 0));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn ephemeral_session_consumer_shares_one_budget_and_binds_root_device() -> TestResult {
    let inbox = SessionInbox::new();
    inbox.set_clock(ReceiverClock { local_now_ms: 1_000_000, monotonic_ms: 0 });
    let raw = frame(envelope(1_001, "held")?)?;
    for _ in 0..65 {
        inbox.push(&raw, 1_006_000);
    }
    assert_eq!(inbox.observation().0, 64, "raw backlog is bounded before authentication");
    let mut consumer = inbox.consumer().ok_or("consumer missing")?;
    let mut waiting = Box::pin(consumer.next(|_| source().ok()));
    poll_pending(waiting.as_mut()).await;
    assert_eq!(inbox.observation(), (1, raw.len(), 1, 0), "duplicates share one hold budget");
    drop(waiting);
    inbox.disconnect(false);
    inbox.reconnect();
    let mut bad = envelope(1_000, "wrong-root")?;
    bad.ext.ext.insert("source_root_commitment".into(), serde_json::json!("foreign"));
    let branch = ramflux_crypto::create_device_branch("session-source", "device", 1, [12; 32]);
    bad.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
        &ramflux_protocol::envelope_sender_signed_bytes(&bad)?,
        &branch,
    );
    let raw = frame(bad)?;
    inbox.push(&raw, 1_005_000);
    let mut waiting = Box::pin(consumer.next(|_| source().ok()));
    poll_pending(waiting.as_mut()).await;
    assert_eq!(inbox.observation(), (0, 0, 0, 0), "foreign root cannot enter the receiver");
    inbox.disconnect(true);
    assert!(waiting.await.is_none());
    let budget = SessionInbox::new();
    budget.set_clock(ReceiverClock { local_now_ms: 1_000_000, monotonic_ms: 0 });
    let mut large = frame(envelope(1_001, "byte-cap")?)?;
    large.resize(crate::RECEIVER_MAX_FRAME_BYTES, b' ');
    for _ in 0..9 {
        budget.push(&large, 1_006_000);
    }
    assert_eq!(
        budget.observation(),
        (8, crate::RECEIVER_CHANNEL_BYTES, 0, 0),
        "original raw bytes share the same 256 KiB budget"
    );
    Ok(())
}
