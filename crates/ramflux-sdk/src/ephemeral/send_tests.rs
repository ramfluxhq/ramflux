// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Named P12 rows: D5 local unsupported, D1 Invalid, delivered, I-NP.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{
    EphemeralSendError, EphemeralSendOutcome, EphemeralWire, decode_ephemeral_result,
    encode_ephemeral_submit, send_ephemeral,
};
use crate::RamfluxClient;
use ramflux_protocol::ephemeral::{
    DELIVERY_MODE_EXTENSION, EphemeralDropReason, EphemeralModeError, GATEWAY_EPHEMERAL_CAPABILITY,
};
use ramflux_protocol::{
    DeliveryClass, Envelope, Ext, GATEWAY_SESSION_PUSH_CAPABILITY, Priority, SignatureAlg,
    SignedFields,
};
use ramflux_storage::AccountDb;
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};

const NOW_MS: u64 = 1_000_000;
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct RecordingWire {
    sent: Vec<Vec<u8>>,
    replies: VecDeque<Vec<u8>>,
}

impl RecordingWire {
    fn with_result(outcome: &str, reason: Option<&str>) -> Self {
        let mut body = serde_json::json!({
            "frame_type": "ephemeral_result",
            "envelope_id": "envelope",
            "outcome": outcome,
        });
        if let Some(reason) = reason {
            body["reason"] = Value::String(reason.to_owned());
        }
        Self { sent: Vec::new(), replies: VecDeque::from([serde_json::to_vec(&body).unwrap()]) }
    }
}

impl EphemeralWire for RecordingWire {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), EphemeralSendError> {
        self.sent.push(frame.to_vec());
        Ok(())
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, EphemeralSendError> {
        self.replies.pop_front().ok_or(EphemeralSendError::TransportRead)
    }
}

struct FailingWire;

impl EphemeralWire for FailingWire {
    fn send_frame(&mut self, _frame: &[u8]) -> Result<(), EphemeralSendError> {
        Err(EphemeralSendError::TransportWrite)
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, EphemeralSendError> {
        Err(EphemeralSendError::TransportRead)
    }
}

fn push() -> String {
    GATEWAY_SESSION_PUSH_CAPABILITY.to_owned()
}

fn ephemeral_cap() -> String {
    GATEWAY_EPHEMERAL_CAPABILITY.to_owned()
}

fn both_caps() -> Vec<String> {
    vec![push(), ephemeral_cap()]
}

fn base_envelope() -> Envelope {
    let mut extensions = BTreeMap::new();
    extensions.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("ephemeral".to_owned()));
    Envelope {
        schema: "ramflux.envelope.v1".to_owned(),
        version: 1,
        domain: "ramflux.message".to_owned(),
        ext: Ext { ext: extensions },
        signed: SignedFields {
            signing_key_id: "key".to_owned(),
            signature_alg: SignatureAlg::Ed25519,
            signature: "fixture".to_owned(),
        },
        envelope_id: "envelope".to_owned(),
        source_principal_id: "principal".to_owned(),
        source_device_id: "device".to_owned(),
        target_delivery_id: "target".to_owned(),
        routing_set_id: None,
        delivery_class: DeliveryClass::OpaqueEvent,
        priority: Priority::Low,
        ttl: 5,
        created_at: 1_000,
        encrypted_payload: "ct".to_owned(),
        payload_hash: "hash".to_owned(),
    }
}

fn send(
    envelope: &Envelope,
    caps: &[String],
    wire: &mut RecordingWire,
) -> Result<EphemeralSendOutcome, EphemeralSendError> {
    send_ephemeral(envelope, caps, NOW_MS, wire)
}

fn row_both_caps_delivers(envelope: &Envelope) -> TestResult {
    let mut wire = RecordingWire::with_result("accepted", None);
    assert_eq!(send(envelope, &both_caps(), &mut wire)?, EphemeralSendOutcome::Delivered);
    assert_eq!(wire.sent.len(), 1, "one submit frame on the wire");
    let sent: Value = serde_json::from_slice(&wire.sent[0])?;
    assert_eq!(sent["frame_type"], "submit");
    assert_eq!(sent["submit"]["envelope"]["envelope_id"], "envelope");
    assert_eq!(encode_ephemeral_submit(envelope)?, wire.sent[0]);
    Ok(())
}

fn row_missing_capability_sends_nothing(envelope: &Envelope) -> TestResult {
    let cases =
        [Vec::new(), vec![push()], vec![ephemeral_cap()], vec!["gateway.other.v1".to_owned()]];
    for caps in cases {
        let mut wire = RecordingWire::with_result("accepted", None);
        assert_eq!(
            send(envelope, &caps, &mut wire)?,
            EphemeralSendOutcome::Unsupported,
            "caps={caps:?}"
        );
        assert!(wire.sent.is_empty(), "zero frames when echo is incomplete: {caps:?}");
    }
    Ok(())
}

fn row_invalid_mode_priority_ttl_sends_nothing() -> TestResult {
    let mut mode = base_envelope();
    mode.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), Value::String("burst".to_owned()));
    let mut object_mode = base_envelope();
    object_mode.ext.ext.insert(DELIVERY_MODE_EXTENSION.to_owned(), serde_json::json!({}));
    let mut durable = base_envelope();
    durable.ext.ext.remove(DELIVERY_MODE_EXTENSION);
    let mut priority = base_envelope();
    priority.priority = Priority::Normal;
    let mut ttl_zero = base_envelope();
    ttl_zero.ttl = 0;
    let mut ttl_six = base_envelope();
    ttl_six.ttl = 6;
    let rows = [
        (mode, EphemeralModeError::InvalidDeliveryMode),
        (object_mode, EphemeralModeError::InvalidDeliveryMode),
        (durable, EphemeralModeError::NotEphemeral),
        (priority, EphemeralModeError::InvalidPriority),
        (ttl_zero, EphemeralModeError::InvalidTtl),
        (ttl_six, EphemeralModeError::InvalidTtl),
    ];
    for (envelope, error) in rows {
        let mut wire = RecordingWire::with_result("accepted", None);
        assert_eq!(send(&envelope, &both_caps(), &mut wire)?, EphemeralSendOutcome::Invalid(error));
        assert!(wire.sent.is_empty(), "nothing sent for {error}");
    }
    Ok(())
}

fn row_remote_results_map(envelope: &Envelope) -> TestResult {
    let rows = [
        ("dropped", Some("rate_limited"), EphemeralSendOutcome::RateLimited),
        ("dropped", Some("replayed"), EphemeralSendOutcome::Replayed),
        ("dropped", Some("unsupported"), EphemeralSendOutcome::Unsupported),
        (
            "dropped",
            Some("invalid"),
            EphemeralSendOutcome::Invalid(EphemeralModeError::InvalidDeliveryMode),
        ),
        ("dropped", Some("offline"), EphemeralSendOutcome::Dropped(EphemeralDropReason::Offline)),
    ];
    for (outcome, reason, expected) in rows {
        let reply = RecordingWire::with_result(outcome, reason).replies[0].clone();
        assert_eq!(decode_ephemeral_result(&reply)?, expected);
        let mut wire = RecordingWire::with_result(outcome, reason);
        assert_eq!(send(envelope, &both_caps(), &mut wire)?, expected);
        assert_eq!(wire.sent.len(), 1);
    }
    Ok(())
}

fn account_snapshot(db: &AccountDb) -> Result<String, Box<dyn std::error::Error>> {
    let bounds = db.journal_bounds()?;
    let journal = db.journal_after(0, 128)?;
    let outbox = db.pending_outbox(256)?;
    let actors = db.list_actor_states::<Value>("")?;
    Ok(format!("{bounds:?}|{journal:?}|{outbox:?}|{actors:?}"))
}

fn row_no_persistence(envelope: &Envelope) -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut client = RamfluxClient::new();
    let root = ramflux_crypto::create_identity_root("alice", [0x31; 32]);
    let commitment = ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key());
    client.create_identity_root("alice", [0x31; 32]);
    client.create_device_branch("alice", "device", 1, [0x32; 32]);
    client.open_account_index(directory.path())?;
    client.create_account("acct", &commitment)?;
    client.unlock_account("acct", b"secret")?;
    let db = client.account_db()?;
    let before = account_snapshot(db)?;
    let mut wire = RecordingWire::with_result("accepted", None);
    assert_eq!(send(envelope, &both_caps(), &mut wire)?, EphemeralSendOutcome::Delivered);
    let mut blocked = RecordingWire::with_result("accepted", None);
    assert_eq!(send(envelope, &[], &mut blocked)?, EphemeralSendOutcome::Unsupported);
    assert_eq!(account_snapshot(db)?, before);
    Ok(())
}

#[test]
fn ephemeral_sdk_send_and_local_unsupported() -> TestResult {
    let envelope = base_envelope();
    row_both_caps_delivers(&envelope)?;
    row_missing_capability_sends_nothing(&envelope)?;
    row_invalid_mode_priority_ttl_sends_nothing()?;
    row_remote_results_map(&envelope)?;
    row_no_persistence(&envelope)?;
    assert_eq!(
        send_ephemeral(&envelope, &both_caps(), NOW_MS, &mut FailingWire),
        Err(EphemeralSendError::TransportWrite)
    );
    Ok(())
}
