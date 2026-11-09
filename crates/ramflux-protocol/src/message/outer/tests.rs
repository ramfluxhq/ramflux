// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    CANDIDATE_ENVELOPE_SCHEMA, CRYPTOBOX_OVERHEAD_BYTES, CandidateDeliveryClass,
    CandidateOuterEnvelope, FRAME_PREFIX_BYTES, IngressSizes, MAX_BOOTSTRAP_CAPSULE_BYTES,
    MAX_COMPLETE_FRAME_BYTES, MAX_ENCRYPTED_HEADER_BYTES, MAX_IDENTIFIER_BYTES, MAX_INNER_BYTES,
    MAX_OUTER_METADATA_BYTES, MAX_PADDED_PLAINTEXT_BYTES, MAX_UNPADDED_PLAINTEXT_BYTES,
    MESSAGE_SCHEMA_V1_PROFILE, NamedDeliveryMode, OuterProfileError, REPORT_OPENING_BYTES,
    TemporaryRatchet, accept_after_size_preflight, decode_candidate_outer_ijson,
    discover_candidate_message_schema, validate_candidate_delivery_mode,
};
use crate::schema_profile::{
    ACTIVE_STORAGE_GENERATION, MESSAGE_SCHEMA_V1_GENERATION, schema_v1_live,
};
use crate::{
    DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields, WellKnownClientRecord,
    canonical_json_bytes, ephemeral,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn live_envelope(mode: Option<&str>) -> Envelope {
    let mut extensions = BTreeMap::new();
    if let Some(mode) = mode {
        extensions
            .insert(ephemeral::DELIVERY_MODE_EXTENSION.to_owned(), Value::String(mode.to_owned()));
    }
    Envelope {
        schema: crate::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: crate::domain::ENVELOPE.to_owned(),
        ext: Ext { ext: extensions },
        signed: SignedFields {
            signing_key_id: "key".to_owned(),
            signature_alg: SignatureAlg::Ed25519,
            signature: "signature".to_owned(),
        },
        envelope_id: "envelope".to_owned(),
        source_principal_id: "principal".to_owned(),
        source_device_id: "device".to_owned(),
        target_delivery_id: "target".to_owned(),
        routing_set_id: None,
        delivery_class: DeliveryClass::OpaqueEvent,
        priority: Priority::Normal,
        ttl: 300,
        created_at: 1_000,
        encrypted_payload: "payload".to_owned(),
        payload_hash: "hash".to_owned(),
    }
}

fn collapse_tag() -> String {
    crate::encode_base64url([0x22_u8; 32])
}

fn candidate_value(mode: &str) -> Value {
    json!({
        "schema": CANDIDATE_ENVELOPE_SCHEMA,
        "version": 2,
        "domain": crate::domain::ENVELOPE,
        "envelope_id": "envelope",
        "source_principal_id": "principal",
        "source_device_id": "device",
        "target_delivery_id": "target",
        "delivery_class": "message",
        "priority": "normal",
        "ttl_seconds": 300,
        "created_at": 1_762_128_000_i64,
        "encrypted_payload": "payload",
        "payload_hash": "hash",
        "collapse_tag": collapse_tag(),
        "delivery_mode": mode,
        "node_report_receipt": null,
        "signing_key_id": "key",
        "signature_alg": "ed25519",
        "signature": "signature",
    })
}

fn sizes_ok() -> Result<IngressSizes, OuterProfileError> {
    IngressSizes::from_inner(1)
}

fn bound_inner() -> Result<IngressSizes, OuterProfileError> {
    IngressSizes::from_inner(MAX_INNER_BYTES)
}

#[test]
fn named_delivery_mode_replaces_signed_ext_bridge_at_reset()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        ephemeral::classify_delivery_mode(&live_envelope(None)),
        ephemeral::DeliveryMode::Durable
    );
    assert_eq!(
        ephemeral::classify_delivery_mode(&live_envelope(Some("durable"))),
        ephemeral::DeliveryMode::Durable
    );
    assert_eq!(
        ephemeral::classify_delivery_mode(&live_envelope(Some("ephemeral"))),
        ephemeral::DeliveryMode::Ephemeral
    );
    assert_eq!(
        ephemeral::classify_delivery_mode(&live_envelope(Some("transient"))),
        ephemeral::DeliveryMode::Invalid
    );

    assert_eq!(
        validate_candidate_delivery_mode(&candidate_value("durable"))?,
        NamedDeliveryMode::Durable
    );
    assert_eq!(
        validate_candidate_delivery_mode(&candidate_value("ephemeral"))?,
        NamedDeliveryMode::Ephemeral
    );
    decode_candidate_outer_ijson(&serde_json::to_vec(&candidate_value("durable"))?)?;

    let mut bridge = candidate_value("durable");
    let Some(object) = bridge.as_object_mut() else {
        return Err("candidate JSON must be an object".into());
    };
    object.remove("delivery_mode");
    bridge["ext"] = json!({"delivery_mode": "ephemeral"});
    assert_eq!(validate_candidate_delivery_mode(&bridge), Err(OuterProfileError::Bridge));
    assert_eq!(
        OuterProfileError::Bridge.to_string(),
        "new profile rejects ext.delivery_mode bridge"
    );

    let mut dual = candidate_value("durable");
    dual["ext"] = json!({"delivery_mode": "ephemeral"});
    assert_eq!(validate_candidate_delivery_mode(&dual), Err(OuterProfileError::DualField));
    assert_eq!(
        OuterProfileError::DualField.to_string(),
        "new profile rejects dual delivery_mode fields"
    );

    assert_eq!(
        validate_candidate_delivery_mode(&candidate_value("transient")),
        Err(OuterProfileError::UnknownMode)
    );
    assert_eq!(
        OuterProfileError::UnknownMode.to_string(),
        "new profile rejects unknown delivery_mode"
    );
    Ok(())
}

#[test]
fn inner_and_complete_frame_caps_precede_state_commit() -> Result<(), Box<dyn std::error::Error>> {
    let mut ratchet = TemporaryRatchet::new();
    accept_after_size_preflight(bound_inner()?, &mut ratchet)?;
    assert!(ratchet.is_committed());
    assert_eq!(bound_inner()?.unpadded_plaintext_bytes, MAX_UNPADDED_PLAINTEXT_BYTES);
    assert_eq!(
        MAX_INNER_BYTES + FRAME_PREFIX_BYTES + REPORT_OPENING_BYTES,
        MAX_UNPADDED_PLAINTEXT_BYTES
    );

    let mut ok = TemporaryRatchet::new();
    accept_after_size_preflight(sizes_ok()?, &mut ok)?;
    assert!(ok.is_committed());

    for (name, over) in cap_overflows()? {
        let mut ratchet = TemporaryRatchet::new();
        assert_eq!(
            accept_after_size_preflight(over, &mut ratchet),
            Err(OuterProfileError::PayloadTooLarge),
            "{name}"
        );
        assert!(!ratchet.is_committed(), "{name} must not expose ratchet state");
        assert_eq!(OuterProfileError::PayloadTooLarge.to_string(), "payload too large");
    }
    Ok(())
}

fn cap_overflows() -> Result<Vec<(&'static str, IngressSizes)>, OuterProfileError> {
    let mut inner = bound_inner()?;
    inner.inner_bytes = MAX_INNER_BYTES + 1;
    inner.unpadded_plaintext_bytes = inner.inner_bytes + FRAME_PREFIX_BYTES + REPORT_OPENING_BYTES;
    let mut unpadded = sizes_ok()?;
    unpadded.unpadded_plaintext_bytes = MAX_UNPADDED_PLAINTEXT_BYTES + 1;
    let mut padded = sizes_ok()?;
    padded.padded_plaintext_bytes = MAX_PADDED_PLAINTEXT_BYTES + 1;
    let mut header = sizes_ok()?;
    header.encrypted_header_bytes = MAX_ENCRYPTED_HEADER_BYTES + 1;
    let mut bootstrap = sizes_ok()?;
    bootstrap.bootstrap_capsule_bytes = MAX_BOOTSTRAP_CAPSULE_BYTES + 1;
    let mut metadata = sizes_ok()?;
    metadata.outer_metadata_bytes = MAX_OUTER_METADATA_BYTES + 1;
    let mut identifier = sizes_ok()?;
    identifier.identifier_bytes = MAX_IDENTIFIER_BYTES + 1;
    let mut frame = sizes_ok()?;
    frame.complete_frame_bytes = MAX_COMPLETE_FRAME_BYTES + 1;
    Ok(vec![
        ("inner", inner),
        ("unpadded", unpadded),
        ("padded", padded),
        ("header", header),
        ("bootstrap", bootstrap),
        ("metadata", metadata),
        ("identifier", identifier),
        ("complete_frame", frame),
    ])
}

#[test]
fn live_envelope_wire_bytes_unchanged_with_schema_gate_off()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(ACTIVE_STORAGE_GENERATION, 0);
    assert_eq!(MESSAGE_SCHEMA_V1_GENERATION, 1);
    assert!(!schema_v1_live());
    let envelope = live_envelope(Some("ephemeral"));
    let first = canonical_json_bytes(&envelope)?;
    let decoded: Envelope = serde_json::from_slice(&first)?;
    let second = canonical_json_bytes(&decoded)?;
    assert_eq!(first, second);
    assert_eq!(envelope.schema, crate::domain::ENVELOPE);
    assert_ne!(envelope.schema, CANDIDATE_ENVELOPE_SCHEMA);
    assert!(envelope.delivery_mode_bridge().is_some());
    Ok(())
}

#[test]
fn candidate_profile_discovery_rejects_old_node() -> Result<(), Box<dyn std::error::Error>> {
    let mut record = WellKnownClientRecord {
        schema: crate::WELL_KNOWN_CLIENT_SCHEMA.to_owned(),
        node_id: "node.example.com".to_owned(),
        node_public_key: "key".to_owned(),
        node_ca_cert_pem: "ca".to_owned(),
        gateway_quic_addr: "node.example.com:443".to_owned(),
        gateway_tcp_addr: "node.example.com:443".to_owned(),
        gateway_server_name: "ramflux-gateway".to_owned(),
        relay_quic_addr: "node.example.com:17447".to_owned(),
        relay_server_name: "ramflux-relay".to_owned(),
        prekey_http_url: "https://node.example.com".to_owned(),
        signaling_turn_addr: "node.example.com:3478".to_owned(),
        protocol_versions: vec!["v1".to_owned()],
        client_capabilities: vec!["prekey".to_owned()],
        updated_at: 1000,
        expires_at: 2000,
        signature: String::new(),
    };
    assert!(discover_candidate_message_schema(&record).is_err());
    super::admit_discovered_profile(&record)?;
    record.protocol_versions.push(MESSAGE_SCHEMA_V1_PROFILE.to_owned());
    discover_candidate_message_schema(&record)?;
    Ok(())
}

#[test]
fn candidate_outer_round_trip_and_sender_excludes_receipt() -> Result<(), Box<dyn std::error::Error>>
{
    let mut value = candidate_value("durable");
    value["node_report_receipt"] = json!({"node_id": "n"});
    let outer: CandidateOuterEnvelope = decode_candidate_outer_ijson(&serde_json::to_vec(&value)?)?;
    assert_eq!(outer.delivery_class, CandidateDeliveryClass::Message);
    let signed = super::candidate_outer_sender_signed_bytes(&outer)?;
    let signed_json: Value = serde_json::from_slice(&signed)?;
    assert!(
        signed_json.get("node_report_receipt").is_none()
            || signed_json["node_report_receipt"].is_null()
    );
    assert_eq!(CRYPTOBOX_OVERHEAD_BYTES, 581);
    Ok(())
}
