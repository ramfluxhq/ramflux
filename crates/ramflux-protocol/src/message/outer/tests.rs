// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    CANDIDATE_ENVELOPE_SCHEMA, COMPACT_CRYPTOBOX_MAGIC, CRYPTOBOX_OVERHEAD_BYTES,
    CandidateDeliveryClass, CandidateOuterEnvelope, FRAME_PREFIX_BYTES, IngressSizes,
    MAX_BOOTSTRAP_CAPSULE_BYTES, MAX_CIPHERTEXT_B64_CHARS, MAX_CIPHERTEXT_BYTES,
    MAX_COMPLETE_FRAME_BYTES, MAX_ENCRYPTED_HEADER_BYTES, MAX_IDENTIFIER_BYTES, MAX_INNER_BYTES,
    MAX_OUTER_METADATA_BYTES, MAX_UNPADDED_PLAINTEXT_BYTES, MESSAGE_SCHEMA_V1_PROFILE,
    NamedDeliveryMode, OuterProfileError, REPORT_OPENING_BYTES, SealedSendSizes, TemporaryRatchet,
    accept_after_size_preflight, advertised_client_protocol_versions, compact_cryptobox_bytes,
    decode_candidate_outer_ijson, decode_candidate_sidecar, decode_compact_candidate_sidecar,
    decode_compact_cryptobox, discover_verified_message_schema, encode_compact_cryptobox,
    live_collapse_tag_bytes, live_report_commitment_bytes, parse_live_named_delivery_mode,
    refuse_named_fields_while_gate_off, require_live_collapse_tag, require_live_report_commitment,
    validate_candidate_delivery_mode, wire_encrypted_payload,
};
use crate::schema_profile::{
    ACTIVE_STORAGE_GENERATION, MESSAGE_SCHEMA_V1_GENERATION, schema_v1_live,
};
use crate::{
    DeliveryClass, Envelope, Ext, Priority, ProtocolError, SignatureAlg, SignedFields,
    WELL_KNOWN_CLIENT_SCHEMA, WellKnownClientRecord, canonical_json_bytes,
    client_discovery_signing_bytes, encode_base64url, ephemeral,
};
use ed25519_dalek::{Signer, SigningKey};
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
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
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

const PAIR_BEFORE: &[u8] = b"pair-session-before";
const PAIR_AFTER: &[u8] = b"pair-session-after-commit";
const LIVE_ENVELOPE_GOLDEN: &[u8] = br#"{"created_at":1000,"delivery_class":"opaque_event","domain":"ramflux.envelope.v1","encrypted_payload":"payload","envelope_id":"envelope","ext":{"delivery_mode":"ephemeral"},"payload_hash":"hash","priority":"normal","schema":"ramflux.envelope.v1","signature":"signature","signature_alg":"ed25519","signing_key_id":"key","source_device_id":"device","source_principal_id":"principal","target_delivery_id":"target","ttl":300,"version":1}"#;

fn candidate_outer(mode: NamedDeliveryMode) -> CandidateOuterEnvelope {
    CandidateOuterEnvelope {
        schema: CANDIDATE_ENVELOPE_SCHEMA.to_owned(),
        version: 2,
        domain: crate::domain::ENVELOPE.to_owned(),
        envelope_id: "envelope".to_owned(),
        source_principal_id: "principal".to_owned(),
        source_device_id: "device".to_owned(),
        target_delivery_id: "target".to_owned(),
        delivery_class: CandidateDeliveryClass::Message,
        priority: Priority::Normal,
        ttl_seconds: 300,
        created_at: 1_762_128_000,
        encrypted_payload: "payload".to_owned(),
        payload_hash: "hash".to_owned(),
        collapse_tag: collapse_tag(),
        delivery_mode: mode,
        node_report_receipt: None,
        signed: SignedFields {
            signing_key_id: "key".to_owned(),
            signature_alg: SignatureAlg::Ed25519,
            signature: "signature".to_owned(),
        },
    }
}

fn max_ciphertext_outer() -> CandidateOuterEnvelope {
    let mut outer = candidate_outer(NamedDeliveryMode::Durable);
    outer.encrypted_payload = encode_base64url(vec![0_u8; MAX_CIPHERTEXT_BYTES]);
    outer
}

fn protocol_err_display(
    result: Result<(), ProtocolError>,
) -> Result<String, Box<dyn std::error::Error>> {
    match result {
        Err(error) => Ok(error.to_string()),
        Ok(()) => Err("expected protocol refusal".into()),
    }
}

fn refuse_over_cap(sizes: IngressSizes) {
    let mut ratchet = TemporaryRatchet::wrap_session(PAIR_BEFORE.to_vec());
    assert_eq!(
        accept_after_size_preflight(sizes, &mut ratchet, PAIR_AFTER.to_vec()),
        Err(OuterProfileError::PayloadTooLarge)
    );
    assert_eq!(ratchet.snapshot(), PAIR_BEFORE);
    assert_eq!(OuterProfileError::PayloadTooLarge.to_string(), "payload too large");
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
    let outer = max_ciphertext_outer();
    assert_eq!(outer.encrypted_payload.len(), MAX_CIPHERTEXT_B64_CHARS);
    let sizes = IngressSizes::measure_candidate(&outer, &[], &[])?;
    assert_eq!(sizes.ciphertext_bytes, MAX_CIPHERTEXT_BYTES);
    let mut ratchet = TemporaryRatchet::wrap_session(PAIR_BEFORE.to_vec());
    accept_after_size_preflight(sizes, &mut ratchet, PAIR_AFTER.to_vec())?;
    assert_eq!(ratchet.snapshot(), PAIR_AFTER);
    assert_eq!(
        MAX_INNER_BYTES + FRAME_PREFIX_BYTES + REPORT_OPENING_BYTES,
        MAX_UNPADDED_PLAINTEXT_BYTES
    );

    let ciphertext = vec![0_u8; MAX_CIPHERTEXT_BYTES];
    let header = vec![0_u8; MAX_ENCRYPTED_HEADER_BYTES];
    let bootstrap = vec![0_u8; MAX_BOOTSTRAP_CAPSULE_BYTES];
    let send = IngressSizes::measure_sealed_send(&SealedSendSizes {
        inner_bytes: MAX_INNER_BYTES,
        ciphertext: &ciphertext,
        encrypted_header: &header,
        bootstrap_capsule: &bootstrap,
        identifiers: ["e", "p", "d", "t"],
        metadata: None,
        complete_frame_bytes: MAX_COMPLETE_FRAME_BYTES,
    })?;
    let mut ok = TemporaryRatchet::wrap_session(PAIR_BEFORE.to_vec());
    accept_after_size_preflight(send, &mut ok, PAIR_AFTER.to_vec())?;
    assert_eq!(ok.snapshot(), PAIR_AFTER);

    one_byte_over_each_real_cap()?;
    Ok(())
}

fn one_byte_over_each_real_cap() -> Result<(), Box<dyn std::error::Error>> {
    let mut over_ct = max_ciphertext_outer();
    over_ct.encrypted_payload = encode_base64url(vec![0_u8; MAX_CIPHERTEXT_BYTES + 1]);
    refuse_over_cap(IngressSizes::measure_candidate(&over_ct, &[], &[])?);

    let mut over_id = max_ciphertext_outer();
    over_id.envelope_id = "i".repeat(MAX_IDENTIFIER_BYTES + 1);
    refuse_over_cap(IngressSizes::measure_candidate(&over_id, &[], &[])?);

    let mut over_meta = max_ciphertext_outer();
    over_meta.node_report_receipt = Some(Value::String("m".repeat(MAX_OUTER_METADATA_BYTES)));
    refuse_over_cap(IngressSizes::measure_candidate(&over_meta, &[], &[])?);

    let over_header = vec![0_u8; MAX_ENCRYPTED_HEADER_BYTES + 1];
    refuse_over_cap(IngressSizes::measure_candidate(&max_ciphertext_outer(), &over_header, &[])?);
    let over_bootstrap = vec![0_u8; MAX_BOOTSTRAP_CAPSULE_BYTES + 1];
    refuse_over_cap(IngressSizes::measure_candidate(
        &max_ciphertext_outer(),
        &[],
        &over_bootstrap,
    )?);

    refuse_over_cap(IngressSizes::measure_sealed_send(&SealedSendSizes {
        inner_bytes: MAX_INNER_BYTES + 1,
        ciphertext: &[0_u8; 1],
        encrypted_header: &[],
        bootstrap_capsule: &[],
        identifiers: ["e", "p", "d", "t"],
        metadata: None,
        complete_frame_bytes: 1,
    })?);
    refuse_over_cap(IngressSizes::measure_sealed_send(&SealedSendSizes {
        inner_bytes: 1,
        ciphertext: &[0_u8; 1],
        encrypted_header: &[],
        bootstrap_capsule: &[],
        identifiers: ["e", "p", "d", "t"],
        metadata: None,
        complete_frame_bytes: MAX_COMPLETE_FRAME_BYTES + 1,
    })?);
    Ok(())
}

#[test]
fn live_envelope_wire_bytes_unchanged_with_schema_gate_off()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(ACTIVE_STORAGE_GENERATION, 0);
    assert_eq!(MESSAGE_SCHEMA_V1_GENERATION, 1);
    assert!(!schema_v1_live());
    let envelope = live_envelope(Some("ephemeral"));
    let first = canonical_json_bytes(&envelope)?;
    assert_eq!(first, LIVE_ENVELOPE_GOLDEN);
    let decoded: Envelope = serde_json::from_slice(&first)?;
    let second = canonical_json_bytes(&decoded)?;
    assert_eq!(first, second);
    assert_eq!(envelope.schema, crate::domain::ENVELOPE);
    assert_ne!(envelope.schema, CANDIDATE_ENVELOPE_SCHEMA);
    assert_eq!(envelope.delivery_mode_bridge(), Some(&Value::String("ephemeral".to_owned())));
    Ok(())
}

fn unsigned_discovery_record() -> WellKnownClientRecord {
    WellKnownClientRecord {
        schema: WELL_KNOWN_CLIENT_SCHEMA.to_owned(),
        node_id: "node.example.com".to_owned(),
        node_public_key: String::new(),
        node_ca_cert_pem: "ca".to_owned(),
        gateway_quic_addr: "node.example.com:443".to_owned(),
        gateway_tcp_addr: "node.example.com:443".to_owned(),
        gateway_server_name: "ramflux-gateway".to_owned(),
        relay_quic_addr: "node.example.com:17447".to_owned(),
        relay_server_name: "ramflux-relay".to_owned(),
        prekey_http_url: "https://node.example.com".to_owned(),
        signaling_turn_addr: "node.example.com:3478".to_owned(),
        protocol_versions: vec!["v1".to_owned(), MESSAGE_SCHEMA_V1_PROFILE.to_owned()],
        client_capabilities: vec!["prekey".to_owned()],
        updated_at: 1000,
        expires_at: 2000,
        signature: String::new(),
    }
}

fn sign_discovery(record: &mut WellKnownClientRecord, seed: u8) -> Result<(), ProtocolError> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    record.node_public_key = encode_base64url(key.verifying_key().to_bytes());
    record.signature =
        encode_base64url(key.sign(&client_discovery_signing_bytes(record)?).to_bytes());
    Ok(())
}

#[test]
fn candidate_profile_discovery_requires_verified_canonical_token()
-> Result<(), Box<dyn std::error::Error>> {
    let unsigned = unsigned_discovery_record();
    assert_eq!(
        protocol_err_display(discover_verified_message_schema(&unsigned, 1500))?,
        ProtocolError::InvalidSignatureLength(0).to_string()
    );

    let mut wrong = unsigned_discovery_record();
    sign_discovery(&mut wrong, 1)?;
    let foreign = SigningKey::from_bytes(&[2; 32]);
    wrong.signature =
        encode_base64url(foreign.sign(&client_discovery_signing_bytes(&wrong)?).to_bytes());
    assert_eq!(
        protocol_err_display(discover_verified_message_schema(&wrong, 1500))?,
        ProtocolError::SignatureVerificationFailed.to_string()
    );

    let mut alternate = unsigned_discovery_record();
    alternate.protocol_versions = vec!["v1".to_owned()];
    alternate.client_capabilities = vec!["prekey".to_owned(), MESSAGE_SCHEMA_V1_PROFILE.to_owned()];
    sign_discovery(&mut alternate, 3)?;
    assert_eq!(
        protocol_err_display(discover_verified_message_schema(&alternate, 1500))?,
        ProtocolError::InvalidDomain {
            expected: MESSAGE_SCHEMA_V1_PROFILE,
            actual: "v1".to_owned(),
        }
        .to_string()
    );

    let mut old = unsigned_discovery_record();
    old.protocol_versions = vec!["v1".to_owned()];
    sign_discovery(&mut old, 4)?;
    assert_eq!(
        protocol_err_display(discover_verified_message_schema(&old, 1500))?,
        ProtocolError::InvalidDomain {
            expected: MESSAGE_SCHEMA_V1_PROFILE,
            actual: "v1".to_owned(),
        }
        .to_string()
    );
    let verified = crate::VerifiedWellKnownClientRecord::verify(&old, 1500)?;
    super::admit_discovered_profile(&verified)?;

    let mut live = unsigned_discovery_record();
    sign_discovery(&mut live, 5)?;
    discover_verified_message_schema(&live, 1500)?;
    assert_eq!(advertised_client_protocol_versions(&["v1".to_owned()]), vec!["v1".to_owned()]);
    assert!(
        !advertised_client_protocol_versions(&["v1".to_owned()])
            .iter()
            .any(|version| version == MESSAGE_SCHEMA_V1_PROFILE)
    );
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

#[test]
fn measure_live_uses_nested_cryptobox_not_json_wrapper() -> Result<(), Box<dyn std::error::Error>> {
    let cryptobox = vec![7_u8; 32];
    let nested = json!({
        "schema": "ramflux.sdk.dm_x3dh_envelope.v2",
        "version": 2,
        "x3dh": {"session_id": "s", "initiator_identity_public": vec![1_u8; 32]},
        "ciphertext": {
            "session_id": "s",
            "counter": 1,
            "nonce": vec![0_u8; 12],
            "ciphertext": cryptobox,
            "canonical_header_bytes": [9, 8, 7],
        }
    });
    let wrapper = serde_json::to_vec(&nested)?;
    let mut envelope = live_envelope(None);
    envelope.encrypted_payload = encode_base64url(&wrapper);
    envelope.source_device_id = "wire-device".to_owned();
    let sizes = IngressSizes::measure_wire(&envelope, 0, &[], &[])?;
    assert_eq!(sizes.ciphertext_bytes, 32);
    assert!(sizes.ciphertext_bytes < wrapper.len());
    assert_eq!(sizes.encrypted_header_bytes, 3);
    assert!(sizes.bootstrap_capsule_bytes > 0);
    assert_eq!(sizes.complete_frame_bytes, canonical_json_bytes(&envelope)?.len());
    assert!(sizes.complete_frame_bytes <= MAX_COMPLETE_FRAME_BYTES);
    assert_eq!(sizes.identifier_bytes, "wire-device".len());
    super::check_ingress_caps(sizes)?;
    Ok(())
}

fn nested_sdk_value(cryptobox: &[u8]) -> Value {
    json!({
        "schema": "ramflux.sdk.dm_x3dh_envelope.v2",
        "version": 2,
        "x3dh": {"session_id": "s"},
        "ciphertext": {
            "ciphertext": cryptobox,
            "canonical_header_bytes": [1, 2, 3],
        }
    })
}

#[test]
fn legacy_encrypted_payload_is_byte_identical_with_gate_off()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(!schema_v1_live());
    let body = serde_json::to_vec(&nested_sdk_value(&[7_u8; 32]))?;
    assert_eq!(wire_encrypted_payload(&body)?, encode_base64url(&body));
    Ok(())
}

#[test]
fn candidate_wire_payload_is_compact_cryptobox() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = crate::schema_profile::SchemaV1LiveGuard::enter();
    let cryptobox = vec![7_u8; 64];
    let body = serde_json::to_vec(&nested_sdk_value(&cryptobox))?;
    let payload = wire_encrypted_payload(&body)?;
    let decoded = crate::decode_base64url(&payload)?;
    assert!(decoded.starts_with(&COMPACT_CRYPTOBOX_MAGIC));
    let compact = decode_compact_cryptobox(&decoded)?;
    assert_eq!(compact.ciphertext, cryptobox.as_slice());
    assert!(!body.windows(4).any(|window| window == COMPACT_CRYPTOBOX_MAGIC));
    Ok(())
}

#[test]
fn compact_cryptobox_round_trip_and_unknown_field() -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&nested_sdk_value(&[9_u8; 8]))?;
    let compact = compact_cryptobox_bytes(&body)?;
    let decoded = decode_compact_cryptobox(&compact)?;
    assert_eq!(decoded.ciphertext, &[9_u8; 8]);
    let mut padded = nested_sdk_value(&[9_u8; 8]);
    padded["pad"] = json!("x");
    assert_eq!(
        compact_cryptobox_bytes(&serde_json::to_vec(&padded)?),
        Err(OuterProfileError::UnknownField)
    );
    assert_eq!(
        OuterProfileError::UnknownField.to_string(),
        "candidate outer envelope has unknown fields"
    );
    Ok(())
}

#[test]
fn sidecar_admits_named_report_fields_and_still_refuses_pad()
-> Result<(), Box<dyn std::error::Error>> {
    let mut nested = nested_sdk_value(&[9_u8; 8]);
    nested["collapse_tag"] = json!(collapse_tag());
    nested["report_commitment"] = json!(crate::encode_base64url([0x33_u8; 32]));
    decode_candidate_sidecar(&serde_json::to_vec(&nested)?)?;
    nested["pad"] = json!("x");
    unknown_field(decode_candidate_sidecar(&serde_json::to_vec(&nested)?))
}

const REAL_250KB: usize = 250 * 1024;
const NESTED_PAD: usize = 100 * 1024;

fn compact_250kb() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let sidecar = serde_json::to_vec(&nested_sdk_value(&[]))?;
    Ok(encode_compact_cryptobox(&vec![7_u8; REAL_250KB], &sidecar)?)
}

fn inject_nested_pad(
    compact: &[u8],
    object: &str,
    pad: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decoded = decode_compact_cryptobox(compact)?;
    let mut sidecar: Value = serde_json::from_slice(decoded.sidecar)?;
    sidecar[object]["pad"] = pad;
    Ok(encode_compact_cryptobox(decoded.ciphertext, &serde_json::to_vec(&sidecar)?)?)
}

fn envelope_with_payload(payload: &[u8]) -> Envelope {
    let mut envelope = live_envelope(None);
    envelope.encrypted_payload = encode_base64url(payload);
    envelope
}

fn unknown_field<T: std::fmt::Debug>(
    result: Result<T, OuterProfileError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(OuterProfileError::UnknownField) => {
            assert_eq!(
                OuterProfileError::UnknownField.to_string(),
                "candidate outer envelope has unknown fields"
            );
            Ok(())
        }
        other => Err(format!("exact unknown-field error, got {other:?}").into()),
    }
}

#[test]
fn nested_ciphertext_pad_is_unknown_field_on_250kb_envelope()
-> Result<(), Box<dyn std::error::Error>> {
    let _gate = crate::schema_profile::SchemaV1LiveGuard::enter();
    let padded = inject_nested_pad(&compact_250kb()?, "ciphertext", json!("p".repeat(NESTED_PAD)))?;
    assert!(padded.len() > REAL_250KB);
    assert!(padded.len() < MAX_COMPLETE_FRAME_BYTES);
    unknown_field(decode_candidate_sidecar(decode_compact_cryptobox(&padded)?.sidecar))?;
    unknown_field(IngressSizes::measure_wire(&envelope_with_payload(&padded), 0, &[], &[]))
}

#[test]
fn nested_x3dh_pad_is_unknown_field_not_bootstrap_cap() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = crate::schema_profile::SchemaV1LiveGuard::enter();
    let padded = inject_nested_pad(&compact_250kb()?, "x3dh", json!("x"))?;
    unknown_field(decode_candidate_sidecar(decode_compact_cryptobox(&padded)?.sidecar))?;
    unknown_field(IngressSizes::measure_wire(&envelope_with_payload(&padded), 0, &[], &[]))
}

#[test]
fn source_principal_commitment_is_refused_at_identifier_cap()
-> Result<(), Box<dyn std::error::Error>> {
    let mut nested = nested_sdk_value(&[7_u8; 8]);
    nested["source_principal_commitment"] = json!("c".repeat(MAX_IDENTIFIER_BYTES));
    decode_candidate_sidecar(&serde_json::to_vec(&nested)?)?;
    nested["source_principal_commitment"] = json!("c".repeat(MAX_IDENTIFIER_BYTES + 1));
    assert_eq!(
        decode_candidate_sidecar(&serde_json::to_vec(&nested)?),
        Err(OuterProfileError::Identifier)
    );
    assert_eq!(OuterProfileError::Identifier.to_string(), "identifier exceeds 256 bytes");
    Ok(())
}

#[test]
fn canonical_header_bytes_are_refused_at_encrypted_header_cap()
-> Result<(), Box<dyn std::error::Error>> {
    let mut nested = nested_sdk_value(&[]);
    nested["ciphertext"]["canonical_header_bytes"] = json!(vec![1_u8; MAX_ENCRYPTED_HEADER_BYTES]);
    decode_candidate_sidecar(&serde_json::to_vec(&nested)?)?;
    nested["ciphertext"]["canonical_header_bytes"] =
        json!(vec![1_u8; MAX_ENCRYPTED_HEADER_BYTES + 1]);
    assert_eq!(
        decode_candidate_sidecar(&serde_json::to_vec(&nested)?),
        Err(OuterProfileError::PayloadTooLarge)
    );
    Ok(())
}

#[test]
fn compact_sidecar_refuses_non_empty_legacy_ciphertext_field() {
    let empty = serde_json::to_vec(&json!({"ciphertext": {"ciphertext": []}})).unwrap_or_default();
    assert_eq!(decode_compact_candidate_sidecar(&empty), Ok(()));
    let full = serde_json::to_vec(&json!({"ciphertext": {"ciphertext": [0]}})).unwrap_or_default();
    assert_eq!(
        decode_compact_candidate_sidecar(&full),
        Err(OuterProfileError::CompactCiphertextField)
    );
    assert_eq!(decode_candidate_sidecar(&full), Ok(()));
}

#[test]
fn compact_sidecar_requires_ciphertext_field() {
    let absent = serde_json::to_vec(&json!({"ciphertext": {}})).unwrap_or_default();
    assert_eq!(
        decode_compact_candidate_sidecar(&absent),
        Err(OuterProfileError::MissingCompactCiphertext)
    );
    assert_eq!(
        OuterProfileError::MissingCompactCiphertext.to_string(),
        "compact candidate sidecar ciphertext field is required"
    );
}

#[test]
fn compact_sidecar_requires_ciphertext_object() {
    let absent = serde_json::to_vec(&json!({})).unwrap_or_default();
    assert_eq!(
        decode_compact_candidate_sidecar(&absent),
        Err(OuterProfileError::MissingCompactCiphertext)
    );
    assert_eq!(decode_candidate_sidecar(&absent), Ok(()));
}

/// Generation-0 `Envelope` fields on `origin/main` before named candidate fields.
const GENERATION_0_ENVELOPE_FIELDS: &[&str] = &[
    "schema",
    "version",
    "domain",
    "ext",
    "signed",
    "envelope_id",
    "source_principal_id",
    "source_device_id",
    "target_delivery_id",
    "routing_set_id",
    "delivery_class",
    "priority",
    "ttl",
    "created_at",
    "encrypted_payload",
    "payload_hash",
];

fn all_envelope_field_names_from_source(src: &str) -> Vec<String> {
    let Some(start) = src.find("pub struct Envelope {") else {
        return Vec::new();
    };
    let Some((body, _)) = src[start..].split_once("\n}") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() {
            names.push(name.to_owned());
        }
    }
    names
}

fn candidate_field_names_from_envelope_source(src: &str) -> Vec<String> {
    let Some(start) = src.find("pub struct Envelope {") else {
        return Vec::new();
    };
    let Some((body, _)) = src[start..].split_once("\n}") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut pending_candidate = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("///") && trimmed.contains("Candidate") {
            pending_candidate = true;
            continue;
        }
        if trimmed.starts_with("///") || trimmed.starts_with("#[") {
            continue;
        }
        if pending_candidate {
            if let Some(rest) = trimmed.strip_prefix("pub ") {
                let name = rest.split(':').next().unwrap_or("").trim();
                if !name.is_empty() {
                    names.push(name.to_owned());
                }
            }
            pending_candidate = false;
        }
    }
    names
}

fn helper_covers_candidate_fields(src: &str, names: &[String]) -> bool {
    let Some(helper) = src.split("fn candidate_fields_present").nth(1) else {
        return false;
    };
    let Some(helper) = helper.split("\n    }").next() else {
        return false;
    };
    names.iter().all(|name| helper.contains(&format!("self.{name}.is_some()")))
}

#[test]
fn candidate_only_fields_are_enumerated() {
    let src = include_str!("../../core_types.rs");
    let names = candidate_field_names_from_envelope_source(src);
    assert_eq!(
        names,
        vec!["delivery_mode".to_owned(), "collapse_tag".to_owned(), "report_commitment".to_owned()]
    );
    assert!(helper_covers_candidate_fields(src, &names));
    let extra: Vec<String> = all_envelope_field_names_from_source(src)
        .into_iter()
        .filter(|name| !GENERATION_0_ENVELOPE_FIELDS.contains(&name.as_str()))
        .collect();
    assert_ne!(extra.len(), 0);
    assert!(
        helper_covers_candidate_fields(src, &extra),
        "fields outside generation-0 Envelope must be in candidate_fields_present: {extra:?}"
    );
    assert!(!schema_v1_live());
    let mut envelope = live_envelope(None);
    assert!(!envelope.candidate_fields_present());
    assert_eq!(refuse_named_fields_while_gate_off(&envelope), Ok(()));
    envelope.delivery_mode = Some("durable".to_owned());
    assert!(envelope.candidate_fields_present());
    assert_eq!(
        refuse_named_fields_while_gate_off(&envelope),
        Err(OuterProfileError::NamedFieldsWhileGateOff)
    );
    envelope.delivery_mode = None;
    envelope.collapse_tag = Some(collapse_tag());
    assert!(envelope.candidate_fields_present());
    assert_eq!(
        refuse_named_fields_while_gate_off(&envelope),
        Err(OuterProfileError::NamedFieldsWhileGateOff)
    );
    envelope.collapse_tag = None;
    envelope.report_commitment = Some(crate::encode_base64url([0x33_u8; 32]));
    assert!(envelope.candidate_fields_present());
    assert_eq!(
        refuse_named_fields_while_gate_off(&envelope),
        Err(OuterProfileError::NamedFieldsWhileGateOff)
    );
}

#[test]
fn gate_off_refuses_named_delivery_mode_and_collapse_tag() {
    assert!(!schema_v1_live());
    let mut envelope = live_envelope(None);
    assert_eq!(refuse_named_fields_while_gate_off(&envelope), Ok(()));
    envelope.delivery_mode = Some("durable".to_owned());
    assert_eq!(
        refuse_named_fields_while_gate_off(&envelope),
        Err(OuterProfileError::NamedFieldsWhileGateOff)
    );
    envelope.delivery_mode = None;
    envelope.collapse_tag = Some(collapse_tag());
    assert_eq!(
        refuse_named_fields_while_gate_off(&envelope),
        Err(OuterProfileError::NamedFieldsWhileGateOff)
    );
    envelope.collapse_tag = None;
    envelope.report_commitment = Some(crate::encode_base64url([0x33_u8; 32]));
    assert_eq!(
        refuse_named_fields_while_gate_off(&envelope),
        Err(OuterProfileError::NamedFieldsWhileGateOff)
    );
    envelope.report_commitment = None;
    envelope.delivery_mode = Some("durable".to_owned());
    envelope.ext.ext.insert(
        ephemeral::DELIVERY_MODE_EXTENSION.to_owned(),
        Value::String("ephemeral".to_owned()),
    );
    assert_eq!(
        refuse_named_fields_while_gate_off(&envelope),
        Err(OuterProfileError::NamedFieldsWhileGateOff)
    );
    assert_eq!(
        OuterProfileError::NamedFieldsWhileGateOff.to_string(),
        "named delivery_mode and collapse_tag are refused while schema v1 is off"
    );
}

#[test]
fn live_named_fields_parse_mode_and_require_32_byte_tag() {
    let mut envelope = live_envelope(None);
    assert_eq!(parse_live_named_delivery_mode(&envelope), Err(OuterProfileError::MissingMode));
    envelope.delivery_mode = Some("bogus".to_owned());
    assert_eq!(parse_live_named_delivery_mode(&envelope), Err(OuterProfileError::UnknownMode));
    envelope.delivery_mode = Some("durable".to_owned());
    assert_eq!(parse_live_named_delivery_mode(&envelope), Ok(NamedDeliveryMode::Durable));
    assert_eq!(NamedDeliveryMode::Durable.as_str(), "durable");
    assert_eq!(live_collapse_tag_bytes(&envelope), Err(OuterProfileError::CollapseTag));
    envelope.collapse_tag = Some(crate::encode_base64url([0x00_u8; 31]));
    let short = live_collapse_tag_bytes(&envelope).unwrap_or_default();
    assert_eq!(short.len(), 31);
    assert_eq!(require_live_collapse_tag(&envelope), Err(OuterProfileError::CollapseTag));
    envelope.collapse_tag = Some(collapse_tag());
    assert_eq!(require_live_collapse_tag(&envelope), Ok([0x22_u8; 32]));
    assert_eq!(live_report_commitment_bytes(&envelope), Ok(None));
    envelope.report_commitment = Some(crate::encode_base64url([0x00_u8; 31]));
    assert_eq!(live_report_commitment_bytes(&envelope), Err(OuterProfileError::ReportCommitment));
    assert_eq!(require_live_report_commitment(&envelope), Err(OuterProfileError::ReportCommitment));
    envelope.report_commitment = Some(crate::encode_base64url([0x33_u8; 32]));
    assert_eq!(require_live_report_commitment(&envelope), Ok([0x33_u8; 32]));
}

#[test]
fn sender_signed_bytes_cover_named_delivery_mode_and_collapse_tag()
-> Result<(), Box<dyn std::error::Error>> {
    let mut envelope = live_envelope(None);
    envelope.delivery_mode = Some("durable".to_owned());
    envelope.collapse_tag = Some(collapse_tag());
    let signed = crate::envelope_sender_signed_bytes(&envelope)?;
    let text = String::from_utf8(signed.clone())?;
    assert!(text.contains("\"delivery_mode\":\"durable\""));
    assert!(text.contains("\"collapse_tag\":"));
    envelope.delivery_mode = Some("ephemeral".to_owned());
    assert_ne!(signed, crate::envelope_sender_signed_bytes(&envelope)?);
    envelope.delivery_mode = Some("durable".to_owned());
    envelope.collapse_tag = Some(crate::encode_base64url([0x00_u8; 32]));
    assert_ne!(signed, crate::envelope_sender_signed_bytes(&envelope)?);
    envelope.collapse_tag = Some(collapse_tag());
    envelope.report_commitment = Some(crate::encode_base64url([0x33_u8; 32]));
    let with_c = crate::envelope_sender_signed_bytes(&envelope)?;
    assert!(String::from_utf8(with_c.clone())?.contains("\"report_commitment\":"));
    envelope.report_commitment = Some(crate::encode_base64url([0x00_u8; 32]));
    assert_ne!(with_c, crate::envelope_sender_signed_bytes(&envelope)?);
    Ok(())
}
