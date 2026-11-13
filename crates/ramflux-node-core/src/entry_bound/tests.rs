// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::expect_used, reason = "independent wire assertions")]
use super::*;
use crate::InboxEntryResponse;
use crate::router_store::incarnation::test_store;
use crate::router_store::publication::tests::{entry, fixture};
fn independent_size(envelope: &ramflux_protocol::Envelope) -> usize {
    let row = serde_json::json!({"inbox_seq":u64::MAX,"target_delivery_id":envelope.target_delivery_id,"envelope":envelope});
    [serde_json::json!({"frame_type":"deliver","entry":row}),
        serde_json::json!({"frame_type":"deliver","incarnation_id":"ffffffffffffffffffffffffffffffff","entry":row,"retain_until":i64::MIN}),
        serde_json::json!({"frame_type":"entry","incarnation_id":"ffffffffffffffffffffffffffffffff","record":{"entry":row,"retain_until":i64::MIN}})]
        .iter().map(|frame|serde_json::to_vec(frame).expect("wire JSON").len()).max().expect("three frames")
}
#[test]
fn downstream_entry_bound_matches_actual_wire_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let mut envelope = entry(1).envelope;
    envelope.encrypted_payload.clear();
    envelope.ext.ext.insert("escaped_metadata".into(), serde_json::json!("\"\\\n".repeat(30)));
    let base = independent_size(&envelope);
    for over in [false, true] {
        envelope.encrypted_payload = "x".repeat(ENTRY_FRAME_BYTE_CAP - base + usize::from(over));
        let actual = independent_size(&envelope);
        assert_eq!(single_entry_frame_size(&envelope)?, actual);
        assert_eq!(actual, ENTRY_FRAME_BYTE_CAP + usize::from(over));
        assert_eq!(check_entry_bound(&envelope).is_err(), over);
    }
    Ok(())
}

#[test]
fn single_entry_bound_serializes_envelope_once() -> Result<(), Box<dyn std::error::Error>> {
    let mut envelope = entry(1).envelope;
    envelope.encrypted_payload = "x".repeat(64 * 1024);
    envelope.ext.ext.insert("escaped".into(), serde_json::json!("\"\\\n".repeat(30)));
    let expected_wire = serde_json::to_vec(&serde_json::json!({"inbox_seq":u64::MAX,"target_delivery_id":envelope.target_delivery_id,"envelope":envelope}))?.len();
    SIZED_BYTES.with(|count| count.set(0));
    let size = single_entry_frame_size(&envelope)?;
    assert_eq!(
        SIZED_BYTES.with(std::cell::Cell::get),
        expected_wire,
        "actual counting-writer bytes: one WireEntry"
    );
    assert_eq!(size, independent_size(&envelope));
    Ok(())
}

fn nested_sdk_json(cryptobox: &[u8], pad: Option<String>) -> serde_json::Value {
    let mut nested = serde_json::json!({
        "schema": "ramflux.sdk.dm_x3dh_envelope.v2",
        "version": 2,
        "x3dh": {"session_id": "s"},
        "ciphertext": {
            "ciphertext": cryptobox,
            "canonical_header_bytes": [1, 2, 3],
        }
    });
    if let Some(pad) = pad {
        nested["pad"] = serde_json::Value::String(pad);
    }
    nested
}

fn bind_candidate_named_fields(envelope: &mut ramflux_protocol::Envelope) {
    if ramflux_protocol::schema_profile::schema_v1_live() {
        envelope.delivery_mode = Some("durable".into());
        envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x22_u8; 32]));
    }
}

fn nested_sdk_envelope(
    cryptobox: &[u8],
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let mut envelope = entry(1).envelope;
    envelope.source_device_id = "wire-device".to_owned();
    envelope.encrypted_payload =
        ramflux_protocol::encode_base64url(serde_json::to_vec(&nested_sdk_json(cryptobox, None))?);
    bind_candidate_named_fields(&mut envelope);
    bind_payload_hash(&mut envelope);
    Ok(envelope)
}

fn compact_sdk_envelope(
    cryptobox: &[u8],
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let sidecar = serde_json::to_vec(&nested_sdk_json(&[], None))?;
    let compact = ramflux_protocol::message::outer::encode_compact_cryptobox(cryptobox, &sidecar)?;
    let mut envelope = entry(1).envelope;
    envelope.source_device_id = "wire-device".to_owned();
    envelope.encrypted_payload = ramflux_protocol::encode_base64url(&compact);
    bind_candidate_named_fields(&mut envelope);
    bind_payload_hash(&mut envelope);
    Ok(envelope)
}

fn bind_payload_hash(envelope: &mut ramflux_protocol::Envelope) {
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        envelope.encrypted_payload.as_bytes(),
    );
}

fn payload_too_large(result: Result<(), NodeCoreError>) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(NodeCoreError::PayloadTooLarge) => Ok(()),
        other => Err(format!("exact PayloadTooLarge, got {other:?}").into()),
    }
}

#[test]
fn candidate_entry_bound_measures_nested_cryptobox_when_gate_on()
-> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let envelope = compact_sdk_envelope(&[7_u8; 32])?;
    check_entry_bound(&envelope)?;
    let sizes =
        ramflux_protocol::message::outer::IngressSizes::measure_wire(&envelope, 0, &[], &[])?;
    assert_eq!(sizes.ciphertext_bytes, 32);
    assert_eq!(
        sizes.complete_frame_bytes,
        ramflux_protocol::canonical_json_bytes(&envelope)?.len()
    );
    ramflux_protocol::message::outer::check_ingress_caps(sizes)?;
    Ok(())
}

#[test]
fn candidate_entry_bound_accepts_392kb_nested_cryptobox() -> Result<(), Box<dyn std::error::Error>>
{
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let cryptobox = vec![7_u8; 522_808];
    let envelope = compact_sdk_envelope(&cryptobox)?;
    let wrapper = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)?;
    assert!(wrapper.starts_with(&ramflux_protocol::message::outer::COMPACT_CRYPTOBOX_MAGIC));
    check_entry_bound(&envelope)?;
    let sizes =
        ramflux_protocol::message::outer::IngressSizes::measure_wire(&envelope, 0, &[], &[])?;
    assert_eq!(sizes.ciphertext_bytes, 522_808);
    assert!(sizes.ciphertext_bytes < wrapper.len());
    assert!(
        sizes.complete_frame_bytes <= ramflux_protocol::message::outer::MAX_COMPLETE_FRAME_BYTES
    );
    assert!(single_entry_frame_size(&envelope)? <= ENTRY_FRAME_BYTE_CAP);
    assert!(sizes.bootstrap_capsule_bytes > 0);
    assert_ne!(envelope.source_device_id, "local");
    ramflux_protocol::message::outer::check_ingress_caps(sizes)?;
    Ok(())
}

#[test]
fn candidate_entry_bound_refuses_one_over_cryptobox() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let over = vec![7_u8; ramflux_protocol::message::outer::MAX_CIPHERTEXT_BYTES + 1];
    payload_too_large(check_entry_bound(&compact_sdk_envelope(&over)?))
}

fn padded_nested_envelope() -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let nested = nested_sdk_json(&[7_u8; 32], Some("p".repeat(8 * 1024 * 1024)));
    let mut envelope = nested_sdk_envelope(&[7_u8; 32])?;
    envelope.encrypted_payload = ramflux_protocol::encode_base64url(serde_json::to_vec(&nested)?);
    Ok(envelope)
}

#[test]
fn padded_nested_field_is_payload_too_large_with_gate_on_and_off()
-> Result<(), Box<dyn std::error::Error>> {
    let envelope = padded_nested_envelope()?;
    payload_too_large(check_entry_bound(&envelope))?;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    payload_too_large(check_entry_bound(&envelope))
}

#[test]
fn candidate_decode_refuses_unknown_nested_field() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let nested = nested_sdk_json(&[7_u8; 32], Some("x".into()));
    let mut envelope = nested_sdk_envelope(&[7_u8; 32])?;
    envelope.encrypted_payload = ramflux_protocol::encode_base64url(serde_json::to_vec(&nested)?);
    bind_payload_hash(&mut envelope);
    match check_entry_bound(&envelope) {
        Err(NodeCoreError::InvalidConfiguration(message))
            if message == "candidate outer envelope has unknown fields" =>
        {
            Ok(())
        }
        other => Err(format!("exact unknown-field error, got {other:?}").into()),
    }
}

#[test]
fn admitted_candidate_envelope_is_fetchable() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let envelope = compact_sdk_envelope(&vec![7_u8; 522_808])?;
    check_entry_bound(&envelope)?;
    let root = fixture("p06-r4-fetch");
    let store = test_store(&root, 0, 2 * 1024 * 1024)?;
    let now = i64::try_from(crate::now_unix_seconds())?;
    let mut row = entry(1);
    row.envelope = envelope;
    row.envelope.created_at = now;
    row.envelope.target_delivery_id = "target".to_owned();
    store.record_submission_increment(
        &crate::tests::request_replay_fixture("p06-r4"),
        now + 3600,
        Some(&row),
    )?;
    let router = store.load_router()?.ok_or("router")?;
    match router.fetch_entry("target", 1, now)? {
        InboxEntryResponse::Entry { .. } => {}
        InboxEntryResponse::EntryTooLarge { .. } => {
            return Err("admitted envelope must stay fetchable".into());
        }
        other @ InboxEntryResponse::EntryGone { .. } => {
            return Err(format!("expected entry, got {other:?}").into());
        }
    }
    drop(router);
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn compact_250kb_envelope() -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    compact_sdk_envelope(&vec![7_u8; 250 * 1024])
}

fn inject_compact_pad(
    envelope: &ramflux_protocol::Envelope,
    object: &str,
    pad: serde_json::Value,
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes)?;
    let mut sidecar: serde_json::Value = serde_json::from_slice(compact.sidecar)?;
    sidecar[object]["pad"] = pad;
    let rebuilt = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )?;
    let mut out = envelope.clone();
    out.encrypted_payload = ramflux_protocol::encode_base64url(&rebuilt);
    bind_payload_hash(&mut out);
    Ok(out)
}

fn unknown_nested_field(
    result: Result<(), NodeCoreError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(NodeCoreError::InvalidConfiguration(message))
            if message == "candidate outer envelope has unknown fields" =>
        {
            Ok(())
        }
        other => Err(format!("exact unknown-field error, got {other:?}").into()),
    }
}

#[test]
fn candidate_250kb_ciphertext_pad_is_unknown_field() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let envelope = inject_compact_pad(
        &compact_250kb_envelope()?,
        "ciphertext",
        serde_json::json!("p".repeat(100 * 1024)),
    )?;
    assert!(single_entry_frame_size(&envelope)? <= ENTRY_FRAME_BYTE_CAP);
    unknown_nested_field(check_entry_bound(&envelope))
}

#[test]
fn candidate_250kb_x3dh_pad_is_unknown_field() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let envelope = inject_compact_pad(&compact_250kb_envelope()?, "x3dh", serde_json::json!("x"))?;
    unknown_nested_field(check_entry_bound(&envelope))
}

#[test]
fn candidate_source_principal_commitment_cap() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let cap = ramflux_protocol::message::outer::MAX_IDENTIFIER_BYTES;
    let mut allowed = compact_250kb_envelope()?;
    let bytes = ramflux_protocol::decode_base64url(&allowed.encrypted_payload)?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes)?;
    let mut sidecar: serde_json::Value = serde_json::from_slice(compact.sidecar)?;
    sidecar["source_principal_commitment"] = serde_json::json!("c".repeat(cap));
    let rebuilt = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )?;
    allowed.encrypted_payload = ramflux_protocol::encode_base64url(&rebuilt);
    bind_payload_hash(&mut allowed);
    check_entry_bound(&allowed)?;
    sidecar["source_principal_commitment"] = serde_json::json!("c".repeat(cap + 1));
    let over = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )?;
    allowed.encrypted_payload = ramflux_protocol::encode_base64url(&over);
    bind_payload_hash(&mut allowed);
    match check_entry_bound(&allowed) {
        Err(NodeCoreError::InvalidConfiguration(message))
            if message == "identifier exceeds 256 bytes" =>
        {
            Ok(())
        }
        other => Err(format!("exact identifier error, got {other:?}").into()),
    }
}

fn set_sidecar_field(
    envelope: &ramflux_protocol::Envelope,
    edit: impl FnOnce(&mut serde_json::Value),
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes)?;
    let mut sidecar: serde_json::Value = serde_json::from_slice(compact.sidecar)?;
    edit(&mut sidecar);
    let rebuilt = ramflux_protocol::message::outer::encode_compact_cryptobox(
        compact.ciphertext,
        &serde_json::to_vec(&sidecar)?,
    )?;
    let mut out = envelope.clone();
    out.encrypted_payload = ramflux_protocol::encode_base64url(&rebuilt);
    out.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        out.encrypted_payload.as_bytes(),
    );
    Ok(out)
}

#[test]
fn candidate_250kb_legacy_ciphertext_field_is_refused_when_non_empty()
-> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let base = compact_250kb_envelope()?;
    check_entry_bound(&base)?;
    let zeros = vec![0_u8; 200 * 1024];
    let padded = set_sidecar_field(&base, |sidecar| {
        sidecar["ciphertext"]["ciphertext"] = serde_json::json!(zeros);
    })?;
    assert!(single_entry_frame_size(&padded)? <= ENTRY_FRAME_BYTE_CAP);
    match check_entry_bound(&padded) {
        Err(NodeCoreError::InvalidConfiguration(message))
            if message == "compact candidate sidecar ciphertext field must be empty" =>
        {
            Ok(())
        }
        other => Err(format!("exact non-empty ciphertext error, got {other:?}").into()),
    }
}

#[test]
fn candidate_250kb_top_level_pad_is_unknown_field() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let padded = set_sidecar_field(&compact_250kb_envelope()?, |sidecar| {
        sidecar["pad"] = serde_json::json!("p".repeat(100 * 1024));
    })?;
    unknown_nested_field(check_entry_bound(&padded))
}

const MISSING_COMPACT_CIPHERTEXT: &str = "compact candidate sidecar ciphertext field is required";
const PAYLOAD_HASH_MISMATCH: &str = "envelope payload hash mismatch";

#[test]
fn candidate_compact_ciphertext_field_is_required() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let missing = set_sidecar_field(&compact_250kb_envelope()?, |sidecar| {
        let object = sidecar["ciphertext"].as_object_mut().expect("ciphertext object");
        object.remove("ciphertext");
    })?;
    match check_entry_bound(&missing) {
        Err(NodeCoreError::InvalidConfiguration(message))
            if message == MISSING_COMPACT_CIPHERTEXT =>
        {
            Ok(())
        }
        other => Err(format!("exact missing ciphertext error, got {other:?}").into()),
    }
}

#[test]
fn candidate_entry_refuses_payload_hash_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let mut envelope = compact_250kb_envelope()?;
    check_entry_bound(&envelope)?;
    envelope.payload_hash = "tampered-payload-hash".into();
    match check_entry_bound(&envelope) {
        Err(NodeCoreError::InvalidConfiguration(message)) if message == PAYLOAD_HASH_MISMATCH => {
            Ok(())
        }
        other => Err(format!("exact payload hash error, got {other:?}").into()),
    }
}

#[test]
fn legacy_entry_accepts_payload_hash_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let mut envelope = nested_sdk_envelope(&[7_u8; 32])?;
    envelope.payload_hash = "legacy-mismatch".into();
    check_entry_bound(&envelope)?;
    Ok(())
}

fn exact_config(
    result: Result<(), NodeCoreError>,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(NodeCoreError::InvalidConfiguration(message)) if message == expected => Ok(()),
        other => Err(format!("exact {expected}, got {other:?}").into()),
    }
}

fn exact_mode_refused(result: Result<(), NodeCoreError>) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(NodeCoreError::DeliveryModeRefused) => Ok(()),
        other => Err(format!("exact DeliveryModeRefused, got {other:?}").into()),
    }
}

#[test]
fn gate_off_named_delivery_mode_is_refused_at_entry() -> Result<(), Box<dyn std::error::Error>> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let mut envelope = nested_sdk_envelope(&[7_u8; 32])?;
    envelope.delivery_mode = Some("ephemeral".into());
    exact_mode_refused(check_entry_bound(&envelope))
}

#[test]
fn gate_off_named_collapse_tag_is_refused_at_entry() -> Result<(), Box<dyn std::error::Error>> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let mut envelope = nested_sdk_envelope(&[7_u8; 32])?;
    envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x00_u8; 32]));
    exact_mode_refused(check_entry_bound(&envelope))
}

#[test]
fn gate_off_named_field_conflicting_with_ext_bridge_is_refused()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let mut envelope = nested_sdk_envelope(&[7_u8; 32])?;
    envelope.delivery_mode = Some("durable".into());
    envelope.ext.ext.insert(
        ramflux_protocol::ephemeral::DELIVERY_MODE_EXTENSION.to_owned(),
        serde_json::json!("ephemeral"),
    );
    exact_mode_refused(check_entry_bound(&envelope))
}

#[test]
fn candidate_entry_refuses_missing_delivery_mode() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let mut envelope = compact_250kb_envelope()?;
    envelope.delivery_mode = None;
    exact_mode_refused(check_entry_bound(&envelope))
}

#[test]
fn candidate_entry_refuses_unknown_delivery_mode() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let mut envelope = compact_250kb_envelope()?;
    envelope.delivery_mode = Some("bogus".into());
    exact_mode_refused(check_entry_bound(&envelope))
}

#[test]
fn candidate_entry_refuses_31_byte_collapse_tag() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let mut envelope = compact_250kb_envelope()?;
    envelope.collapse_tag = Some(ramflux_protocol::encode_base64url([0x00_u8; 31]));
    exact_mode_refused(check_entry_bound(&envelope))
}

#[test]
fn candidate_entry_refuses_31_byte_report_commitment() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let mut envelope = compact_250kb_envelope()?;
    envelope.report_commitment = Some(ramflux_protocol::encode_base64url([0x00_u8; 31]));
    exact_config(check_entry_bound(&envelope), "report_commitment must be 32 bytes")
}

#[test]
fn gate_off_named_report_commitment_is_refused_at_entry() -> Result<(), Box<dyn std::error::Error>>
{
    assert!(!ramflux_protocol::schema_profile::schema_v1_live());
    let mut envelope = nested_sdk_envelope(&[7_u8; 32])?;
    envelope.report_commitment = Some(ramflux_protocol::encode_base64url([0x00_u8; 32]));
    exact_mode_refused(check_entry_bound(&envelope))
}

#[test]
fn candidate_compact_ciphertext_object_is_required() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let missing = set_sidecar_field(&compact_250kb_envelope()?, |sidecar| {
        sidecar.as_object_mut().expect("sidecar object").remove("ciphertext");
    })?;
    exact_config(check_entry_bound(&missing), MISSING_COMPACT_CIPHERTEXT)
}
