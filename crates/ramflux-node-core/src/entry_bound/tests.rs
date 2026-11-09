// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::expect_used, reason = "independent wire assertions")]
use super::*;
use crate::router_store::publication::tests::entry;
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

fn nested_sdk_envelope(
    cryptobox: &[u8],
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let nested = serde_json::json!({
        "schema": "ramflux.sdk.dm_x3dh_envelope.v2",
        "version": 2,
        "x3dh": {"session_id": "s"},
        "ciphertext": {
            "ciphertext": cryptobox,
            "canonical_header_bytes": [1, 2, 3],
        }
    });
    let mut envelope = entry(1).envelope;
    envelope.source_device_id = "wire-device".to_owned();
    envelope.encrypted_payload = ramflux_protocol::encode_base64url(serde_json::to_vec(&nested)?);
    Ok(envelope)
}

#[test]
fn candidate_entry_bound_measures_nested_cryptobox_when_gate_on()
-> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let envelope = nested_sdk_envelope(&[7_u8; 32])?;
    check_entry_bound(&envelope)?;
    let sizes = ramflux_protocol::message::outer::IngressSizes::measure_live(&envelope, &[], &[])?;
    assert_eq!(sizes.ciphertext_bytes, 32);
    ramflux_protocol::message::outer::check_ingress_caps(sizes)?;
    Ok(())
}

#[test]
fn candidate_entry_bound_accepts_392kb_nested_cryptobox() -> Result<(), Box<dyn std::error::Error>>
{
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let cryptobox = vec![7_u8; 522_808];
    let envelope = nested_sdk_envelope(&cryptobox)?;
    let wrapper = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)?;
    check_entry_bound(&envelope)?;
    let sizes = ramflux_protocol::message::outer::IngressSizes::measure_live(&envelope, &[], &[])?;
    assert_eq!(sizes.ciphertext_bytes, 522_808);
    assert!(sizes.ciphertext_bytes < wrapper.len());
    assert!(sizes.bootstrap_capsule_bytes > 0);
    assert_ne!(envelope.source_device_id, "local");
    ramflux_protocol::message::outer::check_ingress_caps(sizes)?;
    Ok(())
}

#[test]
fn candidate_entry_bound_refuses_one_over_cryptobox() -> Result<(), Box<dyn std::error::Error>> {
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let over = vec![7_u8; ramflux_protocol::message::outer::MAX_CIPHERTEXT_BYTES + 1];
    let envelope = nested_sdk_envelope(&over)?;
    match check_entry_bound(&envelope) {
        Err(NodeCoreError::PayloadTooLarge) => Ok(()),
        other => Err(format!("exact PayloadTooLarge, got {other:?}").into()),
    }
}
