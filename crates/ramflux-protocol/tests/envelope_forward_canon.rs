// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::{Envelope, envelope_sender_signed_bytes};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn envelope() -> TestResult<Envelope> {
    Ok(serde_json::from_value(json!({
        "schema":"ramflux.envelope.v1", "version":1, "domain":"ramflux.envelope.v1",
        "signing_key_id":"device", "signature_alg":"ed25519", "signature":"",
        "envelope_id":"message", "source_principal_id":"sender", "source_device_id":"device",
        "target_delivery_id":"target", "routing_set_id":"routing", "delivery_class":"opaque_event", "priority":"normal",
        "ttl":600, "created_at":123, "encrypted_payload":"cipher", "payload_hash":"hash",
        "ext": {"sender_label":"signed", "source_root_commitment":"signed-root",
            "franking":{"sender_tag":"signed-tag", "franking_tag":"node-tag", "node_id":"node", "accepted_at":124}}
    }))?)
}

#[test]
fn hop_marker_is_excluded_but_every_sender_canon_field_is_bound() -> TestResult {
    let mut envelope = envelope()?;
    let key = SigningKey::from_bytes(&[42; 32]);
    let signature = key.sign(&envelope_sender_signed_bytes(&envelope)?);
    envelope.signed.signature = ramflux_protocol::encode_base64url(signature.to_bytes());
    for marker in [None, Some(json!(1)), Some(json!(2))] {
        if let Some(marker) = marker {
            envelope.ext.ext.insert("home_node_migration_forward_count".into(), marker);
        }
        key.verifying_key().verify_strict(&envelope_sender_signed_bytes(&envelope)?, &signature)?;
    }
    // This list names sender fields independently of the canon's output keys.
    // Every case changes the actual Envelope and invokes the production canon again.
    for (field, value) in [
        ("/schema", json!("changed.schema")),
        ("/version", json!(2)),
        ("/domain", json!("changed.domain")),
        ("/envelope_id", json!("changed-message")),
        ("/source_principal_id", json!("changed-sender")),
        ("/source_device_id", json!("changed-device")),
        ("/target_delivery_id", json!("changed-target")),
        ("/routing_set_id", json!("changed-route")),
        ("/routing_set_id", json!(null)),
        ("/delivery_class", json!("notification_wake")),
        ("/priority", json!("high")),
        ("/ttl", json!(601)),
        ("/created_at", json!(124)),
        ("/encrypted_payload", json!("changed-cipher")),
        ("/payload_hash", json!("changed-hash")),
        ("/ext/sender_label", json!("changed-label")),
        ("/ext/source_root_commitment", json!("changed-root")),
        ("/ext/franking/sender_tag", json!("changed-tag")),
    ] {
        let mut changed = serde_json::to_value(envelope.clone())?;
        *changed.pointer_mut(field).ok_or("named sender field missing")? = value;
        let changed: Envelope = serde_json::from_value(changed)?;
        assert!(
            key.verifying_key()
                .verify_strict(&envelope_sender_signed_bytes(&changed)?, &signature)
                .is_err(),
            "unbound sender field {field}"
        );
    }
    Ok(())
}

#[test]
fn appended_authority_and_franking_receipts_preserve_sender_signature() -> TestResult {
    let mut envelope = envelope()?;
    let key = SigningKey::from_bytes(&[42; 32]);
    let signature = key.sign(&envelope_sender_signed_bytes(&envelope)?);
    envelope.ext.ext.insert("source_device_authority".into(), json!({"appended":"evidence"}));
    let receipt = envelope.ext.ext.get_mut("franking").ok_or("missing receipt")?;
    receipt["franking_tag"] = json!("new-node-tag");
    receipt["node_id"] = json!("new-node");
    receipt["accepted_at"] = json!(456);
    key.verifying_key().verify_strict(&envelope_sender_signed_bytes(&envelope)?, &signature)?;
    Ok(())
}
