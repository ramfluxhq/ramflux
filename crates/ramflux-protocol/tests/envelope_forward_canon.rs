// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::{Envelope, envelope_sender_signed_bytes};
use serde_json::json;

#[test]
fn hop_marker_is_excluded_but_every_sender_canon_field_is_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let mut envelope: Envelope = serde_json::from_value(json!({
        "schema":"ramflux.envelope.v1", "version":1, "domain":"ramflux.envelope.v1",
        "signing_key_id":"device", "signature_alg":"ed25519", "signature":"",
        "envelope_id":"message", "source_principal_id":"sender", "source_device_id":"device",
        "target_delivery_id":"target", "routing_set_id":"routing", "delivery_class":"opaque_event", "priority":"normal",
        "ttl":600, "created_at":123, "encrypted_payload":"cipher", "payload_hash":"hash"
    }))?;
    let key = SigningKey::from_bytes(&[42; 32]);
    let signature = key.sign(&envelope_sender_signed_bytes(&envelope)?);
    envelope.signed.signature = ramflux_protocol::encode_base64url(signature.to_bytes());
    for marker in [None, Some(json!(1)), Some(json!(2))] {
        if let Some(marker) = marker {
            envelope.ext.ext.insert("home_node_migration_forward_count".into(), marker);
        }
        key.verifying_key().verify_strict(&envelope_sender_signed_bytes(&envelope)?, &signature)?;
    }
    // Mutate each field of the actual canonical object, including unknown sender extensions.
    envelope.ext.ext.insert("sender_label".into(), json!("signed"));
    let canon = envelope_sender_signed_bytes(&envelope)?;
    let signature = key.sign(&canon);
    let object: serde_json::Value = serde_json::from_slice(&canon)?;
    let fields = object.as_object().ok_or("canonical envelope is not an object")?;
    for field in fields.keys() {
        let mut changed = object.clone();
        changed[field] = json!(format!("altered-{field}"));
        let changed = ramflux_protocol::canonical_json_bytes(&changed)?;
        assert!(
            key.verifying_key().verify_strict(&changed, &signature).is_err(),
            "unbound {field}"
        );
    }
    Ok(())
}
