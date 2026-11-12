// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A retained retry hint cannot replace the packet admitted by durable W0.
use super::merge_retry_inputs;
use crate::bus::connection_manager::ReceiveEntry;
use crate::{GatewayInboxEntry, SdkError};

fn entry(authority: &str) -> Result<GatewayInboxEntry, SdkError> {
    Ok(serde_json::from_value(serde_json::json!({
        "inbox_seq": 3, "target_delivery_id": "target", "envelope": {
            "schema":"ramflux.envelope.v1", "version":1, "domain":"ramflux.envelope.v1",
            "signing_key_id":"key", "signature_alg":"ed25519", "signature":"signature",
            "envelope_id":"message", "source_principal_id":"principal", "source_device_id":"device",
            "target_delivery_id":"target", "delivery_class":"opaque_event", "priority":"normal",
            "ttl":60, "created_at":1, "encrypted_payload":"YQ", "payload_hash":"hash",
            "ext":{"source_device_authority":{"snapshot":authority}}
        }
    }))?)
}

#[test]
fn recovered_w0_overrides_enriched_hint_and_preserves_retry_context() -> Result<(), SdkError> {
    let original = entry("original")?;
    let mut retries = vec![ReceiveEntry {
        entry: entry("enriched")?,
        retry_key: Some("retained-key".into()),
        replay: true,
        turn: None,
    }];
    let inputs = [ramflux_storage::RecoveryInput {
        sequence: 3,
        disposition: "staged".into(),
        entry_json: serde_json::to_vec(&original)?,
    }];
    merge_retry_inputs(&mut retries, &inputs);
    assert_eq!(retries.len(), 1, "one receive input for the admitted coordinate");
    assert_eq!(retries[0].entry, original, "W0 retains its admitted authority snapshot");
    assert_eq!(retries[0].retry_key.as_deref(), Some("retained-key"));
    assert!(retries[0].replay, "retained retry semantics survive recovery");
    Ok(())
}
