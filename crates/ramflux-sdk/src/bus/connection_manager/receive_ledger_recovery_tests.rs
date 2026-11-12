// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Resume must retain the authority snapshot already admitted by W0.
use super::select_resume_input;
use crate::bus::connection_manager::ReceiveEntry;
use crate::{GatewayInboxEntry, SdkError};
use std::collections::BTreeMap;

#[test]
fn resumed_w0_retains_original_packet_and_retry_context() -> Result<(), SdkError> {
    let original: GatewayInboxEntry = serde_json::from_value(serde_json::json!({
        "inbox_seq":3, "target_delivery_id":"target", "envelope": {
            "schema":"ramflux.envelope.v1", "version":1, "domain":"ramflux.envelope.v1",
            "signing_key_id":"key", "signature_alg":"ed25519", "signature":"signature",
            "envelope_id":"message", "source_principal_id":"principal", "source_device_id":"device",
            "target_delivery_id":"target", "delivery_class":"opaque_event", "priority":"normal",
            "ttl":60, "created_at":1, "encrypted_payload":"YQ", "payload_hash":"hash",
            "ext":{"source_device_authority":{"snapshot":"original"}}
        }
    }))?;
    let mut enriched = original.clone();
    enriched
        .envelope
        .ext
        .ext
        .insert("source_device_authority".into(), serde_json::json!({"snapshot":"enriched"}));
    let recovered = ReceiveEntry {
        entry: original.clone(),
        retry_key: Some("retained-key".into()),
        replay: true,
        turn: None,
    };
    let mut retries = BTreeMap::from([(super::entry_id(&original), recovered)]);
    let selected = select_resume_input(enriched.clone(), &mut retries);
    assert_eq!(selected.entry, original, "Resume must reuse the admitted W0 packet");
    assert_eq!(selected.retry_key.as_deref(), Some("retained-key"));
    assert!(selected.replay, "retain the recovery disposition");
    assert!(retries.is_empty(), "consume exactly the matching recovery input");
    let fresh = select_resume_input(enriched.clone(), &mut retries);
    assert_eq!(fresh.entry, enriched, "a fresh coordinate uses its network packet");
    assert_eq!(fresh.retry_key, None);
    assert!(!fresh.replay);
    Ok(())
}
