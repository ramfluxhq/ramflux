// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only retained-quarantine keys for adversarial native admission fixtures.
use crate::prelude::*;

pub(crate) fn legacy_key(entry: &GatewayInboxEntry) -> Result<String, SdkError> {
    // Match sender authentication: gateway-added receipt fields do not identify a new message.
    let mut envelope = entry.envelope.clone();
    if let Some(receipt) =
        envelope.ext.ext.get_mut("franking").and_then(serde_json::Value::as_object_mut)
    {
        for field in ["franking_tag", "node_id", "accepted_at"] {
            receipt.remove(field);
        }
    }
    Ok(format!(
        "legacy:{}",
        ramflux_protocol::hash_base64url(
            "ramflux.legacy.inbox.v1",
            &ramflux_protocol::canonical_json_bytes(&envelope)?,
        )
    ))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_group_key_is_stable_for_the_same_envelope() -> Result<(), SdkError> {
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: "t".into(),
            envelope: ramflux_protocol::Envelope {
                schema: "ramflux.envelope.v1".into(),
                version: 1,
                domain: "test".into(),
                ext: ramflux_protocol::Ext::default(),
                signed: crate::prelude::sdk_device_signed_fields("device", ""),
                envelope_id: "env".into(),
                source_principal_id: "source".into(),
                source_device_id: "device".into(),
                target_delivery_id: "t".into(),
                routing_set_id: None,
                delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
                priority: ramflux_protocol::Priority::Normal,
                ttl: 60,
                created_at: 1,
                encrypted_payload: "cipher".into(),
                payload_hash: "hash".into(),
                delivery_mode: None,
                collapse_tag: None,
                report_commitment: None,
            },
        };
        let first = legacy_key(&entry)?;
        let second = legacy_key(&entry)?;
        assert_eq!(first, second);
        assert!(first.starts_with("legacy:"));
        Ok(())
    }
}
