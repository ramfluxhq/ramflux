// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::{NodeCoreError, NodeServiceConfig};

pub const NODE_SERVICE_SIGNING_SEED_ENV: &str = "RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL";
pub const NODE_SERVICE_SIGNING_KEY_ID: &str = "node-service-ed25519-v1";

#[derive(Clone)]
pub struct NodeServiceSigningKey {
    seed: [u8; 32],
    public_key_bytes: [u8; 32],
    public_key_base64url: String,
}

#[derive(Clone, Copy, Debug)]
pub struct NodeFrankingTagInput<'a> {
    pub node_id: &'a str,
    pub envelope_id: &'a str,
    pub message_event_id: &'a str,
    pub sender_device_id_hash: &'a [u8],
    pub commitment: &'a str,
    pub ciphertext_hash: &'a str,
    pub accepted_at_unix_ms: u64,
}

impl NodeServiceSigningKey {
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let public_key_bytes = ramflux_crypto::public_key_bytes_from_seed(seed);
        Self {
            seed,
            public_key_bytes,
            public_key_base64url: ramflux_crypto::public_key_base64url_from_seed(seed),
        }
    }

    #[must_use]
    pub fn signing_key_id(&self) -> &'static str {
        NODE_SERVICE_SIGNING_KEY_ID
    }

    #[must_use]
    pub fn public_key_base64url(&self) -> &str {
        &self.public_key_base64url
    }

    #[must_use]
    pub fn sign_franking_node_tag(&self, input: NodeFrankingTagInput<'_>) -> String {
        ramflux_crypto::sign_franking_node_tag_with_seed(
            input.node_id,
            input.envelope_id,
            input.message_event_id,
            input.sender_device_id_hash,
            input.commitment,
            input.ciphertext_hash,
            input.accepted_at_unix_ms,
            self.seed,
        )
    }

    /// # Errors
    /// Returns an error when the wake cannot be canonicalized or signed.
    pub fn sign_notification_wake(
        &self,
        wake: &mut ramflux_protocol::NotificationWake,
    ) -> Result<(), NodeCoreError> {
        self.signing_key_id().clone_into(&mut wake.signed.signing_key_id);
        wake.signed.signature_alg = ramflux_protocol::SignatureAlg::Ed25519;
        wake.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(wake, self.seed)
            .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the wake signature is missing, uses the wrong key, or fails
    /// canonical Ed25519 verification.
    pub fn verify_notification_wake(
        &self,
        wake: &ramflux_protocol::NotificationWake,
    ) -> Result<(), NodeCoreError> {
        if wake.signed.signing_key_id != self.signing_key_id() {
            return Err(NodeCoreError::Unauthorized("notify wake signing key rejected".to_owned()));
        }
        if wake.signed.signature_alg != ramflux_protocol::SignatureAlg::Ed25519 {
            return Err(NodeCoreError::Unauthorized(
                "notify wake signature algorithm rejected".to_owned(),
            ));
        }
        let signed_bytes = ramflux_protocol::signed_bytes(wake)
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        ramflux_crypto::verify_canonical_signature(
            &signed_bytes,
            &wake.signed.signature,
            self.public_key_base64url(),
        )
        .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
    }

    /// # Errors
    /// Returns the wake indices that fail key-id, algorithm, canonicalization, signature parsing,
    /// or strict Ed25519 batch verification.
    pub fn verify_notification_wakes_batch(
        &self,
        wakes: &[&ramflux_protocol::NotificationWake],
    ) -> Result<(), Vec<usize>> {
        let mut failures = Vec::new();
        let mut original_indices = Vec::with_capacity(wakes.len());
        let mut signed_bytes = Vec::with_capacity(wakes.len());
        let mut signatures = Vec::with_capacity(wakes.len());
        for (index, wake) in wakes.iter().enumerate() {
            if wake.signed.signing_key_id != self.signing_key_id()
                || wake.signed.signature_alg != ramflux_protocol::SignatureAlg::Ed25519
            {
                failures.push(index);
                continue;
            }
            let Ok(canonical) = ramflux_protocol::signed_bytes(wake) else {
                failures.push(index);
                continue;
            };
            let Ok(signature) = notification_wake_signature_bytes(wake) else {
                failures.push(index);
                continue;
            };
            original_indices.push(index);
            signed_bytes.push(canonical);
            signatures.push(signature);
        }
        if signed_bytes.is_empty() {
            return if failures.is_empty() { Ok(()) } else { Err(failures) };
        }
        let items = signed_bytes
            .iter()
            .zip(signatures.iter())
            .map(|(canonical, signature)| ramflux_crypto::CanonicalSignatureSingleKeyBatchItem {
                canonical,
                signature_bytes: signature,
            })
            .collect::<Vec<_>>();
        if let Err(batch_failures) = ramflux_crypto::verify_canonical_signatures_batch_single_key(
            &self.public_key_bytes,
            &items,
        ) {
            failures.extend(batch_failures.into_iter().map(|index| original_indices[index]));
        }
        failures.sort_unstable();
        failures.dedup();
        if failures.is_empty() { Ok(()) } else { Err(failures) }
    }
}

fn notification_wake_signature_bytes(
    wake: &ramflux_protocol::NotificationWake,
) -> Result<[u8; 64], NodeCoreError> {
    let bytes = ramflux_protocol::decode_base64url(&wake.signed.signature)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        NodeCoreError::ItestJson(format!(
            "notify wake signature must be 64 bytes, got {}",
            bytes.len()
        ))
    })
}

impl std::fmt::Debug for NodeServiceSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeServiceSigningKey")
            .field("signing_key_id", &NODE_SERVICE_SIGNING_KEY_ID)
            .field("public_key_bytes", &self.public_key_bytes)
            .field("public_key_base64url", &self.public_key_base64url)
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl Drop for NodeServiceSigningKey {
    fn drop(&mut self) {
        for byte in &mut self.seed {
            *byte = 0;
        }
    }
}

/// # Errors
/// Returns an error when a configured seed is not valid base64url-encoded 32-byte data.
pub fn node_service_signing_key_from_config(
    config: &NodeServiceConfig,
) -> Result<Option<NodeServiceSigningKey>, NodeCoreError> {
    let Some(seed) = config.node_service_signing_seed_b64url.as_ref().map(RedactedString::as_str)
    else {
        return Ok(None);
    };
    decode_node_service_signing_seed(seed).map(|seed| Some(NodeServiceSigningKey::from_seed(seed)))
}

/// # Errors
/// Returns an error when no node service signing seed is configured or the seed is invalid.
pub fn require_node_service_signing_key(
    config: &NodeServiceConfig,
) -> Result<NodeServiceSigningKey, NodeCoreError> {
    node_service_signing_key_from_config(config)?.ok_or_else(|| {
        NodeCoreError::ItestHttp(format!(
            "missing node service signing seed; set {NODE_SERVICE_SIGNING_SEED_ENV}"
        ))
    })
}

/// # Errors
/// Returns an error when the seed is not valid base64url-encoded 32-byte data.
pub fn decode_node_service_signing_seed(value: &str) -> Result<[u8; 32], NodeCoreError> {
    let bytes = ramflux_protocol::decode_base64url(value)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        NodeCoreError::ItestJson(format!(
            "node service signing seed must be 32 bytes, got {}",
            bytes.len()
        ))
    })
}

#[derive(Clone, Eq, PartialEq, serde::Deserialize)]
pub struct RedactedString(String);

impl RedactedString {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RedactedString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn node_service_signing_key_signs_and_rejects_tampered_wake()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = NodeServiceSigningKey::from_seed([7_u8; 32]);
        let mut wake = test_wake("wake_service_signing", "target_service_signing");
        key.sign_notification_wake(&mut wake)?;
        key.verify_notification_wake(&wake)?;

        wake.push_alias.push_str("_tampered");
        assert!(matches!(
            key.verify_notification_wake(&wake),
            Err(NodeCoreError::Unauthorized(_message))
        ));
        Ok(())
    }

    #[test]
    fn node_service_signing_key_signs_franking_node_tag() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = NodeServiceSigningKey::from_seed([8_u8; 32]);
        let sender_device_id_hash = [0xa8; 32];
        let signature = key.sign_franking_node_tag(NodeFrankingTagInput {
            node_id: "node-service-franking",
            envelope_id: "env-service-franking",
            message_event_id: "msg-service-franking",
            sender_device_id_hash: &sender_device_id_hash,
            commitment: "commitment-service-franking",
            ciphertext_hash: "ciphertext-hash-service-franking",
            accepted_at_unix_ms: 1_760_000_000_123,
        });
        let preimage = ramflux_crypto::franking_node_tag_preimage(
            "node-service-franking",
            "env-service-franking",
            "msg-service-franking",
            &sender_device_id_hash,
            "commitment-service-franking",
            "ciphertext-hash-service-franking",
            1_760_000_000_123,
        );
        let verifying_key =
            ramflux_crypto::verifying_key_from_base64url(key.public_key_base64url())?;
        ramflux_crypto::verify_franking_node_tag(&preimage, &signature, &verifying_key)?;
        Ok(())
    }

    #[test]
    fn node_service_signing_key_batch_accepts_valid_wakes() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = NodeServiceSigningKey::from_seed([7_u8; 32]);
        let wakes = signed_test_wakes(&key, 8)?;
        let wake_refs = wakes.iter().collect::<Vec<_>>();

        assert_eq!(key.verify_notification_wakes_batch(&wake_refs), Ok(()));
        Ok(())
    }

    #[test]
    fn node_service_signing_key_batch_reports_bad_wake_indices()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = NodeServiceSigningKey::from_seed([7_u8; 32]);
        let mut wakes = signed_test_wakes(&key, 8)?;
        wakes[2].push_alias.push_str("_tampered");
        wakes[5].signed.signing_key_id = "wrong-key".to_owned();
        let wake_refs = wakes.iter().collect::<Vec<_>>();

        assert_eq!(key.verify_notification_wakes_batch(&wake_refs), Err(vec![2, 5]));
        Ok(())
    }

    #[ignore = "microbenchmark; run explicitly with --ignored --nocapture"]
    #[test]
    fn verify_wake_batch_bench() -> Result<(), Box<dyn std::error::Error>> {
        let total = bench_usize_env("RAMFLUX_WAKE_VERIFY_TOTAL", 1_000_000);
        let batch_size = bench_usize_env("RAMFLUX_WAKE_VERIFY_BATCH", 1_024);
        let key = NodeServiceSigningKey::from_seed([7_u8; 32]);
        let wakes = signed_test_wakes(&key, total)?;
        let wake_refs = wakes.iter().collect::<Vec<_>>();

        let started = Instant::now();
        for chunk in wake_refs.chunks(batch_size) {
            key.verify_notification_wakes_batch(chunk).map_err(|indices| {
                NodeCoreError::Unauthorized(format!(
                    "wake verify bench unexpectedly failed at indices {indices:?}"
                ))
            })?;
        }
        let elapsed = started.elapsed();
        let total_f64 = u32::try_from(total).map_or(f64::from(u32::MAX), f64::from);
        let elapsed_secs = elapsed.as_secs_f64();
        let ops_per_sec = if elapsed_secs > 0.0 { total_f64 / elapsed_secs } else { f64::INFINITY };
        let us_per_wake =
            if total > 0 { elapsed.as_secs_f64() * 1_000_000.0 / total_f64 } else { 0.0 };
        eprintln!(
            "WAKE_VERIFY_BENCH label=verify_wake_batch batch_size={batch_size} total={total} elapsed_ms={} ops_per_sec={ops_per_sec:.2} us_per_wake={us_per_wake:.3}",
            elapsed.as_millis()
        );
        Ok(())
    }

    fn signed_test_wakes(
        key: &NodeServiceSigningKey,
        total: usize,
    ) -> Result<Vec<ramflux_protocol::NotificationWake>, NodeCoreError> {
        let mut wakes = Vec::with_capacity(total);
        for index in 0..total {
            let mut wake = test_wake(
                &format!("wake_service_signing_{index}"),
                &format!("target_service_signing_{}", index % 64),
            );
            key.sign_notification_wake(&mut wake)?;
            wakes.push(wake);
        }
        Ok(wakes)
    }

    fn test_wake(wake_id: &str, push_alias: &str) -> ramflux_protocol::NotificationWake {
        ramflux_protocol::NotificationWake {
            schema: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: NODE_SERVICE_SIGNING_KEY_ID.to_owned(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: String::new(),
            },
            wake_id: wake_id.to_owned(),
            push_alias: push_alias.to_owned(),
            delivery_class: ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
            priority: ramflux_protocol::PushPriority::Normal,
            ttl: 60,
            collapse_key: Some("collapse".to_owned()),
            encrypted_hint: Some("hint".to_owned()),
        }
    }

    fn bench_usize_env(name: &str, default: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default)
    }
}
