// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed client endpoint discovery, alongside the federation server record.

use crate::{ProtocolError, canonical_json_bytes, signed_bytes, verify_canonical_signature};
use serde::{Deserialize, Serialize};

pub const WELL_KNOWN_CLIENT_SCHEMA: &str = "ramflux.well_known_client.v1";
pub const CLIENT_DISCOVERY_DOMAIN: &str = "ramflux.client_discovery.v1";
pub const DISCOVERY_CLOCK_SKEW_SECONDS: u64 = 300;
pub const DISCOVERY_MAX_CACHE_TTL_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WellKnownClientRecord {
    pub schema: String,
    pub node_id: String,
    pub node_public_key: String,
    pub node_ca_cert_pem: String,
    pub gateway_quic_addr: String,
    pub gateway_tcp_addr: String,
    pub gateway_server_name: String,
    pub relay_quic_addr: String,
    pub relay_server_name: String,
    pub prekey_http_url: String,
    pub signaling_turn_addr: String,
    pub protocol_versions: Vec<String>,
    pub client_capabilities: Vec<String>,
    pub updated_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// Applies the shared server/client discovery freshness window.
///
/// # Errors
/// Returns an error for an expired record or a future issue time.
pub fn verify_discovery_freshness(
    updated_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), ProtocolError> {
    if expires_at.saturating_add(DISCOVERY_CLOCK_SKEW_SECONDS) < now {
        return Err(ProtocolError::SignedRequestExpired);
    }
    if updated_at > now.saturating_add(DISCOVERY_CLOCK_SKEW_SECONDS) {
        return Err(ProtocolError::SignedRequestFromFuture);
    }
    Ok(())
}

/// Canonical JSON excluding signature, wrapped with the client signature domain.
///
/// # Errors
/// Returns an error when canonical encoding fails.
pub fn client_discovery_signing_bytes(
    record: &WellKnownClientRecord,
) -> Result<Vec<u8>, ProtocolError> {
    let body: serde_json::Value = serde_json::from_slice(&signed_bytes(record)?)?;
    canonical_json_bytes(&serde_json::json!({"domain": CLIENT_DISCOVERY_DOMAIN, "record": body}))
}

/// Verifies the schema, CA presence, freshness, and the node's Ed25519 signature.
/// Trust in the self-declared node key is established separately by pinning.
///
/// # Errors
/// Returns an error when record validation or signature verification fails.
pub fn verify_client_discovery_record(
    record: &WellKnownClientRecord,
    now: u64,
) -> Result<(), ProtocolError> {
    if record.schema != WELL_KNOWN_CLIENT_SCHEMA || record.node_ca_cert_pem.trim().is_empty() {
        return Err(ProtocolError::InvalidDomain {
            expected: WELL_KNOWN_CLIENT_SCHEMA,
            actual: record.schema.clone(),
        });
    }
    verify_discovery_freshness(record.updated_at, record.expires_at, now)?;
    verify_canonical_signature(
        &client_discovery_signing_bytes(record)?,
        &record.signature,
        &record.node_public_key,
    )
}

#[must_use]
pub fn discovery_cache_ttl(expires_at: u64, now: u64, max_ttl: u64) -> u64 {
    expires_at.saturating_sub(now).min(max_ttl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signed_record_round_trip_rejects_expiry_tampering_and_future_issue()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = SigningKey::from_bytes(&[42; 32]);
        let mut record = WellKnownClientRecord {
            schema: WELL_KNOWN_CLIENT_SCHEMA.to_owned(),
            node_id: "node.example.com".to_owned(),
            node_public_key: crate::encode_base64url(key.verifying_key().to_bytes()),
            node_ca_cert_pem: "test CA".to_owned(),
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
        record.signature =
            crate::encode_base64url(key.sign(&client_discovery_signing_bytes(&record)?).to_bytes());
        let decoded =
            serde_json::from_slice::<WellKnownClientRecord>(&canonical_json_bytes(&record)?)?;
        assert_eq!(record, decoded);
        verify_client_discovery_record(&decoded, 1500)?;
        assert!(verify_client_discovery_record(&decoded, 2301).is_err());
        assert!(verify_client_discovery_record(&decoded, 699).is_err());
        record.gateway_tcp_addr = "evil.example.com:443".to_owned();
        assert!(verify_client_discovery_record(&record, 1500).is_err());
        assert!(
            verify_canonical_signature(
                &signed_bytes(&decoded)?,
                &decoded.signature,
                &decoded.node_public_key
            )
            .is_err()
        );
        assert_eq!(discovery_cache_ttl(2000, 1500, 100), 100);
        assert_eq!(discovery_cache_ttl(2000, 2001, 100), 0);
        Ok(())
    }

    #[test]
    fn python_discovery_fixture_is_signed_by_rust_canonicalizer()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture =
            include_str!("../../../deploy/scripts/tests/fixtures/rust-signed-discovery.json");
        let record: WellKnownClientRecord = serde_json::from_str(fixture)?;
        let key = SigningKey::from_bytes(&[42; 32]);
        assert_eq!(record.node_public_key, crate::encode_base64url(key.verifying_key().to_bytes()));
        assert_eq!(
            record.signature,
            crate::encode_base64url(key.sign(&client_discovery_signing_bytes(&record)?).to_bytes())
        );
        Ok(())
    }
}
