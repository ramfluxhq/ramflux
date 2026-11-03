// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A deterministic integration-node record with an independent Ed25519 signature.
use ed25519_dalek::SigningKey;
use ramflux_crypto::custody::{sign_node_identity_record, verify_node_identity_record};
use ramflux_protocol::custody::{Envelope, NodeIdentityRecord};
#[test]
fn integration_node_record_signature_matches_frozen_ed25519_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/dalek_node_record.json"))?;
    let expected: Envelope<NodeIdentityRecord> = serde_json::from_value(fixture["record"].clone())?;
    let key = SigningKey::from_bytes(&[7; 32]);
    let actual = sign_node_identity_record(&key, expected.body.clone())?;
    assert_eq!(actual.signature, expected.signature);
    assert_eq!(
        ramflux_protocol::canonical_json_bytes(&actual)?,
        ramflux_protocol::canonical_json_bytes(&expected)?
    );
    verify_node_identity_record(
        &actual,
        "fixture.example",
        &expected.body.node_signing_public_key,
        1_700_000_000,
    )?;
    Ok(())
}
