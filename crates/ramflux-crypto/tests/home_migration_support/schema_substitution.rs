// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real signatures under identical keys cannot cross custody/migration transcripts.
use super::*;
use serde::Serialize;
fn reject_both_directions<T: Serialize>(
    envelope: &Envelope<T>,
    tag: &str,
    signer: &SigningKey,
) -> TestResult {
    let original = ramflux_protocol::custody::signing_bytes(tag, &envelope.body)?;
    let signature = ed25519_dalek::Signature::from_slice(&ramflux_protocol::decode_base64url(
        &envelope.signature,
    )?)?;
    signer.verifying_key().verify_strict(&original, &signature)?;
    let (_, _, authority) = authority()?;
    let raw = super::super::offer_vector(&authority)?;
    let offer: Offer = serde_json::from_value(raw["signed"]["body"].clone())?;
    let mut migration = sign_node(offer, "A", signer)?;
    verify_signatures(&migration)?;
    let migration_signature = ed25519_dalek::Signature::from_slice(
        &ramflux_protocol::decode_base64url(&migration.signatures[0])?,
    )?;
    assert!(signer.verifying_key().verify_strict(&original, &migration_signature).is_err());
    migration.signatures[0].clone_from(&envelope.signature);
    assert!(verify_signatures(&migration).is_err());
    Ok(())
}
#[test]
fn genuine_master_branch_and_node_signatures_cannot_substitute_in_either_direction() -> TestResult {
    let (_, _, authority) = authority()?;
    let mut seed = zeroize::Zeroizing::new([0_u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&[0_u8; 32]), &[0_u8; 32])
        .expand(domain::CUSTODY_MASTER_SEED.as_bytes(), &mut *seed)
        .map_err(|_| "HKDF fixture length")?;
    reject_both_directions(
        &authority.envelope().body.master_certificate,
        domain::CUSTODY_MASTER_CERTIFICATE,
        &SigningKey::from_bytes(&seed),
    )?;
    reject_both_directions(
        authority.envelope().body.devices[0].branch_certificate.as_ref().ok_or("branch")?,
        domain::CUSTODY_BRANCH_CERTIFICATE,
        &key(2),
    )?;
    reject_both_directions(&node("A", 8)?, domain::CUSTODY_NODE_RECORD, &key(8))?;
    Ok(())
}
