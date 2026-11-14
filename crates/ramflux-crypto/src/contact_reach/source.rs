// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticate the existing appended source-device authority without adopting any peer trust.
use super::{
    CryptoError, VerifiedRecord, custody, durable_capability, reject, verify_submission, wire,
};
use serde::{Deserialize, Serialize};

/// Existing `DeviceAuthKeyResponse` JSON inside `Envelope.ext.source_device_authority`.
/// This is a reader for that existing carrier; it adds no wire field or signing domain.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExistingAuthority {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody_authority: Option<Box<custody::CustodyAuthority>>,
    #[serde(default)]
    root_public_key: Option<String>,
    #[serde(default)]
    signed_device_set: Option<serde_json::Value>,
    principal_id: String,
    device_id: String,
    device_epoch: u64,
    branch_public_key: String,
    target_delivery_id: String,
    revoked: bool,
}

/// Verify the immutable original envelope, route and signing-time source evidence.
/// This never proves current authorization or permits delivery, trust adoption or ratchet changes.
/// # Errors
/// Refuses mixed/legacy proof, malformed or substituted original bytes and expired retention.
pub fn verify_original_source_submission(
    submission: &wire::Submission,
    now: u64,
) -> Result<(), CryptoError> {
    original(submission, now).map(|_| ())
}

fn original(submission: &wire::Submission, now: u64) -> Result<VerifiedRecord, CryptoError> {
    let envelope = &submission.envelope;
    let route = &submission.route.body;
    let value = envelope
        .ext
        .ext
        .get("source_device_authority")
        .ok_or_else(|| reject("original native source authority is missing"))?;
    let proof: ExistingAuthority =
        custody::decode(&ramflux_protocol::canonical_json_bytes(value)?, wire::MAX_FRAME_BYTES)?;
    if proof.revoked || proof.root_public_key.is_some() || proof.signed_device_set.is_some() {
        return Err(reject("mixed or revoked native source authority"));
    }
    let publication =
        proof.custody_authority.ok_or_else(|| reject("native source publication required"))?;
    let historical = crate::custody::verify_publication(&publication, route.issued_at)?;
    let capability = durable_capability(route.traffic);
    let historical_branch = historical.authorize(&route.source, capability, route.issued_at)?;
    if proof.device_id != route.source.device_id
        || proof.device_epoch != route.source.device_epoch
        || proof.principal_id != historical.envelope().body.principal_id
        || proof.branch_public_key != historical_branch.branch_signing_public_key
        || proof.target_delivery_id
            != ramflux_protocol::qualified_device_id(
                &route.source.account_anchor,
                &route.source.device_id,
            )?
        || envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
            != Some(route.source.account_anchor.as_str())
    {
        return Err(reject("original native source binding mismatch"));
    }
    verify_submission(submission, &historical, now)?;
    Ok(historical)
}

/// Verify original sender evidence against independently verified current authority.
/// Current authority must still authorize the exact same signing and agreement keys. The caller
/// separately authenticates the sender's current home; this function performs no trust writes.
/// # Errors
/// Refuses invalid originals, changed roots/devices/keys, current revocation or expired retention.
pub fn verify_current_source_submission(
    submission: &wire::Submission,
    current: &VerifiedRecord,
    now: u64,
) -> Result<(), CryptoError> {
    let historical = original(submission, now)?;
    let route = &submission.route.body;
    let capability = durable_capability(route.traffic);
    let historical_branch = historical.authorize(&route.source, capability, route.issued_at)?;
    let current_branch = current.authorize(&route.source, capability, now)?;
    if historical.envelope().body.account_anchor != current.envelope().body.account_anchor
        || historical.envelope().body.principal_id != current.envelope().body.principal_id
        || historical_branch.branch_signing_public_key != current_branch.branch_signing_public_key
        || historical_branch.agreement_identity_public_key
            != current_branch.agreement_identity_public_key
    {
        return Err(reject("original/current native source binding mismatch"));
    }
    Ok(())
}
