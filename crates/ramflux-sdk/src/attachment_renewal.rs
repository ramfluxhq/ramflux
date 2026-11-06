// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant recipient-home renewal preparation. Transport retries reuse the returned bytes.
use crate::{
    SdkError,
    custody::{BornAccount, PrimaryVault},
};
use ed25519_dalek::Signer;
use ramflux_protocol::large_attachment::{
    FormatError, ForwardAttestation, QualifiedOwner, RenewalRequest, RequesterPop,
    VerifiedScopedGrant, requester_digest,
};

/// Pinned recipient-home and source/relay trust; never take these fields from a request.
pub struct RenewalTrust<'a> {
    pub home: &'a str,
    pub home_key: &'a [u8; 32],
    pub source: &'a str,
    pub relay: &'a str,
    pub authority_generation: u64,
}
/// Requester proof plus its exact native signature. A source still must admit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRenewalPop {
    pub proof: RequesterPop,
    pub signature: [u8; 64],
}
/// Validates the home proof before using the account's current branch credential.
/// # Errors
/// Refuses fenced account/credentials, wrong home, changed request or invalid signature.
pub fn sign_home_renewal(
    account: &BornAccount,
    vault: &dyn PrimaryVault,
    input: &RenewalSigningRequest<'_>,
) -> Result<SignedRenewalPop, SdkError> {
    account.require_networking()?;
    let (device, credentials) =
        account.credentials(vault, &input.attestation.requester.device_id, input.now)?;
    let requester = QualifiedOwner {
        account_anchor: device.account_anchor,
        device_id: device.device_id,
        device_epoch: device.device_epoch,
        signing_public_key: credentials.signing.signing_key.verifying_key().to_bytes(),
        home_node_id: input.trust.home.into(),
    };
    sign_with_branch(&credentials.signing.signing_key, &requester, input).map_err(|error| {
        SdkError::LocalBusRefused {
            code: "AttachmentRenewalRefused".into(),
            message: error.to_string(),
            body: Box::new(serde_json::json!({"reason":error.0})),
        }
    })
}
/// One exact renewal attempt, including externally generated fresh challenge and nonce.
pub struct RenewalSigningRequest<'a> {
    pub request: &'a RenewalRequest,
    pub grant: &'a VerifiedScopedGrant,
    pub trust: &'a RenewalTrust<'a>,
    pub attestation: &'a ForwardAttestation,
    pub home_signature: &'a [u8; 64],
    pub challenge: &'a [u8; 32],
    pub nonce: [u8; 32],
    pub now: u64,
}
fn sign_with_branch(
    key: &ed25519_dalek::SigningKey,
    requester: &QualifiedOwner,
    input: &RenewalSigningRequest<'_>,
) -> Result<SignedRenewalPop, FormatError> {
    let RenewalSigningRequest {
        request,
        grant,
        trust,
        attestation: w,
        home_signature: signature,
        challenge,
        nonce,
        now,
    } = input;
    request.validate(grant, requester, trust.source, trust.relay, *now)?;
    if request.target()?.0.authority_generation != trust.authority_generation { return Err(FormatError("renewal source generation")); }
    w.validate(request, grant, requester, challenge, *now)?;
    if w.home_issuer != trust.home {
        return Err(FormatError("renewal home"));
    }
    w.verify(trust.home_key, signature)?;
    let proof = RequesterPop {
        operation_hash: w.operation_hash,
        requester_digest: requester_digest(requester)?,
        nonce: *nonce,
        issued_at: *now,
        expires_at: w.expires_at,
        forward_digest: w.hash()?,
    };
    proof.validate(w, *now)?;
    let signature = key.sign(&proof.signing_bytes()?).to_bytes();
    Ok(SignedRenewalPop { proof, signature })
}
#[cfg(test)]
#[path = "attachment_renewal_tests.rs"]
mod tests;
