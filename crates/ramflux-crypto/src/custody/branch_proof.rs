// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Branch possession bound to a verifier challenge and the client-facing TLS connection.

use super::{
    VerifiedNodeRecord, VerifiedRecord,
    validate::{bytes, id, reference, reject, signature, time},
};
use crate::{CryptoError, DeviceBranch};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::{
    custody::{
        AcceptanceIssuer, AcceptancePurpose, BindingMode, BranchChallenge, BranchProofV3,
        CLOCK_SKEW_SECONDS, Envelope, RelayAcceptance, object_hash, signing_bytes,
    },
    domain, encode_base64url,
};
use sha2::{Digest, Sha256};

pub const MAX_BRANCH_PROOF_BYTES: usize = 8192;

/// Evidence independently obtained by the receiving verifier, never a forwarded header.
#[derive(Clone, Copy)]
pub enum ProofChannel<'a> {
    DirectExporter {
        observed_hash: &'a str,
        receiving_node: &'a VerifiedNodeRecord,
    },
    HomeRelayReceipt {
        receipt: &'a Envelope<RelayAcceptance>,
        historical_node: &'a VerifiedNodeRecord,
        current_node: &'a VerifiedNodeRecord,
    },
    NoChannelBinding {
        operator_opt_in: bool,
        receiving_node: &'a VerifiedNodeRecord,
    },
}

/// Hash exactly the 32 bytes returned by the client-facing TLS 1.3 exporter.
#[must_use]
pub fn branch_exporter_hash(exporter: &[u8; 32]) -> String {
    encode_base64url(Sha256::digest(exporter))
}

fn lifetime(issued: u64, expires: u64, now: u64) -> Result<(), CryptoError> {
    time(issued)?;
    time(expires)?;
    time(now)?;
    if issued >= expires
        || expires - issued > 300
        || issued > now.saturating_add(CLOCK_SKEW_SECONDS)
        || now > expires.saturating_add(CLOCK_SKEW_SECONDS)
    {
        return Err(reject("branch proof or challenge expired"));
    }
    Ok(())
}
fn structure(body: &BranchProofV3) -> Result<(), CryptoError> {
    if body.schema != domain::BRANCH_PROOF_V3 || body.version != 3 {
        return Err(reject("unsupported branch proof"));
    }
    reference(&body.device_ref)?;
    id(&body.audience)?;
    for value in [
        &body.certificate_hash,
        &body.record_hash,
        &body.proof_id,
        &body.challenge_nonce,
        &body.transport_binding,
    ] {
        bytes(value, 32)?;
    }
    lifetime(body.issued_at, body.expires_at, body.issued_at)
}

/// Sign the v3 proof with a branch key, never the offline master or a v1 proof helper.
/// # Errors
/// Rejects malformed proof bodies, another device/epoch and excessive encoded size.
pub fn sign_branch_proof_v3(
    branch: &DeviceBranch,
    body: BranchProofV3,
) -> Result<Envelope<BranchProofV3>, CryptoError> {
    structure(&body)?;
    if branch.device_id != body.device_ref.device_id
        || branch.device_epoch != body.device_ref.device_epoch
    {
        return Err(reject("branch proof signer device mismatch"));
    }
    let signature = encode_base64url(
        branch.signing_key.sign(&signing_bytes(domain::BRANCH_PROOF_V3, &body)?).to_bytes(),
    );
    let envelope = Envelope { body, signature };
    if ramflux_protocol::canonical_json_bytes(&envelope)?.len() > MAX_BRANCH_PROOF_BYTES {
        return Err(reject("branch proof byte limit"));
    }
    Ok(envelope)
}

fn allows(node: &VerifiedNodeRecord, mode: BindingMode) -> Result<(), CryptoError> {
    if !node.envelope().body.channel_binding_modes.contains(&mode) {
        return Err(reject("branch binding mode not advertised by receiving node"));
    }
    Ok(())
}

/// Verify possession and channel evidence against a fully verified current authority.
/// The caller must require durable authority pins and atomically consume the issued
/// challenge and proof id after this succeeds. No receipt is a substitute for that.
/// # Errors
/// Rejects stale authority, wrong signer/head/lease/capability, challenge and hop substitution.
pub fn verify_branch_proof_v3(
    authority: &VerifiedRecord,
    proof: &Envelope<BranchProofV3>,
    challenge: &BranchChallenge,
    capability: &str,
    channel: ProofChannel<'_>,
    now: u64,
) -> Result<(), CryptoError> {
    if ramflux_protocol::canonical_json_bytes(proof)?.len() > MAX_BRANCH_PROOF_BYTES {
        return Err(reject("branch proof byte limit"));
    }
    let body = &proof.body;
    structure(body)?;
    lifetime(body.issued_at, body.expires_at, now)?;
    lifetime(challenge.issued_at, challenge.expires_at, now)?;
    bytes(&challenge.challenge_nonce, 32)?;
    id(&challenge.audience)?;
    if body.challenge_nonce != challenge.challenge_nonce
        || body.audience != challenge.audience
        || body.binding_mode != challenge.binding_mode
        || body.expires_at > challenge.expires_at
        || body.issued_at.saturating_add(CLOCK_SKEW_SECONDS) < challenge.issued_at
        || body.record_hash != object_hash(authority.envelope())?
    {
        return Err(reject("branch proof challenge or current head mismatch"));
    }
    let certificate = authority.authorize(&body.device_ref, capability, now)?;
    let signed_certificate = authority
        .envelope()
        .body
        .devices
        .iter()
        .find(|d| d.device_id == body.device_ref.device_id)
        .and_then(|d| d.branch_certificate.as_ref())
        .ok_or_else(|| reject("branch certificate unavailable"))?;
    if body.certificate_hash != object_hash(signed_certificate)? {
        return Err(reject("branch certificate hash mismatch"));
    }
    signature(
        &super::validate::key(&certificate.branch_signing_public_key)?,
        domain::BRANCH_PROOF_V3,
        proof,
    )?;
    match channel {
        ProofChannel::DirectExporter { observed_hash, receiving_node } => {
            allows(receiving_node, BindingMode::DirectExporter)?;
            bytes(observed_hash, 32)?;
            if body.binding_mode != BindingMode::DirectExporter
                || body.transport_binding != observed_hash
            {
                return Err(reject("direct TLS exporter mismatch"));
            }
        }
        ProofChannel::HomeRelayReceipt { receipt, historical_node, current_node } => {
            allows(current_node, BindingMode::HomeRelayReceipt)?;
            if body.binding_mode != BindingMode::HomeRelayReceipt {
                return Err(reject("proxy receipt cannot change binding mode"));
            }
            verify_proxy_acceptance(proof, receipt, historical_node, current_node, now)?;
        }
        ProofChannel::NoChannelBinding { operator_opt_in, receiving_node } => {
            allows(receiving_node, BindingMode::NoChannelBinding)?;
            if !operator_opt_in || body.binding_mode != BindingMode::NoChannelBinding {
                return Err(reject("explicit no-channel-binding opt-in required"));
            }
        }
    }
    Ok(())
}

fn verify_proxy_acceptance(
    proof: &Envelope<BranchProofV3>,
    receipt: &Envelope<RelayAcceptance>,
    historical: &VerifiedNodeRecord,
    current: &VerifiedNodeRecord,
    now: u64,
) -> Result<(), CryptoError> {
    if ramflux_protocol::canonical_json_bytes(receipt)?.len() > 8192 {
        return Err(reject("proxy receipt byte limit"));
    }
    allows(historical, BindingMode::HomeRelayReceipt)?;
    let body = &receipt.body;
    let p = &proof.body;
    let history = &historical.envelope().body;
    let live = &current.envelope().body;
    if history.node_id != live.node_id
        || history.node_signing_public_key != live.node_signing_public_key
        || body.schema != domain::CUSTODY_RELAY_ACCEPTANCE
        || body.version != 1
        || body.issuer_kind != AcceptanceIssuer::NodeProxy
        || body.purpose != AcceptancePurpose::BranchProof
        || body.node_identity_record_hash != historical.hash()
        || body.client_exporter_hash.as_deref() != Some(p.transport_binding.as_str())
        || body.message_hash != object_hash(proof)?
        || body.audience != p.audience
        || body.source_device_ref.as_ref() != Some(&p.device_ref)
        || body.branch_certificate_hash.as_deref() != Some(p.certificate_hash.as_str())
        || body.target_anchor.is_some()
        || body.challenge_nonce.as_deref() != Some(p.challenge_nonce.as_str())
        || live.revoked_proxy_key_ids.contains(&body.relay_key_id)
    {
        return Err(reject("proxy acceptance purpose, source or current revocation mismatch"));
    }
    bytes(&body.receipt_id, 32)?;
    bytes(&body.relay_key_id, 32)?;
    time(body.accepted_at)?;
    if body.accepted_at > now.saturating_add(CLOCK_SKEW_SECONDS)
        || body.accepted_at.saturating_add(CLOCK_SKEW_SECONDS) < p.issued_at
        || body.accepted_at > p.expires_at.saturating_add(CLOCK_SKEW_SECONDS)
    {
        return Err(reject("proxy receipt outside proof lifetime"));
    }
    let descriptor = history
        .proxy_keys
        .iter()
        .find(|k| k.key_id == body.relay_key_id)
        .ok_or_else(|| reject("node-authorized proxy key unavailable"))?;
    if descriptor.proxy_id != body.relay_id
        || !descriptor.audiences.contains(&body.audience)
        || body.accepted_at < descriptor.not_before
        || body.accepted_at > descriptor.sign_until
        || history.revoked_proxy_key_ids.contains(&descriptor.key_id)
    {
        return Err(reject("proxy audience or issuance interval mismatch"));
    }
    signature(
        &super::validate::key(&descriptor.public_key)?,
        domain::CUSTODY_RELAY_ACCEPTANCE,
        receipt,
    )
}

/// Dedicated software proxy signer. Its seed is not a node identity, relay or account key.
/// The gateway must obtain `observed_hash` from its actual client-facing TLS connection.
/// # Errors
/// Rejects another TLS observation, unauthorized key/role/audience and expired signing leases.
pub fn sign_proxy_acceptance(
    signer: &SigningKey,
    node: &VerifiedNodeRecord,
    proof: &Envelope<BranchProofV3>,
    observed_hash: &str,
    receipt_id: String,
    now: u64,
) -> Result<Envelope<RelayAcceptance>, CryptoError> {
    let p = &proof.body;
    structure(p)?;
    lifetime(p.issued_at, p.expires_at, now)?;
    bytes(observed_hash, 32)?;
    bytes(&receipt_id, 32)?;
    time(now)?;
    if p.binding_mode != BindingMode::HomeRelayReceipt || p.transport_binding != observed_hash {
        return Err(reject("proxy must independently observe the client exporter"));
    }
    allows(node, BindingMode::HomeRelayReceipt)?;
    let public = encode_base64url(signer.verifying_key().to_bytes());
    let descriptor = node
        .envelope()
        .body
        .proxy_keys
        .iter()
        .find(|k| k.public_key == public)
        .ok_or_else(|| reject("proxy signing key not authorized by receiving node"))?;
    if node.envelope().body.revoked_proxy_key_ids.contains(&descriptor.key_id)
        || now < descriptor.not_before
        || now > descriptor.sign_until
        || !descriptor.audiences.contains(&p.audience)
    {
        return Err(reject("proxy signing role is unavailable"));
    }
    let body = RelayAcceptance {
        schema: domain::CUSTODY_RELAY_ACCEPTANCE.into(),
        version: 1,
        issuer_kind: AcceptanceIssuer::NodeProxy,
        relay_id: descriptor.proxy_id.clone(),
        relay_key_id: descriptor.key_id.clone(),
        node_identity_record_hash: node.hash().into(),
        client_exporter_hash: Some(observed_hash.into()),
        receipt_id,
        message_hash: object_hash(proof)?,
        purpose: AcceptancePurpose::BranchProof,
        audience: p.audience.clone(),
        source_device_ref: Some(p.device_ref.clone()),
        branch_certificate_hash: Some(p.certificate_hash.clone()),
        target_anchor: None,
        challenge_nonce: Some(p.challenge_nonce.clone()),
        accepted_at: now,
    };
    let signature = encode_base64url(
        signer.sign(&signing_bytes(domain::CUSTODY_RELAY_ACCEPTANCE, &body)?).to_bytes(),
    );
    Ok(Envelope { body, signature })
}
