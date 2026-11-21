// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent master custody: the vault item layout, genesis and primary-rebind master certificates,
//! and the primary-branch signature over an agent registration decision.
//!
//! Vault implementations call these functions after their own presence and item checks. The
//! functions take no clock: every time is an explicit input.
use super::{MasterKey, validate};
use crate::{CryptoError, DeviceBranch, identity_root_commitment};
use ramflux_protocol::{
    PrincipalKind,
    custody::{
        AgentDecisionRequest, CustodyKind, DeviceRef, Envelope, MASTER_SCOPES, MAX_RANGE,
        MasterCertificate, REGISTER_AUTHORIZATION_SCHEMA, RegisterDecision, RegisterDecisionBody,
        decision_signing_bytes, object_hash, register_decision_body,
        validate_register_decision_body,
    },
    domain,
};

/// Genesis (`Create`) or the next-range certificate after a primary transfer (`Rebind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentMasterPurpose {
    Create,
    Rebind,
}

/// Public inputs of one master certificate. The master never signs anything else.
pub struct AgentMasterRequest {
    pub purpose: AgentMasterPurpose,
    pub anchor: String,
    pub principal_id: String,
    pub principal_kind: PrincipalKind,
    pub cert_id: String,
    pub self_signing_public_key: String,
    /// The custodian primary device; for an agent this is the human primary.
    pub external_ref: DeviceRef,
    /// Create: the genesis range (1). Rebind: the range after the previous certificate.
    pub range: u64,
    /// Rebind only: the previous master certificate. Create only: `None`.
    pub previous: Option<Envelope<MasterCertificate>>,
    pub issued_at: u64,
}

/// The decoded vault item: the master and the hash of the last certificate issued for it.
/// The vault codec that reads and writes this item lives in the SDK vault layer.
pub struct AgentMasterItem {
    pub master: MasterKey,
    pub last_certificate_hash: Option<String>,
}

/// Account anchor of an agent master: the root commitment of its public key.
/// # Errors
/// Refuses a master whose public key is not canonical.
pub fn master_anchor(master: &MasterKey) -> Result<String, CryptoError> {
    Ok(identity_root_commitment(&validate::key(&master.public_key())?))
}

/// Issue the master certificate for `request` from the stored item.
/// Returns the certificate and its hash; the caller persists the hash before returning the
/// certificate to anyone.
/// # Errors
/// Refuses a wrong anchor, a create with an existing history, a rebind whose previous
/// certificate is not the stored one (hash, signature, anchor, principal or range), and any
/// certificate the master-body validator rejects.
pub fn certify_agent_master(
    item: &AgentMasterItem,
    request: AgentMasterRequest,
) -> Result<(Envelope<MasterCertificate>, String), CryptoError> {
    let master_public = item.master.public_key();
    let master_key = validate::key(&master_public)?;
    let anchor = master_anchor(&item.master)?;
    if request.anchor != anchor {
        return Err(validate::reject("agent master anchor mismatch"));
    }
    let previous_hash = match (request.purpose, &request.previous, &item.last_certificate_hash) {
        (AgentMasterPurpose::Create, None, None) if request.range == 1 => None,
        (AgentMasterPurpose::Create, _, _) => {
            return Err(validate::reject("agent master genesis already issued"));
        }
        (AgentMasterPurpose::Rebind, Some(previous), Some(stored)) => {
            let hash = object_hash(previous)?;
            if &hash != stored {
                return Err(validate::reject("agent master previous certificate is not current"));
            }
            validate::signature(&master_key, domain::CUSTODY_MASTER_CERTIFICATE, previous)?;
            let prior = &previous.body;
            if prior.master_public_key != master_public
                || prior.account_anchor != request.anchor
                || prior.principal_id != request.principal_id
            {
                return Err(validate::reject("agent master previous certificate identity"));
            }
            let expected = prior
                .range_index
                .checked_add(1)
                .filter(|next| *next <= MAX_RANGE)
                .ok_or_else(|| validate::reject("agent master range exhausted"))?;
            if request.range != expected {
                return Err(validate::reject("agent master rebind range is not the next range"));
            }
            Some(hash)
        }
        (AgentMasterPurpose::Rebind, _, _) => {
            return Err(validate::reject("agent master rebind needs the current certificate"));
        }
    };
    let body = MasterCertificate {
        schema: domain::CUSTODY_MASTER_CERTIFICATE.into(),
        version: 1,
        account_anchor: request.anchor,
        principal_id: request.principal_id,
        principal_kind: request.principal_kind,
        master_public_key: master_public,
        self_signing_public_key: request.self_signing_public_key,
        primary_device_ref: request.external_ref,
        custody_kind: CustodyKind::ExternalHuman,
        scopes: MASTER_SCOPES.into_iter().map(str::to_owned).collect(),
        range_index: request.range,
        issued_at: request.issued_at,
        cert_id: request.cert_id,
        legacy_binding_hash: None,
        previous_certificate_hash: previous_hash,
    };
    let envelope = item.master.certify(body)?;
    let hash = object_hash(&envelope)?;
    Ok((envelope, hash))
}

/// Sign the exact decision body with the primary branch key. The caller has already checked
/// user presence and that the branch belongs to the plan's human primary.
/// # Errors
/// Refuses an invalid body and canonical serialization failures.
pub fn sign_register_decision(
    primary_branch: &DeviceBranch,
    body: RegisterDecisionBody,
) -> Result<RegisterDecision, CryptoError> {
    let bytes = decision_signing_bytes(&body)?;
    let signature = crate::sign_canonical_bytes_with_device_branch(&bytes, primary_branch);
    Ok(Envelope { body, signature })
}

/// Build the body for `request` (binding it to the exact plan) and sign it with the primary
/// branch key.
/// # Errors
/// Refuses everything [`register_decision_body`] refuses, plus signing failures.
pub fn sign_register_decision_request(
    primary_branch: &DeviceBranch,
    request: &AgentDecisionRequest,
) -> Result<RegisterDecision, CryptoError> {
    let body = register_decision_body(request)?;
    sign_register_decision(primary_branch, body)
}

/// Verify a decision signature against the primary branch signing public key.
/// # Errors
/// Refuses an invalid body, a non-canonical key and any signature mismatch.
pub fn verify_register_decision(
    primary_branch_signing_public_key: &str,
    decision: &RegisterDecision,
) -> Result<(), CryptoError> {
    validate_register_decision_body(&decision.body)?;
    let key = validate::key(primary_branch_signing_public_key)?;
    validate::signature(&key, REGISTER_AUTHORIZATION_SCHEMA, decision)
}
