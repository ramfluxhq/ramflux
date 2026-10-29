// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit offline-master replacement preserves identity and all retained denials.
use super::{MasterKey, SelfSigningKey, VerifiedRecord, validate::reject};
use crate::{CryptoError, DeviceBranch, X25519KeyPair};
use ramflux_protocol::{
    DeviceSetStatus, PrincipalKind,
    custody::{
        BranchCertificate, Device, DeviceRef, DeviceSet, Envelope, MAX_BRANCH_LEASE_SECONDS,
        MigrationState, decode_epoch, encode_epoch, object_hash,
    },
};

/// Public replacement intent; key material is supplied as separate capabilities.
pub struct RecoveryInput {
    pub highest_observed_range: u64,
    pub issued_at: u64,
    pub master_cert_id: String,
    pub branch_cert_id: String,
}

/// Replace the primary in a higher master-authorized range and revoke every old branch.
/// Existing delegation restrictions, compacted denials and immutable identity remain intact.
/// # Errors
/// Refuses wrong phrases/identity, time rollback, reused device IDs and exhausted bounds.
pub fn recover_primary(
    master: &MasterKey,
    primary: &SelfSigningKey,
    branch: &DeviceBranch,
    agreement: &X25519KeyPair,
    current: &VerifiedRecord,
    input: RecoveryInput,
) -> Result<Envelope<DeviceSet>, CryptoError> {
    let previous = current.envelope();
    if previous.body.principal_kind != PrincipalKind::Human
        || master.public_key() != previous.body.master_certificate.body.master_public_key
        || branch.principal_id != previous.body.principal_id
        || branch.device_epoch != 1
        || previous.body.devices.iter().any(|d| d.device_id == branch.device_id)
        || current.revoked_ids().contains(&branch.device_id)
        || input.issued_at < previous.body.issued_at
    {
        return Err(reject("recovery identity, device or trusted time mismatch"));
    }
    let range = input
        .highest_observed_range
        .max(decode_epoch(previous.body.device_set_epoch)?.0)
        .checked_add(1)
        .ok_or_else(|| reject("recovery range exhausted"))?;
    let mut certificate = previous.body.master_certificate.body.clone();
    certificate.range_index = range;
    certificate.self_signing_public_key = primary.public_key();
    certificate.primary_device_ref = DeviceRef {
        account_anchor: previous.body.account_anchor.clone(),
        device_id: branch.device_id.clone(),
        device_epoch: 1,
    };
    certificate.previous_certificate_hash = Some(object_hash(&previous.body.master_certificate)?);
    certificate.issued_at = input.issued_at;
    certificate.cert_id = input.master_cert_id;
    let certificate = master.certify(certificate)?;
    let signing = ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let agreement_public = ramflux_protocol::encode_base64url(agreement.public);
    let (signing_key_commitment, agreement_key_commitment) =
        crate::device_key_commitments(&signing, &agreement_public)?;
    let branch_certificate = primary.certify_branch(BranchCertificate {
        schema: ramflux_protocol::domain::CUSTODY_BRANCH_CERTIFICATE.into(),
        version: 1,
        account_anchor: previous.body.account_anchor.clone(),
        master_certificate_hash: object_hash(&certificate)?,
        device_id: branch.device_id.clone(),
        device_epoch: 1,
        principal_kind: previous.body.principal_kind,
        branch_signing_public_key: signing,
        agreement_identity_public_key: agreement_public,
        capabilities: ["call", "group", "message", "register", "sync"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        not_before: input.issued_at,
        expires_at: input
            .issued_at
            .checked_add(MAX_BRANCH_LEASE_SECONDS)
            .ok_or_else(|| reject("recovery lease overflow"))?,
        cert_id: input.branch_cert_id,
    })?;
    let mut body = previous.body.clone();
    for device in &mut body.devices {
        if device.status == DeviceSetStatus::Active {
            device.status = DeviceSetStatus::Revoked;
            device.migration_state = MigrationState::Revoked;
            device.revoked_at = Some(input.issued_at);
            device.branch_certificate = None;
        }
    }
    body.devices.push(Device {
        device_id: branch.device_id.clone(),
        device_epoch: 1,
        signing_key_commitment,
        agreement_key_commitment,
        status: DeviceSetStatus::Active,
        revoked_at: None,
        branch_certificate: Some(branch_certificate),
        migration_state: MigrationState::Native,
    });
    body.devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    body.device_set_epoch = encode_epoch(range, 1)?;
    body.previous_record_hash = Some(object_hash(previous)?);
    body.issued_at = input.issued_at;
    body.master_certificate = certificate;
    if let Some(previous_checkpoint) = &previous.body.revoked_device_checkpoint {
        let mut checkpoint = previous_checkpoint.body.clone();
        checkpoint.master_certificate_hash = object_hash(&body.master_certificate)?;
        checkpoint.device_set_epoch = body.device_set_epoch;
        checkpoint.previous_checkpoint_hash = Some(object_hash(previous_checkpoint)?);
        checkpoint.issued_at = input.issued_at;
        let signature = crate::sign_canonical_bytes_with_seed(
            &ramflux_protocol::custody::signing_bytes(
                ramflux_protocol::domain::CUSTODY_REVOKED_CHECKPOINT,
                &checkpoint,
            )?,
            *primary.vault_seed(),
        );
        body.revoked_device_checkpoint = Some(Envelope { body: checkpoint, signature });
    }
    primary.sign_record(body)
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
