// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Master-authorized cooperative management transfer. Existing branches are retained exactly.

use super::{MasterKey, SelfSigningKey, VerifiedRecord, validate::reject};
use crate::CryptoError;
use ramflux_protocol::{
    DeviceSetStatus, PrincipalKind,
    custody::{
        BranchCertificate, Device, DeviceRef, DeviceSet, Envelope, MAX_ENROLLMENT_ROSTER,
        MigrationState, decode_epoch, encode_epoch, object_hash,
    },
};

/// Public transfer intent. A fresh destination supplies only a public branch certificate body.
pub struct CooperativeTransferInput {
    pub destination: DeviceRef,
    pub fresh_destination: Option<BranchCertificate>,
    pub highest_observed_range: u64,
    pub issued_at: u64,
    pub master_cert_id: String,
}

/// Certify a fresh management key in a higher range while preserving every branch and denial.
///
/// # Errors
/// Refuses wrong identity, time rollback, expired branches, same-device transfer, reused or
/// revoked destinations and unsupported delegation profiles. No recovery transform is called.
pub fn cooperative_transfer_preserving_devices(
    master: &MasterKey,
    primary: &SelfSigningKey,
    current: &VerifiedRecord,
    input: CooperativeTransferInput,
) -> Result<Envelope<DeviceSet>, CryptoError> {
    let prior = current.envelope();
    let old = &prior.body.master_certificate.body;
    if prior.body.principal_kind != PrincipalKind::Human
        || master.public_key() != old.master_public_key
        || primary.public_key() == old.self_signing_public_key
        || input.destination.account_anchor != prior.body.account_anchor
        || input.destination == old.primary_device_ref
        || input.issued_at < prior.body.issued_at
        || current.revoked_ids().contains(&input.destination.device_id)
    {
        return Err(reject("cooperative transfer identity, destination or time mismatch"));
    }
    let range = input
        .highest_observed_range
        .max(decode_epoch(prior.body.device_set_epoch)?.0)
        .checked_add(1)
        .ok_or_else(|| reject("cooperative transfer range exhausted"))?;
    let mut master_body = old.clone();
    master_body.range_index = range;
    master_body.self_signing_public_key = primary.public_key();
    master_body.primary_device_ref = input.destination.clone();
    master_body.previous_certificate_hash = Some(object_hash(&prior.body.master_certificate)?);
    master_body.issued_at = input.issued_at;
    master_body.cert_id = input.master_cert_id;
    let master_certificate = master.certify(master_body)?;
    let master_hash = object_hash(&master_certificate)?;
    let mut body = prior.body.clone();
    let existing =
        body.devices.iter().find(|device| device.device_id == input.destination.device_id);
    match (&input.fresh_destination, existing) {
        (None, Some(device))
            if device.status == DeviceSetStatus::Active
                && device.device_epoch == input.destination.device_epoch => {}
        (Some(branch), None)
            if branch.device_id == input.destination.device_id
                && branch.device_epoch == input.destination.device_epoch
                && branch.account_anchor == body.account_anchor
                && branch.principal_kind == body.principal_kind
                && body.devices.len() < MAX_ENROLLMENT_ROSTER =>
        {
            let (signing_key_commitment, agreement_key_commitment) = crate::device_key_commitments(
                &branch.branch_signing_public_key,
                &branch.agreement_identity_public_key,
            )?;
            let mut branch = branch.clone();
            branch.master_certificate_hash.clone_from(&master_hash);
            let certificate = primary.certify_branch(branch)?;
            body.devices.push(Device {
                device_id: input.destination.device_id.clone(),
                device_epoch: input.destination.device_epoch,
                signing_key_commitment,
                agreement_key_commitment,
                status: DeviceSetStatus::Active,
                revoked_at: None,
                branch_certificate: Some(certificate),
                message_layer: None,
                migration_state: MigrationState::Native,
            });
        }
        _ => return Err(reject("cooperative transfer destination is not an active owned branch")),
    }
    for device in &mut body.devices {
        if device.status != DeviceSetStatus::Active {
            continue;
        }
        let certificate = device
            .branch_certificate
            .as_ref()
            .ok_or_else(|| reject("cooperative transfer missing branch certificate"))?;
        let mut branch = certificate.body.clone();
        if input.issued_at < branch.not_before || input.issued_at >= branch.expires_at {
            return Err(reject("cooperative transfer requires current branch leases"));
        }
        branch.master_certificate_hash.clone_from(&master_hash);
        branch.cert_id = ramflux_protocol::encode_base64url(*super::random_secret()?);
        device.branch_certificate = Some(primary.certify_branch(branch)?);
    }
    body.devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    body.device_set_epoch = encode_epoch(range, 1)?;
    body.previous_record_hash = Some(object_hash(prior)?);
    body.issued_at = input.issued_at;
    body.master_certificate = master_certificate;
    if let Some(previous) = &prior.body.revoked_device_checkpoint {
        let mut checkpoint = previous.body.clone();
        checkpoint.master_certificate_hash = master_hash;
        checkpoint.device_set_epoch = body.device_set_epoch;
        checkpoint.previous_checkpoint_hash = Some(object_hash(previous)?);
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
mod tests;
