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

/// Independently check the complete roster and denial policy before the old primary approves.
/// Both records must already have passed signature and custody verification.
/// # Errors
/// Rejects any unrelated authority change, removed branch, altered lease, or lost denial.
pub fn verify_cooperative_preservation(
    previous: &VerifiedRecord,
    candidate: &VerifiedRecord,
    destination: &DeviceRef,
    fresh_destination: bool,
) -> Result<(), CryptoError> {
    let before = &previous.envelope().body;
    let after = &candidate.envelope().body;
    let old_master = &before.master_certificate.body;
    let new_master = &after.master_certificate.body;
    if new_master.primary_device_ref != *destination
        || old_master.primary_device_ref == *destination
        || new_master.self_signing_public_key == old_master.self_signing_public_key
        || new_master.range_index <= old_master.range_index
        || new_master.previous_certificate_hash.as_deref()
            != Some(object_hash(&before.master_certificate)?.as_str())
        || after.previous_record_hash.as_deref() != Some(object_hash(previous.envelope())?.as_str())
        || after.issued_at < before.issued_at
        || previous.revoked_ids() != candidate.revoked_ids()
        || after.devices.len() != before.devices.len() + usize::from(fresh_destination)
    {
        return Err(reject("cooperative transfer preservation mismatch"));
    }
    let mut master = new_master.clone();
    master.range_index = old_master.range_index;
    master.self_signing_public_key.clone_from(&old_master.self_signing_public_key);
    master.primary_device_ref = old_master.primary_device_ref.clone();
    master.previous_certificate_hash.clone_from(&old_master.previous_certificate_hash);
    master.issued_at = old_master.issued_at;
    master.cert_id.clone_from(&old_master.cert_id);
    if master != *old_master {
        return Err(reject("cooperative transfer changed master policy"));
    }
    for old in &before.devices {
        let next = after
            .devices
            .iter()
            .find(|next| next.device_id == old.device_id)
            .ok_or_else(|| reject("cooperative transfer omitted branch"))?;
        let mut normalized = next.clone();
        match (&old.branch_certificate, &next.branch_certificate) {
            (Some(old_cert), Some(new_cert)) => {
                let mut branch = new_cert.body.clone();
                branch.master_certificate_hash.clone_from(&old_cert.body.master_certificate_hash);
                branch.cert_id.clone_from(&old_cert.body.cert_id);
                if branch != old_cert.body {
                    return Err(reject("cooperative transfer changed branch policy"));
                }
            }
            (None, None) => {}
            _ => return Err(reject("cooperative transfer changed branch evidence")),
        }
        normalized.branch_certificate.clone_from(&old.branch_certificate);
        if normalized != *old {
            return Err(reject("cooperative transfer changed device identity or status"));
        }
    }
    let prior_destination =
        before.devices.iter().any(|device| device.device_id == destination.device_id);
    if prior_destination == fresh_destination
        || !after.devices.iter().any(|device| {
            device.device_id == destination.device_id
                && device.device_epoch == destination.device_epoch
                && device.status == DeviceSetStatus::Active
        })
    {
        return Err(reject("cooperative transfer destination mode mismatch"));
    }
    let mut normalized = after.clone();
    normalized.devices.clone_from(&before.devices);
    normalized.device_set_epoch = before.device_set_epoch;
    normalized.issued_at = before.issued_at;
    normalized.previous_record_hash.clone_from(&before.previous_record_hash);
    normalized.master_certificate = before.master_certificate.clone();
    normalize_checkpoint(before, &mut normalized)?;
    normalized.section_hashes = ramflux_protocol::custody::section_hashes(&normalized)?;
    if normalized != *before {
        return Err(reject("cooperative transfer changed retained authority"));
    }
    Ok(())
}

fn normalize_checkpoint(before: &DeviceSet, after: &mut DeviceSet) -> Result<(), CryptoError> {
    match (&before.revoked_device_checkpoint, &after.revoked_device_checkpoint) {
        (None, None) => {}
        (Some(old), Some(new)) => {
            let mut body = new.body.clone();
            body.master_certificate_hash.clone_from(&old.body.master_certificate_hash);
            body.device_set_epoch = old.body.device_set_epoch;
            body.previous_checkpoint_hash.clone_from(&old.body.previous_checkpoint_hash);
            body.issued_at = old.body.issued_at;
            if body != old.body
                || new.body.previous_checkpoint_hash.as_deref() != Some(object_hash(old)?.as_str())
            {
                return Err(reject("cooperative transfer changed denial checkpoint"));
            }
            after.revoked_device_checkpoint = Some(old.clone());
        }
        _ => return Err(reject("cooperative transfer lost denial checkpoint")),
    }
    Ok(())
}

impl SelfSigningKey {
    /// Approve an exact independently checked candidate with the old management authority.
    /// The caller must bind this body to its locally confirmed, still-live SAS transcript.
    /// # Errors
    /// Refuses a foreign signer, nonpreserving candidate, changed hashes or expired approval.
    pub fn sign_cooperative_preservation(
        &self,
        previous: &VerifiedRecord,
        candidate: &VerifiedRecord,
        body: ramflux_protocol::custody::pairing::channel::PreservationBody,
        now: u64,
    ) -> Result<Envelope<ramflux_protocol::custody::pairing::channel::PreservationBody>, CryptoError>
    {
        self.check_preservation_candidate(previous, candidate, &body, now)?;
        let signature = self.sign_group_state_bytes(&ramflux_protocol::custody::signing_bytes(
            &body.schema,
            &body,
        )?);
        Ok(Envelope { body, signature })
    }

    /// Bind full-data verification and reverse restrictions to the exact preserving candidate.
    /// The coordinator supplies hashes only after the real storage owners verify their streams.
    /// # Errors
    /// Refuses a nonpreserving candidate, foreign signer, expired or malformed full context.
    pub fn sign_cooperative_full_preservation(
        &self,
        previous: &VerifiedRecord,
        candidate: &VerifiedRecord,
        body: ramflux_protocol::custody::pairing::full_transfer::PreservationFull,
        now: u64,
    ) -> Result<
        Envelope<ramflux_protocol::custody::pairing::full_transfer::PreservationFull>,
        CryptoError,
    > {
        use ramflux_protocol::custody::pairing::PairingWire as _;
        body.validate().map_err(|_| reject("full cooperative preservation body"))?;
        self.check_preservation_candidate(previous, candidate, &body.candidate_context(), now)?;
        let signature = self.sign_group_state_bytes(&ramflux_protocol::custody::signing_bytes(
            &body.schema,
            &body,
        )?);
        Ok(Envelope { body, signature })
    }

    fn check_preservation_candidate(
        &self,
        previous: &VerifiedRecord,
        candidate: &VerifiedRecord,
        body: &ramflux_protocol::custody::pairing::channel::PreservationBody,
        now: u64,
    ) -> Result<(), CryptoError> {
        use ramflux_protocol::custody::pairing::PairingWire as _;
        body.validate().map_err(|_| reject("cooperative preservation body"))?;
        if self.public_key()
            != previous.envelope().body.master_certificate.body.self_signing_public_key
            || body.old_record_hash != object_hash(previous.envelope())?
            || body.new_record_hash != object_hash(candidate.envelope())?
            || body.expires_at <= now
            || body.expires_at > now.saturating_add(300)
        {
            return Err(reject("cooperative preservation authority or context"));
        }
        verify_cooperative_preservation(
            previous,
            candidate,
            &body.destination_ref,
            body.recipient_mode == "new",
        )
    }
}

#[cfg(test)]
mod tests;
