// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed primary operations preserve space and give revocation priority over enrollment.
use super::{
    SelfSigningKey, VerifiedRecord,
    validate::{message_layer_declaration, reject},
};
use crate::CryptoError;
use ramflux_protocol::{
    DeviceSetStatus,
    custody::{
        BranchCertificate, Device, DeviceRef, DeviceSet, Envelope, MAX_ENROLLMENT_ROSTER,
        MigrationState, SignedLayerDeclaration, decode_epoch, encode_epoch, object_hash,
    },
};

/// Sign the enrolling branch's own message-layer declaration for the certificate it joins with.
/// The declaration starts at the lease start and lasts at most 24 hours, inside the lease.
/// # Errors
/// Returns an error when the signing bytes cannot be built.
pub fn sign_enrollment_layer(
    branch: &crate::DeviceBranch,
    certificate: &BranchCertificate,
) -> Result<SignedLayerDeclaration, CryptoError> {
    let issued_at = certificate.not_before;
    let expires_at = certificate.expires_at.min(
        issued_at.saturating_add(ramflux_protocol::custody::MAX_LAYER_DECLARATION_VALIDITY_SECONDS),
    );
    let declaration = ramflux_protocol::custody::LayerDeclaration {
        device: DeviceRef {
            account_anchor: certificate.account_anchor.clone(),
            device_id: certificate.device_id.clone(),
            device_epoch: certificate.device_epoch,
        },
        max_layer: ramflux_protocol::custody::MESSAGE_LAYER_FLOOR,
        declaration_sequence: 1,
        issued_at,
        expires_at,
    };
    let bytes = ramflux_protocol::custody::signing_bytes(
        ramflux_protocol::domain::CUSTODY_MESSAGE_LAYER_DECLARATION,
        &declaration,
    )
    .map_err(|_| reject("message-layer declaration signing bytes"))?;
    Ok(SignedLayerDeclaration {
        branch_signature: crate::sign_canonical_bytes_with_device_branch(&bytes, branch),
        declaration,
    })
}

/// Verify a recipient's enrollment declaration against the exact certificate it will join with.
/// The primary runs this before journaling, so an invalid or out-of-lease statement never reaches
/// the authority signature.
/// # Errors
/// Rejects a declaration that is not bound to the certificate's exact device, is out of lease,
/// newer than `now`, outside the layer bounds, or has a bad branch signature.
pub fn verify_enrollment_layer(
    certificate: &Envelope<BranchCertificate>,
    declaration: &SignedLayerDeclaration,
    now: u64,
) -> Result<(), CryptoError> {
    let branch = &certificate.body;
    message_layer_declaration(
        declaration,
        &DeviceRef {
            account_anchor: branch.account_anchor.clone(),
            device_id: branch.device_id.clone(),
            device_epoch: branch.device_epoch,
        },
        branch,
        now,
    )
}

impl SelfSigningKey {
    /// Revoke in place, including the primary branch, without allocating a roster slot or
    /// growing the compacted list. A full checkpoint never prevents this operation.
    /// # Errors
    /// Rejects an absent/already revoked device, wrong signer, time rollback or exhausted range.
    pub fn revoke_device(
        &self,
        current: &VerifiedRecord,
        device_id: &str,
        now: u64,
    ) -> Result<Envelope<DeviceSet>, CryptoError> {
        let mut body = Self::next_body(current, now)?;
        let device = body
            .devices
            .iter_mut()
            .find(|d| d.device_id == device_id)
            .ok_or_else(|| reject("custody revocation target unavailable"))?;
        if device.status != DeviceSetStatus::Active {
            return Err(reject("custody device already revoked"));
        }
        device.status = DeviceSetStatus::Revoked;
        device.migration_state = MigrationState::Revoked;
        device.revoked_at = Some(now);
        device.branch_certificate = None;
        device.message_layer = None;
        self.sign_record(body)
    }
    /// Enroll an explicitly certified new id, preserving 64 roster slots for safety headroom.
    /// The recipient's branch-signed layer declaration is endorsed by this same authority signature.
    /// # Errors
    /// Rejects exhausted capacity, reused/revoked ids, unrelated certificates, an invalid or
    /// out-of-lease declaration, or invalid authority.
    pub fn enroll_device(
        &self,
        current: &VerifiedRecord,
        certificate: Envelope<BranchCertificate>,
        message_layer: SignedLayerDeclaration,
        now: u64,
    ) -> Result<Envelope<DeviceSet>, CryptoError> {
        let mut body = Self::next_body(current, now)?;
        let branch = &certificate.body;
        if body.devices.len() >= MAX_ENROLLMENT_ROSTER
            || current.revoked_ids().contains(&branch.device_id)
            || body.devices.iter().any(|d| d.device_id == branch.device_id)
        {
            return Err(reject("custody enrollment capacity or reused device id"));
        }
        message_layer_declaration(
            &message_layer,
            &DeviceRef {
                account_anchor: branch.account_anchor.clone(),
                device_id: branch.device_id.clone(),
                device_epoch: branch.device_epoch,
            },
            branch,
            now,
        )?;
        let (signing, agreement) = crate::device_key_commitments(
            &branch.branch_signing_public_key,
            &branch.agreement_identity_public_key,
        )?;
        body.devices.push(Device {
            device_id: branch.device_id.clone(),
            device_epoch: branch.device_epoch,
            signing_key_commitment: signing,
            agreement_key_commitment: agreement,
            status: DeviceSetStatus::Active,
            revoked_at: None,
            branch_certificate: Some(certificate),
            message_layer: Some(message_layer),
            migration_state: MigrationState::Native,
        });
        body.devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        self.sign_record(body)
    }
    /// Endorse an active secondary's own renewed message-layer declaration into a new roster head.
    /// The declaration must be strictly newer than the endorsed one; the primary signs only the
    /// roster, never the secondary's assertion.
    /// # Errors
    /// Rejects a missing or non-active target, an out-of-lease or mis-bound declaration, a
    /// sequence that is not newer than the endorsed one, rollback time, or invalid authority.
    pub fn endorse_device_layer(
        &self,
        current: &VerifiedRecord,
        device_id: &str,
        message_layer: SignedLayerDeclaration,
        now: u64,
    ) -> Result<Envelope<DeviceSet>, CryptoError> {
        let mut body = Self::next_body(current, now)?;
        let device = body
            .devices
            .iter_mut()
            .find(|d| d.device_id == device_id && d.status == DeviceSetStatus::Active)
            .ok_or_else(|| reject("custody layer endorsement target unavailable"))?;
        let certificate = device
            .branch_certificate
            .as_ref()
            .ok_or_else(|| reject("custody layer endorsement target has no branch"))?;
        let expected = DeviceRef {
            account_anchor: certificate.body.account_anchor.clone(),
            device_id: certificate.body.device_id.clone(),
            device_epoch: certificate.body.device_epoch,
        };
        message_layer_declaration(&message_layer, &expected, &certificate.body, now)?;
        if let Some(endorsed) = &device.message_layer
            && message_layer.declaration.declaration_sequence
                <= endorsed.declaration.declaration_sequence
        {
            return Err(reject("custody layer endorsement is not newer"));
        }
        device.message_layer = Some(message_layer);
        self.sign_record(body)
    }

    fn next_body(current: &VerifiedRecord, now: u64) -> Result<DeviceSet, CryptoError> {
        let mut body = current.envelope().body.clone();
        let (range, revision) = decode_epoch(body.device_set_epoch)?;
        if now < body.issued_at || now > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
            return Err(reject("custody management time rollback"));
        }
        body.device_set_epoch = encode_epoch(
            range,
            revision
                .checked_add(1)
                .ok_or_else(|| reject("custody range exhausted; master re-attestation required"))?,
        )?;
        body.previous_record_hash = Some(object_hash(current.envelope())?);
        body.issued_at = now;
        Ok(body)
    }
}
