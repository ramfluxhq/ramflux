// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed primary operations preserve space and give revocation priority over enrollment.
use super::{SelfSigningKey, VerifiedRecord, validate::reject};
use crate::CryptoError;
use ramflux_protocol::{DeviceSetStatus, custody::*};

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
        let mut body = self.next_body(current, now)?;
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
        self.sign_record(body)
    }
    /// Enroll an explicitly certified new id, preserving 64 roster slots for safety headroom.
    /// # Errors
    /// Rejects exhausted capacity, reused/revoked ids, unrelated certificates or invalid authority.
    pub fn enroll_device(
        &self,
        current: &VerifiedRecord,
        certificate: Envelope<BranchCertificate>,
        now: u64,
    ) -> Result<Envelope<DeviceSet>, CryptoError> {
        let mut body = self.next_body(current, now)?;
        let branch = &certificate.body;
        if body.devices.len() >= MAX_ENROLLMENT_ROSTER
            || current.revoked_ids().contains(&branch.device_id)
            || body.devices.iter().any(|d| d.device_id == branch.device_id)
        {
            return Err(reject("custody enrollment capacity or reused device id"));
        }
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
            migration_state: MigrationState::Native,
        });
        body.devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        self.sign_record(body)
    }
    fn next_body(&self, current: &VerifiedRecord, now: u64) -> Result<DeviceSet, CryptoError> {
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
