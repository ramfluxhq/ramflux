// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified record capability; public bytes cannot manufacture this type by deserialization.
use super::validate::{bytes, key, record_structure, reject, signature};
use crate::CryptoError;
use ramflux_protocol::{
    DeviceSetStatus, MAX_SAFE_JSON_INTEGER, PrincipalKind,
    custody::{
        BranchCertificate, CLOCK_SKEW_SECONDS, CustodyKind, DeviceRef, DeviceSet, Envelope,
        MAX_RECORD_BYTES, MAX_REVOKED_IDS, MAX_REVOKED_LIST_BYTES, MAX_ROSTER, decode_epoch,
        framed_hash, object_hash,
    },
    domain,
};
use std::collections::BTreeSet;

/// Complete authenticated authority, still subject to freshness and durable mode/epoch pins.
#[derive(Clone, Debug)]
pub struct VerifiedRecord {
    envelope: Envelope<DeviceSet>,
    revoked: BTreeSet<String>,
    encoded_bytes: usize,
    compacted_bytes: usize,
    human_custodian: Option<Box<VerifiedRecord>>,
}
/// Authenticated capacity warnings; crossing a threshold never blocks revocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapacityLimit {
    Roster,
    RecordBytes,
    CompactedCount,
    CompactedBytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapacityPressure {
    warnings: BTreeSet<CapacityLimit>,
}
impl CapacityPressure {
    #[must_use]
    pub fn any(&self) -> bool {
        !self.warnings.is_empty()
    }
    #[must_use]
    pub fn warned(&self, limit: CapacityLimit) -> bool {
        self.warnings.contains(&limit)
    }
}
impl VerifiedRecord {
    #[must_use]
    pub const fn envelope(&self) -> &Envelope<DeviceSet> {
        &self.envelope
    }
    #[must_use]
    pub fn revoked_ids(&self) -> &BTreeSet<String> {
        &self.revoked
    }
    /// Look up a currently leased capability; a record signature alone is not device possession.
    /// # Errors
    /// Rejects wrong anchors/epochs, revocation, missing capabilities and expired/future leases.
    pub fn authorize(
        &self,
        reference: &DeviceRef,
        capability: &str,
        now: u64,
    ) -> Result<&BranchCertificate, CryptoError> {
        let record = &self.envelope.body;
        if let Some(human) = &self.human_custodian {
            human.authorize(&record.master_certificate.body.primary_device_ref, "register", now)?;
        }
        if reference.account_anchor != record.account_anchor
            || self.revoked.contains(&reference.device_id)
        {
            return Err(reject("custody device anchor or revocation mismatch"));
        }
        let device = record
            .devices
            .iter()
            .find(|d| {
                d.device_id == reference.device_id && d.device_epoch == reference.device_epoch
            })
            .ok_or_else(|| reject("custody device unavailable"))?;
        let cert = &device
            .branch_certificate
            .as_ref()
            .filter(|_| device.status == DeviceSetStatus::Active)
            .ok_or_else(|| reject("custody device revoked"))?
            .body;
        if now > MAX_SAFE_JSON_INTEGER
            || cert.not_before > now.saturating_add(CLOCK_SKEW_SECONDS)
            || now > cert.expires_at.saturating_add(CLOCK_SKEW_SECONDS)
            || !cert.capabilities.iter().any(|cap| cap == capability)
        {
            return Err(reject("custody device lease or capability unavailable"));
        }
        Ok(cert)
    }
    #[must_use]
    pub fn capacity_pressure(&self) -> CapacityPressure {
        fn warn(used: usize, limit: usize) -> bool {
            used >= limit - limit / 5
        }
        let values = [
            (CapacityLimit::Roster, self.envelope.body.devices.len(), MAX_ROSTER),
            (CapacityLimit::RecordBytes, self.encoded_bytes, MAX_RECORD_BYTES),
            (
                CapacityLimit::CompactedCount,
                self.envelope
                    .body
                    .revoked_device_checkpoint
                    .as_ref()
                    .map_or(0, |c| usize::try_from(c.body.count).unwrap_or(MAX_REVOKED_IDS)),
                MAX_REVOKED_IDS,
            ),
            (CapacityLimit::CompactedBytes, self.compacted_bytes, MAX_REVOKED_LIST_BYTES),
        ];
        CapacityPressure {
            warnings: values
                .into_iter()
                .filter_map(|(limit, used, max)| warn(used, max).then_some(limit))
                .collect(),
        }
    }
}
/// Verify exact native v3 authority, including every nested signature and key commitment.
/// The caller must obtain the external human's current verified authority independently.
/// # Errors
/// Rejects malformed/future/unsupported records, missing compacted evidence, and invalid custody.
pub fn verify_record(
    envelope: &Envelope<DeviceSet>,
    now: u64,
    compacted_ids: Option<&[String]>,
    human_custodian: Option<&VerifiedRecord>,
) -> Result<VerifiedRecord, CryptoError> {
    if now > MAX_SAFE_JSON_INTEGER {
        return Err(reject("trusted custody time unavailable"));
    }
    record_structure(&envelope.body)?;
    let body = &envelope.body;
    let master = &body.master_certificate.body;
    signature(&key(&master.self_signing_public_key)?, domain::SIGNED_DEVICE_SET_V3, envelope)?;
    let encoded_bytes = ramflux_protocol::canonical_json_bytes(envelope)?.len();
    if encoded_bytes > MAX_RECORD_BYTES {
        return Err(reject("custody record byte budget exceeded"));
    }
    let future = now.saturating_add(CLOCK_SKEW_SECONDS);
    if body.issued_at > future
        || master.issued_at > future
        || body.devices.iter().any(|d| d.revoked_at.is_some_and(|at| at > future))
    {
        return Err(reject("custody event is in the future"));
    }
    if master.custody_kind == CustodyKind::ExternalHuman {
        let human = human_custodian
            .ok_or_else(|| reject("verified human custodian authority unavailable"))?;
        let authority = &human.envelope.body;
        if authority.principal_kind != PrincipalKind::Human
            || authority.master_certificate.body.custody_kind != CustodyKind::LocalHuman
            || authority.master_certificate.body.primary_device_ref != master.primary_device_ref
        {
            return Err(reject("service custodian is not the current human primary"));
        }
        human.authorize(&master.primary_device_ref, "register", now)?;
    }
    let mut revoked = BTreeSet::new();
    let mut compacted_bytes = 0;
    if let Some(checkpoint) = &body.revoked_device_checkpoint {
        let c = &checkpoint.body;
        if c.schema != domain::CUSTODY_REVOKED_CHECKPOINT
            || c.version != 1
            || c.account_anchor != body.account_anchor
            || c.master_certificate_hash != object_hash(&body.master_certificate)?
            || c.count == 0
            || c.count > MAX_REVOKED_IDS as u64
            || c.device_set_epoch > body.device_set_epoch
            || decode_epoch(c.device_set_epoch)?.0 != master.range_index
            || c.issued_at > future
            || c.compacted_before
                > c.issued_at
                    .checked_sub(7_776_000)
                    .ok_or_else(|| reject("invalid compaction time"))?
        {
            return Err(reject("invalid custody revocation checkpoint"));
        }
        bytes(&c.list_hash, 32)?;
        if let Some(previous) = &c.previous_checkpoint_hash {
            bytes(previous, 32)?;
        }
        signature(
            &key(&master.self_signing_public_key)?,
            domain::CUSTODY_REVOKED_CHECKPOINT,
            checkpoint,
        )?;
        let ids = compacted_ids
            .ok_or_else(|| reject("compacted revocation membership evidence unavailable"))?;
        if ids.len() > MAX_REVOKED_IDS
            || ids.len() as u64 != c.count
            || !ids.windows(2).all(|pair| pair[0] < pair[1])
            || ids
                .iter()
                .any(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        {
            return Err(reject("invalid compacted revocation membership list"));
        }
        compacted_bytes = ramflux_protocol::canonical_json_bytes(&ids)?.len();
        if compacted_bytes > MAX_REVOKED_LIST_BYTES
            || framed_hash(domain::CUSTODY_REVOKED_LIST, &ids)? != c.list_hash
        {
            return Err(reject("revocation membership count, hash or byte budget mismatch"));
        }
        revoked.extend(ids.iter().cloned());
    } else if compacted_ids.is_some_and(|ids| !ids.is_empty()) {
        return Err(reject("revocation evidence has no signed checkpoint"));
    }
    for device in &body.devices {
        if device.status == DeviceSetStatus::Revoked {
            revoked.insert(device.device_id.clone());
        } else if revoked.contains(&device.device_id) {
            return Err(reject("compacted device cannot reactivate"));
        }
    }
    Ok(VerifiedRecord {
        envelope: envelope.clone(),
        revoked,
        encoded_bytes,
        compacted_bytes,
        human_custodian: (master.custody_kind == CustodyKind::ExternalHuman)
            .then(|| human_custodian.cloned().map(Box::new))
            .flatten(),
    })
}
