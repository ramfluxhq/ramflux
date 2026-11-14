// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact full-profile management approval; never interchangeable with selected-key approval.
use super::{DeviceRef, PairingWire, Result, b32, budget, require};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreservationFull {
    pub schema: String,
    pub version: u32,
    pub transfer_id: String,
    pub transcript_hash: String,
    pub old_record_hash: String,
    pub new_record_hash: String,
    pub destination_ref: DeviceRef,
    pub recipient_mode: String,
    pub policy: String,
    pub expires_at: u64,
    pub manifest_chain_hash: String,
    pub data_verified_hash: String,
    pub target_restrictions_root: String,
}
impl PreservationFull {
    /// Shared candidate-preservation checks do not include any full-data approval.
    #[must_use]
    pub fn candidate_context(&self) -> super::super::channel::PreservationBody {
        super::super::channel::PreservationBody {
            schema: "ramflux.identity.transfer.preserve.v1".into(),
            version: self.version,
            transfer_id: self.transfer_id.clone(),
            transcript_hash: self.transcript_hash.clone(),
            old_record_hash: self.old_record_hash.clone(),
            new_record_hash: self.new_record_hash.clone(),
            destination_ref: self.destination_ref.clone(),
            recipient_mode: self.recipient_mode.clone(),
            policy: self.policy.clone(),
            expires_at: self.expires_at,
        }
    }
}
impl PairingWire for PreservationFull {
    const LIMIT: usize = 11_700;
    fn validate(&self) -> Result<()> {
        require(self.schema == "ramflux.identity.transfer.preserve.full.v1", "schema")?;
        self.candidate_context().validate()?;
        for hash in
            [&self.manifest_chain_hash, &self.data_verified_hash, &self.target_restrictions_root]
        {
            b32(hash, "full_preservation_hash")?;
        }
        budget(self, Self::LIMIT)
    }
}
