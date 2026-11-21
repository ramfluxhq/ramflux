// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact Auth-HPKE AAD. The historical base remains pinned across encrypted Rebind/deltas.
use super::{DeviceRef, PairingWire, Result, b32, budget, reference, require};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataBinding {
    pub profile: String,
    pub transfer_id: String,
    pub manifest_hash: String,
    pub epoch: String,
    pub source_ref: DeviceRef,
    pub destination_ref: DeviceRef,
    pub base_record_hash: String,
}
impl PairingWire for DataBinding {
    const LIMIT: usize = 8192;
    fn validate(&self) -> Result<()> {
        require(self.profile == super::PROFILE, "profile")?;
        for hash in [&self.transfer_id, &self.manifest_hash, &self.epoch, &self.base_record_hash] {
            b32(hash, "data_binding")?;
        }
        reference(&self.source_ref)?;
        reference(&self.destination_ref)?;
        require(
            self.source_ref.account_anchor == self.destination_ref.account_anchor
                && self.source_ref != self.destination_ref,
            "data_binding",
        )?;
        budget(self, Self::LIMIT)
    }
}
