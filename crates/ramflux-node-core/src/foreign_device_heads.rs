// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Permanent compact epoch fences and a capacity-limited cache of complete foreign sets.
use crate::NodeCoreError;
use ramflux_protocol::SignedDeviceSetRecord;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

pub(crate) const FOREIGN_HEAD_LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct EpochFence {
    pub(crate) epoch: u64,
    pub(crate) hash: [u8; 32],
}
impl EpochFence {
    pub(crate) fn of(record: &SignedDeviceSetRecord) -> Result<Self, NodeCoreError> {
        Ok(Self {
            epoch: record.device_set_epoch,
            hash: ramflux_crypto::blake3_256(
                "ramflux.node.foreign_device_set.v1",
                &ramflux_protocol::canonical_json_bytes(record)
                    .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?,
            ),
        })
    }
    pub(crate) fn check(self, next: Self) -> Result<(), NodeCoreError> {
        if next.epoch < self.epoch || (next.epoch == self.epoch && next.hash != self.hash) {
            return Err(NodeCoreError::SourceAuthorityRefused {
                reason_code: crate::EnvelopeAuthorityReason::StaleEpoch,
            });
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct HeadObservation {
    pub(crate) fence: EpochFence,
    pub(crate) fence_changed: bool,
    pub(crate) set_changed: bool,
    pub(crate) capacity: bool,
}
impl HeadObservation {
    pub(crate) fn admitted(self) -> Result<(), NodeCoreError> {
        if self.capacity {
            return Err(NodeCoreError::Capacity { resource: "foreign_device_sets" });
        }
        Ok(())
    }
    pub(crate) fn changed(self) -> bool {
        self.fence_changed || self.set_changed
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ForeignDeviceHeads {
    // Retain the r6 sequence representation solely for backwards-compatible snapshot import.
    #[serde(default)]
    pub(crate) records: VecDeque<SignedDeviceSetRecord>,
    #[serde(default)]
    pub(crate) fences: BTreeMap<String, EpochFence>,
}
impl ForeignDeviceHeads {
    pub(crate) fn inspect(
        record: &SignedDeviceSetRecord,
        old_fence: Option<EpochFence>,
        old_set: Option<&SignedDeviceSetRecord>,
        full_count: usize,
    ) -> Result<HeadObservation, NodeCoreError> {
        let next = EpochFence::of(record)?;
        if let Some(old) = old_fence {
            old.check(next)?;
        }
        if let Some(old) = old_set {
            ramflux_crypto::validate_device_set_transition(old, record)
                .map_err(|e| NodeCoreError::ItestHttp(e.to_string()))?;
        }
        let capacity = old_set.is_none() && full_count >= FOREIGN_HEAD_LIMIT;
        Ok(HeadObservation {
            fence: next,
            fence_changed: old_fence != Some(next),
            set_changed: !capacity && old_set != Some(record),
            capacity,
        })
    }
    pub(crate) fn prepare(
        &self,
        record: &SignedDeviceSetRecord,
    ) -> Result<HeadObservation, NodeCoreError> {
        Self::inspect(
            record,
            self.fences.get(&record.principal_commitment).copied(),
            self.records.iter().find(|old| old.principal_commitment == record.principal_commitment),
            self.records.len(),
        )
    }
    pub(crate) fn apply(&mut self, record: &SignedDeviceSetRecord, observation: HeadObservation) {
        if observation.fence_changed {
            self.fences.insert(record.principal_commitment.clone(), observation.fence);
        }
        if observation.set_changed {
            self.records.retain(|old| old.principal_commitment != record.principal_commitment);
            self.records.push_back(record.clone());
        }
    }
    pub(crate) fn observe(
        &mut self,
        record: &SignedDeviceSetRecord,
    ) -> Result<HeadObservation, NodeCoreError> {
        let observation = self.prepare(record)?;
        self.apply(record, observation);
        Ok(observation)
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.fences.is_empty() && self.records.is_empty()
    }
}
