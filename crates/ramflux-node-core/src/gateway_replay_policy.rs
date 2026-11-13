// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Configured replay allocations must have backing storage before admitting signed work.
use crate::NodeCoreError;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const GATEWAY_REPLAY_PAGE_CACHE_BYTES: usize = 8 * 1024 * 1024;
pub const GATEWAY_REPLAY_MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const PLANNED_IDENTITY_BYTES: u64 = 512;
const PLANNED_ROOT_BYTES: u64 = 256;
const WORKING_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

/// Full-validity allocation per account root, shared across all its devices.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayReplayConfig {
    pub root_budget: u64,
    pub per_root_share: u64,
    pub storage_budget_bytes: u64,
}
impl Default for GatewayReplayConfig {
    fn default() -> Self {
        Self::small_node()
    }
}
impl GatewayReplayConfig {
    pub(super) const fn unfunded(self, available_bytes: u64) -> NodeCoreError {
        NodeCoreError::GatewayReplayUnfunded {
            root_budget: self.root_budget,
            per_root_share: self.per_root_share,
            required_bytes: self.storage_budget_bytes,
            available_bytes,
        }
    }

    /// Smaller-node profile with the same per-root full-validity traffic allowance.
    #[must_use]
    pub const fn small_node() -> Self {
        Self {
            root_budget: 256,
            per_root_share: 32_768,
            storage_budget_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
    /// Planned logical allowance, excluding working space. This is not a redb measurement.
    /// # Errors
    /// Refuses zero, overflowing, or unfunded allocations.
    pub fn planned_logical_bytes(&self) -> Result<u64, NodeCoreError> {
        if self.root_budget == 0 || self.per_root_share == 0 {
            return Err(self.unfunded(0));
        }
        let logical = self
            .root_budget
            .checked_mul(self.per_root_share)
            .and_then(|count| count.checked_mul(PLANNED_IDENTITY_BYTES))
            .and_then(|bytes| {
                self.root_budget
                    .checked_mul(PLANNED_ROOT_BYTES)
                    .and_then(|roots| bytes.checked_add(roots))
            })
            .ok_or_else(|| self.unfunded(0))?;
        if logical
            .checked_add(WORKING_RESERVE_BYTES)
            .is_none_or(|required| required > self.storage_budget_bytes)
        {
            return Err(self.unfunded(0));
        }
        Ok(logical)
    }
    pub(super) fn require_funded(&self, path: &Path) -> Result<(), NodeCoreError> {
        let available =
            fs2::available_space(path).map_err(|error| NodeCoreError::Redb(error.to_string()))?;
        let existing =
            std::fs::metadata(path).map_err(|error| NodeCoreError::Redb(error.to_string()))?.len();
        self.planned_logical_bytes().map_err(|_| self.unfunded(available))?;
        if available.saturating_add(existing) < self.storage_budget_bytes {
            return Err(self.unfunded(available));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_allocations_reject_unfunded_and_overflowing_budgets() -> Result<(), NodeCoreError> {
        let default = GatewayReplayConfig::default();
        assert_eq!(default.planned_logical_bytes()?, 4 * 1024 * 1024 * 1024 + 64 * 1024);
        assert!(GatewayReplayConfig::small_node().planned_logical_bytes().is_ok());
        for config in [
            GatewayReplayConfig { storage_budget_bytes: 1, ..default },
            GatewayReplayConfig { root_budget: u64::MAX, ..default },
            GatewayReplayConfig { per_root_share: 0, ..default },
        ] {
            assert!(matches!(
                config.planned_logical_bytes(),
                Err(NodeCoreError::GatewayReplayUnfunded { .. })
            ));
        }
        Ok(())
    }
}
