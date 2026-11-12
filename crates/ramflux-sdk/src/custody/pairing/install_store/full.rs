// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A5.M5 immutable local generation operands. Paths never come from a relay document.
use super::{SdkError, b32, require};
use ramflux_protocol::custody::pairing::full_transfer::U64;
use serde::{Deserialize, Serialize};

/// Exact prior `AccountIndex` selection that the generation owner must recheck at G2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorGeneration {
    pub db_relative_path: String,
    pub object_relative_path: String,
}

/// Data-generation fence, required only by full-profile transfer-destination Install.v3.
/// Roots/nonce are immutable initial receipts; ordinary later writes do not rehash the DB.
/// This is a closed local record, never a permission to select paths or publish authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullInstall {
    pub chain_hash: String,
    pub db_relative_path: String,
    pub object_relative_path: String,
    pub stage_id: String,
    pub generation_nonce: String,
    pub expected_prior_generation: PriorGeneration,
    pub expected_prior_privacy_epoch: U64,
    pub initial_union_root: String,
}

impl FullInstall {
    /// Validate exact local hash widths, signed SQLite epoch range and canonical paths.
    /// Actual prepared-byte/root verification and all-owner comparison remain mandatory.
    /// # Errors
    /// Refuses malformed hashes, unsafe paths, reused prior paths or invalid epochs.
    pub fn validate(&self) -> Result<(), SdkError> {
        b32(&self.chain_hash, "full_transfer.chain_hash")?;
        b32(&self.stage_id, "full_transfer.stage_id")?;
        b32(&self.generation_nonce, "full_transfer.generation_nonce")?;
        b32(&self.initial_union_root, "full_transfer.initial_union_root")?;
        path(&self.db_relative_path)?;
        path(&self.object_relative_path)?;
        path(&self.expected_prior_generation.db_relative_path)?;
        path(&self.expected_prior_generation.object_relative_path)?;
        require(
            self.db_relative_path != self.object_relative_path
                && self.db_relative_path != self.expected_prior_generation.db_relative_path
                && self.object_relative_path != self.expected_prior_generation.object_relative_path
                && self.db_relative_path != self.expected_prior_generation.object_relative_path
                && self.object_relative_path != self.expected_prior_generation.db_relative_path,
            "full_transfer.paths",
        )?;
        require(
            i64::try_from(self.expected_prior_privacy_epoch.0).is_ok(),
            "full_transfer.expected_prior_privacy_epoch",
        )
    }
}

fn path(value: &str) -> Result<(), SdkError> {
    require(
        !value.is_empty()
            && value.len() <= 1024
            && !value.chars().any(char::is_control)
            && !value.contains(['\\', ':'])
            && value.split('/').all(|part| !matches!(part, "" | "." | "..")),
        "full_transfer.paths",
    )
}

// Missing stays None for v2. An explicitly present null is invalid in BOTH versions.
pub(super) fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<FullInstall>, D::Error> {
    FullInstall::deserialize(deserializer).map(Some)
}
