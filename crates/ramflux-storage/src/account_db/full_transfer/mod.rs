// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-local full-transfer staging owners. They grant no native authority.
mod catalog;
mod keys;
mod source_cut;
mod stage;
mod stage_chunks;
pub use keys::{EncryptedStageChunk, FullStageKey, StageDirection, WrappedFullStageKey};
pub use stage::FullTransferStage;

#[cfg(test)]
mod stage_tests;

pub use catalog::{
    CellRule, CodecRule, FamilyRule, FamilySelector, FieldRule, MergeRule, VariantRule,
    full_census_hash,
};

#[cfg(test)]
mod catalog_tests;
