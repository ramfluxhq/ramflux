// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-local full-transfer staging owners. They grant no native authority.
mod catalog;
mod inventory;
mod keys;
mod native_floor;
mod scalar;
mod source_cut;
mod source_receipt;
mod stage;
mod stage_chunks;
mod stage_reader;
mod stage_validation;
pub use keys::{EncryptedStageChunk, FullStageKey, StageDirection, WrappedFullStageKey};
pub use stage::FullTransferStage;
pub use stage_reader::FullForwardReader;

#[cfg(test)]
mod stage_tests;

pub use catalog::{
    CellRule, CodecRule, FamilyRule, FamilySelector, FieldRule, MergeRule, VariantRule,
    full_census_hash, full_transfer_catalog,
};

#[cfg(test)]
mod catalog_tests;

pub use inventory::FullTransferSchema;

pub use scalar::copy_full_scalar_record;

#[cfg(test)]
mod scalar_tests;
