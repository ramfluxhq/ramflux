// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-local full-transfer staging owners. They grant no native authority.
mod catalog;
mod inventory;
mod keys;
mod native_floor;
mod scalar;
mod scalar_sql;
mod source_cut;
mod source_receipt;
mod source_scalar;
mod stage;
mod stage_chunks;
mod stage_reader;
mod stage_validation;
pub use keys::{EncryptedStageChunk, FullStageKey, StageDirection, WrappedFullStageKey};
pub use source_scalar::FullScalarSourceCounts;
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
pub use scalar_sql::write_full_scalar_sql_row;

#[cfg(test)]
mod scalar_tests;

#[cfg(test)]
mod source_scalar_tests;
