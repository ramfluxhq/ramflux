// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-local full-transfer staging owners. They grant no native authority.
mod catalog;
mod fixed_union;
mod inventory;
mod keys;
mod native_floor;
mod receiver_input;
mod scalar;
mod scalar_sql;
mod source_base;
mod source_cut;
mod source_delta;
mod source_owner;
mod source_preparation;
mod source_receipt;
mod source_scalar;
mod stage;
mod stage_chunks;
mod stage_reader;
mod stage_validation;
mod target_observation;
pub use keys::{EncryptedStageChunk, FullStageKey, StageDirection, WrappedFullStageKey};
pub use receiver_input::FullScalarInputCounts;
pub use source_base::FullBaseSourceEncoding;
pub use source_preparation::{
    FullSourcePreparation, FullSourcePreparationCancel, PreparedFullSource,
};
pub use source_scalar::FullScalarSourceCounts;
pub use stage::FullTransferStage;
pub use stage_reader::FullForwardReader;
pub use target_observation::FullTargetObservation;

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

#[cfg(test)]
mod source_base_tests;

#[cfg(test)]
mod source_preparation_tests;

#[cfg(test)]
mod source_delta_tests;
