// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-local full-transfer staging owners. They grant no native authority.
mod catalog;
mod duplex;
pub use duplex::FullDuplexReceipt;
mod fixed_union;
mod inventory;
pub(in crate::account_db) use inventory::inspect as inspect_pinned_full_transfer;
mod io_cancel;
pub use io_cancel::FullStageIoCancel;
mod keys;
mod local_unlock;
pub use local_unlock::FullLocalUnlockGuard;
mod native_floor;
mod preservation;
mod read_work;
mod rebind;
mod resume_position;
pub use resume_position::FullForwardResumePosition;
mod receiver_contributions;
mod receiver_copy;
mod receiver_read;
pub use receiver_copy::{
    FullAppliedDataReceipt, FullGenerationRecoveryDraft, FullGenerationRecoveryWork,
    FullPinnedReceiverBase, FullPreparedReceiverDatabase, FullReceiverBaseCopy,
    FullReceiverDatabaseWork, FullSelectedReceiverGeneration,
};
pub use receiver_read::FullReceiverReplayWork;
mod receiver_input;
mod receiver_materialization;
mod receiver_projection;
mod receiver_scratch;
mod reverse_application;
mod reverse_chunks;
mod reverse_manifest;
mod reverse_source;
pub use reverse_source::{FullReverseSourceDraft, FullReverseSourceWork};
mod reverse_merge;
mod reverse_validation;
pub use reverse_validation::{FullReverseValidationWork, FullValidatedReverseInput};
mod scalar;
mod scalar_sql;
mod source_base;
mod source_cut;
mod source_delta;
mod source_successor;
pub use source_successor::{FullSourceDeltaDraft, FullSourceSuccessorWork};
mod data_terminal;
mod install_reconciliation;
mod installed_tail;
pub use installed_tail::FullInstalledTailScope;
mod receiver_retirement;
mod source_primary_owner;
mod source_reconciliation;
mod source_retirement;
pub use source_primary_owner::FullSourcePrimaryOwner;
mod source_owner;
mod source_preparation;
mod source_receipt;
mod source_scalar;
mod source_wire;
mod stage;
mod stage_chunks;
mod stage_reader;
mod stage_validation;
mod tail;
mod tail_apply;
mod tail_receipt;
pub use tail_receipt::FullTailAppliedReceipt;
mod tail_capture;
mod tail_encode;
mod tail_endpoint;
mod tail_validation;
pub use install_reconciliation::{FullRecipientInstallStage, FullRecipientRecoveryIdentity};
pub use tail_capture::{FullSourceTailCut, FullSourceTailWork};
pub use tail_encode::FullSourceTailEncodingWork;
pub use tail_endpoint::FullTailEndpoint;
pub use tail_validation::{FullTailValidationWork, FullValidatedTailInput};
mod target_observation;
mod union_encoding;
pub use keys::{EncryptedStageChunk, FullStageKey, StageDirection, WrappedFullStageKey};
pub use receiver_input::FullScalarInputCounts;
pub use source_base::FullBaseSourceEncoding;
pub use source_preparation::{
    FullSourcePreparation, FullSourcePreparationCancel, FullSourcePreparationWork,
    PreparedFullSource,
};
pub use source_scalar::FullScalarSourceCounts;
pub use stage::FullTransferStage;
pub use stage_reader::FullForwardReader;
pub use target_observation::FullTargetObservation;
pub use union_encoding::{FullUnionEncoding, FullUnionEncodingBuilder};

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

#[cfg(any(test, feature = "test-instrumentation"))]
mod test_support;
