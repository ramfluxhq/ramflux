// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client-local storage primitives for MVP-1 multi-account tests.

mod account_db;
pub use account_db::backup::{AccountBackupSnapshot, BackupCounts};
pub use account_db::backup_database::{
    BackupAttachmentVerification, BackupDatabase, BackupInputObservation, BackupOpenMode,
};
pub use account_db::backup_merge::BackupMergeReport;
mod account_erase;
mod account_index;
mod account_writer;
pub use account_writer::AccountWriterLease;
#[cfg(test)]
mod account_writer_tests;
pub use account_index::BackupIndexInstall;
mod clock;
mod constants;
mod conversation_helpers;
mod database;
#[cfg(feature = "itest-work-budget")]
mod database_work;
#[cfg(feature = "itest-work-budget")]
pub use database_work::{SqlWorkProbe, SqlWorkScope, SqlWorkSnapshot};
mod database_checkpoint;
#[cfg(any(test, feature = "durability-test-hooks"))]
pub mod durability_test_hooks;
#[cfg(all(feature = "durability-test-hooks", ramflux_production))]
compile_error!("durability-test-hooks must not be enabled in a production build");
#[cfg(any(test, feature = "test-instrumentation"))]
pub use account_db::receive::ReceiveLedgerSnap;
pub use account_db::receive::ack::{
    ACK_BATCH_MAX, ACK_FLUSH_COUNT, ACK_FLUSH_SECS, ReceiveAckApply, ReceiveAckApplyResult,
    ReceiveAckOutcome, ReceiveAckResult,
};
pub use account_db::receive::cover::{
    ReceiveCover, ReceiveCoverKind, ReceiveCoverResult, ReceiveGap,
};
pub use account_db::receive::hold::{
    ReceiveHold, ReceiveHoldClass, ReceiveHoldJournal, ReceiveHoldResult,
};
pub use account_db::receive::migrate::{ReceiveMigrate, ReceiveMigrateResult};
pub use account_db::receive::page::{
    ReceiveCoverStep, ReceiveGapOwned, ReceiveKnownLoss, ReceivePageView, ReceiveReconcileResult,
};
pub use account_db::receive::privacy::ReceiveBind;
pub use account_db::receive::removal::{
    ReceiveFailure, ReceiveFailureKind, ReceiveFailureReason, ReceiveFailureResult,
};
pub use account_db::receive::reset::{
    CURSOR_AHEAD, RETIRED_FENCE_CAP, ReceiveIssued, ReceiveReset, ReceiveResetReason,
    ReceiveResetResult,
};
pub use account_db::receive::settle::{ReceiveSettle, ReceiveSettleKind, ReceiveSettleResult};
pub use account_db::receive::stage::{ReceiveStage, ReceiveStageResult};
pub use account_db::receive::{ReceiveExpectation, ReceiveTransaction};
mod encryption;
mod error;
mod event_store;
mod group_permissions;
mod history_hash;
mod records;
mod row_mappers;
mod schema;
mod schema_contact_requests;
mod schema_device_namespace;
mod schema_generation;
mod schema_group_control_identity;
mod schema_group_sender_identity;
mod schema_identity_keys;
mod schema_large_segments;
mod schema_object_erasure;
mod schema_receipt_identity;
#[cfg(any(test, feature = "test-instrumentation"))]
mod sqlite_work;

pub use account_db::AccountDb;
pub use account_db::home_migration::{HomeMigrationStateRow, HomeMigrationWrite};
pub use account_db::journal::{
    InboxFailurePolicy, InboxFailureSource, JournalBounds, JournalEvent,
};
pub use account_db::large_segments::{
    SegmentCleanupPage, SegmentDirection, SegmentOrphanSweep, SegmentPageEntry, SegmentReference,
    SegmentStore,
};
pub use account_db::object_retention::{
    ObjectReferenceAdmission, ObjectReferenceOwner, ObjectResourceRetirement, ObjectRetention,
    ObjectRetirementObserver, PreSendObjectHold, PrivacyResourceRegistration,
};
pub use account_db::raw_inner::{
    KnownContentEvidence, RawInnerCopy, RawInnerCopyKind, RawInnerCopyWrite, RawInnerQuota,
    RawInnerQuotaScope,
};
pub use account_db::runtime::{AccountOutboxEntry, OperationLookup};
pub use account_db::safety_verification::LEGACY_SAFETY_VERIFICATION_MARKER;
pub use account_index::AccountIndex;
pub use clock::{AccountClock, unix_now};
pub use constants::*;
pub use encryption::{
    AccountDbKey, AccountKeyWrappingProvider, EncryptionMode, FileVaultSecretSource,
    LocalVaultKeyWrappingProvider, VaultSecretSource, WrappedAccountDbKey,
    unwrap_with_vault_secret, wrap_with_vault_secret,
};
pub use error::StorageError;
pub use event_store::{EventStore, ProjectionStore};
pub use records::*;

#[cfg(test)]
mod contact_request_tests;
#[cfg(test)]
mod tests;

mod schema_shared_group;

pub use account_db::{NativeGrantAssociation, PendingAttachmentRetirement};
