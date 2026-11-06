// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant, closed username wire vocabulary. No service or production caller is enabled.
use serde::{Deserialize, Serialize};

mod codec;
pub use codec::*;

/// Frozen schema and comparison data identity; changing it needs an audited migration.
pub const SCHEMA_POLICY: &str = "username-ascii-uts39-us0.1.2-v1";
const RELEASE_ENABLED: bool = false;
/// The complete directory remains disabled until final activation.
#[must_use]
pub const fn enabled() -> bool {
    RELEASE_ENABLED
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Claim,
    Rename,
    Release,
    SetVisibility,
    Delete,
    MoveHome,
    ProfileUpdate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    Human,
    HeadlessAi,
    Bot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaType {
    #[serde(rename = "image/jpeg")]
    ImageJpeg,
    #[serde(rename = "image/png")]
    ImagePng,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    Reserved,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexState {
    Active,
    Reserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaKind {
    Reserve,
    Commit,
    Abort,
    Expire,
    Gc,
    Clock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuePhase {
    Reservation,
    Detail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    RootSlots,
    ActiveNames,
    HeldNames,
    PendingOperations,
    OperationDetails,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryCode {
    AuthenticationRequired,
    InvalidUsername,
    InvalidProfile,
    InvalidAvatar,
    UsernameTaken,
    UsernameHeld,
    UsernameReserved,
    RateLimited,
    Capacity,
    DirectoryUnavailable,
    UnsupportedVersion,
    OperationPending,
    StaleEpoch,
    Replay,
    OwnershipMismatch,
    SignatureInvalid,
    NotFound,
    KeyChanged,
    NameChanged,
    StaleProfile,
    ProfileRollback,
    ProfileEquivocation,
    ProfileDowngrade,
    ClockUnsafe,
    MigrationRequired,
    AccountDeleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub body: T,
    pub signature: String,
}
pub type UsernameBinding = Signed<UsernameBindingBody>;
pub type SignedIdentityProfileV2 = Signed<IdentityProfileV2Body>;
pub type UsernameOperation = Signed<UsernameOperationBody>;
pub type DirectoryReceipt = Signed<DirectoryReceiptBody>;
pub type DirectoryResolve = Signed<DirectoryResolveBody>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameBindingBody {
    pub name: String,
    pub node: String,
    pub principal_commitment: String,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRef {
    pub version: u8,
    pub epoch: u64,
    pub hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvatarRef {
    pub content_hash: String,
    pub media_type: MediaType,
    pub size: u64,
    pub relay_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProfileV2Body {
    pub schema: String,
    pub principal_id: String,
    pub principal_commitment: String,
    pub kind: ProfileKind,
    pub display_name: String,
    pub bio: String,
    pub avatar: Option<AvatarRef>,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameOperationBody {
    pub action: Action,
    pub operation_id: String,
    pub principal_commitment: String,
    pub expected_epoch: u64,
    pub next_epoch: u64,
    pub expected_profile: ProfileRef,
    pub profile: ProfileRef,
    pub old_name: Option<String>,
    pub binding: Option<UsernameBinding>,
    pub discoverable: bool,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryReceiptBody {
    pub center_id: String,
    pub operation_id: String,
    pub operation_hash: String,
    pub principal_commitment: String,
    pub epoch: u64,
    pub state: ReceiptState,
    pub binding_hash: Option<String>,
    pub profile: ProfileRef,
    pub discoverable: bool,
    pub committed_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryResolveBody {
    pub center_id: String,
    pub name: String,
    pub node: String,
    pub principal_commitment: String,
    pub epoch: u64,
    pub binding_hash: String,
    pub profile: ProfileRef,
    pub request_nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDecision {
    pub committed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootRow {
    pub epoch: u64,
    pub name: Option<String>,
    pub node: String,
    pub discoverable: bool,
    pub deleted: bool,
    pub profile: ProfileRef,
    pub binding_hash: Option<String>,
    pub current_binding: Option<UsernameBinding>,
    pub receipt_decision: Option<ReceiptDecision>,
    pub last_operation_id: Option<String>,
    pub last_operation_hash: Option<String>,
    pub pending_operation_id: Option<String>,
    pub changes: Vec<u64>,
    pub hold_deadlines: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameRow {
    pub root: String,
    pub state: IndexState,
    pub operation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkeletonRow {
    pub name: String,
    pub root: String,
    pub state: IndexState,
    pub operation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldKey {
    pub name: String,
    pub skeleton: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldRow {
    pub release_at: u64,
    pub hold_until: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationKey {
    pub root: String,
    pub operation_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRow {
    pub operation: UsernameOperation,
    pub operation_hash: String,
    pub state: ReceiptState,
    pub reserved_at: u64,
    pub reservation_expires_at: u64,
    pub finished_at: Option<u64>,
    pub retain_until: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationOwnerRow {
    pub root: String,
    pub operation_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DueRow {
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterRow {
    pub value: u64,
}

/// Single caller CAS for a witness-built delete pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedHead {
    pub lsn: u64,
    pub digest: String,
}

/// The witness derives both members; callers supply no rows or member identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletePreemptingPending {
    pub tx_id: String,
    pub operation: UsernameOperation,
    pub expected_head: ExpectedHead,
    pub requested_time: u64,
}

/// Original decision returned for an identical whole-request retry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchResult {
    pub abort_digest: String,
    pub delete_digest: String,
    pub clock_floor: u64,
}

/// Witness-owned metadata retaining the identity and result of an atomic pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRow {
    pub batch_id: String,
    pub root: String,
    pub request_hash: String,
    pub abort_tx_id: String,
    pub lsn_n1: u64,
    pub lsn_n2: u64,
    pub retain_until: u64,
    pub result: BatchResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointDelta {
    pub kind: DeltaKind,
    pub tx_id: String,
    pub writer_incarnation: String,
    pub clock_floor: u64,
    pub operation: Option<UsernameOperation>,
    pub rows: Vec<Replacement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub center_id: String,
    pub generation: u64,
    pub lsn: u64,
    pub previous_digest: String,
    pub delta: CheckpointDelta,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeRevalidateRequest {
    pub root: String,
    pub known_directory_epoch: u64,
    pub operation_id: Option<String>,
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeRevalidateResult {
    pub root: String,
    pub nonce: String,
    pub current_binding: Option<UsernameBinding>,
    pub current_receipt: Option<DirectoryReceipt>,
    pub pending_receipt: Option<DirectoryReceipt>,
    pub lookup_allowed: bool,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFailure {
    pub code: DirectoryCode,
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "table", rename_all = "snake_case", deny_unknown_fields)]
pub enum Replacement {
    Batch { key: String, old: Option<BatchRow>, new: Option<BatchRow> },
    Root { key: String, old: Option<RootRow>, new: Option<RootRow> },
    Name { key: String, old: Option<NameRow>, new: Option<NameRow> },
    Skeleton { key: String, old: Option<SkeletonRow>, new: Option<SkeletonRow> },
    Hold { key: HoldKey, old: Option<HoldRow>, new: Option<HoldRow> },
    Operation { key: OperationKey, old: Option<OperationRow>, new: Option<OperationRow> },
    OpOwner { key: String, old: Option<OperationOwnerRow>, new: Option<OperationOwnerRow> },
    Due { key: DueKey, old: Option<DueRow>, new: Option<DueRow> },
    Counter { key: CounterKey, old: Option<CounterRow>, new: Option<CounterRow> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DueKey {
    Hold { at: u64, name: String, skeleton: String },
    Operation { at: u64, root: String, operation_id: String, phase: DuePhase },
    RootWindow { at: u64, root: String },
    HomeHoldCredit { at: u64, home: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum CounterKey {
    Global { metric: Metric },
    Home { home: String, metric: Metric },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServeCandidate {
    Receipt {
        generation: u64,
        witness_boot: String,
        writer_incarnation: String,
        primary_lsn: u64,
        primary_digest: String,
        call_id: String,
        response: DirectoryReceipt,
    },
    Status {
        generation: u64,
        witness_boot: String,
        writer_incarnation: String,
        primary_lsn: u64,
        primary_digest: String,
        call_id: String,
        response: DirectoryReceipt,
    },
    Resolve {
        generation: u64,
        witness_boot: String,
        writer_incarnation: String,
        primary_lsn: u64,
        primary_digest: String,
        call_id: String,
        response: DirectoryResolve,
    },
    Refusal {
        generation: u64,
        witness_boot: String,
        writer_incarnation: String,
        primary_lsn: u64,
        primary_digest: String,
        call_id: String,
        response: DirectoryFailure,
    },
}

#[cfg(test)]
mod tests;
