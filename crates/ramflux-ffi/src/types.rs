// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Value types that cross the binding boundary. Shared by Swift and Kotlin.
//!
//! Bodies are message-schema ProtoJSON text (exact `u64` as decimal strings, field presence
//! preserved). The binding never re-encodes a body, so a field a host does not know survives.

/// Version of the binding API (not of the message schema, and not of the wire protocol).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ApiVersion {
    pub major: u32,
    pub minor: u32,
}

/// What the host was generated against. Sent once, when the core object is created.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct HostHandshake {
    /// Binding API version the host bindings were generated from.
    pub api: ApiVersion,
    /// Lower-case hex descriptor fingerprint the host models were generated from.
    pub descriptor_fingerprint: String,
    /// Capabilities the host asks for. Unknown names are ignored, never an error.
    pub capabilities: Vec<String>,
}

/// Result of version negotiation.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Negotiated {
    /// Binding API version of this core.
    pub core_api: ApiVersion,
    /// Lower-case hex fingerprint of the descriptor compiled into this core.
    pub core_descriptor_fingerprint: String,
    /// False when host and core models differ. Calls still work: content the host models do
    /// not know arrives as [`UpdateState::Unsupported`] rows, never as an error.
    pub descriptor_matches: bool,
    /// Intersection of requested and offered capabilities, sorted.
    pub capabilities: Vec<String>,
}

/// Where the host application keeps core data. The core never guesses a container path.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CoreConfig {
    /// Absolute data root inside the application's own container (iOS: a child of
    /// `Library/Application Support`; Android: a child of `getNoBackupFilesDir()`).
    pub data_root: String,
    pub handshake: HostHandshake,
    /// Largest number of update rows the core may hold for one subscription while the host
    /// has granted no credit. Past it the subscription reports a lag and the host re-reads.
    pub max_pending_updates: u32,
}

/// Lifecycle state of the in-process core.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CoreState {
    Stopped,
    Running,
    Suspended,
}

/// Evidence returned by a completed suspension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SuspendEvidence {
    /// The supervisor thread exited, which closes every database connection it owned.
    pub supervisor_joined: bool,
    /// A fresh descriptor took and dropped the exclusive data-root lock after the join.
    pub data_root_lock_released: bool,
    /// Wall time of the suspension in milliseconds.
    pub elapsed_ms: u64,
}

/// A change of the default network, reported by the host's path monitor.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NetworkChange {
    /// A usable default network appeared. `label` is opaque and hashed by the core.
    Available { label: Vec<u8> },
    /// The default interface, address or NAT64 prefix changed while connected.
    Changed { label: Vec<u8> },
    /// There is no default network.
    Lost,
}

/// One request to the core.
///
/// `Debug` prints the body length, never the body: a body may carry a passphrase.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoreRequest {
    /// Method name from the API descriptor, for example `account.create`.
    pub method: String,
    /// Account the request addresses, or `None` for a process-level method.
    pub account_id: Option<String>,
    /// ProtoJSON request body.
    pub body_json: String,
    /// Time allowed, in milliseconds from the call. Zero is rejected.
    pub deadline_ms: u64,
    /// Caller-chosen operation key of a mutation. The binding never invents, changes or
    /// reuses one, and never retries on the caller's behalf.
    pub operation_id: Option<String>,
}

/// A completed reply. `Debug` prints the body length, never the body.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoreResponse {
    pub method: String,
    pub account_id: Option<String>,
    /// ProtoJSON response body.
    pub body_json: String,
    /// The operation key the core executed under, echoed unchanged.
    pub operation_id: Option<String>,
}

impl std::fmt::Debug for CoreRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreRequest")
            .field("method", &self.method)
            .field("account_id", &self.account_id)
            .field("body_bytes", &self.body_json.len())
            .field("deadline_ms", &self.deadline_ms)
            .field("operation_id", &self.operation_id)
            .finish()
    }
}

impl std::fmt::Debug for CoreResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoreResponse")
            .field("method", &self.method)
            .field("account_id", &self.account_id)
            .field("body_bytes", &self.body_json.len())
            .field("operation_id", &self.operation_id)
            .finish()
    }
}

/// Why the caller stopped waiting before a reply arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum WaiterEnd {
    /// The host cancelled through the [`crate::CancelHandle`].
    Cancelled,
    /// The request deadline passed.
    Deadline,
    /// The core dropped the reply channel (for example it was suspended or closed).
    ReplyLost,
}

/// Outcome of `execute`. A cancelled or lost waiter is deliberately not an error: the two
/// cancelled cases mean different things and the host must not confuse them.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ExecuteOutcome {
    /// The core replied.
    Completed { response: CoreResponse },
    /// The waiter ended before the core claimed the request. Proven: nothing was executed
    /// and nothing will be.
    EndedBeforeClaim { end: WaiterEnd },
    /// The waiter ended after the core claimed the request. The core keeps executing and
    /// keeps the receipt. The effect is UNKNOWN to this caller: a send may have happened.
    /// Reconcile by reading the operation under `operation_id`. Do not retry with a new key.
    EndedAfterClaim { end: WaiterEnd, operation_id: Option<String>, lifecycle: bool },
}

/// What a subscription wants to receive.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SubscribeFilter {
    /// Account whose updates are wanted, or `None` for process-level topics only.
    pub account_id: Option<String>,
    /// Topic names from the API descriptor. Empty means every topic the scope allows.
    pub topics: Vec<String>,
    /// Resume after this journal sequence. `None` starts at the live edge.
    pub after_journal_sequence: Option<u64>,
    /// Update rows the host is ready to take before its first `grant`.
    pub initial_credit: u32,
}

/// The state carried by one update row.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UpdateState {
    /// Content the compiled schema knows. `json` is the ProtoJSON `Content`.
    Content { json: String },
    /// Content this core cannot interpret. This is a successful row, not an error; `json`
    /// is the ProtoJSON `UnsupportedView`.
    Unsupported { json: String },
    /// A deletion. `json` is the ProtoJSON `Delete`.
    Tombstone { json: String },
    /// A row whose state case this binding version does not know. Still a successful row;
    /// `json` is the whole update.
    Unknown { json: String },
}

/// One typed update row.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UpdateRow {
    pub topic: String,
    pub account_id: Option<String>,
    /// Journal sequence of the row; the resume point after the host has applied it.
    pub journal_sequence: u64,
    /// ProtoJSON `EventIdentity`, when the row has one.
    pub identity_json: Option<String>,
    pub state: UpdateState,
}

/// Why a subscription ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SubscriptionEnd {
    /// The host called `cancel`.
    Cancelled,
    /// The core was suspended; subscribe again after `resume`.
    Suspended,
    /// The core was closed.
    Closed,
    /// The listener returned an error or the core failed; see the lag/resume point.
    Failed,
}
