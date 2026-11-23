// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed client for the PRX management API.
//!
//! The client talks to a PRX daemon on loopback with a bearer token. It knows
//! nothing about ramflux accounts, custody or the bus. Every route is
//! documented in PRX's token document (`docs/rf-contract/capability-tokens.md`
//! at the pinned commit); unknown 2xx fields and malformed bodies fail closed.

#![allow(clippy::module_name_repetitions)]

mod agent;
mod apply;
mod approvals;
mod automation;
mod autonomy;
mod capabilities;
mod catalog;
mod client;
mod delete;
mod erase;
mod error;
mod history;
mod job;
mod message;
mod name;
mod owner;
mod publish;
mod purge;
mod revision;
mod run;
mod session;
mod sync;
mod targeted;
#[cfg(test)]
mod test_support;
mod transport;

pub use agent::{
    AgentConfig, AgentLimits, AgentList, AgentReadback, AgentStatus, DEFAULT_APPROVAL_WAIT_SECS,
    MainReadback, PROMPT_MAX_BYTES, PutKind, PutOutcome, Retired, Tools,
};
pub use apply::ApplyOutcome;
pub use approvals::ApprovalReceipt;
pub use automation::{AutomationItem, AutomationKind};
pub use autonomy::Autonomy;
pub use capabilities::{
    AGENT_CATALOG_V1, AGENT_CRUD_V1, AGENT_LIMITS_V1, AGENT_MAIN_READBACK_V1,
    AGENT_MEMORY_PURGE_V1, BuildCommit, CAPABILITIES_V1, Capabilities, HISTORY_ERASE_V1,
    HOST_BOOTSTRAP_V1, LimitsFacts, MESSAGE_CONTEXT_DELIVERY_V1, MESSAGE_DELETE_V1,
    MESSAGE_FORGET_WRITES_V1, MESSAGE_IDEMPOTENCY_V1, MESSAGE_TARGET_V1, OWNER_ID_STABLE_V1,
    RUN_APPROVALS_V1, SESSION_KEY_V1, STREAM_FRAMES_V1, SYNC_SNAPSHOT_V1, SYNC_WS_V1,
    TARGETED_AGENTS_V1, require,
};
pub use catalog::{Catalog, CatalogModel, CatalogTool};
pub use client::PrxClient;
pub use delete::{
    AgentRuns, BatchItem, EraseForEveryone, EraseNotice, ForgetCounts, ForgetReport, ForgetWrites,
    Forgotten, MessageDeleted, ReplyDeleted,
};
pub use erase::{EraseHistory, HistoryErased, HistoryForgotten, HistoryScope};
pub use error::{ApiCode, NotReadyReason, PrxError, limit_or_rate};
pub use history::{HistoryRow, RowBody};
pub use job::{JobState, JobStatus};
pub use message::{
    Chat, ChatKind, ContextRecorded, RfMessage, Sender, Target, TurnAccepted, TurnDisposition,
};
pub use name::AgentName;
pub use owner::OwnerId;
pub use publish::{NamedLimits, publish_named_limits};
pub use purge::{PURGE_STORES, PurgeReceipt};
pub use revision::{CatalogRevision, ConfigRevision};
pub use run::{JobCancel, RunCancel, RunCode, RunState};
pub use session::SessionCreated;
pub use sync::{
    ApprovalCopy, EraseCopy, JournalEvent, LiveBody, LiveNotice, MirrorOp, PONG_FRAME,
    SNAPSHOT_MAX_BODY, SNAPSHOT_PAGE_LIMIT, ServerFrame, SnapshotPage, SnapshotRow, SyncCursor,
    SyncDial, TurnBody, TurnCopy, ack_frame, decode_server, format_cursor, hello_frame,
    parse_cursor,
};
pub use targeted::{ReloadReport, ReloadStatus, TargetedAgents};
pub use transport::{ClientConfig, DEFAULT_MAX_BODY_BYTES, DEFAULT_REQUEST_TIMEOUT};
