// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The client side of `dm_order` (spec §3.1, §3.3, §3.4): wire types of the `DmOrder` frame, the
//! per-conversation state (`mls/conv/<scope>`), `submit` / `since` / `status`, first contact and
//! re-establish, the switch-over to the group the orderer names, the 7-day read-only old group and
//! the orderer-down backoff.
//!
//! Rules kept here:
//!
//! * Rule V: nothing in this file reads a clock to decide whether a commit or Welcome is valid.
//!   `now` is passed in and only schedules (read-only window, backoff, pending age).
//! * The orderer names the current group. A Welcome alone never switches `mls/conv/<scope>`;
//!   [`reconcile`] switches when `status` names a group this device has already joined.
//! * An own commit is merged locally by the facade before it is submitted. Its bytes are kept as
//!   the conversation's `pending` commit until the orderer accepts, so a lost answer, a down
//!   orderer or a rate limit re-submits the same bytes. A log entry at the pending epoch that is
//!   not the pending commit is a fork ([`CatchUpOutcome::Forked`]): the recovery is
//!   [`establish`] with [`EstablishKind::ReEstablish`].
//!
//! The gateway answers `Nack mls_dm_frames_unsupported` until the node wires the frames; every
//! driver reports that as `NotYetAvailable`.
#![allow(dead_code, reason = "MLS: allowance removed in D4a")]

use ramflux_mls::{
    ConversationRole, GroupKind, Mls, MlsError, MlsKv, MlsKvError, ReceivedMessage, RfConversation,
    WriteBatch, WriteOp,
};
use ramflux_protocol::message::dm_scope::{self, MLS_KIND_DM, MLS_KIND_SELF};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::key_packages::{FetchedKeyPackage, b64};
use crate::SdkError;
use crate::gateway::access::MlsFrameAccess;

/// `submit` per anchor per minute at the orderer.
pub(crate) const SUBMIT_PER_MINUTE: usize = 30;
/// `since` per anchor per minute.
pub(crate) const SINCE_PER_MINUTE: usize = 120;
/// `status` per anchor per minute.
pub(crate) const STATUS_PER_MINUTE: usize = 60;
/// Most commits in one `since` answer.
pub(crate) const SINCE_MAX_ENTRIES: usize = 64;
/// Largest commit the orderer accepts.
pub(crate) const COMMIT_MAX_BYTES: usize = 1 << 20;
/// Nonce length of a derived group id.
pub(crate) const GROUP_NONCE_BYTES: usize = 16;
/// How long the old group stays readable after a switch-over (7 days).
pub(crate) const OLD_GROUP_READ_ONLY_SECS: u64 = 7 * 86_400;
/// An own commit unanswered this long is looked up with `since` (30 s).
pub(crate) const PENDING_LOOKUP_SECS: u64 = 30;
/// Most `since` pages one catch-up reads (bounds the loop at the orderer's 4 096 hard cap).
const CATCH_UP_MAX_PAGES: usize = 64;
/// First delay of the orderer-down backoff.
const BACKOFF_BASE_SECS: u64 = 5;
/// Largest delay of the orderer-down backoff.
const BACKOFF_MAX_SECS: u64 = 900;
/// Row label of the conversation state, keyed by scope id.
const CONV_LABEL: &str = "mls/conv";
/// Row label of the reverse index, keyed by group id (current and old group) to the scope id.
const CONV_GROUP_LABEL: &str = "mls/conv_group";
/// Largest stored conversation row (the pending commit is at most 1 MiB, base64 inflates it).
const CONV_ROW_MAX_BYTES: usize = 2 << 20;
/// The gateway's answer while the DM frames are not wired.
pub(crate) const UNSUPPORTED_NACK: &str = "mls_dm_frames_unsupported";
const UNAVAILABLE_CODE: &str = "dm_frames_unsupported";

/// The typed error of the not-yet-wired gateway answer.
pub(crate) fn not_yet_available() -> SdkError {
    SdkError::Mls {
        code: UNAVAILABLE_CODE,
        detail: "the node does not serve the MLS DM frames yet".to_owned(),
    }
}

/// True for the error [`not_yet_available`] builds.
pub(crate) fn is_not_yet_available(error: &SdkError) -> bool {
    matches!(error, SdkError::Mls { code, .. } if *code == UNAVAILABLE_CODE)
}

/// Kind of an ordered group.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DmGroupKind {
    /// A one-to-one DM between two anchors.
    Dm,
    /// The own-device group of one anchor.
    #[serde(rename = "self")]
    SelfGroup,
}

impl DmGroupKind {
    const fn byte(self) -> u8 {
        match self {
            Self::Dm => MLS_KIND_DM,
            Self::SelfGroup => MLS_KIND_SELF,
        }
    }

    const fn mls_kind(self) -> GroupKind {
        match self {
            Self::Dm => GroupKind::Dm,
            Self::SelfGroup => GroupKind::Own,
        }
    }

    const fn role(self) -> ConversationRole {
        match self {
            Self::Dm => ConversationRole::Dm,
            Self::SelfGroup => ConversationRole::Own,
        }
    }
}

/// Which special submit this is.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DmSubmitFlag {
    /// First commit of a scope.
    Create,
    /// A new group replaces the scope's current one (lost state, fork).
    ReEstablish,
}

/// `submit`: one commit to order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DmSubmit {
    /// The group the commit belongs to.
    #[serde(with = "b64")]
    pub group_id: Vec<u8>,
    /// Kind of the group.
    pub kind: DmGroupKind,
    /// Conversation scope (`dm:` id as UTF-8, or the 32 byte self scope).
    #[serde(with = "b64")]
    pub scope_id: Vec<u8>,
    /// Epoch the commit was made in.
    pub epoch: u64,
    /// The commit, an MLS `PrivateMessage` (at most 1 MiB).
    #[serde(with = "b64")]
    pub commit: Vec<u8>,
    /// `create` or `re_establish`; absent for an ordinary commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag: Option<DmSubmitFlag>,
    /// Group id nonce (16 bytes) of a `create` or `re_establish`.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "b64")]
    pub nonce: Vec<u8>,
    /// Anchors of the group (two for a dm, one for self); `create` and `re_establish` carry them
    /// so the orderer can bind them to `scope_id`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<String>,
}

/// `since`: commits after `log_seq`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DmSince {
    /// The group.
    #[serde(with = "b64")]
    pub group_id: Vec<u8>,
    /// The highest `log_seq` the requester already has (0: none).
    pub log_seq: u64,
}

/// `status`: the current group of a scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DmStatus {
    /// Kind of the scope.
    pub kind: DmGroupKind,
    /// The scope id.
    #[serde(with = "b64")]
    pub scope_id: Vec<u8>,
}

/// One `dm_order` request body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DmOrderOp {
    /// Order a commit.
    Submit(DmSubmit),
    /// Fetch commits.
    Since(DmSince),
    /// Ask for the current group of a scope.
    Status(DmStatus),
}

/// Why a request was refused.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DmRefusal {
    /// Malformed field or missing flag input.
    BadRequest,
    /// The commit is empty or over 1 MiB.
    TooLarge,
    /// The outer header is not a commit of the named group and epoch.
    HeaderMismatch,
    /// `group_id` is not `BLAKE3(MLS_GROUP_ID_V1 || kind || scope_id || nonce)`.
    GroupDerivation,
    /// The kind, scope or anchors do not bind together.
    ScopeMismatch,
    /// The requester's anchor is not one of the group's anchors.
    NotMember,
    /// No such group on this node.
    UnknownGroup,
}

/// One commit of a `since` answer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DmCommitEntry {
    /// Position in the group's log.
    pub log_seq: u64,
    /// Epoch the commit was made in.
    pub epoch: u64,
    /// Node that submitted it.
    pub origin_node: String,
    /// The commit.
    #[serde(with = "b64")]
    pub commit: Vec<u8>,
}

/// One `dm_order` answer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum DmOrderReply {
    /// The commit is ordered; `epoch` and `log_seq` are the new head.
    Accepted {
        /// Head epoch after the commit.
        epoch: u64,
        /// Log position of the commit.
        log_seq: u64,
    },
    /// The commit's epoch is not the head's: apply what is missing.
    Stale {
        /// Head epoch.
        epoch: u64,
        /// Head log position.
        log_seq: u64,
    },
    /// The scope already has a group.
    ScopeTaken {
        /// Its current group.
        #[serde(with = "b64")]
        group_id: Vec<u8>,
    },
    /// The group id was used before.
    GroupTaken,
    /// The group was replaced; use this one.
    Replaced {
        /// The replacing group.
        #[serde(with = "b64")]
        group_id: Vec<u8>,
    },
    /// Refused.
    Refused {
        /// Why.
        code: DmRefusal,
    },
    /// Over a limit.
    RateLimited {
        /// Seconds until the next try may succeed.
        retry_after: u64,
    },
    /// Commits after the requested position.
    Commits {
        /// At most 64 entries.
        entries: Vec<DmCommitEntry>,
        /// More follow.
        more: bool,
    },
    /// The requested position is older than the retained log; re-establish.
    Pruned,
    /// The current group of a scope.
    Status {
        /// Current group.
        #[serde(with = "b64")]
        group_id: Vec<u8>,
        /// Head epoch.
        epoch: u64,
        /// Head log position.
        log_seq: u64,
    },
    /// No group for the scope on this node.
    UnknownScope,
}

/// What a conversation is ordered under: its kind, scope id and the anchors the orderer binds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Scope {
    pub(crate) kind: DmGroupKind,
    pub(crate) conversation_id: Vec<u8>,
    pub(crate) anchors: Vec<String>,
}

impl Scope {
    /// The scope of the DM between two anchors.
    ///
    /// # Errors
    /// Malformed or equal anchors.
    pub(crate) fn dm(own: &str, peer: &str) -> Result<Self, SdkError> {
        let binding = RfConversation::dm(own, peer)?;
        Ok(Self {
            kind: DmGroupKind::Dm,
            conversation_id: binding.conversation_id,
            anchors: vec![own.to_owned(), peer.to_owned()],
        })
    }

    /// The scope of the own-device group of `anchor`.
    pub(crate) fn own(anchor: &str) -> Self {
        Self {
            kind: DmGroupKind::SelfGroup,
            conversation_id: RfConversation::own(anchor).conversation_id,
            anchors: vec![anchor.to_owned()],
        }
    }

    fn binding(&self) -> RfConversation {
        RfConversation { role: self.kind.role(), conversation_id: self.conversation_id.clone() }
    }
}

/// The group this device read from before a switch-over.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct OldGroup {
    #[serde(with = "b64")]
    pub(crate) group_id: Vec<u8>,
    /// Unix second the read-only window ends.
    pub(crate) read_only_until: u64,
}

/// An own commit merged locally and not yet accepted by the orderer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PendingCommit {
    /// Epoch the commit was made in.
    pub(crate) epoch: u64,
    #[serde(with = "b64")]
    pub(crate) commit: Vec<u8>,
    /// Unix second of the first submit attempt.
    pub(crate) submitted_at: u64,
}

/// `mls/conv/<scope>`: the state of one conversation's MLS group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ConvState {
    /// The group the orderer named as current.
    #[serde(with = "b64")]
    pub(crate) group_id: Vec<u8>,
    /// Highest log position applied (0: none).
    pub(crate) log_seq: u64,
    /// The previous group, readable for 7 days after the switch-over.
    pub(crate) old: Option<OldGroup>,
    /// The own commit awaiting the orderer.
    pub(crate) pending: Option<PendingCommit>,
    /// Unix second the own leaf was created or last updated.
    pub(crate) leaf_updated_at: u64,
    /// Epoch the generation counter below belongs to.
    pub(crate) generations_epoch: u64,
    /// Application messages sealed by this device in `generations_epoch`.
    pub(crate) generations: u64,
    /// This device was removed from the group.
    pub(crate) removed: bool,
}

impl ConvState {
    /// The state of a group this device just created or joined and the orderer named.
    pub(crate) fn new(group_id: Vec<u8>, log_seq: u64, now: u64) -> Self {
        Self {
            group_id,
            log_seq,
            old: None,
            pending: None,
            leaf_updated_at: now,
            generations_epoch: 0,
            generations: 0,
            removed: false,
        }
    }

    /// Whether `group_id` may be read at `now`: the current group, or the old one inside its
    /// read-only window. Sending is only ever allowed in the current group.
    pub(crate) fn readable(&self, group_id: &[u8], now: u64) -> bool {
        self.group_id == group_id
            || self
                .old
                .as_ref()
                .is_some_and(|old| old.group_id == group_id && now < old.read_only_until)
    }

    /// Drop the old group once its window has ended; true when something was dropped.
    pub(crate) fn expire_old(&mut self, now: u64) -> bool {
        if self.old.as_ref().is_some_and(|old| now >= old.read_only_until) {
            self.old = None;
            return true;
        }
        false
    }

    /// An own commit is waiting and its last attempt is old enough for a `since` lookup.
    pub(crate) fn pending_lookup_due(&self, now: u64) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| now.saturating_sub(pending.submitted_at) >= PENDING_LOOKUP_SECS)
    }

    /// Point the conversation at `group_id`, keeping the previous group readable for 7 days.
    fn switch_to(&mut self, group_id: Vec<u8>, log_seq: u64, now: u64) {
        if self.group_id == group_id {
            return;
        }
        let previous = std::mem::replace(&mut self.group_id, group_id);
        self.old = Some(OldGroup {
            group_id: previous,
            read_only_until: now.saturating_add(OLD_GROUP_READ_ONLY_SECS),
        });
        self.log_seq = log_seq;
        self.pending = None;
        self.leaf_updated_at = now;
        self.generations_epoch = 0;
        self.generations = 0;
        self.removed = false;
    }
}

fn kv_error(error: MlsKvError) -> SdkError {
    SdkError::from(MlsError::from(error))
}

fn conv_error(detail: &str) -> SdkError {
    SdkError::Mls { code: "internal", detail: format!("conversation state: {detail}") }
}

/// Reads and writes `mls/conv/<scope>` rows on the MLS key-value store.
pub(crate) struct ConvStore<'a, K: MlsKv> {
    kv: &'a K,
}

impl<'a, K: MlsKv> ConvStore<'a, K> {
    pub(crate) fn new(kv: &'a K) -> Self {
        Self { kv }
    }

    /// The state of `scope_id`, if the conversation has a group.
    ///
    /// # Errors
    /// Storage failure or a corrupt row.
    pub(crate) fn get(&self, scope_id: &[u8]) -> Result<Option<ConvState>, SdkError> {
        let Some(row) = self.kv.get(CONV_LABEL, scope_id).map_err(kv_error)? else {
            return Ok(None);
        };
        if row.len() > CONV_ROW_MAX_BYTES {
            return Err(conv_error("row exceeds the decode bound"));
        }
        serde_json::from_slice(&row).map(Some).map_err(|_| conv_error("row does not decode"))
    }

    /// The scope a group (current or old) belongs to.
    ///
    /// # Errors
    /// Storage failure.
    pub(crate) fn scope_of(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, SdkError> {
        Ok(self
            .kv
            .get(CONV_GROUP_LABEL, group_id)
            .map_err(kv_error)?
            .map(|row| row.as_slice().to_vec()))
    }

    /// Persist `state` and index its groups, in one transaction.
    ///
    /// # Errors
    /// Storage failure or an encode failure.
    pub(crate) fn put(&self, scope_id: &[u8], state: &ConvState) -> Result<(), SdkError> {
        let encoded = serde_json::to_vec(state).map_err(|_| conv_error("state does not encode"))?;
        let mut ops = vec![WriteOp::Put {
            label: CONV_LABEL.to_owned(),
            key: scope_id.to_vec(),
            value: Zeroizing::new(encoded),
        }];
        for group_id in
            std::iter::once(&state.group_id).chain(state.old.iter().map(|old| &old.group_id))
        {
            ops.push(WriteOp::Put {
                label: CONV_GROUP_LABEL.to_owned(),
                key: group_id.clone(),
                value: Zeroizing::new(scope_id.to_vec()),
            });
        }
        self.kv
            .commit_batch(WriteBatch { ops, epoch_changed: false }, |_tx| Ok(()))
            .map_err(kv_error)
    }

    fn require(&self, scope: &Scope) -> Result<ConvState, SdkError> {
        self.get(&scope.conversation_id)?.ok_or_else(|| SdkError::Mls {
            code: "not_found",
            detail: "the conversation has no MLS group".to_owned(),
        })
    }
}

/// Orderer-down backoff (spec §3.1): exponential from 5 s to 15 min, never shorter than a
/// `rate_limited` answer asked for. Pure; the caller supplies the time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Backoff {
    failures: u32,
    not_before: u64,
}

impl Backoff {
    /// Delay after `failures` consecutive failures (1 is the first).
    pub(crate) fn delay_secs(failures: u32) -> u64 {
        let shift = failures.saturating_sub(1).min(16);
        BACKOFF_BASE_SECS.saturating_mul(1_u64 << shift).min(BACKOFF_MAX_SECS)
    }

    /// Record a failed attempt at `now`; `retry_after` is the orderer's own wait, if it gave one.
    pub(crate) fn on_failure(&mut self, now: u64, retry_after: Option<u64>) {
        self.failures = self.failures.saturating_add(1);
        let wait = Self::delay_secs(self.failures).max(retry_after.unwrap_or(0));
        self.not_before = now.saturating_add(wait);
    }

    /// Record an answer from the orderer.
    pub(crate) fn on_success(&mut self) {
        *self = Self::default();
    }

    /// Whether an attempt may be made at `now`.
    pub(crate) fn ready(&self, now: u64) -> bool {
        now >= self.not_before
    }

    /// Whether the conversation should show as pending (the orderer failed at least once).
    pub(crate) fn is_pending(&self) -> bool {
        self.failures > 0
    }
}

/// A `submit` answer, classified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SubmitOutcome {
    /// Ordered at this position.
    Accepted { epoch: u64, log_seq: u64 },
    /// Another commit took the epoch; catch up.
    Stale { epoch: u64, log_seq: u64 },
    /// The scope already has this group.
    ScopeTaken { group_id: Vec<u8> },
    /// The group id was used before.
    GroupTaken,
    /// This group was replaced by `group_id`.
    Replaced { group_id: Vec<u8> },
    /// The orderer refused the request.
    Refused(DmRefusal),
    /// Over a limit.
    RateLimited { retry_after: u64 },
    /// The node does not serve the frames yet.
    NotYetAvailable,
}

/// Classify a `submit` answer.
///
/// # Errors
/// An answer that no `submit` can produce.
pub(crate) fn classify_submit(reply: DmOrderReply) -> Result<SubmitOutcome, SdkError> {
    Ok(match reply {
        DmOrderReply::Accepted { epoch, log_seq } => SubmitOutcome::Accepted { epoch, log_seq },
        DmOrderReply::Stale { epoch, log_seq } => SubmitOutcome::Stale { epoch, log_seq },
        DmOrderReply::ScopeTaken { group_id } => SubmitOutcome::ScopeTaken { group_id },
        DmOrderReply::GroupTaken => SubmitOutcome::GroupTaken,
        DmOrderReply::Replaced { group_id } => SubmitOutcome::Replaced { group_id },
        DmOrderReply::Refused { code } => SubmitOutcome::Refused(code),
        DmOrderReply::RateLimited { retry_after } => SubmitOutcome::RateLimited { retry_after },
        DmOrderReply::Commits { .. }
        | DmOrderReply::Pruned
        | DmOrderReply::Status { .. }
        | DmOrderReply::UnknownScope => return Err(unexpected("submit")),
    })
}

fn unexpected(op: &str) -> SdkError {
    SdkError::Mls { code: "internal", detail: format!("unexpected dm_order answer to {op}") }
}

fn refused_error(code: DmRefusal) -> SdkError {
    SdkError::Mls { code: "dm_order_refused", detail: format!("the orderer refused: {code:?}") }
}

async fn call(
    access: &mut impl MlsFrameAccess,
    request: DmOrderOp,
) -> Result<Option<DmOrderReply>, SdkError> {
    match access.dm_order(request).await {
        Ok(reply) => Ok(Some(reply)),
        Err(error) if is_not_yet_available(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Submit one commit.
///
/// # Errors
/// A commit over 1 MiB, gateway failures other than the not-yet-available answer, an answer that
/// no `submit` can produce.
pub(crate) async fn submit(
    access: &mut impl MlsFrameAccess,
    request: DmSubmit,
) -> Result<SubmitOutcome, SdkError> {
    if request.commit.is_empty() || request.commit.len() > COMMIT_MAX_BYTES {
        return Err(SdkError::Mls {
            code: "too_large",
            detail: "a commit is empty or over 1 MiB".to_owned(),
        });
    }
    match call(access, DmOrderOp::Submit(request)).await? {
        Some(reply) => classify_submit(reply),
        None => Ok(SubmitOutcome::NotYetAvailable),
    }
}

/// How a catch-up ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CatchUpOutcome {
    /// Every commit up to the head is applied; the log position is `log_seq`.
    Current { log_seq: u64 },
    /// A commit removed this device from the group.
    Removed,
    /// A commit could not be applied, or a competing commit took the pending commit's epoch:
    /// re-establish.
    Forked,
    /// The orderer replaced the group; reconcile.
    Replaced { group_id: Vec<u8> },
    /// The retained log no longer reaches back to the position; re-establish.
    Pruned,
    /// The node does not serve the frames yet.
    NotYetAvailable,
}

/// Applying one log entry.
enum Applied {
    Epoch(u64),
    Skipped,
    Removed,
    Failed,
}

fn apply_entry<K: MlsKv>(
    mls: &Mls<K>,
    state: &mut ConvState,
    local_epoch: u64,
    entry: &DmCommitEntry,
) -> Result<Applied, SdkError> {
    if let Some(pending) = &state.pending
        && entry.epoch >= pending.epoch
    {
        // The log reached the pending commit's epoch: it is ours or a fork.
        if entry.epoch == pending.epoch && entry.commit == pending.commit {
            state.pending = None;
            return Ok(Applied::Skipped);
        }
        return Ok(Applied::Failed);
    }
    if entry.epoch < local_epoch {
        return Ok(Applied::Skipped);
    }
    if entry.epoch > local_epoch {
        return Ok(Applied::Failed);
    }
    match mls.receive(&entry.commit) {
        Ok(staged) => match staged.commit_plain().map_err(MlsError::from)? {
            ReceivedMessage::Commit { epoch, removed: false } => Ok(Applied::Epoch(epoch)),
            ReceivedMessage::Commit { removed: true, .. } => Ok(Applied::Removed),
            ReceivedMessage::Own { .. } => Ok(Applied::Skipped),
            ReceivedMessage::Application { .. } | ReceivedMessage::Proposal { .. } => {
                Ok(Applied::Failed)
            }
        },
        Err(MlsError::Storage(error)) => Err(kv_error(error)),
        Err(MlsError::Internal(detail)) => Err(SdkError::Mls { code: "internal", detail }),
        Err(_) => Ok(Applied::Failed),
    }
}

/// Fetch and apply the commits after the conversation's log position, page by page.
///
/// # Errors
/// Storage failures, gateway failures other than the not-yet-available answer, an answer that
/// `since` cannot produce.
pub(crate) async fn catch_up<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
) -> Result<CatchUpOutcome, SdkError> {
    let mut state = store.require(scope)?;
    let mut local_epoch = mls.status(&state.group_id)?.epoch;
    for _ in 0..CATCH_UP_MAX_PAGES {
        let request =
            DmOrderOp::Since(DmSince { group_id: state.group_id.clone(), log_seq: state.log_seq });
        let Some(reply) = call(access, request).await? else {
            return Ok(CatchUpOutcome::NotYetAvailable);
        };
        let (entries, more) = match reply {
            DmOrderReply::Commits { entries, more } => (entries, more),
            DmOrderReply::Replaced { group_id } => {
                return Ok(CatchUpOutcome::Replaced { group_id });
            }
            DmOrderReply::Pruned => return Ok(CatchUpOutcome::Pruned),
            _ => return Err(unexpected("since")),
        };
        if entries.is_empty() {
            return Ok(CatchUpOutcome::Current { log_seq: state.log_seq });
        }
        for entry in &entries {
            if entry.log_seq <= state.log_seq {
                return Err(unexpected("since (log position went backwards)"));
            }
            match apply_entry(mls, &mut state, local_epoch, entry)? {
                Applied::Epoch(epoch) => local_epoch = epoch,
                Applied::Skipped => {}
                Applied::Removed => {
                    state.removed = true;
                    state.log_seq = entry.log_seq;
                    store.put(&scope.conversation_id, &state)?;
                    return Ok(CatchUpOutcome::Removed);
                }
                Applied::Failed => return Ok(CatchUpOutcome::Forked),
            }
            state.log_seq = entry.log_seq;
        }
        store.put(&scope.conversation_id, &state)?;
        if !more {
            return Ok(CatchUpOutcome::Current { log_seq: state.log_seq });
        }
    }
    Ok(CatchUpOutcome::Current { log_seq: state.log_seq })
}

/// What `status` said.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StatusOutcome {
    /// The orderer's current group of the scope.
    Group { group_id: Vec<u8>, epoch: u64, log_seq: u64 },
    /// The orderer has no group for the scope (first contact, or after a home migration).
    UnknownScope,
    /// The node does not serve the frames yet.
    NotYetAvailable,
}

/// Ask the orderer for the current group of the scope.
///
/// # Errors
/// Gateway failures other than the not-yet-available answer, an answer `status` cannot produce.
pub(crate) async fn status(
    access: &mut impl MlsFrameAccess,
    scope: &Scope,
) -> Result<StatusOutcome, SdkError> {
    let request =
        DmOrderOp::Status(DmStatus { kind: scope.kind, scope_id: scope.conversation_id.clone() });
    match call(access, request).await? {
        None => Ok(StatusOutcome::NotYetAvailable),
        Some(DmOrderReply::Status { group_id, epoch, log_seq }) => {
            Ok(StatusOutcome::Group { group_id, epoch, log_seq })
        }
        Some(DmOrderReply::UnknownScope) => Ok(StatusOutcome::UnknownScope),
        Some(DmOrderReply::RateLimited { retry_after }) => Err(SdkError::Mls {
            code: "rate_limited",
            detail: format!("status rate limited, retry after {retry_after} s"),
        }),
        Some(_) => Err(unexpected("status")),
    }
}

/// How a reconcile ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReconcileOutcome {
    /// The local current group is the orderer's.
    InSync { group_id: Vec<u8> },
    /// The conversation now points at the group the orderer named.
    Switched { group_id: Vec<u8> },
    /// The orderer names a group this device has not joined; its Welcome has not arrived.
    WaitingForWelcome { group_id: Vec<u8> },
    /// The orderer has no group for the scope.
    UnknownScope,
    /// The node does not serve the frames yet.
    NotYetAvailable,
}

/// Compare the local current group with the orderer's and switch only when the orderer names a
/// group this device has already joined (a Welcome alone never switches).
///
/// # Errors
/// Storage failures and the errors of [`status`].
pub(crate) async fn reconcile<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    now: u64,
) -> Result<ReconcileOutcome, SdkError> {
    let (group_id, head_epoch, head_log_seq) = match status(access, scope).await? {
        StatusOutcome::NotYetAvailable => return Ok(ReconcileOutcome::NotYetAvailable),
        StatusOutcome::UnknownScope => return Ok(ReconcileOutcome::UnknownScope),
        StatusOutcome::Group { group_id, epoch, log_seq } => (group_id, epoch, log_seq),
    };
    let current = store.get(&scope.conversation_id)?;
    if current.as_ref().is_some_and(|state| state.group_id == group_id) {
        return Ok(ReconcileOutcome::InSync { group_id });
    }
    let Ok(joined) = mls.status(&group_id) else {
        return Ok(ReconcileOutcome::WaitingForWelcome { group_id });
    };
    // A group joined by Welcome already holds the commits up to its epoch; the log position is
    // known only when that epoch is the head. Otherwise `since` starts at 0 and skips the entries
    // below the local epoch.
    let log_seq = if joined.epoch == head_epoch { head_log_seq } else { 0 };
    let mut state = match current {
        Some(mut state) => {
            state.switch_to(group_id.clone(), log_seq, now);
            state
        }
        None => ConvState::new(group_id.clone(), log_seq, now),
    };
    state.expire_old(now);
    store.put(&scope.conversation_id, &state)?;
    Ok(ReconcileOutcome::Switched { group_id })
}

/// Which first commit [`establish`] submits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EstablishKind {
    /// First contact: the scope has no group yet.
    Create,
    /// Lost state or a fork: a new group replaces the scope's current one.
    ReEstablish,
}

/// What [`establish`] creates a group for.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Establish<'a> {
    /// The conversation.
    pub(crate) scope: &'a Scope,
    /// One verified `KeyPackage` per device to add.
    pub(crate) key_packages: &'a [FetchedKeyPackage],
    /// First contact or re-establish.
    pub(crate) kind: EstablishKind,
}

/// How an establish ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EstablishOutcome {
    /// The orderer accepted the new group; fan the Welcome out as envelopes.
    Established { group_id: Vec<u8>, epoch: u64, log_seq: u64, welcome: Vec<u8> },
    /// Another device won the scope; follow the group the orderer names.
    LostRace(ReconcileOutcome),
    /// Over the limit with no group to follow; retry after the wait.
    RateLimited { retry_after: u64 },
    /// The node does not serve the frames yet.
    NotYetAvailable,
}

/// First contact and re-establish: create the group with the derived id, add every verified device
/// (`key_packages`), submit the commit with `create` or `re_establish`.
///
/// The caller verified each `KeyPackage` against the directory (spec §3.4) and holds the Welcome
/// until the orderer accepted. A lost race leaves the freshly created local group unreferenced.
///
/// # Errors
/// No `KeyPackages`, MLS failures, storage failures, an orderer refusal, gateway failures other
/// than the not-yet-available answer.
pub(crate) async fn establish<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    request: Establish<'_>,
    now: u64,
) -> Result<EstablishOutcome, SdkError> {
    let Establish { scope, key_packages, kind } = request;
    if key_packages.is_empty() {
        return Err(SdkError::Mls {
            code: "policy_rejected",
            detail: "a group needs at least one device to add".to_owned(),
        });
    }
    let mut nonce = [0_u8; GROUP_NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| SdkError::Mls {
        code: "rng_unavailable",
        detail: "the random source failed".to_owned(),
    })?;
    let group_id = dm_scope::mls_group_id(scope.kind.byte(), &scope.conversation_id, &nonce);
    let binding = scope.binding();
    mls.create_with(scope.kind.mls_kind(), None, Some(&binding), Some(group_id))?
        .commit_plain()
        .map_err(MlsError::from)?;
    let packages: Vec<Vec<u8>> =
        key_packages.iter().map(|entry| entry.key_package.clone()).collect();
    let added = mls.add(&group_id, &packages)?.commit_plain().map_err(MlsError::from)?;
    let flag = match kind {
        EstablishKind::Create => DmSubmitFlag::Create,
        EstablishKind::ReEstablish => DmSubmitFlag::ReEstablish,
    };
    let request = DmSubmit {
        group_id: group_id.to_vec(),
        kind: scope.kind,
        scope_id: scope.conversation_id.clone(),
        // `AddOutput::epoch` is the epoch after the commit; the orderer wants the one it was made in.
        epoch: added.epoch.saturating_sub(1),
        commit: added.commit,
        flag: Some(flag),
        nonce: nonce.to_vec(),
        anchors: scope.anchors.clone(),
    };
    match submit(access, request).await? {
        SubmitOutcome::Accepted { epoch, log_seq } => {
            let mut state = match store.get(&scope.conversation_id)? {
                Some(mut state) => {
                    state.switch_to(group_id.to_vec(), log_seq, now);
                    state
                }
                None => ConvState::new(group_id.to_vec(), log_seq, now),
            };
            state.expire_old(now);
            store.put(&scope.conversation_id, &state)?;
            Ok(EstablishOutcome::Established {
                group_id: group_id.to_vec(),
                epoch,
                log_seq,
                welcome: added.welcome,
            })
        }
        SubmitOutcome::NotYetAvailable => Ok(EstablishOutcome::NotYetAvailable),
        SubmitOutcome::ScopeTaken { .. } | SubmitOutcome::Replaced { .. } => {
            Ok(EstablishOutcome::LostRace(reconcile(access, mls, store, scope, now).await?))
        }
        SubmitOutcome::RateLimited { retry_after } if kind == EstablishKind::ReEstablish => {
            // The losing re-establish: the winner's group is the scope's current one.
            match reconcile(access, mls, store, scope, now).await? {
                ReconcileOutcome::UnknownScope => Ok(EstablishOutcome::RateLimited { retry_after }),
                other => Ok(EstablishOutcome::LostRace(other)),
            }
        }
        SubmitOutcome::RateLimited { retry_after } => {
            Ok(EstablishOutcome::RateLimited { retry_after })
        }
        SubmitOutcome::Refused(code) => Err(refused_error(code)),
        SubmitOutcome::GroupTaken | SubmitOutcome::Stale { .. } => Err(SdkError::Mls {
            code: "dm_order_refused",
            detail: "the orderer answered a first commit with a group or epoch conflict".to_owned(),
        }),
    }
}

/// An own commit the facade merged locally.
pub(crate) struct MadeCommit<T> {
    /// Epoch after the commit (as the facade reports it).
    pub(crate) epoch_after: u64,
    /// The commit message.
    pub(crate) commit: Vec<u8>,
    /// What the caller wants back (for an Add: the Welcome).
    pub(crate) extra: T,
}

/// How an own commit ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommitOutcome<T> {
    /// Ordered at this position.
    Accepted { log_seq: u64, extra: T },
    /// The group is not at the head; nothing was made.
    NotCurrent(CatchUpOutcome),
    /// An earlier own commit is still waiting for the orderer; nothing was made.
    EarlierPending,
    /// The commit was made and merged locally but the orderer has not ordered it: it stays
    /// pending and [`retry_pending`] re-submits it.
    Pending { extra: T },
    /// The commit lost its epoch to another commit: the group is forked.
    Forked,
    /// The orderer replaced the group; reconcile.
    Replaced { group_id: Vec<u8> },
}

/// Catch up, make one own commit with `build`, and submit it.
///
/// `build` receives the group id and returns the merged commit (for example `Mls::remove`,
/// `Mls::update` or `Mls::add` followed by `commit_plain`).
///
/// # Errors
/// Storage failures, MLS failures from `make`, an orderer refusal and the errors of
/// [`catch_up`].
pub(crate) async fn commit_and_submit<K, T, F>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    now: u64,
    build: F,
) -> Result<CommitOutcome<T>, SdkError>
where
    K: MlsKv,
    F: FnOnce(&Mls<K>, &[u8]) -> Result<MadeCommit<T>, SdkError>,
{
    let state = store.require(scope)?;
    if state.pending.is_some() {
        // An earlier own commit is still unordered: it goes first ([`retry_pending`]).
        return Ok(CommitOutcome::EarlierPending);
    }
    match catch_up(access, mls, store, scope).await? {
        CatchUpOutcome::Current { .. } => {}
        other => return Ok(CommitOutcome::NotCurrent(other)),
    }
    let mut state = store.require(scope)?;
    let made = build(mls, &state.group_id)?;
    let epoch = made.epoch_after.saturating_sub(1);
    state.pending = Some(PendingCommit { epoch, commit: made.commit.clone(), submitted_at: now });
    store.put(&scope.conversation_id, &state)?;
    let request = DmSubmit {
        group_id: state.group_id.clone(),
        kind: scope.kind,
        scope_id: scope.conversation_id.clone(),
        epoch,
        commit: made.commit,
        flag: None,
        nonce: Vec::new(),
        anchors: Vec::new(),
    };
    finish_submit(access, mls, store, scope, request, made.extra).await
}

async fn finish_submit<K: MlsKv, T>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    request: DmSubmit,
    extra: T,
) -> Result<CommitOutcome<T>, SdkError> {
    match submit(access, request).await? {
        SubmitOutcome::Accepted { log_seq, .. } => {
            let mut state = store.require(scope)?;
            state.pending = None;
            state.log_seq = log_seq;
            store.put(&scope.conversation_id, &state)?;
            Ok(CommitOutcome::Accepted { log_seq, extra })
        }
        SubmitOutcome::Stale { .. } => match catch_up(access, mls, store, scope).await? {
            CatchUpOutcome::Forked | CatchUpOutcome::Pruned => Ok(CommitOutcome::Forked),
            CatchUpOutcome::Replaced { group_id } => Ok(CommitOutcome::Replaced { group_id }),
            CatchUpOutcome::Current { .. }
            | CatchUpOutcome::Removed
            | CatchUpOutcome::NotYetAvailable => Ok(CommitOutcome::Pending { extra }),
        },
        SubmitOutcome::Replaced { group_id } => Ok(CommitOutcome::Replaced { group_id }),
        SubmitOutcome::NotYetAvailable | SubmitOutcome::RateLimited { .. } => {
            Ok(CommitOutcome::Pending { extra })
        }
        SubmitOutcome::Refused(code) => Err(refused_error(code)),
        SubmitOutcome::ScopeTaken { .. } | SubmitOutcome::GroupTaken => Err(SdkError::Mls {
            code: "dm_order_refused",
            detail: "the orderer answered an ordinary commit with a scope or group conflict"
                .to_owned(),
        }),
    }
}

/// Re-submit the pending own commit (orderer back up, rate limit over, answer lost).
///
/// # Errors
/// Storage failures, an orderer refusal, gateway failures other than the not-yet-available
/// answer.
pub(crate) async fn retry_pending<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    now: u64,
) -> Result<Option<CommitOutcome<()>>, SdkError> {
    let mut state = store.require(scope)?;
    let Some(pending) = state.pending.clone() else {
        return Ok(None);
    };
    state.pending = Some(PendingCommit { submitted_at: now, ..pending.clone() });
    store.put(&scope.conversation_id, &state)?;
    let request = DmSubmit {
        group_id: state.group_id,
        kind: scope.kind,
        scope_id: scope.conversation_id.clone(),
        epoch: pending.epoch,
        commit: pending.commit,
        flag: None,
        nonce: Vec::new(),
        anchors: Vec::new(),
    };
    finish_submit(access, mls, store, scope, request, ()).await.map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ConvState {
        ConvState::new(vec![1; 32], 7, 1_000)
    }

    #[test]
    fn backoff_doubles_to_the_cap() {
        let delays: Vec<u64> = (1..=10).map(Backoff::delay_secs).collect();
        assert_eq!(delays, [5, 10, 20, 40, 80, 160, 320, 640, 900, 900], "5 s doubling to 15 min");
    }

    #[test]
    fn backoff_honours_the_orderers_wait_and_resets() {
        let mut backoff = Backoff::default();
        assert!(backoff.ready(0), "a fresh backoff allows the first attempt");
        backoff.on_failure(100, Some(60));
        assert!(!backoff.ready(159), "the orderer asked for 60 s");
        assert!(backoff.ready(160), "the wait is over");
        assert!(backoff.is_pending(), "a failed attempt shows the conversation as pending");
        backoff.on_success();
        assert!(!backoff.is_pending(), "an answer clears the pending display");
    }

    #[test]
    fn switch_over_keeps_the_old_group_readable_for_seven_days() {
        let mut state = state();
        state.switch_to(vec![2; 32], 0, 5_000);
        assert!(state.readable(&[2; 32], 5_000), "the new group is the current one");
        assert!(
            state.readable(&[1; 32], 5_000 + OLD_GROUP_READ_ONLY_SECS - 1),
            "inside the window"
        );
        assert!(!state.readable(&[1; 32], 5_000 + OLD_GROUP_READ_ONLY_SECS), "window over");
        assert!(state.expire_old(5_000 + OLD_GROUP_READ_ONLY_SECS), "the old group is dropped");
        assert!(state.old.is_none(), "nothing left to read");
    }

    #[test]
    fn switching_to_the_current_group_changes_nothing() {
        let mut state = state();
        let before = state.clone();
        state.switch_to(vec![1; 32], 99, 9_000);
        assert_eq!(state, before, "the orderer naming the same group is not a switch-over");
    }

    #[test]
    fn pending_lookup_waits_thirty_seconds() {
        let mut state = state();
        assert!(!state.pending_lookup_due(10_000), "nothing pending");
        state.pending = Some(PendingCommit { epoch: 3, commit: vec![9], submitted_at: 10_000 });
        assert!(!state.pending_lookup_due(10_000 + PENDING_LOOKUP_SECS - 1), "too early");
        assert!(state.pending_lookup_due(10_000 + PENDING_LOOKUP_SECS), "30 s unanswered");
    }

    #[test]
    fn submit_answers_classify_and_foreign_answers_are_errors() {
        assert_eq!(
            classify_submit(DmOrderReply::RateLimited { retry_after: 9 }).ok(),
            Some(SubmitOutcome::RateLimited { retry_after: 9 }),
            "a rate limit keeps its wait"
        );
        assert!(classify_submit(DmOrderReply::Pruned).is_err(), "pruned is not a submit answer");
    }

    #[test]
    fn unsupported_nack_is_recognised_only_by_its_code() {
        assert!(is_not_yet_available(&not_yet_available()), "the typed error round-trips");
        let other = SdkError::Mls { code: "internal", detail: String::new() };
        assert!(!is_not_yet_available(&other), "other MLS errors are real failures");
    }

    #[test]
    fn wire_frames_use_the_node_tags() -> Result<(), serde_json::Error> {
        let reply: DmOrderReply =
            serde_json::from_str(r#"{"reply":"stale","epoch":2,"log_seq":5}"#)?;
        assert_eq!(reply, DmOrderReply::Stale { epoch: 2, log_seq: 5 }, "reply tag");
        let op = DmOrderOp::Since(DmSince { group_id: vec![1, 2], log_seq: 3 });
        let text = serde_json::to_string(&op)?;
        assert!(text.contains(r#""op":"since""#), "op tag: {text}");
        Ok(())
    }
}
