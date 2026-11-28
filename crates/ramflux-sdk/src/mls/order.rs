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
//! * An own commit is staged, not merged. Its bytes, and an Add's Welcome, stay in the
//!   conversation's `pending` commit until the orderer accepts, then [`ramflux_mls::Mls::merge_own`]
//!   runs. A lost answer, a down orderer or a rate limit re-submits the same bytes. Another
//!   commit at that epoch discards ours ([`CommitOutcome::Lost`]) and is applied. A log entry
//!   past the local epoch is [`CatchUpOutcome::Forked`]: the recovery is [`establish`] with
//!   [`EstablishKind::ReEstablish`].
//!
//! The gateway answers `Nack mls_dm_frames_unsupported` until the node wires the frames; every
//! driver reports that as `NotYetAvailable`.

use ramflux_mls::{
    ConversationRole, GroupKind, Mls, MlsError, MlsKv, MlsKvError, ReceivedMessage, RfConversation,
    WriteBatch, WriteOp,
};
use ramflux_protocol::message::dm_scope::{self, MLS_KIND_DM, MLS_KIND_SELF};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::key_packages::{self, FetchedKeyPackage, b64};
use crate::SdkError;
use crate::gateway::access::MlsFrameAccess;

/// `submit` per anchor per minute at the orderer.
#[allow(dead_code)]
pub(crate) const SUBMIT_PER_MINUTE: usize = 30;
/// `since` per anchor per minute.
#[allow(dead_code)]
pub(crate) const SINCE_PER_MINUTE: usize = 120;
/// `status` per anchor per minute.
#[allow(dead_code)]
pub(crate) const STATUS_PER_MINUTE: usize = 60;
/// Most commits in one `since` answer.
#[allow(dead_code)]
pub(crate) const SINCE_MAX_ENTRIES: usize = 64;
/// Largest commit the orderer accepts.
pub(crate) const COMMIT_MAX_BYTES: usize = 1 << 20;
/// Nonce length of a derived group id.
pub(crate) const GROUP_NONCE_BYTES: usize = 16;
/// How long the old group stays readable after a switch-over (7 days).
pub(crate) const OLD_GROUP_READ_ONLY_SECS: u64 = 7 * 86_400;
/// Most replaced groups kept (self 6 Updates/hour × 7 days). One extra slot is not stored.
pub(crate) const OLD_GROUP_CAP: usize = 1008;
/// An own commit unanswered this long is looked up with `since` (30 s).
pub(crate) const PENDING_LOOKUP_SECS: u64 = 30;
/// Most `since` pages one catch-up reads (bounds the loop at the orderer's 4 096 hard cap).
const CATCH_UP_MAX_PAGES: usize = 64;
/// First delay of the orderer-down backoff.
#[allow(dead_code)]
const BACKOFF_BASE_SECS: u64 = 5;
/// Largest delay of the orderer-down backoff.
#[allow(dead_code)]
const BACKOFF_MAX_SECS: u64 = 900;
/// Row label of the conversation state, keyed by scope id.
const CONV_LABEL: &str = "mls/conv";
/// Row label of the reverse index, keyed by group id (current and old group) to the scope id.
const CONV_GROUP_LABEL: &str = "mls/conv_group";
/// Largest stored conversation or establish row (commit and Welcome, base64, bounded at 4 MiB).
const CONV_ROW_MAX_BYTES: usize = 4 << 20;
/// Row label of a staged first commit, keyed by scope id, written before the first submit.
const ESTABLISH_LABEL: &str = "mls/establish";
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

/// An own commit staged locally and not yet merged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct PendingCommit {
    /// Epoch the commit was made in.
    pub(crate) epoch: u64,
    #[serde(with = "b64")]
    pub(crate) commit: Vec<u8>,
    /// Welcome of an Add, kept so a retry can still fan it out. Absent for other commits.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "key_packages::opt_b64")]
    pub(crate) welcome: Option<Vec<u8>>,
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
    /// Replaced groups, oldest first, each readable for 7 days. Empty when none are kept.
    #[serde(default)]
    pub(crate) old: Vec<OldGroup>,
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
            old: Vec::new(),
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
            || self.old.iter().any(|old| old.group_id == group_id && now < old.read_only_until)
    }

    /// Drop every old group whose window has ended. The caller deletes each returned id.
    pub(crate) fn expire_old(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut expired = Vec::new();
        self.old.retain(|old| {
            if now < old.read_only_until {
                true
            } else {
                expired.push(old.group_id.clone());
                false
            }
        });
        expired
    }

    /// An own commit is waiting and its last attempt is old enough for a `since` lookup.
    pub(crate) fn pending_lookup_due(&self, now: u64) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| now.saturating_sub(pending.submitted_at) >= PENDING_LOOKUP_SECS)
    }

    /// Point the conversation at `group_id`, appending the previous group.
    ///
    /// Above [`OLD_GROUP_CAP`] the oldest ids are returned for an immediate `delete_group`.
    fn switch_to(&mut self, group_id: Vec<u8>, log_seq: u64, now: u64) -> Vec<Vec<u8>> {
        if self.group_id == group_id {
            return Vec::new();
        }
        let previous = std::mem::replace(&mut self.group_id, group_id);
        self.old.push(OldGroup {
            group_id: previous,
            read_only_until: now.saturating_add(OLD_GROUP_READ_ONLY_SECS),
        });
        let mut evicted = Vec::new();
        if self.old.len() > OLD_GROUP_CAP {
            let overflow = self.old.len() - OLD_GROUP_CAP;
            evicted.extend(self.old.drain(..overflow).map(|old| old.group_id));
        }
        self.log_seq = log_seq;
        self.pending = None;
        self.leaf_updated_at = now;
        self.generations_epoch = 0;
        self.generations = 0;
        self.removed = false;
        evicted
    }
}

/// What to do with a staged first commit after `status`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StageKeep {
    /// The frames are unwired. Keep the row and surface `NotYetAvailable`.
    NotYetAvailable,
    /// The orderer has no group yet. Keep the row and surface `RateLimited`.
    RateLimited,
    /// `status` names our staged group. Merge it.
    Adopt,
    /// `status` names another group. Delete only our staged group.
    Delete,
}

/// Keep the staged first commit unless `status` names a different group.
pub(crate) fn keep_stage(status: &StatusOutcome, our_group: &[u8]) -> StageKeep {
    match status {
        StatusOutcome::NotYetAvailable => StageKeep::NotYetAvailable,
        StatusOutcome::UnknownScope => StageKeep::RateLimited,
        StatusOutcome::Group { group_id, .. } if group_id.as_slice() == our_group => {
            StageKeep::Adopt
        }
        StatusOutcome::Group { .. } => StageKeep::Delete,
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
    #[allow(dead_code)]
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

    /// The staged first commit of `scope_id`, if one was written.
    fn establish_get(&self, scope_id: &[u8]) -> Result<Option<EstablishRow>, SdkError> {
        let Some(row) = self.kv.get(ESTABLISH_LABEL, scope_id).map_err(kv_error)? else {
            return Ok(None);
        };
        decode_establish_row(&row).map(Some)
    }

    /// Persist the staged first commit before it is submitted.
    fn establish_put(&self, scope_id: &[u8], row: &EstablishRow) -> Result<(), SdkError> {
        let encoded =
            serde_json::to_vec(row).map_err(|_| conv_error("establish row does not encode"))?;
        if encoded.len() > CONV_ROW_MAX_BYTES {
            return Err(SdkError::Mls {
                code: "too_large",
                detail: "the establish row exceeds 4 MiB".to_owned(),
            });
        }
        self.write_row(ESTABLISH_LABEL, scope_id, encoded)
    }

    /// Drop the staged first-commit row.
    fn establish_delete(&self, scope_id: &[u8]) -> Result<(), SdkError> {
        self.delete_row(ESTABLISH_LABEL, scope_id)
    }

    /// Drop the reverse index entry of a group that is no longer current or old.
    fn delete_group_index(&self, group_id: &[u8]) -> Result<(), SdkError> {
        self.delete_row(CONV_GROUP_LABEL, group_id)
    }

    fn write_row(&self, label: &str, key: &[u8], value: Vec<u8>) -> Result<(), SdkError> {
        self.kv
            .commit_batch(
                WriteBatch {
                    ops: vec![WriteOp::Put {
                        label: label.to_owned(),
                        key: key.to_vec(),
                        value: Zeroizing::new(value),
                    }],
                    epoch_changed: false,
                },
                |_tx| Ok(()),
            )
            .map_err(kv_error)
    }

    fn delete_row(&self, label: &str, key: &[u8]) -> Result<(), SdkError> {
        self.kv
            .commit_batch(
                WriteBatch {
                    ops: vec![WriteOp::Delete { label: label.to_owned(), key: key.to_vec() }],
                    epoch_changed: false,
                },
                |_tx| Ok(()),
            )
            .map_err(kv_error)
    }
}

/// `mls/establish/<scope>`: one staged first commit, written before its first submit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct EstablishRow {
    #[serde(with = "b64")]
    group_id: Vec<u8>,
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    flag: DmSubmitFlag,
    epoch: u64,
    #[serde(with = "b64")]
    commit: Vec<u8>,
    #[serde(with = "b64")]
    welcome: Vec<u8>,
    submitted_at: u64,
}

fn decode_establish_row(row: &[u8]) -> Result<EstablishRow, SdkError> {
    if row.len() > CONV_ROW_MAX_BYTES {
        return Err(conv_error("establish row exceeds the decode bound"));
    }
    serde_json::from_slice(row).map_err(|_| conv_error("establish row does not decode"))
}

/// Orderer-down backoff (spec §3.1): exponential from 5 s to 15 min, never shorter than a
/// `rate_limited` answer asked for. Pure; the caller supplies the time.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Backoff {
    failures: u32,
    not_before: u64,
}

#[allow(dead_code)]
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

/// What a catch-up did with a staged own commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnResolution {
    /// No staged own commit was resolved.
    None,
    /// Our staged commit was the log entry at `log_seq` and was merged.
    Merged { log_seq: u64 },
    /// A foreign commit took the epoch; our staged commit was discarded.
    Discarded,
}

/// How a catch-up ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CatchUpOutcome {
    /// Every commit up to the head is applied. `own` reports a staged own commit resolved here.
    Current { log_seq: u64, own: OwnResolution },
    /// A commit removed this device from the group.
    Removed,
    /// A commit could not be applied, or the log jumped past the local epoch: re-establish.
    Forked,
    /// The orderer replaced the group; reconcile.
    Replaced { group_id: Vec<u8> },
    /// The retained log no longer reaches back to the position; re-establish.
    Pruned,
    /// The node does not serve the frames yet.
    NotYetAvailable,
}

/// What one log entry asks the device to do. Pure: no storage and no clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryAction {
    /// The entry is our staged commit.
    MergeOwn,
    /// The entry took our staged commit's epoch. Discard ours, then apply or skip it.
    DiscardThenApply,
    /// The entry is older than the local epoch.
    Skip,
    /// The entry is the next commit and is not ours.
    Apply,
    /// The entry is ahead of the local epoch, or ahead of a still-staged own commit.
    Fork,
}

fn classify_entry(
    pending: Option<&PendingCommit>,
    local_epoch: u64,
    entry_epoch: u64,
    entry_commit: &[u8],
) -> EntryAction {
    if let Some(pending) = pending {
        if entry_epoch == pending.epoch {
            if entry_commit == pending.commit.as_slice() {
                return EntryAction::MergeOwn;
            }
            return EntryAction::DiscardThenApply;
        }
        if entry_epoch > pending.epoch {
            return EntryAction::Fork;
        }
    }
    match entry_epoch.cmp(&local_epoch) {
        std::cmp::Ordering::Less => EntryAction::Skip,
        std::cmp::Ordering::Equal => EntryAction::Apply,
        std::cmp::Ordering::Greater => EntryAction::Fork,
    }
}

/// Applying one log entry.
enum Applied {
    Epoch(u64),
    Skipped,
    Removed,
    Failed,
}

enum OwnMark {
    Merged,
    Discarded,
}

struct ApplyResult {
    applied: Applied,
    own: Option<OwnMark>,
}

fn merge_staged<K: MlsKv>(
    mls: &Mls<K>,
    group_id: &[u8],
    pending_epoch: u64,
) -> Result<u64, SdkError> {
    match mls.merge_own(group_id) {
        Ok(staged) => Ok(staged.commit_plain().map_err(kv_error)?.epoch),
        // A crash between the merge and the conversation-row write: the group is already ahead.
        Err(MlsError::NotFound(detail)) if detail == "pending commit" => {
            let status = mls.status(group_id)?;
            if status.epoch == pending_epoch.saturating_add(1) {
                Ok(status.epoch)
            } else {
                Err(MlsError::NotFound(detail).into())
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn discard_staged<K: MlsKv>(mls: &Mls<K>, group_id: &[u8]) -> Result<bool, SdkError> {
    mls.discard_own(group_id)?.commit_plain().map_err(kv_error)
}

fn delete_local_group<K: MlsKv>(mls: &Mls<K>, group_id: &[u8]) -> Result<(), SdkError> {
    match mls.delete_group(group_id) {
        Ok(staged) => staged.commit_plain().map_err(kv_error),
        Err(MlsError::NotFound(_)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn forget_group<K: MlsKv>(
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    group_id: &[u8],
) -> Result<(), SdkError> {
    delete_local_group(mls, group_id)?;
    store.delete_group_index(group_id)
}

/// Delete an expired old group, then persist `state` (which no longer names it).
fn persist_expiring<K: MlsKv>(
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope_id: &[u8],
    state: &mut ConvState,
    now: u64,
) -> Result<(), SdkError> {
    for group_id in state.expire_old(now) {
        forget_group(mls, store, &group_id)?;
    }
    store.put(scope_id, state)
}

fn receive_commit<K: MlsKv>(mls: &Mls<K>, entry: &DmCommitEntry) -> Result<Applied, SdkError> {
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

fn apply_entry<K: MlsKv>(
    mls: &Mls<K>,
    state: &mut ConvState,
    local_epoch: u64,
    entry: &DmCommitEntry,
) -> Result<ApplyResult, SdkError> {
    let action = classify_entry(state.pending.as_ref(), local_epoch, entry.epoch, &entry.commit);
    match action {
        EntryAction::MergeOwn => {
            let pending_epoch = state
                .pending
                .as_ref()
                .map(|pending| pending.epoch)
                .ok_or_else(|| conv_error("the pending commit disappeared"))?;
            let epoch = merge_staged(mls, &state.group_id, pending_epoch)?;
            state.pending = None;
            Ok(ApplyResult { applied: Applied::Epoch(epoch), own: Some(OwnMark::Merged) })
        }
        EntryAction::DiscardThenApply => {
            discard_staged(mls, &state.group_id)?;
            state.pending = None;
            let applied = match entry.epoch.cmp(&local_epoch) {
                std::cmp::Ordering::Less => Applied::Skipped,
                std::cmp::Ordering::Equal => receive_commit(mls, entry)?,
                std::cmp::Ordering::Greater => Applied::Failed,
            };
            Ok(ApplyResult { applied, own: Some(OwnMark::Discarded) })
        }
        EntryAction::Skip => Ok(ApplyResult { applied: Applied::Skipped, own: None }),
        EntryAction::Fork => Ok(ApplyResult { applied: Applied::Failed, own: None }),
        EntryAction::Apply => Ok(ApplyResult { applied: receive_commit(mls, entry)?, own: None }),
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
    let mut own = OwnResolution::None;
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
            return Ok(CatchUpOutcome::Current { log_seq: state.log_seq, own });
        }
        for entry in &entries {
            if entry.log_seq <= state.log_seq {
                return Err(unexpected("since (log position went backwards)"));
            }
            let result = apply_entry(mls, &mut state, local_epoch, entry)?;
            match result.own {
                Some(OwnMark::Merged) => {
                    own = OwnResolution::Merged { log_seq: entry.log_seq };
                }
                Some(OwnMark::Discarded) => own = OwnResolution::Discarded,
                None => {}
            }
            match result.applied {
                Applied::Epoch(epoch) => local_epoch = epoch,
                Applied::Skipped => {}
                Applied::Removed => {
                    state.removed = true;
                    state.log_seq = entry.log_seq;
                    store.put(&scope.conversation_id, &state)?;
                    return Ok(CatchUpOutcome::Removed);
                }
                Applied::Failed => {
                    store.put(&scope.conversation_id, &state)?;
                    return Ok(CatchUpOutcome::Forked);
                }
            }
            state.log_seq = entry.log_seq;
        }
        store.put(&scope.conversation_id, &state)?;
        if !more {
            return Ok(CatchUpOutcome::Current { log_seq: state.log_seq, own });
        }
    }
    Ok(CatchUpOutcome::Current { log_seq: state.log_seq, own })
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
            let evicted = state.switch_to(group_id.clone(), log_seq, now);
            for id in evicted {
                forget_group(mls, store, &id)?;
            }
            state
        }
        None => ConvState::new(group_id.clone(), log_seq, now),
    };
    for expired in state.expire_old(now) {
        forget_group(mls, store, &expired)?;
    }
    store.put(&scope.conversation_id, &state)?;
    Ok(ReconcileOutcome::Switched { group_id })
}

/// Drop a conversation's old group once its 7-day window has ended (the D5 daily hook).
/// A missing group is already gone.
///
/// # Errors
/// Storage failure.
pub(crate) fn expire_old_group<K: MlsKv>(
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    now: u64,
) -> Result<(), SdkError> {
    let Some(mut state) = store.get(&scope.conversation_id)? else {
        return Ok(());
    };
    persist_expiring(mls, store, &scope.conversation_id, &mut state, now)
}

/// Which first commit [`establish`] submits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EstablishKind {
    /// First contact: the scope has no group yet.
    Create,
    /// Lost state or a fork: a new group replaces the scope's current one.
    #[allow(dead_code)]
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
    /// `forgotten` groups were deleted by the switch and must leave the seal cache.
    Established {
        group_id: Vec<u8>,
        epoch: u64,
        log_seq: u64,
        welcome: Vec<u8>,
        forgotten: Vec<Vec<u8>>,
    },
    /// Another device won the scope; follow the group the orderer names.
    LostRace(ReconcileOutcome),
    /// Over the limit with no group to follow; retry after the wait.
    RateLimited { retry_after: u64 },
    /// The node does not serve the frames yet.
    NotYetAvailable,
}

/// First contact and re-establish: create the group with the derived id, add every verified device
/// (`key_packages`), and submit the commit with `create` or `re_establish`.
///
/// The staged first commit is written to `mls/establish/<scope>` before the first submit. A later
/// call whose group still loads re-submits those bytes, so a scope keeps one staged group. The
/// caller verified each `KeyPackage` against the directory (spec §3.4). The Welcome stays in the
/// row until the orderer has the group and [`ramflux_mls::Mls::merge_own`] has run.
///
/// # Errors
/// No `KeyPackages` on a fresh start, MLS failures, storage failures, an orderer refusal, gateway
/// failures other than the not-yet-available answer.
pub(crate) async fn establish<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    request: Establish<'_>,
    now: u64,
) -> Result<EstablishOutcome, SdkError> {
    let Establish { scope, key_packages, kind } = request;
    let flag = match kind {
        EstablishKind::Create => DmSubmitFlag::Create,
        EstablishKind::ReEstablish => DmSubmitFlag::ReEstablish,
    };
    if let Some(existing) = store.establish_get(&scope.conversation_id)? {
        if existing.flag == flag {
            match mls.status(&existing.group_id) {
                Ok(_) => return finish_establish(access, mls, store, scope, &existing, now).await,
                Err(MlsError::NotFound(_)) => {
                    store.establish_delete(&scope.conversation_id)?;
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            delete_local_group(mls, &existing.group_id)?;
            store.establish_delete(&scope.conversation_id)?;
        }
    }
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
    let packages: Vec<Vec<u8>> =
        key_packages.iter().map(|entry| entry.key_package.clone()).collect();
    let added = match stage_first_commit(mls, scope, group_id, &binding, &packages) {
        Ok(added) => added,
        Err(error) => {
            delete_local_group(mls, &group_id)?;
            return Err(error);
        }
    };
    let row = EstablishRow {
        group_id: group_id.to_vec(),
        nonce: nonce.to_vec(),
        flag,
        epoch: added.epoch,
        commit: added.commit,
        welcome: added.welcome,
        submitted_at: now,
    };
    if let Err(error) = store.establish_put(&scope.conversation_id, &row) {
        delete_local_group(mls, &group_id)?;
        return Err(error);
    }
    finish_establish(access, mls, store, scope, &row, now).await
}

fn stage_first_commit<K: MlsKv>(
    mls: &Mls<K>,
    scope: &Scope,
    group_id: [u8; 32],
    binding: &RfConversation,
    packages: &[Vec<u8>],
) -> Result<ramflux_mls::AddOutput, SdkError> {
    mls.create_with(scope.kind.mls_kind(), None, Some(binding), Some(group_id))?
        .commit_plain()
        .map_err(kv_error)?;
    mls.add(&group_id, packages)?.commit_plain().map_err(kv_error)
}

fn abandon_establish<K: MlsKv>(
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope_id: &[u8],
    group_id: &[u8],
) -> Result<(), SdkError> {
    delete_local_group(mls, group_id)?;
    store.establish_delete(scope_id)
}

fn record_established<K: MlsKv>(
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    group_id: &[u8],
    log_seq: u64,
    now: u64,
) -> Result<Vec<Vec<u8>>, SdkError> {
    let mut forgotten = Vec::new();
    let mut state = match store.get(&scope.conversation_id)? {
        Some(mut state) => {
            let evicted = state.switch_to(group_id.to_vec(), log_seq, now);
            for id in &evicted {
                forget_group(mls, store, id)?;
            }
            forgotten.extend(evicted);
            state
        }
        None => ConvState::new(group_id.to_vec(), log_seq, now),
    };
    let expired = state.expire_old(now);
    for id in &expired {
        forget_group(mls, store, id)?;
    }
    forgotten.extend(expired);
    store.put(&scope.conversation_id, &state)?;
    store.establish_delete(&scope.conversation_id)?;
    Ok(forgotten)
}

async fn finish_establish<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    row: &EstablishRow,
    now: u64,
) -> Result<EstablishOutcome, SdkError> {
    let request = DmSubmit {
        group_id: row.group_id.clone(),
        kind: scope.kind,
        scope_id: scope.conversation_id.clone(),
        epoch: row.epoch,
        commit: row.commit.clone(),
        flag: Some(row.flag),
        nonce: row.nonce.clone(),
        anchors: scope.anchors.clone(),
    };
    match submit(access, request).await? {
        SubmitOutcome::Accepted { log_seq, .. } => {
            let epoch = merge_staged(mls, &row.group_id, row.epoch)?;
            let forgotten = record_established(mls, store, scope, &row.group_id, log_seq, now)?;
            Ok(EstablishOutcome::Established {
                group_id: row.group_id.clone(),
                epoch,
                log_seq,
                welcome: row.welcome.clone(),
                forgotten,
            })
        }
        SubmitOutcome::NotYetAvailable => Ok(EstablishOutcome::NotYetAvailable),
        SubmitOutcome::RateLimited { retry_after } if row.flag == DmSubmitFlag::Create => {
            Ok(EstablishOutcome::RateLimited { retry_after })
        }
        SubmitOutcome::GroupTaken
        | SubmitOutcome::ScopeTaken { .. }
        | SubmitOutcome::Replaced { .. }
        | SubmitOutcome::RateLimited { .. } => {
            lost_or_adopted(access, mls, store, scope, row, now).await
        }
        SubmitOutcome::Refused(code) => {
            abandon_establish(mls, store, &scope.conversation_id, &row.group_id)?;
            Err(refused_error(code))
        }
        SubmitOutcome::Stale { .. } => {
            abandon_establish(mls, store, &scope.conversation_id, &row.group_id)?;
            Err(SdkError::Mls {
                code: "dm_order_refused",
                detail: "the orderer answered a first commit with a group or epoch conflict"
                    .to_owned(),
            })
        }
    }
}

async fn lost_or_adopted<K: MlsKv>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    row: &EstablishRow,
    now: u64,
) -> Result<EstablishOutcome, SdkError> {
    let named = status(access, scope).await?;
    match keep_stage(&named, &row.group_id) {
        StageKeep::NotYetAvailable => Ok(EstablishOutcome::NotYetAvailable),
        StageKeep::RateLimited => {
            Ok(EstablishOutcome::RateLimited { retry_after: PENDING_LOOKUP_SECS })
        }
        StageKeep::Adopt => {
            let epoch = merge_staged(mls, &row.group_id, row.epoch)?;
            let forgotten = record_established(mls, store, scope, &row.group_id, 0, now)?;
            Ok(EstablishOutcome::Established {
                group_id: row.group_id.clone(),
                epoch,
                log_seq: 0,
                welcome: row.welcome.clone(),
                forgotten,
            })
        }
        StageKeep::Delete => {
            abandon_establish(mls, store, &scope.conversation_id, &row.group_id)?;
            Ok(EstablishOutcome::LostRace(reconcile(access, mls, store, scope, now).await?))
        }
    }
}

/// An own commit staged locally, not yet merged.
pub(crate) struct MadeCommit<T> {
    /// Epoch the commit was made in. The group stays there until [`ramflux_mls::Mls::merge_own`].
    pub(crate) epoch: u64,
    /// The commit message.
    pub(crate) commit: Vec<u8>,
    /// Welcome of an Add. Stored beside `extra` so a retry can return it after a restart.
    pub(crate) welcome: Option<Vec<u8>>,
    /// What the caller wants back (for an Add: the Welcome).
    pub(crate) extra: T,
}

/// How an own commit ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommitOutcome<T> {
    /// Ordered at this position. The group is already merged.
    Accepted { log_seq: u64, extra: T },
    /// The group is not at the head; nothing was made.
    NotCurrent(CatchUpOutcome),
    /// An earlier own commit is still waiting for the orderer; nothing was made.
    EarlierPending,
    /// The commit is staged and the orderer has not ordered it. [`retry_pending`] re-submits the
    /// same bytes.
    Pending { extra: T },
    /// Another commit took the epoch. Ours was discarded; rebuild it if it is still needed.
    Lost,
    /// The commit lost its epoch and the log could not be applied: the group is forked.
    Forked,
    /// The orderer replaced the group; reconcile.
    Replaced { group_id: Vec<u8> },
}

/// Catch up, stage one own commit with `build`, and submit it.
///
/// `build` receives the group id and returns the staged commit (for example `Mls::remove`,
/// `Mls::update` or `Mls::add` followed by `commit_plain`). A stage left behind with no pending
/// row is discarded first.
///
/// # Errors
/// Storage failures, MLS failures from `build`, an orderer refusal and the errors of
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
    discard_staged(mls, &state.group_id)?;
    match catch_up(access, mls, store, scope).await? {
        CatchUpOutcome::Current { .. } => {}
        other => return Ok(CommitOutcome::NotCurrent(other)),
    }
    let mut state = store.require(scope)?;
    if state.pending.is_some() {
        return Ok(CommitOutcome::EarlierPending);
    }
    let made = build(mls, &state.group_id)?;
    state.pending = Some(PendingCommit {
        epoch: made.epoch,
        commit: made.commit.clone(),
        welcome: made.welcome,
        submitted_at: now,
    });
    store.put(&scope.conversation_id, &state)?;
    let request = DmSubmit {
        group_id: state.group_id.clone(),
        kind: scope.kind,
        scope_id: scope.conversation_id.clone(),
        epoch: made.epoch,
        commit: made.commit,
        flag: None,
        nonce: Vec::new(),
        anchors: Vec::new(),
    };
    finish_submit(access, mls, store, scope, request, made.extra).await
}

fn discard_pending<K: MlsKv>(
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
) -> Result<(), SdkError> {
    let mut state = store.require(scope)?;
    discard_staged(mls, &state.group_id)?;
    state.pending = None;
    store.put(&scope.conversation_id, &state)
}

async fn finish_submit<K: MlsKv, T>(
    access: &mut impl MlsFrameAccess,
    mls: &Mls<K>,
    store: &ConvStore<'_, K>,
    scope: &Scope,
    request: DmSubmit,
    extra: T,
) -> Result<CommitOutcome<T>, SdkError> {
    let group_id = request.group_id.clone();
    let epoch = request.epoch;
    match submit(access, request).await? {
        SubmitOutcome::Accepted { log_seq, .. } => {
            merge_staged(mls, &group_id, epoch)?;
            let mut state = store.require(scope)?;
            state.pending = None;
            state.log_seq = log_seq;
            store.put(&scope.conversation_id, &state)?;
            Ok(CommitOutcome::Accepted { log_seq, extra })
        }
        SubmitOutcome::Stale { .. } => match catch_up(access, mls, store, scope).await? {
            CatchUpOutcome::Current { log_seq, own: OwnResolution::Merged { .. } } => {
                Ok(CommitOutcome::Accepted { log_seq, extra })
            }
            CatchUpOutcome::Current { own: OwnResolution::Discarded, .. } => {
                Ok(CommitOutcome::Lost)
            }
            CatchUpOutcome::Current { own: OwnResolution::None, .. }
            | CatchUpOutcome::NotYetAvailable => Ok(CommitOutcome::Pending { extra }),
            // The removal already cleared the stage. The device is out; nothing is rebuilt.
            CatchUpOutcome::Removed => Ok(CommitOutcome::NotCurrent(CatchUpOutcome::Removed)),
            CatchUpOutcome::Forked | CatchUpOutcome::Pruned => Ok(CommitOutcome::Forked),
            CatchUpOutcome::Replaced { group_id } => Ok(CommitOutcome::Replaced { group_id }),
        },
        SubmitOutcome::NotYetAvailable | SubmitOutcome::RateLimited { .. } => {
            Ok(CommitOutcome::Pending { extra })
        }
        SubmitOutcome::Replaced { group_id } => {
            discard_pending(mls, store, scope)?;
            Ok(CommitOutcome::Replaced { group_id })
        }
        SubmitOutcome::Refused(code) => {
            discard_pending(mls, store, scope)?;
            Err(refused_error(code))
        }
        SubmitOutcome::ScopeTaken { .. } | SubmitOutcome::GroupTaken => {
            discard_pending(mls, store, scope)?;
            Err(SdkError::Mls {
                code: "dm_order_refused",
                detail: "the orderer answered an ordinary commit with a scope or group conflict"
                    .to_owned(),
            })
        }
    }
}

/// Re-submit the pending own commit (orderer back up, rate limit over, answer lost).
///
/// `Accepted` carries the Welcome stored with the pending commit (`None` for any other commit).
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
) -> Result<Option<CommitOutcome<Option<Vec<u8>>>>, SdkError> {
    let mut state = store.require(scope)?;
    let Some(mut pending) = state.pending.clone() else {
        return Ok(None);
    };
    let welcome = pending.welcome.clone();
    pending.submitted_at = now;
    state.pending = Some(pending.clone());
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
    finish_submit(access, mls, store, scope, request, welcome).await.map(Some)
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
        assert!(
            state.expire_old(5_000 + OLD_GROUP_READ_ONLY_SECS - 1).is_empty(),
            "one second inside 30 d keeps the group"
        );
        assert_eq!(
            state.expire_old(5_000 + OLD_GROUP_READ_ONLY_SECS),
            vec![vec![1; 32]],
            "the dropped group id"
        );
        assert!(state.old.is_empty(), "nothing left to read");
    }

    #[test]
    fn old_group_cap_evicts_only_past_one_thousand_eight() {
        let mut state = state();
        let mut evicted = Vec::new();
        for n in 0..OLD_GROUP_CAP {
            let mut id = vec![0_u8; 32];
            let step = u32::try_from(n).expect("test: cap fits u32");
            id[0] = u8::try_from((step / 256) + 2).expect("test: id byte");
            id[1] = u8::try_from(step % 256).expect("test: id byte");
            evicted.extend(state.switch_to(id, 0, 5_000));
        }
        assert!(evicted.is_empty(), "1008 old groups stay");
        assert_eq!(state.old.len(), OLD_GROUP_CAP, "the cap is full and not over");
        let dropped = state.switch_to(vec![9; 32], 0, 5_000);
        assert_eq!(dropped, vec![vec![1; 32]], "the 1009th switch deletes the oldest id");
        assert_eq!(state.old.len(), OLD_GROUP_CAP, "the list stays at the cap");
    }

    #[test]
    fn keep_stage_holds_the_row_unless_status_names_another_group() {
        let ours = vec![1; 32];
        assert_eq!(
            keep_stage(&StatusOutcome::NotYetAvailable, &ours),
            StageKeep::NotYetAvailable,
            "an unwired node is not a lost race"
        );
        assert_eq!(
            keep_stage(&StatusOutcome::UnknownScope, &ours),
            StageKeep::RateLimited,
            "no named group keeps the staged row"
        );
        assert_eq!(
            keep_stage(
                &StatusOutcome::Group { group_id: ours.clone(), epoch: 1, log_seq: 0 },
                &ours
            ),
            StageKeep::Adopt,
            "our group is adopted"
        );
        assert_eq!(
            keep_stage(
                &StatusOutcome::Group { group_id: vec![2; 32], epoch: 1, log_seq: 4 },
                &ours
            ),
            StageKeep::Delete,
            "another group deletes only the loser"
        );
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
        state.pending =
            Some(PendingCommit { epoch: 3, commit: vec![9], welcome: None, submitted_at: 10_000 });
        assert!(!state.pending_lookup_due(10_000 + PENDING_LOOKUP_SECS - 1), "too early");
        assert!(state.pending_lookup_due(10_000 + PENDING_LOOKUP_SECS), "30 s unanswered");
    }

    #[test]
    fn classify_entry_orders_own_other_below_and_above() {
        let ours =
            PendingCommit { epoch: 4, commit: vec![1, 2, 3], welcome: None, submitted_at: 0 };
        assert_eq!(
            classify_entry(Some(&ours), 4, 4, &[1, 2, 3]),
            EntryAction::MergeOwn,
            "our bytes at the staged epoch"
        );
        assert_eq!(
            classify_entry(Some(&ours), 4, 4, &[9]),
            EntryAction::DiscardThenApply,
            "other bytes at the staged epoch"
        );
        assert_eq!(
            classify_entry(Some(&ours), 4, 3, &[9]),
            EntryAction::Skip,
            "an entry below the local epoch"
        );
        assert_eq!(
            classify_entry(None, 4, 5, &[9]),
            EntryAction::Fork,
            "an entry above the local epoch"
        );
        assert_eq!(
            classify_entry(Some(&ours), 4, 6, &[9]),
            EntryAction::Fork,
            "an entry past the staged epoch"
        );
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
