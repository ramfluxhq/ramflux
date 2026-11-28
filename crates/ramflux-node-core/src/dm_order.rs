// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `dm_order`: the one total order of commits of a DM or self group (MLS-SPEC r1.1 3.1).
//!
//! The orderer is the home of the smaller anchor (dm) or the own home (self). Three operations,
//! `submit`, `since` and `status`, run on the `dm_order` tables of the router database. The node
//! sees only the outer `PrivateMessage` header of a commit (`mls_header`); it never reads a clock
//! to decide whether a commit is valid (`now` only feeds limits and log retention).
//!
//! The caller authenticates the requester before it gets here: a local session whose device
//! passed the custody check (Active, not revoked, lease valid, branch key = custody record) or a
//! `dm.order` call from a mesh-authenticated pinned peer naming the anchor (no origin-is-home
//! check, spec M2).
use crate::mls_header::{MlsContentType, parse_outer_header};
use crate::router_store::dm_order::{
    ANCHORS_MAX, COMMIT_MAX_BYTES, DmHead, DmLogEntry, DmScopeRow, DmWrite, GroupId,
    RE_ESTABLISH_KEEP, SCOPE_ID_MAX_BYTES,
};
use crate::{NodeCoreError, RouterRedbStore};
use ramflux_protocol::message::dm_scope::{self, MLS_KIND_DM, MLS_KIND_SELF};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// `submit` per anchor per minute at the orderer.
pub const SUBMIT_PER_MINUTE: usize = 30;
/// `since` per anchor per minute.
pub const SINCE_PER_MINUTE: usize = 120;
/// `status` per anchor per minute.
pub const STATUS_PER_MINUTE: usize = 60;
/// Most commits in one `since` answer.
pub const SINCE_MAX_ENTRIES: usize = 64;
/// Soft byte cap of one `since` answer (at least one entry is always returned). Provisional until
/// the transport frame bound is measured.
pub const SINCE_MAX_BYTES: usize = 4 << 20;
/// Window of the re-establish limit.
pub const RE_ESTABLISH_WINDOW_SECS: u64 = 3_600;
/// Re-establishes per scope per window for a DM, counted across both anchors.
pub const DM_RE_ESTABLISH_PER_WINDOW: usize = 1;
/// Re-establishes per scope per window for a self group.
pub const SELF_RE_ESTABLISH_PER_WINDOW: usize = 6;
/// Nonce length of a derived group id.
pub const GROUP_NONCE_BYTES: usize = 16;
/// Anchors and node ids longer than this are refused.
const CALLER_ID_MAX: usize = 128;
/// Rate-limit keys tracked at once.
const LIMIT_KEYS_MAX: usize = 16_384;
const LIMIT_WINDOW_SECS: u64 = 60;

/// Base64url form of binary fields in the JSON frames.
pub(crate) mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&ramflux_protocol::encode_base64url(value))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        ramflux_protocol::decode_base64url(&text).map_err(serde::de::Error::custom)
    }
}

/// A list of binary fields in the JSON frames.
pub(crate) mod b64_list {
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        values: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            seq.serialize_element(&ramflux_protocol::encode_base64url(value))?;
        }
        seq.end()
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|text| ramflux_protocol::decode_base64url(text).map_err(serde::de::Error::custom))
            .collect()
    }
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
    /// Anchors of the group (two for a dm, one for self); needed by `create` and
    /// `re_establish`, which bind them to `scope_id`.
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
    /// The commit's epoch is not the head's: apply what is missing, redo.
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

fn refused(code: DmRefusal) -> DmOrderReply {
    DmOrderReply::Refused { code }
}

/// The authenticated requester.
#[derive(Clone, Copy, Debug)]
pub struct DmCaller<'a> {
    /// Account anchor the request acts for.
    pub anchor: &'a str,
    /// Node the request entered through (this node, or the pinned peer that signed the call).
    pub origin_node: &'a str,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum LimitOp {
    Submit,
    Since,
    Status,
}

#[derive(Default)]
struct Limits {
    windows: HashMap<(LimitOp, String), VecDeque<u64>>,
}

impl Limits {
    /// Count one request; `Err` carries the seconds to wait.
    fn admit(&mut self, op: LimitOp, anchor: &str, now: u64, per_minute: usize) -> Result<(), u64> {
        if self.windows.len() >= LIMIT_KEYS_MAX
            && !self.windows.contains_key(&(op, anchor.to_owned()))
        {
            self.windows.retain(|_, hits| {
                while hits.front().is_some_and(|at| at.saturating_add(LIMIT_WINDOW_SECS) <= now) {
                    hits.pop_front();
                }
                !hits.is_empty()
            });
            if self.windows.len() >= LIMIT_KEYS_MAX {
                return Err(LIMIT_WINDOW_SECS);
            }
        }
        let hits = self.windows.entry((op, anchor.to_owned())).or_default();
        while hits.front().is_some_and(|at| at.saturating_add(LIMIT_WINDOW_SECS) <= now) {
            hits.pop_front();
        }
        if hits.len() >= per_minute {
            let first = hits.front().copied().unwrap_or(now);
            return Err(first.saturating_add(LIMIT_WINDOW_SECS).saturating_sub(now).max(1));
        }
        hits.push_back(now);
        Ok(())
    }
}

/// The orderer: limits plus the three operations.
#[derive(Default)]
pub struct DmOrderService {
    limits: Mutex<Limits>,
}

/// The id of the own-device scope of `anchor`: `blake3(MLS_SELF_SCOPE_V1 || anchor)`.
fn self_scope_id(anchor: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ramflux_protocol::domain::MLS_SELF_SCOPE_V1.as_bytes());
    hasher.update(anchor.as_bytes());
    *hasher.finalize().as_bytes()
}

fn group_array(bytes: &[u8]) -> Option<GroupId> {
    GroupId::try_from(bytes).ok()
}

fn scope_ok(scope_id: &[u8]) -> bool {
    !scope_id.is_empty() && scope_id.len() <= SCOPE_ID_MAX_BYTES
}

impl DmOrderService {
    /// An orderer with empty limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run one request.
    ///
    /// # Errors
    /// Database failures; every refusal is a [`DmOrderReply`].
    pub fn handle(
        &self,
        store: &RouterRedbStore,
        caller: &DmCaller<'_>,
        op: &DmOrderOp,
        now: u64,
    ) -> Result<DmOrderReply, NodeCoreError> {
        if caller.anchor.is_empty()
            || caller.anchor.len() > CALLER_ID_MAX
            || caller.origin_node.len() > CALLER_ID_MAX
        {
            return Ok(refused(DmRefusal::BadRequest));
        }
        let (limit_op, per_minute) = match op {
            DmOrderOp::Submit(_) => (LimitOp::Submit, SUBMIT_PER_MINUTE),
            DmOrderOp::Since(_) => (LimitOp::Since, SINCE_PER_MINUTE),
            DmOrderOp::Status(_) => (LimitOp::Status, STATUS_PER_MINUTE),
        };
        let admitted = self.limits.lock().unwrap_or_else(std::sync::PoisonError::into_inner).admit(
            limit_op,
            caller.anchor,
            now,
            per_minute,
        );
        if let Err(retry_after) = admitted {
            return Ok(DmOrderReply::RateLimited { retry_after });
        }
        match op {
            DmOrderOp::Submit(request) => submit(store, caller, request, now),
            DmOrderOp::Since(request) => since(store, caller, request),
            DmOrderOp::Status(request) => status(store, caller, request),
        }
    }
}

fn submit(
    store: &RouterRedbStore,
    caller: &DmCaller<'_>,
    request: &DmSubmit,
    now: u64,
) -> Result<DmOrderReply, NodeCoreError> {
    if request.commit.is_empty() || request.commit.len() > COMMIT_MAX_BYTES {
        return Ok(refused(DmRefusal::TooLarge));
    }
    let (Some(group), true) = (group_array(&request.group_id), scope_ok(&request.scope_id)) else {
        return Ok(refused(DmRefusal::BadRequest));
    };
    let Ok(header) = parse_outer_header(&request.commit) else {
        return Ok(refused(DmRefusal::HeaderMismatch));
    };
    if header.content_type != MlsContentType::Commit
        || header.group_id != group
        || header.epoch != request.epoch
    {
        return Ok(refused(DmRefusal::HeaderMismatch));
    }
    match request.flag {
        None => ordinary(store, caller, request, &group, now),
        Some(flag) => establish(store, caller, request, flag, group, now),
    }
}

fn ordinary(
    store: &RouterRedbStore,
    caller: &DmCaller<'_>,
    request: &DmSubmit,
    group: &GroupId,
    now: u64,
) -> Result<DmOrderReply, NodeCoreError> {
    store.dm_order_write(|tx| {
        let Some(mut head) = tx.head(group)? else {
            return Ok(DmWrite::Abort(refused(DmRefusal::UnknownGroup)));
        };
        if head.kind != request.kind.byte() || head.scope_id != request.scope_id {
            return Ok(DmWrite::Abort(refused(DmRefusal::ScopeMismatch)));
        }
        if !head.anchors.iter().any(|anchor| anchor == caller.anchor) {
            return Ok(DmWrite::Abort(refused(DmRefusal::NotMember)));
        }
        if let Some(replacement) = head.replaced_by {
            return Ok(DmWrite::Abort(DmOrderReply::Replaced { group_id: replacement.to_vec() }));
        }
        if request.epoch != head.epoch {
            return Ok(DmWrite::Abort(DmOrderReply::Stale {
                epoch: head.epoch,
                log_seq: head.log_seq,
            }));
        }
        let (Some(epoch), Some(log_seq)) = (head.epoch.checked_add(1), head.log_seq.checked_add(1))
        else {
            return Ok(DmWrite::Abort(refused(DmRefusal::BadRequest)));
        };
        tx.append(
            group,
            &DmLogEntry {
                log_seq,
                epoch: request.epoch,
                accepted_at: now,
                origin_node: caller.origin_node.to_owned(),
                commit: request.commit.clone(),
            },
            now,
        )?;
        head.epoch = epoch;
        head.log_seq = log_seq;
        tx.put_head(group, &head)?;
        Ok(DmWrite::Commit(DmOrderReply::Accepted { epoch, log_seq }))
    })
}

/// Check the id derivation and the scope binding of a `create` / `re_establish`.
fn check_binding(
    caller: &DmCaller<'_>,
    request: &DmSubmit,
    group: &GroupId,
) -> Result<(), DmRefusal> {
    let nonce: &[u8; GROUP_NONCE_BYTES] =
        request.nonce.as_slice().try_into().map_err(|_| DmRefusal::BadRequest)?;
    if request.epoch != 0 {
        return Err(DmRefusal::BadRequest);
    }
    if dm_scope::mls_group_id(request.kind.byte(), &request.scope_id, nonce) != *group {
        return Err(DmRefusal::GroupDerivation);
    }
    if request.anchors.is_empty()
        || request.anchors.len() > ANCHORS_MAX
        || !request.anchors.iter().any(|anchor| anchor == caller.anchor)
    {
        return Err(DmRefusal::NotMember);
    }
    match (request.kind, request.anchors.as_slice()) {
        (DmGroupKind::Dm, [first, second]) => {
            let derived = dm_scope::derive(first, second).map_err(|_| DmRefusal::ScopeMismatch)?;
            if derived.as_bytes() == request.scope_id.as_slice() {
                Ok(())
            } else {
                Err(DmRefusal::ScopeMismatch)
            }
        }
        (DmGroupKind::SelfGroup, [anchor]) => {
            if self_scope_id(anchor).as_slice() == request.scope_id.as_slice() {
                Ok(())
            } else {
                Err(DmRefusal::ScopeMismatch)
            }
        }
        _ => Err(DmRefusal::ScopeMismatch),
    }
}

fn same_anchors(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().all(|anchor| right.contains(anchor))
}

fn establish(
    store: &RouterRedbStore,
    caller: &DmCaller<'_>,
    request: &DmSubmit,
    flag: DmSubmitFlag,
    group: GroupId,
    now: u64,
) -> Result<DmOrderReply, NodeCoreError> {
    if let Err(code) = check_binding(caller, request, &group) {
        return Ok(refused(code));
    }
    let kind = request.kind.byte();
    let limit = match request.kind {
        DmGroupKind::Dm => DM_RE_ESTABLISH_PER_WINDOW,
        DmGroupKind::SelfGroup => SELF_RE_ESTABLISH_PER_WINDOW,
    };
    store.dm_order_write(|tx| {
        if tx.id_used(&group)? {
            return Ok(DmWrite::Abort(DmOrderReply::GroupTaken));
        }
        let mut row = DmScopeRow { group_id: group, re_established: Vec::new() };
        match (flag, tx.scope(kind, &request.scope_id)?) {
            (DmSubmitFlag::Create, Some(taken)) => {
                return Ok(DmWrite::Abort(DmOrderReply::ScopeTaken {
                    group_id: taken.group_id.to_vec(),
                }));
            }
            (DmSubmitFlag::Create, None) => {}
            (DmSubmitFlag::ReEstablish, None) => row.re_established.push(now),
            (DmSubmitFlag::ReEstablish, Some(current)) => {
                let Some(mut old) = tx.head(&current.group_id)? else {
                    return Ok(DmWrite::Abort(refused(DmRefusal::UnknownGroup)));
                };
                if !old.anchors.iter().any(|anchor| anchor == caller.anchor) {
                    return Ok(DmWrite::Abort(refused(DmRefusal::NotMember)));
                }
                if !same_anchors(&old.anchors, &request.anchors) {
                    return Ok(DmWrite::Abort(refused(DmRefusal::ScopeMismatch)));
                }
                let recent: Vec<u64> = current
                    .re_established
                    .iter()
                    .copied()
                    .filter(|at| at.saturating_add(RE_ESTABLISH_WINDOW_SECS) > now)
                    .collect();
                if recent.len() >= limit {
                    let first = recent.first().copied().unwrap_or(now);
                    let retry_after =
                        first.saturating_add(RE_ESTABLISH_WINDOW_SECS).saturating_sub(now).max(1);
                    return Ok(DmWrite::Abort(DmOrderReply::RateLimited { retry_after }));
                }
                row.re_established = recent;
                row.re_established.push(now);
                let keep_from = row.re_established.len().saturating_sub(RE_ESTABLISH_KEEP);
                row.re_established.drain(..keep_from);
                old.replaced_by = Some(group);
                tx.put_head(&current.group_id, &old)?;
            }
        }
        tx.append(
            &group,
            &DmLogEntry {
                log_seq: 1,
                epoch: 0,
                accepted_at: now,
                origin_node: caller.origin_node.to_owned(),
                commit: request.commit.clone(),
            },
            now,
        )?;
        tx.put_head(
            &group,
            &DmHead {
                kind,
                scope_id: request.scope_id.clone(),
                anchors: request.anchors.clone(),
                epoch: 1,
                log_seq: 1,
                replaced_by: None,
            },
        )?;
        tx.mark_id(&group, kind)?;
        tx.put_scope(kind, &request.scope_id, &row)?;
        Ok(DmWrite::Commit(DmOrderReply::Accepted { epoch: 1, log_seq: 1 }))
    })
}

fn since(
    store: &RouterRedbStore,
    caller: &DmCaller<'_>,
    request: &DmSince,
) -> Result<DmOrderReply, NodeCoreError> {
    let Some(group) = group_array(&request.group_id) else {
        return Ok(refused(DmRefusal::BadRequest));
    };
    store.dm_order_read(|view| {
        let Some(head) = view.head(&group)? else {
            return Ok(refused(DmRefusal::UnknownGroup));
        };
        if !head.anchors.iter().any(|anchor| anchor == caller.anchor) {
            return Ok(refused(DmRefusal::NotMember));
        }
        if let Some(replacement) = head.replaced_by {
            return Ok(DmOrderReply::Replaced { group_id: replacement.to_vec() });
        }
        if let Some(oldest) = view.oldest(&group)?
            && request.log_seq.saturating_add(1) < oldest
        {
            return Ok(DmOrderReply::Pruned);
        }
        let (rows, more) =
            view.after(&group, request.log_seq, SINCE_MAX_ENTRIES, SINCE_MAX_BYTES)?;
        let entries = rows
            .into_iter()
            .map(|row| DmCommitEntry {
                log_seq: row.log_seq,
                epoch: row.epoch,
                origin_node: row.origin_node,
                commit: row.commit,
            })
            .collect();
        Ok(DmOrderReply::Commits { entries, more })
    })
}

fn status(
    store: &RouterRedbStore,
    caller: &DmCaller<'_>,
    request: &DmStatus,
) -> Result<DmOrderReply, NodeCoreError> {
    if !scope_ok(&request.scope_id) {
        return Ok(refused(DmRefusal::BadRequest));
    }
    store.dm_order_read(|view| {
        let Some(row) = view.scope(request.kind.byte(), &request.scope_id)? else {
            return Ok(DmOrderReply::UnknownScope);
        };
        let Some(head) = view.head(&row.group_id)? else {
            return Ok(DmOrderReply::UnknownScope);
        };
        if !head.anchors.iter().any(|anchor| anchor == caller.anchor) {
            return Ok(refused(DmRefusal::NotMember));
        }
        Ok(DmOrderReply::Status {
            group_id: row.group_id.to_vec(),
            epoch: head.epoch,
            log_seq: head.log_seq,
        })
    })
}
