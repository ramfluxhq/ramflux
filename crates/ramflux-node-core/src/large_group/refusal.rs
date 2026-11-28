// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed refusals of the group host (MLS-SPEC r1.1 2.3). Every refusal aborts the write
//! transaction it was raised in, so a refused request changes nothing (a token is not spent).

use ramflux_crypto::large_group::LgError;

use crate::NodeCoreError;

/// Why the host refused one request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LgRefusal {
    /// The frame's `group_id` is not the session's.
    #[error("session_scope")]
    SessionScope,
    /// No valid token, admin signature or proof.
    #[error("unauthorized")]
    Unauthorized,
    /// The token was redeemed before.
    #[error("token_spent")]
    TokenSpent,
    /// The token is for an epoch the host no longer accepts.
    #[error("token_epoch_stale")]
    TokenEpochStale,
    /// Envelope kind, MLS header and authenticated data disagree.
    #[error("header_mismatch")]
    HeaderMismatch,
    /// The epoch rule failed; the client catches up to `epoch`.
    #[error("stale")]
    Stale {
        /// The head epoch.
        epoch: u64,
    },
    /// Commit pacing or the 24 h commit cap; the client waits until `retry_at_ms`.
    #[error("paced")]
    Paced {
        /// Earliest host time (ms) a commit can be accepted again.
        retry_at_ms: u64,
    },
    /// A commit adds a pseudonym without a pending join entry, or violates an add rule.
    #[error("commit_bad_adds")]
    CommitBadAdds,
    /// A commit removes a pseudonym it may not remove.
    #[error("commit_bad_removes")]
    CommitBadRemoves,
    /// A blob reference is incomplete or unknown.
    #[error("blob_missing")]
    BlobMissing,
    /// A blob upload broke a size, order or hash rule.
    #[error("blob_bad")]
    BlobBad,
    /// The group is full (leaf cap).
    #[error("leaf_cap")]
    LeafCap,
    /// Only tier 1000 exists in the beta.
    #[error("tier_unavailable")]
    TierUnavailable,
    /// Unknown group, entry or row.
    #[error("not_found")]
    NotFound,
    /// The caller has no right to do this.
    #[error("forbidden")]
    Forbidden,
    /// The owner can neither be removed nor demoted.
    #[error("owner_unremovable")]
    OwnerUnremovable,
    /// A group with this genesis exists already.
    #[error("group_exists")]
    GroupExists,
    /// The invite is unknown, expired, revoked, used up or its proof is wrong.
    #[error("invite_invalid")]
    InviteInvalid,
    /// The join request used a retired join key.
    #[error("join_key_stale")]
    JoinKeyStale,
    /// The group's join bucket (1/s, burst 10) is empty.
    #[error("join_rate_limited")]
    JoinRateLimited,
    /// The join queue holds 1 000 pending requests.
    #[error("pending_full")]
    PendingFull,
    /// The pseudonym is a member or already waits.
    #[error("already_joined")]
    AlreadyJoined,
    /// The per-day issuance quota of the bucket is used up.
    #[error("quota")]
    Quota,
    /// Retained log starts after the requested position.
    #[error("pruned")]
    Pruned {
        /// The first retained `log_seq`.
        floor_seq: u64,
    },
    /// The token root key has evaluated 2^30 elements: no more tokens are issued (the root is
    /// fixed in the beta; rotation is the post-beta card `TOKEN-ROOT-ROTATE`).
    #[error("token_root_exhausted")]
    TokenRootExhausted,
    /// A bounded host resource is full (routes, uploads, admin chain).
    #[error("limit")]
    Limit,
    /// Malformed or structurally invalid request.
    #[error("bad_request")]
    BadRequest,
    /// The host key file is missing or unusable.
    #[error("key_file")]
    KeyFile,
    /// Storage or internal invariant failure (details are logged without group data).
    #[error("internal")]
    Internal,
}

impl LgRefusal {
    /// The status token sent to the client.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::SessionScope => "session_scope",
            Self::Unauthorized => "unauthorized",
            Self::TokenSpent => "token_spent",
            Self::TokenEpochStale => "token_epoch_stale",
            Self::HeaderMismatch => "header_mismatch",
            Self::Stale { .. } => "stale",
            Self::Paced { .. } => "paced",
            Self::CommitBadAdds => "commit_bad_adds",
            Self::CommitBadRemoves => "commit_bad_removes",
            Self::BlobMissing => "blob_missing",
            Self::BlobBad => "blob_bad",
            Self::LeafCap => "leaf_cap",
            Self::TierUnavailable => "tier_unavailable",
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::OwnerUnremovable => "owner_unremovable",
            Self::GroupExists => "group_exists",
            Self::InviteInvalid => "invite_invalid",
            Self::JoinKeyStale => "join_key_stale",
            Self::JoinRateLimited => "join_rate_limited",
            Self::PendingFull => "pending_full",
            Self::AlreadyJoined => "already_joined",
            Self::Quota => "quota",
            Self::Pruned { .. } => "pruned",
            Self::TokenRootExhausted => "token_root_exhausted",
            Self::Limit => "limit",
            Self::BadRequest => "bad_request",
            Self::KeyFile => "key_file",
            Self::Internal => "internal",
        }
    }
}

impl From<NodeCoreError> for LgRefusal {
    fn from(error: NodeCoreError) -> Self {
        // The text names a table or a format, never a group, pseudonym or address.
        tracing::warn!(%error, "group host store error");
        Self::Internal
    }
}

impl From<LgError> for LgRefusal {
    fn from(error: LgError) -> Self {
        match error {
            LgError::Format("tier_unavailable") => Self::TierUnavailable,
            LgError::KeyFile(_) => Self::KeyFile,
            LgError::Random | LgError::Crypto(_) | LgError::PoprfProtocol | LgError::Poprf(_) => {
                Self::Internal
            }
            LgError::Format(_) | LgError::Verify(_) => Self::BadRequest,
        }
    }
}

/// Result of one host operation.
pub type LgResult<T> = Result<T, LgRefusal>;
