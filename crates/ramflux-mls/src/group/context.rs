// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The context the gate hands to the commit and roster policies.
//!
//! The shapes are the ones MLS-LG needs (card MLS-LG r2 section 3), so the policy traits do not
//! change again when groups land. For `dm` and `self` the `meta` bytes are the commit
//! authenticated data (`rf-dm-aad-v1`), for groups the canonical envelope header.

/// What a commit decision may look at besides the tree and the commit itself.
#[derive(Clone, Copy, Debug)]
pub struct CommitCtx<'a> {
    /// Group id.
    pub group_id: &'a [u8],
    /// Epoch the commit applies to (the group's epoch before the merge).
    pub epoch: u64,
    /// Orderer-signed accept time for a received commit; the committer's own clock (or `None`)
    /// while it stages its own commit before submitting.
    pub accepted_at: Option<u64>,
    /// Commit authenticated data (`dm`, `self`) or canonical envelope header (group).
    pub meta: &'a [u8],
}

/// What a Welcome decision may look at.
#[derive(Clone, Copy, Debug)]
pub struct WelcomeCtx<'a> {
    /// Group id of the Welcome's group.
    pub group_id: &'a [u8],
    /// The group id the caller expects (named by the orderer), when it knows one.
    pub expected_group_id: Option<&'a [u8]>,
    /// Leaf cap that applies to the joined tree.
    pub leaf_cap: usize,
}

/// The per-operation inputs of an own or received commit that the facade passes to the gate.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommitMeta<'a> {
    /// Authenticated data of an own commit (set before the commit is built). Received commits
    /// carry their own, read from the message.
    pub aad: &'a [u8],
    /// Time every lease check of this commit uses: the orderer-signed `accepted_at` of a received
    /// commit, the committer's clock for an own one. `None` where the caller has none.
    pub accepted_at: Option<u64>,
}
