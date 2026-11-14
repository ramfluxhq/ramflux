// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home activation cannot turn unavailable reach state transfer into empty permissions.
use super::Reason;

pub(crate) fn require_reach_transfer(
    _tx: &redb::WriteTransaction,
    _root: &str,
) -> std::result::Result<(), crate::NodeCoreError> {
    // The deferred transfer cannot authenticate either an empty or a populated reach image.
    Err(crate::NodeCoreError::ContactReachRefused(Reason::HomeEvidenceRequired))
}
