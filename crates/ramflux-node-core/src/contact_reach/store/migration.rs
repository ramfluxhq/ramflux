// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home activation cannot turn unavailable reach state transfer into empty permissions.
use super::{ACCOUNTS, ReadableTable, Reason};

pub(crate) fn require_empty_reach_activation(
    tx: &redb::WriteTransaction,
    root: &str,
) -> std::result::Result<(), crate::NodeCoreError> {
    let table =
        tx.open_table(ACCOUNTS).map_err(|error| crate::NodeCoreError::Redb(error.to_string()))?;
    let present =
        table.get(root).map_err(|error| crate::NodeCoreError::Redb(error.to_string()))?.is_some();
    // Existing legacy accounts remain under their old inactive-profile contract. When reach
    // activates, the deferred transfer has no authenticated empty-state proof, so hold it too.
    if present || super::super::enabled() {
        return Err(crate::NodeCoreError::ContactReachRefused(Reason::HomeEvidenceRequired));
    }
    Ok(())
}
