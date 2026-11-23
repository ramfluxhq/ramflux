// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ceremony reservation beside one revoked same-owner account.
//! A live account for the anchor is left in place. An unpublished leftover with
//! no host marker is released so a failed join can be retried.

use super::{authority_exists, genesis};
use crate::SdkError;
use crate::custody::agent_creation::{host_branch_marked, marked_account_anchor};
use std::path::{Path, PathBuf};

pub(super) fn reserve_for_ceremony(
    root: &Path,
    id: &str,
    anchor: &str,
) -> Result<PathBuf, SdkError> {
    if let Some(retained) = retained_revoked(root, id, anchor)? {
        return genesis::reserve_beside_retained(root, id, anchor, &retained);
    }
    genesis::reserve_account(root, id, anchor)
}

fn retained_revoked(root: &Path, id: &str, anchor: &str) -> Result<Option<String>, SdkError> {
    let index = ramflux_storage::AccountIndex::open(root)?;
    let live = index.live_account_id(anchor)?;
    drop(index);
    let Some(existing) = live else {
        return Ok(None);
    };
    if existing == id {
        return Ok(None);
    }
    if !authority_exists(root, &existing)? && !host_branch_marked(root, &existing) {
        genesis::discard_unpublished(root, &existing, anchor)?;
        return Ok(None);
    }
    if host_branch_marked(root, &existing)
        && marked_account_anchor(root, &existing).as_deref() == Some(anchor)
    {
        return Ok(Some(existing));
    }
    Ok(None)
}
