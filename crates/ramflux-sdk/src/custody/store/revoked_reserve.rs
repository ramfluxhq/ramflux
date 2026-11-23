// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ceremony reservation beside one revoked same-owner account.
//! A live account for the anchor is left in place. An unpublished leftover with
//! no host marker is released so a failed join can be retried.

use super::{authority_exists, genesis};
use crate::SdkError;
use crate::custody::agent_creation::{host_branch_marked, marked_account_anchor};
use std::path::{Path, PathBuf};

/// One in-process reservation at a time for an anchor, held through the
/// credential slot bind so a second join observes that slot instead of
/// discarding the first row.
pub(crate) fn with_anchor_ceremony<T>(
    anchor: &str,
    body: impl FnOnce() -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    let arc = {
        let mut gates = ceremony_gates().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        gates
            .entry(anchor.to_owned())
            .or_insert_with(|| std::sync::Arc::new(std::sync::Mutex::new(())))
            .clone()
    };
    let result = {
        let _guard = arc.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        body()
    };
    let mut gates = ceremony_gates().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if std::sync::Arc::strong_count(&arc) == 1 {
        gates.remove(anchor);
    }
    result
}

fn ceremony_gates() -> &'static std::sync::Mutex<
    std::collections::BTreeMap<String, std::sync::Arc<std::sync::Mutex<()>>>,
> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<String, std::sync::Arc<std::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

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
        // A bound credential slot is an in-flight ceremony for this anchor.
        // Discarding it would let a second join erase the first reservation.
        if crate::custody::pairing::local_credential::reservation_held(root, &existing) {
            return Err(SdkError::PairingCode("Busy"));
        }
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
