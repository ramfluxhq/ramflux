// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test support: erase through the real object-retention trigger.
#![allow(clippy::expect_used)]

use crate::prelude::*;
use ramflux_storage::{AccountDb, ObjectReferenceAdmission, ObjectReferenceOwner};
use serde_json::json;

/// Erases through the real object-retention trigger: a message that owns a retired
/// selector reference is deleted, which advances the private-erasure generation.
/// Names are unique per current generation so a second call on the same DB does not
/// reuse a deleted message id (`register_object_reference` is `ObjectErased` then).
pub(crate) fn erase_through_retention(db: &AccountDb) -> Result<(), SdkError> {
    let before = db.privacy_erasure_generation()?;
    let owner = format!("erase-owner-{before}");
    db.send_direct_message("thread", &owner, "peer", b"body")?;
    erase_message_through_retention(db, &owner)
}

/// Erases `owner` through the real object-retention trigger (same generation bump).
pub(crate) fn erase_message_through_retention(db: &AccountDb, owner: &str) -> Result<(), SdkError> {
    let before = db.privacy_erasure_generation()?;
    let alias = format!("erase-alias-{before}");
    let hash = format!("erase-ref-{before}");
    let wire = format!("erase-wire-{before}");
    db.register_object_reference(
        ObjectReferenceAdmission::FreshMessage,
        &ObjectReferenceOwner {
            reference_hash: &hash,
            wire_id: &wire,
            manifest_hash: "manifest",
            selector: &alias,
            message_id: owner,
            reference: &json!({"object_id": wire.as_str(), "slot": hash.as_str()}),
            metadata: &json!({"object_id": alias.as_str(), "message_id": owner}),
        },
    )?;
    db.persist_actor_state(
        &format!("attachment/reference/{alias}"),
        &json!({"reference":{"object_id": wire, "manifest_hash":"manifest"}}),
    )?;
    db.set_object_tombstoned(&alias)?;
    let slot = format!("attachment/reference-by-slot/{alias}");
    db.persist_actor_state(&slot, &json!(alias))?;
    db.register_object_reference_actor(&hash, &slot)?;
    db.delete_direct_message("thread", owner, "local", "erase-tombstone")?;
    assert!(db.privacy_erasure_generation()? > before, "real erase advances the generation");
    Ok(())
}
