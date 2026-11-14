// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current-format encrypted rows and bounded decoding; these fixtures grant no authority.
use super::*;
use crate::{AccountDbKey, AccountIndex};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn saved() -> ReachSavedState {
    let digest = ramflux_protocol::encode_base64url([1; 32]);
    ReachSavedState {
        root: digest.clone(),
        revision: 1,
        admission_revision: 0,
        home_head_hash: digest.clone(),
        home_node_key: digest.clone(),
        authority_head_hash: digest.clone(),
        custodian_head_hash: None,
        state_hash: digest.clone(),
        provenance_hash: digest,
        records: vec![],
        restrictions: BTreeMap::new(),
        conflict: false,
        positive_pending: true,
    }
}

#[test]
fn cr_saved_reach_row_requires_current_fields_before_projection() -> TestResult {
    let temp = tempfile::TempDir::new()?;
    let index = AccountIndex::open(temp.path())?;
    let current = saved();
    index.create_account("acct", &current.root)?;
    let db = AccountDb::open(&index, "acct", &AccountDbKey::generate()?)?;
    db.persist_reach_saved_state(&current)?;
    assert_eq!(
        db.reach_saved_state()?,
        Some(current.clone()),
        "the complete format must round-trip"
    );
    for field in
        ["root", "home_node_key", "custodian_head_hash", "provenance_hash", "positive_pending"]
    {
        let mut missing = serde_json::to_value(&current)?;
        missing.as_object_mut().ok_or("saved object")?.remove(field);
        db.connection.execute(
            "UPDATE runtime_actor_state SET state_json=?1 WHERE state_kind=?2",
            rusqlite::params![serde_json::to_vec(&missing)?, KEY],
        )?;
        assert!(
            db.reach_saved_state().is_err(),
            "missing {field} must refuse rather than select an old shape"
        );
    }
    db.persist_reach_saved_state(&current)?;
    db.connection.execute(
        "UPDATE runtime_actor_state SET state_json=zeroblob(?1) WHERE state_kind=?2",
        rusqlite::params![MAX_BYTES + 1, KEY],
    )?;
    assert!(
        matches!(
            db.reach_saved_state(),
            Err(StorageError::SegmentResourceCapacity { limit: MAX_BYTES })
        ),
        "SQL must refuse excess bytes before allocating or decoding an invalid saved image"
    );
    Ok(())
}
