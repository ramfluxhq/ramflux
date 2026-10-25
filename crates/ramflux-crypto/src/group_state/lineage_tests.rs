// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fork preference is stable across branch growth and checkpoint compaction.
use super::*;
#[test]
fn first_divergent_hash_decides_a_fork_independently_of_later_branch_length()
-> Result<(), CryptoError> {
    let owner = person("owner", "phone", 101, 102)?;
    let initial = create(&owner)?;
    let left = step(&initial, &owner, GroupStateChange::SetName { name: "left".into() })?;
    let right = step(&initial, &owner, GroupStateChange::SetName { name: "right".into() })?;
    let (winner, loser) = if ramflux_protocol::decode_base64url(&left.view.head_hash)?
        < ramflux_protocol::decode_base64url(&right.view.head_hash)?
    {
        (left, right)
    } else {
        (right, left)
    };
    assert_eq!(winner.relation_to(&loser)?, GroupStateRelation::IncomingPreferred);
    assert_eq!(loser.relation_to(&winner)?, GroupStateRelation::ExistingPreferred);
    let longer = step(&loser, &owner, GroupStateChange::SetName { name: "longer".into() })?;
    assert_eq!(winner.relation_to(&longer)?, GroupStateRelation::IncomingPreferred);
    assert_eq!(longer.relation_to(&winner)?, GroupStateRelation::ExistingPreferred);
    assert_eq!(winner.common_epoch(&longer), Some(1));
    assert!(!winner.extends(&longer));
    Ok(())
}
#[test]
fn compacted_lineage_keeps_recent_ancestry_and_reports_an_unrelated_old_head()
-> Result<(), CryptoError> {
    let owner = person("owner", "phone", 111, 112)?;
    let mut current = create(&owner)?;
    let mut old = None;
    let mut recent = None;
    for index in 0..120 {
        current = advance_group_state(
            &owner.root,
            &owner.branch,
            &owner.actor,
            &current,
            GroupStateChange::SetName { name: format!("revision {index}") },
        )?;
        if index == 0 {
            old = Some(current.clone());
        }
        if index == 70 {
            recent = Some(current.clone());
        }
    }
    assert!(
        current.snapshot.checkpoint.as_ref().is_some_and(|checkpoint| checkpoint.lineage.len()
            <= ramflux_protocol::group_state::MAX_GROUP_STATE_LINEAGE)
    );
    let current = verify_group_state_snapshot(current.snapshot().clone())?;
    assert_eq!(
        current.relation_to(&recent.ok_or_else(|| invalid("recent"))?)?,
        GroupStateRelation::Extension
    );
    assert_eq!(
        current.relation_to(&old.ok_or_else(|| invalid("old"))?)?,
        GroupStateRelation::Unrelated
    );
    Ok(())
}
#[test]
fn a_branch_signature_cannot_change_root_authenticated_checkpoint_lineage()
-> Result<(), CryptoError> {
    let owner = person("owner", "phone", 121, 122)?;
    let initial = create(&owner)?;
    let named = step(&initial, &owner, GroupStateChange::SetName { name: "named".into() })?;
    let compact = compact_group_state(&owner.root, &owner.branch, &owner.actor, &named)?;
    let mut snapshot = compact.snapshot().clone();
    let checkpoint = snapshot.checkpoint.as_mut().ok_or_else(|| invalid("checkpoint"))?;
    checkpoint.lineage[0].head_hash = ramflux_protocol::encode_base64url([7; 32]);
    snapshot.signature = crate::sign_with_device_branch(&owner.branch, &snapshot_body(&snapshot))?;
    assert!(verify_group_state_snapshot(snapshot).is_err());
    Ok(())
}
