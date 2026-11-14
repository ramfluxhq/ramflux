// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Derive continuous root membership from adopted, creator-authenticated successive heads.
use super::{Admission, GroupRoster, SdkError, Signed, Subject, VerifiedGroupState, pending};
use ramflux_protocol::contact_reach::GroupRosterMember;
use std::collections::BTreeMap;

fn roots(state: &VerifiedGroupState, own: &str) -> BTreeMap<String, u64> {
    state
        .view()
        .members
        .iter()
        .filter(|member| member.identity.root_commitment != own)
        .map(|member| (member.identity.root_commitment.clone(), state.view().epoch))
        .collect()
}
pub(super) fn derive(
    db: &ramflux_storage::AccountDb,
    grant: &Signed<Admission>,
    target: &VerifiedGroupState,
    checkpoint: Option<&GroupRoster>,
) -> Result<Vec<GroupRosterMember>, SdkError> {
    let Subject::Group { group_epoch, membership_hash, genesis_hash, .. } = &grant.body.subject
    else {
        return Err(pending());
    };
    let own = &grant.body.recipient_root;
    let checkpoint =
        checkpoint.filter(|roster| roster.header.body.group_epoch < target.view().epoch);
    let (epoch, mut hash, mut members) = if let Some(roster) = checkpoint {
        roster.validate(grant)?;
        (
            roster.header.body.group_epoch,
            roster.header.body.membership_hash.clone(),
            roster.members.iter().map(|member| (member.root.clone(), member.since_epoch)).collect(),
        )
    } else {
        let start = db
            .shared_group_state_at_epoch(&target.view().group_id, *group_epoch)?
            .ok_or_else(pending)?;
        if !start.contains_head(*group_epoch, membership_hash)
            || start.genesis_hash()? != *genesis_hash
        {
            return Err(pending());
        }
        (*group_epoch, membership_hash.clone(), roots(&start, own))
    };
    if target.view().epoch < epoch || target.view().epoch.saturating_sub(epoch) > 64 {
        return Err(pending());
    }
    let chain = db
        .shared_group_state_range(&target.view().group_id, epoch, target.view().epoch)?
        .ok_or_else(pending)?;
    for next in chain {
        if next.genesis_hash()? != *genesis_hash
            || next.snapshot().previous_hash.as_deref() != Some(hash.as_str())
        {
            return Err(pending());
        }
        let mut current = roots(&next, own);
        for (root, since) in &mut current {
            if let Some(previous) = members.get(root) {
                *since = *previous;
            }
        }
        members = current;
        hash.clone_from(&next.snapshot().state_hash);
    }
    if hash != target.snapshot().state_hash {
        return Err(pending());
    }
    Ok(members
        .into_iter()
        .map(|(root, since_epoch)| GroupRosterMember { root, since_epoch })
        .collect())
}
