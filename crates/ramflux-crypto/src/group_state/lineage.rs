// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated ancestry windows and deterministic comparison of related group forks.
use super::{CryptoError, VerifiedGroupState, group_state_head_hash, invalid};
use ramflux_protocol::group_state::{
    GroupStateCheckpoint, GroupStateHead, MAX_GROUP_STATE_LINEAGE,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupStateRelation {
    Same,
    Extension,
    Ancestor,
    IncomingPreferred,
    ExistingPreferred,
    Unrelated,
}
impl VerifiedGroupState {
    /// Compare the first divergent authenticated operation hash, independently of branch length.
    /// # Errors
    /// Rejects malformed hash encoding; ordinary unrelated histories return `Unrelated`.
    pub fn relation_to(&self, previous: &Self) -> Result<GroupStateRelation, CryptoError> {
        use GroupStateRelation::{
            Ancestor, ExistingPreferred, Extension, IncomingPreferred, Same, Unrelated,
        };
        if self.view.group_id != previous.view.group_id
            || self.genesis_hash().is_none()
            || self.genesis_hash() != previous.genesis_hash()
        {
            return Ok(Unrelated);
        }
        if self.view.head_hash == previous.view.head_hash && self.view.epoch == previous.view.epoch
        {
            return Ok(if self.view == previous.view { Same } else { Unrelated });
        }
        if self.contains_head(previous.view.epoch, &previous.view.head_hash) {
            return Ok(Extension);
        }
        if previous.contains_head(self.view.epoch, &self.view.head_hash) {
            return Ok(Ancestor);
        }
        let common = self
            .heads
            .iter()
            .filter(|(epoch, head)| previous.contains_head(**epoch, head))
            .map(|(epoch, _)| *epoch)
            .max();
        let Some(next) = common.and_then(|epoch| epoch.checked_add(1)) else {
            return Ok(Unrelated);
        };
        let Some((left, right)) = self.heads.get(&next).zip(previous.heads.get(&next)) else {
            return Ok(Unrelated);
        };
        let left = ramflux_protocol::decode_base64url(left)?;
        let right = ramflux_protocol::decode_base64url(right)?;
        Ok(match left.cmp(&right) {
            std::cmp::Ordering::Less => IncomingPreferred,
            std::cmp::Ordering::Greater => ExistingPreferred,
            std::cmp::Ordering::Equal => Unrelated,
        })
    }
    /// Last common epoch before divergence, when both proofs retain its next operation.
    #[must_use]
    pub fn common_epoch(&self, other: &Self) -> Option<u64> {
        if self.genesis_hash().is_none() || self.genesis_hash() != other.genesis_hash() {
            return None;
        }
        self.heads
            .iter()
            .filter(|(epoch, head)| other.contains_head(**epoch, head))
            .map(|(epoch, _)| *epoch)
            .max()
    }
}
pub(super) fn validate(checkpoint: &GroupStateCheckpoint) -> Result<(), CryptoError> {
    if checkpoint.lineage.len() > MAX_GROUP_STATE_LINEAGE {
        return Err(invalid("checkpoint lineage budget exceeded"));
    }
    let mut previous = None;
    for head in &checkpoint.lineage {
        if head.epoch == 0
            || head.epoch > checkpoint.state.epoch
            || ramflux_protocol::decode_base64url(&head.head_hash)?.len() != 32
            || previous.is_some_and(|epoch: u64| epoch.checked_add(1) != Some(head.epoch))
        {
            return Err(invalid("invalid checkpoint lineage"));
        }
        previous = Some(head.epoch);
    }
    if checkpoint.lineage.last().is_some_and(|head| {
        head.epoch != checkpoint.state.epoch || head.head_hash != checkpoint.state.head_hash
    }) {
        return Err(invalid("checkpoint lineage does not end at its head"));
    }
    Ok(())
}
pub(super) fn merge(
    heads: &mut BTreeMap<u64, String>,
    checkpoint: Option<&GroupStateCheckpoint>,
) -> Result<(), CryptoError> {
    if let Some(checkpoint) = checkpoint {
        for head in &checkpoint.lineage {
            heads.insert(head.epoch, head.head_hash.clone());
        }
        heads.insert(1, group_state_head_hash(&checkpoint.genesis)?);
    }
    Ok(())
}
pub(super) fn retained(previous: &VerifiedGroupState) -> Vec<GroupStateHead> {
    let mut retained = Vec::<GroupStateHead>::new();
    for (epoch, hash) in previous.heads.iter().rev() {
        if retained.len() >= MAX_GROUP_STATE_LINEAGE
            || retained.last().is_some_and(|head| epoch.checked_add(1) != Some(head.epoch))
        {
            break;
        }
        retained.push(GroupStateHead { epoch: *epoch, head_hash: hash.clone() });
    }
    retained.reverse();
    retained
}
