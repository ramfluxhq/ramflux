// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Proposal and sender allowlists and the two hooks the group layers fill in later.

use openmls::prelude::{LeafNodeIndex, Proposal, Sender};

use crate::MlsError;
use crate::credential::MemberIdentity;

/// Who may add and remove members. MLS-LG and MLS-DM fill this without a second merge site.
pub trait CommitPolicy: Send + Sync {
    /// May `committer` add `added`?
    fn may_add(&self, committer: &MemberIdentity, added: &MemberIdentity) -> bool;
    /// May `committer` remove `removed`?
    fn may_remove(&self, committer: &MemberIdentity, removed: &MemberIdentity) -> bool;
}

/// MLS-0 default: every member may add and remove.
pub struct PermissiveCommitPolicy;

impl CommitPolicy for PermissiveCommitPolicy {
    fn may_add(&self, _committer: &MemberIdentity, _added: &MemberIdentity) -> bool {
        true
    }

    fn may_remove(&self, _committer: &MemberIdentity, _removed: &MemberIdentity) -> bool {
        true
    }
}

/// Roster of a pseudonym group. A pseudonym key proves nothing by itself; MLS-LG decides which
/// keys belong.
pub trait RosterPolicy: Send + Sync {
    /// May this member be added to the group?
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] when the roster does not know the member.
    fn accept_member(&self, member: &MemberIdentity) -> Result<(), MlsError>;

    /// May `new` replace `old` as the same member (Update or UpdatePath with another key)?
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] when the roster does not accept the successor.
    fn accept_successor(&self, old: &MemberIdentity, new: &MemberIdentity) -> Result<(), MlsError>;

    /// Judge the whole tree a Welcome delivers, in one call.
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] when the roster does not accept the tree.
    fn accept_welcome(&self, members: &[MemberIdentity]) -> Result<(), MlsError>;
}

/// MLS-0 production default: no roster exists, so every pseudonym group operation is refused.
pub struct DenyAllRoster;

impl RosterPolicy for DenyAllRoster {
    fn accept_member(&self, _member: &MemberIdentity) -> Result<(), MlsError> {
        Err(MlsError::PolicyRejected("no roster policy is installed".to_owned()))
    }

    fn accept_successor(
        &self,
        _old: &MemberIdentity,
        _new: &MemberIdentity,
    ) -> Result<(), MlsError> {
        Err(MlsError::PolicyRejected("no roster policy is installed".to_owned()))
    }

    fn accept_welcome(&self, _members: &[MemberIdentity]) -> Result<(), MlsError> {
        Err(MlsError::PolicyRejected("no roster policy is installed".to_owned()))
    }
}

/// Only Add, Update and Remove are allowed, in commits and before a proposal is stored. Every
/// other type (PreSharedKey, ReInit, ExternalInit, GroupContextExtensions with any
/// `ExternalSenders`, custom and unknown types, and the leave-by-sender kind) is refused.
pub(crate) fn check_proposal_type(proposal: &Proposal) -> Result<(), MlsError> {
    match proposal {
        Proposal::Add(_) | Proposal::Update(_) | Proposal::Remove(_) => Ok(()),
        other => Err(MlsError::PolicyRejected(format!(
            "proposal type {:?} is not allowed",
            other.proposal_type()
        ))),
    }
}

/// Only members may send handshake messages: External, NewMemberProposal and NewMemberCommit
/// bypass the wire-format check and are refused.
pub(crate) fn check_sender(sender: &Sender) -> Result<LeafNodeIndex, MlsError> {
    match sender {
        Sender::Member(index) => Ok(*index),
        other => Err(MlsError::PolicyRejected(format!("sender {other:?} is not allowed"))),
    }
}
