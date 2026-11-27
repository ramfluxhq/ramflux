// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Proposal and sender allowlists and the two hooks the group layers fill in later.

use openmls::prelude::{LeafNodeIndex, Proposal, Sender};

use super::context::{CommitCtx, WelcomeCtx};
use crate::MlsError;
use crate::credential::MemberIdentity;

/// Who may add and remove members. MLS-LG and MLS-DM fill this without a second merge site.
///
/// Every check returns a typed refusal. [`MlsError::ProofInputUnavailable`] is not a refusal: the
/// caller holds the commit and retries.
pub trait CommitPolicy: Send + Sync {
    /// May `committer` add `added`?
    ///
    /// # Errors
    /// The typed refusal.
    fn may_add(
        &self,
        ctx: &CommitCtx<'_>,
        committer: &MemberIdentity,
        added: &MemberIdentity,
    ) -> Result<(), MlsError>;

    /// May `committer` remove `removed`, as proposed by `proposer` (the committer itself for an
    /// inline proposal)?
    ///
    /// # Errors
    /// The typed refusal.
    fn may_remove(
        &self,
        ctx: &CommitCtx<'_>,
        committer: &MemberIdentity,
        proposer: &MemberIdentity,
        removed: &MemberIdentity,
    ) -> Result<(), MlsError>;

    /// Whole-commit check after the per-member checks.
    ///
    /// # Errors
    /// The typed refusal.
    fn check_delta(
        &self,
        ctx: &CommitCtx<'_>,
        committer: &MemberIdentity,
        added: &[MemberIdentity],
        removed: &[MemberIdentity],
    ) -> Result<(), MlsError> {
        let _ = (ctx, committer, added, removed);
        Ok(())
    }
}

/// MLS-0 default: every member may add and remove.
pub struct PermissiveCommitPolicy;

impl CommitPolicy for PermissiveCommitPolicy {
    fn may_add(
        &self,
        _ctx: &CommitCtx<'_>,
        _committer: &MemberIdentity,
        _added: &MemberIdentity,
    ) -> Result<(), MlsError> {
        Ok(())
    }

    fn may_remove(
        &self,
        _ctx: &CommitCtx<'_>,
        _committer: &MemberIdentity,
        _proposer: &MemberIdentity,
        _removed: &MemberIdentity,
    ) -> Result<(), MlsError> {
        Ok(())
    }
}

/// Roster of a pseudonym group. A pseudonym key proves nothing by itself; MLS-LG decides which
/// keys belong.
pub trait RosterPolicy: Send + Sync {
    /// May this member be added to the group?
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] when the roster does not know the member.
    fn accept_member(&self, ctx: &CommitCtx<'_>, member: &MemberIdentity) -> Result<(), MlsError>;

    /// May `new` replace `old` as the same member (Update or `UpdatePath` with another key)?
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] when the roster does not accept the successor.
    fn accept_successor(
        &self,
        ctx: &CommitCtx<'_>,
        old: &MemberIdentity,
        new: &MemberIdentity,
    ) -> Result<(), MlsError>;

    /// Judge the whole tree a Welcome delivers, in one call.
    ///
    /// # Errors
    /// [`MlsError::PolicyRejected`] when the roster does not accept the tree.
    fn accept_welcome(
        &self,
        ctx: &WelcomeCtx<'_>,
        members: &[MemberIdentity],
    ) -> Result<(), MlsError>;
}

/// MLS-0 production default: no roster exists, so every pseudonym group operation is refused.
pub struct DenyAllRoster;

impl RosterPolicy for DenyAllRoster {
    fn accept_member(
        &self,
        _ctx: &CommitCtx<'_>,
        _member: &MemberIdentity,
    ) -> Result<(), MlsError> {
        Err(MlsError::PolicyRejected("no roster policy is installed".to_owned()))
    }

    fn accept_successor(
        &self,
        _ctx: &CommitCtx<'_>,
        _old: &MemberIdentity,
        _new: &MemberIdentity,
    ) -> Result<(), MlsError> {
        Err(MlsError::PolicyRejected("no roster policy is installed".to_owned()))
    }

    fn accept_welcome(
        &self,
        _ctx: &WelcomeCtx<'_>,
        _members: &[MemberIdentity],
    ) -> Result<(), MlsError> {
        Err(MlsError::PolicyRejected("no roster policy is installed".to_owned()))
    }
}

/// Only Add, Update and Remove are allowed, in commits and before a proposal is stored. Every
/// other type (`PreSharedKey`, `ReInit`, `ExternalInit`, `GroupContextExtensions` with any
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

/// Only members may send handshake messages: External, `NewMemberProposal` and `NewMemberCommit`
/// bypass the wire-format check and are refused.
pub(crate) fn check_sender(sender: &Sender) -> Result<LeafNodeIndex, MlsError> {
    match sender {
        Sender::Member(index) => Ok(*index),
        other => Err(MlsError::PolicyRejected(format!("sender {other:?} is not allowed"))),
    }
}
