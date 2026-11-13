// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Primary-approved receiving actions. Prepared operations retain their exact ids on retry.
use super::{BornAccount, PrimaryVault};
use crate::SdkError;
use ramflux_crypto::contact_reach::{VerifiedPeer, verify_notice};
use ramflux_protocol::{
    contact_reach::{
        Admission, COMMAND_LIFETIME, CONVERSATION_LIFETIME, Decision, NOTICE_DOMAIN, Notice,
        Operation, PeerReply, Permissions, ReachMode, ReachPolicy, Reason, Subject, Submission,
        Traffic,
    },
    custody::{self, DeviceRef},
};

/// Current home and CAS observations supplied by a verified complete state read.
/// A linked device cannot replace the primary approving actor with its own identity.
#[derive(Clone, Copy)]
pub struct ReachCommandContext<'a> {
    pub actor: &'a DeviceRef,
    pub home_head_hash: &'a str,
    pub expected_revision: u64,
    pub now: u64,
}

/// Exact user-reviewed allow action. Receipt and typing choices are explicit signed fields.
pub struct ReachAllow<'a> {
    pub subject: Subject,
    pub permissions: Permissions,
    pub peer: &'a VerifiedPeer,
    pub peer_evidence: &'a PeerReply,
    pub notice: &'a Notice,
    pub acknowledged_notice_hash: &'a str,
}

/// Start and Reply have identical atomic grant/outbox requirements and distinct wire outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReachConversationAction {
    Start,
    Reply,
}

fn refused() -> SdkError {
    SdkError::ReachRefused(Reason::ForeignReadRefused)
}
fn operation_id() -> Result<String, SdkError> {
    Ok(ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?))
}
fn expiry(now: u64, lifetime: u64) -> Result<u64, SdkError> {
    now.checked_add(lifetime)
        .filter(|n| *n <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
        .ok_or_else(refused)
}
impl BornAccount {
    /// Prepare an explicit Settings action. Setup uses revision zero and `ContactsOnly`.
    /// Retain this operation unchanged until its original outcome is known.
    /// # Errors
    /// Refuses unavailable primary authority, malformed context and unsafe revisions/times.
    pub fn prepare_reach_policy(
        &self,
        vault: &dyn PrimaryVault,
        context: ReachCommandContext<'_>,
        mode: ReachMode,
    ) -> Result<Operation, SdkError> {
        if context.expected_revision == 0 && mode != ReachMode::ContactsOnly {
            return Err(SdkError::ReachRefused(Reason::ReachPolicyRequired));
        }
        let body = ReachPolicy {
            version: 1,
            operation_id: operation_id()?,
            account_anchor: self.record().body.account_anchor.clone(),
            home_head_hash: context.home_head_hash.into(),
            expected_revision: context.expected_revision,
            revision: context.expected_revision.checked_add(1).ok_or_else(refused)?,
            mode,
            authority_head_hash: custody::object_hash(self.record())?,
            master_certificate_hash: custody::object_hash(&self.record().body.master_certificate)?,
            actor: context.actor.clone(),
            issued_at: context.now,
            expires_at: expiry(context.now, COMMAND_LIFETIME)?,
        };
        Ok(Operation::Policy {
            update: self.group_primary(vault)?.sign_reach_policy(
                body,
                self.verified(),
                context.now,
            )?,
        })
    }

    /// Prepare an allow only after independently verified evidence and exact Notice acknowledgment.
    /// This installs no local friendship. Start/reply combine this update with the sealed outbox.
    /// # Errors
    /// Refuses expired peer evidence, mismatched Notice/subject, missing primary or changed facts.
    pub fn prepare_reach_allow(
        &self,
        vault: &dyn PrimaryVault,
        context: ReachCommandContext<'_>,
        action: ReachAllow<'_>,
    ) -> Result<Operation, SdkError> {
        let root = &self.record().body.account_anchor;
        verify_notice(action.notice, root, action.peer)?;
        if action.subject.root() != Some(action.peer.root())
            || action.peer.expires_at() <= context.now
            || custody::object_hash(&action.peer_evidence.snapshot)? != action.peer.snapshot_hash()
            || custody::framed_hash(
                ramflux_protocol::contact_reach::PAYLOAD_HASH_DOMAIN,
                &action.peer_evidence.payload,
            )? != action.peer_evidence.snapshot.body.payload_hash
            || custody::framed_hash(NOTICE_DOMAIN, action.notice)?
                != action.acknowledged_notice_hash
        {
            return Err(refused());
        }
        let mut body = self.reach_decision_body(&context, action.subject, Decision::Allow)?;
        body.permissions = Some(action.permissions);
        body.grant_until = Some(if matches!(body.subject, Subject::Conversation { .. }) {
            expiry(context.now, CONVERSATION_LIFETIME)?
        } else {
            0
        });
        body.notice_hash = Some(action.acknowledged_notice_hash.into());
        body.evidence_hash = Some(action.peer.snapshot_hash().into());
        let update =
            self.group_primary(vault)?.sign_reach_admission(body, self.verified(), context.now)?;
        Ok(Operation::Admission {
            update,
            peer_evidence: Some(Box::new(action.peer_evidence.clone())),
            notice: Some(Box::new(action.notice.clone())),
        })
    }

    /// Prepare the complete atomic grant plus already sealed outbound operation.
    /// Keep the returned operation unchanged through uncertain outcomes; never reseal on retry.
    /// # Errors
    /// Refuses nonconversation approvals, wrong source/target, changed sealed bytes or bad evidence.
    pub fn prepare_reach_conversation(
        &self,
        vault: &dyn PrimaryVault,
        context: ReachCommandContext<'_>,
        approval: ReachAllow<'_>,
        action: ReachConversationAction,
        submission: Submission,
    ) -> Result<Operation, SdkError> {
        let Subject::Conversation { root, conversation_id } = &approval.subject else {
            return Err(refused());
        };
        let route = &submission.route.body;
        if route.source.account_anchor != self.record().body.account_anchor
            || &route.recipient_root != root
            || &route.conversation_id != conversation_id
            || route.traffic != Traffic::Dm
        {
            return Err(refused());
        }
        ramflux_crypto::contact_reach::verify_submission(
            &submission,
            self.verified(),
            context.now,
        )?;
        let target_node_id = approval.peer.node().to_owned();
        let Operation::Admission {
            update,
            peer_evidence: Some(peer_evidence),
            notice: Some(notice),
        } = self.prepare_reach_allow(vault, context, approval)?
        else {
            return Err(refused());
        };
        Ok(match action {
            ReachConversationAction::Start => Operation::Start {
                update,
                peer_evidence,
                notice,
                target_node_id,
                submission: Box::new(submission),
            },
            ReachConversationAction::Reply => Operation::Reply {
                update,
                peer_evidence,
                notice,
                target_node_id,
                submission: Box::new(submission),
            },
        })
    }

    /// Prepare a silent local decline, block, unblock or revocation. No contact decision is emitted.
    /// # Errors
    /// Refuses Allow, invalid subject/decision combinations and unavailable primary authority.
    pub fn prepare_reach_denial(
        &self,
        vault: &dyn PrimaryVault,
        context: ReachCommandContext<'_>,
        subject: Subject,
        decision: Decision,
    ) -> Result<Operation, SdkError> {
        if decision == Decision::Allow {
            return Err(refused());
        }
        let body = self.reach_decision_body(&context, subject, decision)?;
        Ok(Operation::Admission {
            update: self.group_primary(vault)?.sign_reach_admission(
                body,
                self.verified(),
                context.now,
            )?,
            peer_evidence: None,
            notice: None,
        })
    }

    fn reach_decision_body(
        &self,
        context: &ReachCommandContext<'_>,
        subject: Subject,
        decision: Decision,
    ) -> Result<Admission, SdkError> {
        Ok(Admission {
            version: 2,
            operation_id: operation_id()?,
            recipient_root: self.record().body.account_anchor.clone(),
            home_head_hash: context.home_head_hash.into(),
            expected_revision: context.expected_revision,
            subject,
            decision,
            permissions: None,
            grant_until: None,
            authority_head_hash: custody::object_hash(self.record())?,
            master_certificate_hash: custody::object_hash(&self.record().body.master_certificate)?,
            actor: context.actor.clone(),
            notice_hash: None,
            evidence_hash: None,
            issued_at: context.now,
            expires_at: expiry(context.now, COMMAND_LIFETIME)?,
        })
    }
}
