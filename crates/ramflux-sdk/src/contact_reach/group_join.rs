// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Foreground group consent persists both retry identities before any primary signature or RPC.
use super::refused;
use crate::{
    RamfluxClient, SdkError,
    custody::{PrimaryVault, ReachCommandContext},
};
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::{
    contact_reach::{
        Decision, GROUP_JOIN_NOTICE_DOMAIN, GROUP_ROSTER_MEMBERS_DOMAIN, GroupJoinNotice,
        GroupRoster, GroupRosterHeader, GroupRosterMember, OPERATION_HASH_DOMAIN, Operation,
        OperationResult, Permissions, Reason, Subject,
    },
    custody,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const PREFIX: &str = "reach-group-join/";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinIntent {
    notice: GroupJoinNotice,
    grant_id: String,
    roster_id: String,
    grant: Option<Operation>,
    grant_applied: bool,
    roster: Option<Operation>,
    complete: bool,
}
fn invalid() -> SdkError {
    refused(Reason::ReachRouteInvalid)
}
fn key(group: &str) -> String {
    format!("{PREFIX}{}", ramflux_protocol::encode_base64url(group))
}
fn notice(state: &VerifiedGroupState, root: &str) -> Result<GroupJoinNotice, SdkError> {
    let roots: BTreeSet<_> = state
        .view()
        .members
        .iter()
        .map(|member| member.identity.root_commitment.as_str())
        .collect();
    if !roots.contains(root) {
        return Err(invalid());
    }
    let notice = GroupJoinNotice {
        version: 1,
        recipient_root: root.into(),
        group_id: state.view().group_id.clone(),
        conversation_id: state.view().conversation_id.clone(),
        genesis_hash: state.genesis_hash()?,
        epoch: state.view().epoch,
        membership_hash: state.snapshot().state_hash.clone(),
        inviter_root: state.snapshot().issuer.identity.root_commitment.clone(),
        member_root_count: u64::try_from(roots.len()).map_err(|_| invalid())?,
    };
    notice.validate()?;
    Ok(notice)
}
impl RamfluxClient {
    fn require_group_join_primary(&self) -> Result<(), SdkError> {
        let account = self.born_v3_account.as_ref().ok_or_else(invalid)?;
        self.require_reach_authority_head(
            &account.record().body.account_anchor,
            &custody::object_hash(account.record())?,
            super::current_authority::custodian_head(account.verified())?.as_deref(),
            crate::custody::network_now()?,
        )?;
        let own = self.owned_device_identity()?;
        let primary = &account.record().body.master_certificate.body.primary_device_ref;
        if own.root_commitment() != primary.account_anchor || own.device_id() != primary.device_id {
            return Err(SdkError::PairingCode("PrimaryRequired"));
        }
        Ok(())
    }
    /// Recompute the exact JOIN facts from the currently adopted native group head.
    /// # Errors
    /// Refuses missing signed state or a head without this account's membership.
    pub fn reach_group_join_notice(&self, group: &str) -> Result<GroupJoinNotice, SdkError> {
        let state = self.account_db()?.shared_group_state(group)?.ok_or_else(invalid)?;
        notice(&state, self.owned_device_identity()?.root_commitment())
    }

    /// Persist a foreground JOIN and its dependent initial roster without signing either.
    /// Existing own-account Consent must already accept this genesis. Retry does not replace ids.
    /// # Errors
    /// Refuses changed notice, absent Consent, conflicting pending JOIN or the bounded intent cap.
    pub fn stage_reach_group_join(
        &self,
        group: &str,
        acknowledged_hash: &str,
    ) -> Result<(), SdkError> {
        self.require_group_join_primary()?;
        self.check_group_decline_fence(group)?;
        self.require_reach_group_roster_unforked(group)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            let state = db.shared_group_state(group)?.ok_or_else(invalid)?;
            let expected = self.reach_group_join_notice(group)?;
            if !self.own_group_acceptance(&state)?
                || custody::framed_hash(GROUP_JOIN_NOTICE_DOMAIN, &expected)? != acknowledged_hash
            {
                return Err(invalid());
            }
            let id = key(group);
            if let Some(old) = db.load_actor_state::<JoinIntent>(&id)? {
                if !old.complete {
                    return if old.notice == expected { Ok(()) } else { Err(invalid()) };
                }
            } else if db.actor_state_usage(PREFIX)?.0 >= 1024 {
                return Err(refused(Reason::ForeignCapacity));
            }
            let intent = JoinIntent {
                notice: expected,
                grant_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                roster_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                grant: None,
                grant_applied: false,
                roster: None,
                complete: false,
            };
            db.persist_actor_state(&id, &intent)?;
            Ok(())
        })
    }

    /// Sign the next persisted JOIN operation, retaining exact signed bytes before returning it.
    /// The caller submits the returned operation on its authenticated home session and records
    /// its correlated result with `apply_reach_group_join_result` before requesting the roster.
    /// # Errors
    /// Refuses changed head/Consent, unavailable primary, completed intents or conflicting writers.
    pub fn prepare_reach_group_join_operation(
        &self,
        vault: &dyn PrimaryVault,
        context: ReachCommandContext<'_>,
        group: &str,
    ) -> Result<Operation, SdkError> {
        self.require_group_join_primary()?;
        self.check_group_decline_fence(group)?;
        self.require_reach_group_roster_unforked(group)?;
        let db = self.account_db()?;
        let mut intent: JoinIntent = db.load_actor_state(&key(group))?.ok_or_else(invalid)?;
        if intent.complete {
            return Err(invalid());
        }
        let state = db.shared_group_state(group)?.ok_or_else(invalid)?;
        if self.reach_group_join_notice(group)? != intent.notice
            || !self.own_group_acceptance(&state)?
        {
            return Err(invalid());
        }
        if let Some(operation) = if intent.grant_applied { &intent.roster } else { &intent.grant } {
            return Ok(operation.clone());
        }
        let account = self.born_v3_account.as_ref().ok_or_else(invalid)?;
        let primary = account.group_primary(vault)?;
        let operation = if intent.grant_applied {
            initial_roster(&intent, &state, &primary, account.verified(), context.now)?
        } else {
            let n = &intent.notice;
            let subject = Subject::Group {
                group_id: n.group_id.clone(),
                conversation_id: n.conversation_id.clone(),
                genesis_hash: n.genesis_hash.clone(),
                group_epoch: n.epoch,
                membership_hash: n.membership_hash.clone(),
            };
            let mut body = account.reach_decision_body(&context, subject, Decision::Allow)?;
            body.operation_id.clone_from(&intent.grant_id);
            body.permissions = Some(Permissions::UNACCEPTED);
            body.grant_until = Some(0);
            body.notice_hash = Some(custody::framed_hash(GROUP_JOIN_NOTICE_DOMAIN, n)?);
            body.evidence_hash = Some(n.membership_hash.clone());
            Operation::Admission {
                update: primary.sign_reach_admission(body, account.verified(), context.now)?,
                peer_evidence: None,
                notice: None,
            }
        };
        let old = ramflux_protocol::canonical_json_bytes(&intent)?;
        if intent.grant_applied {
            intent.roster = Some(operation.clone());
        } else {
            intent.grant = Some(operation.clone());
        }
        db.write_transaction(|| {
            let current: JoinIntent = db.load_actor_state(&key(group))?.ok_or_else(invalid)?;
            self.require_group_join_primary()?;
            self.require_reach_group_roster_unforked(group)?;
            if ramflux_protocol::canonical_json_bytes(&current)? != old
                || self.reach_group_join_notice(group)? != intent.notice
                || !self.own_group_acceptance(&state)?
            {
                return Err(invalid());
            }
            self.retain_reach_intent_signer(&operation, context.now)?;
            db.persist_actor_state(&key(group), &intent)?;
            Ok::<_, SdkError>(())
        })?;
        Ok(operation)
    }

    /// Record an authenticated, request-correlated home result. Errors retain the exact retry.
    /// # Errors
    /// Refuses a different request, non-admission result or a result outside the operation's CAS.
    pub fn apply_reach_group_join_result(
        &self,
        group: &str,
        operation: &Operation,
        result: &OperationResult,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let mut intent: JoinIntent = db.load_actor_state(&key(group))?.ok_or_else(invalid)?;
            let is_grant = intent.grant.as_ref() == Some(operation);
            let is_roster = intent.roster.as_ref() == Some(operation);
            if !(is_grant && matches!(result, OperationResult::Admission { .. })
                || is_roster && matches!(result, OperationResult::GroupRoster { .. }))
            {
                return Err(invalid());
            }
            operation.validate_result(result)?;
            if is_roster {
                intent.complete = true;
            } else {
                intent.grant_applied = true;
            }
            db.persist_actor_state(&key(group), &intent)?;
            Ok(())
        })
    }

    /// Submit one previously staged JOIN phase on the authenticated native home connection.
    /// The account writer closes before signing and before the await; an uncertain network result
    /// leaves the persisted operation unchanged. Call again for the dependent initial roster.
    /// # Errors
    /// Returns primary/Consent/state refusals, session/transport errors and mismatched home results.
    pub async fn send_reach_group_join_step<S>(
        &self,
        connection: &mut crate::custody::CustodyConnection<S>,
        vault: &dyn PrimaryVault,
        context: ReachCommandContext<'_>,
        group: &str,
    ) -> Result<OperationResult, SdkError>
    where
        S: ramflux_transport::GatewaySessionTransport + Send,
    {
        let operation = self.prepare_reach_group_join_operation(vault, context, group)?;
        let result = connection.reach_operation(operation.clone()).await?;
        self.apply_reach_group_join_result(group, &operation, &result)?;
        Ok(result)
    }
}

fn initial_roster(
    intent: &JoinIntent,
    state: &VerifiedGroupState,
    primary: &ramflux_crypto::custody::SelfSigningKey,
    authority: &ramflux_crypto::custody::VerifiedRecord,
    now: u64,
) -> Result<Operation, SdkError> {
    let Some(Operation::Admission { update, .. }) = &intent.grant else {
        return Err(invalid());
    };
    ramflux_crypto::contact_reach::verify_retained_admission(update, authority, now)?;
    let roots: BTreeSet<_> = state
        .view()
        .members
        .iter()
        .map(|member| member.identity.root_commitment.clone())
        .filter(|root| root != &intent.notice.recipient_root)
        .collect();
    let members: Vec<_> = roots
        .into_iter()
        .map(|root| GroupRosterMember { root, since_epoch: intent.notice.epoch })
        .collect();
    let header = GroupRosterHeader {
        authority_head_hash: custody::object_hash(authority.envelope())?,
        master_certificate_hash: custody::object_hash(
            &authority.envelope().body.master_certificate,
        )?,
        version: 1,
        recipient_root: intent.notice.recipient_root.clone(),
        group_id: intent.notice.group_id.clone(),
        conversation_id: intent.notice.conversation_id.clone(),
        grant_hash: custody::framed_hash(OPERATION_HASH_DOMAIN, update)?,
        group_epoch: intent.notice.epoch,
        membership_hash: intent.notice.membership_hash.clone(),
        members_hash: custody::framed_hash(GROUP_ROSTER_MEMBERS_DOMAIN, &members)?,
        member_count: u64::try_from(members.len()).map_err(|_| invalid())?,
        issued_at: now,
    };
    let roster =
        GroupRoster { header: primary.sign_group_roster_header(header, authority, now)?, members };
    roster.validate(update)?;
    Ok(Operation::GroupRoster { operation_id: intent.roster_id.clone(), roster: Box::new(roster) })
}

#[cfg(test)]
mod tests;
