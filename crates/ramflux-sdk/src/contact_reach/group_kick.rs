// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adopted own-root removal stages a restrictive intent in the same account commit as the head.
use super::{SavedReachState, refused};
use crate::{
    RamfluxClient, SdkError,
    custody::{PrimaryVault, ReachCommandContext},
};
use ramflux_crypto::{GroupStateRelation, VerifiedGroupState};
use ramflux_protocol::{
    contact_reach::{
        Decision, OPERATION_HASH_DOMAIN, Operation, OperationResult, Reason, StateRecord, Subject,
    },
    custody,
};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "reach-group-kick/";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KickIntent {
    operation_id: String,
    grant_hash: String,
    subject: Subject,
    operation: Option<Operation>,
    complete: bool,
}

#[cfg(test)]
mod tests;
fn key(group: &str) -> String {
    format!("{PREFIX}{}", ramflux_protocol::encode_base64url(group))
}
fn pending() -> SdkError {
    SdkError::InboundPending(
        "group revoke requires verified current grant and head evidence".into(),
    )
}
impl RamfluxClient {
    pub(super) fn group_reach_mirror(&self) -> Result<Option<SavedReachState>, SdkError> {
        let state: Option<SavedReachState> = self
            .account_db()?
            .client_record("reach", "state")?
            .map(serde_json::from_value)
            .transpose()?;
        if let Some(state) = &state {
            self.require_reach_authority_head(
                &state.root,
                &state.authority_head_hash,
                state.custodian_head_hash.as_deref(),
                crate::custody::network_now()?,
            )?;
        }
        Ok(state)
    }

    /// Called only after adoption, inside the caller's account writer; performs no signing/RPC.
    pub(crate) fn stage_reach_group_kick(
        &self,
        adopted: &VerifiedGroupState,
        previous: Option<&VerifiedGroupState>,
    ) -> Result<(), SdkError> {
        let Some(previous) = previous else {
            return Ok(());
        };
        self.stage_reach_group_roster(adopted, previous)?;
        if !matches!(
            adopted.relation_to(previous)?,
            GroupStateRelation::Extension | GroupStateRelation::IncomingPreferred
        ) {
            return Ok(());
        }
        self.enqueue_reach_group_kick(adopted)
    }

    pub(super) fn enqueue_reach_group_kick(
        &self,
        adopted: &VerifiedGroupState,
    ) -> Result<(), SdkError> {
        let Some(mirror) = self.group_reach_mirror()? else {
            return Ok(());
        };
        let own = self.owned_device_identity()?;
        if mirror.conflict || mirror.root != own.root_commitment() {
            return Err(pending());
        }
        if adopted
            .view()
            .members
            .iter()
            .any(|member| member.identity.root_commitment == own.root_commitment())
        {
            return Ok(());
        }
        let group = &adopted.view().group_id;
        let grant = mirror.records.iter().find_map(|record| match record {
            StateRecord::Grant { subject: Subject::Group { group_id, .. }, update, .. }
                if group_id == group =>
            {
                Some(update)
            }
            _ => None,
        });
        let Some(grant) = grant else {
            return Ok(());
        };
        let Subject::Group { conversation_id, genesis_hash, .. } = &grant.body.subject else {
            return Err(pending());
        };
        if conversation_id != &adopted.view().conversation_id
            || genesis_hash != &adopted.genesis_hash()?
        {
            return Err(pending());
        }
        let grant_hash = custody::framed_hash(OPERATION_HASH_DOMAIN, grant)?;
        let db = self.account_db()?;
        let id = key(group);
        if db.load_actor_state::<KickIntent>(&id)?.is_some_and(|old| old.grant_hash == grant_hash) {
            return Ok(());
        }
        if !db.actor_state_exists(&id)? && db.actor_state_usage(PREFIX)?.0 >= 1024 {
            return Err(refused(Reason::ForeignCapacity));
        }
        db.persist_actor_state(
            &id,
            &KickIntent {
                operation_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                grant_hash,
                subject: Subject::Group {
                    group_id: group.clone(),
                    conversation_id: adopted.view().conversation_id.clone(),
                    genesis_hash: adopted.genesis_hash()?,
                    group_epoch: adopted.view().epoch,
                    membership_hash: adopted.snapshot().state_hash.clone(),
                },
                operation: None,
                complete: false,
            },
        )?;
        Ok(())
    }

    /// Reconstruct a missing own-kick intent from the current adopted head after restore/restart.
    /// # Errors
    /// Refuses absent native state or unverifiable grant binding; creates no allow or roster.
    pub fn stage_reach_group_kick_repair(&self, group: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let state = db.shared_group_state(group)?.ok_or_else(pending)?;
            self.enqueue_reach_group_kick(&state)
        })
    }

    /// Sign a committed own-kick intent against the exact verified live grant and CAS observation.
    /// An uncertain retry returns the exact saved signed operation; it never creates an allow.
    /// # Errors
    /// Refuses missing intent/state, unavailable primary, changed grant, head, CAS or writer races.
    pub fn prepare_reach_group_kick(
        &self,
        vault: &dyn PrimaryVault,
        context: ReachCommandContext<'_>,
        group: &str,
    ) -> Result<Operation, SdkError> {
        let db = self.account_db()?;
        let mut intent: KickIntent = db.load_actor_state(&key(group))?.ok_or_else(pending)?;
        if intent.complete {
            return Err(pending());
        }
        if let Some(operation) = &intent.operation {
            return Ok(operation.clone());
        }
        let mirror = self.group_reach_mirror()?.ok_or_else(pending)?;
        if mirror.conflict
            || mirror.home_head_hash != context.home_head_hash
            || mirror.admission_revision != context.expected_revision
            || !mirror.records.iter().any(|record| match record {
                StateRecord::Grant { subject: Subject::Group { group_id, .. }, update, .. }
                    if group_id == group =>
                {
                    custody::framed_hash(OPERATION_HASH_DOMAIN, update)
                        .is_ok_and(|hash| hash == intent.grant_hash)
                }
                _ => false,
            })
        {
            return Err(pending());
        }
        let account = self.born_v3_account.as_ref().ok_or_else(pending)?;
        self.require_reach_authority_head(
            &account.record().body.account_anchor,
            &custody::object_hash(account.record())?,
            super::current_authority::custodian_head(account.verified())?.as_deref(),
            context.now,
        )?;
        let mut body =
            account.reach_decision_body(&context, intent.subject.clone(), Decision::Revoke)?;
        body.operation_id.clone_from(&intent.operation_id);
        let operation = Operation::Admission {
            update: account.group_primary(vault)?.sign_reach_admission(
                body,
                account.verified(),
                context.now,
            )?,
            peer_evidence: None,
            notice: None,
        };
        let old = ramflux_protocol::canonical_json_bytes(&intent)?;
        intent.operation = Some(operation.clone());
        db.write_transaction(|| {
            let current: KickIntent = db.load_actor_state(&key(group))?.ok_or_else(pending)?;
            let latest = self.group_reach_mirror()?.ok_or_else(pending)?;
            if ramflux_protocol::canonical_json_bytes(&current)? != old
                || latest.conflict
                || latest.state_hash != mirror.state_hash
                || latest.revision != mirror.revision
            {
                return Err(pending());
            }
            self.retain_reach_intent_signer(&operation, context.now)?;
            db.persist_actor_state(&key(group), &intent)?;
            Ok::<_, SdkError>(())
        })?;
        Ok(operation)
    }

    /// Settle only the exact persisted revoke after its correlated home result.
    /// # Errors
    /// Refuses a changed operation or a result outside its Admission CAS binding.
    pub fn apply_reach_group_kick_result(
        &self,
        group: &str,
        operation: &Operation,
        result: &OperationResult,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let mut intent: KickIntent = db.load_actor_state(&key(group))?.ok_or_else(pending)?;
            if intent.operation.as_ref() != Some(operation)
                || !matches!(result, OperationResult::Admission { .. })
            {
                return Err(pending());
            }
            operation.validate_result(result)?;
            intent.complete = true;
            db.persist_actor_state(&key(group), &intent)?;
            Ok(())
        })
    }

    /// Submit the committed own-kick revoke outside the account writer.
    /// # Errors
    /// Returns primary, state, session and correlated home-result refusals without changing retries.
    pub async fn send_reach_group_kick<S>(
        &self,
        connection: &mut crate::custody::CustodyConnection<S>,
        vault: &dyn PrimaryVault,
        context: ReachCommandContext<'_>,
        group: &str,
    ) -> Result<OperationResult, SdkError>
    where
        S: ramflux_transport::GatewaySessionTransport + Send,
    {
        let operation = self.prepare_reach_group_kick(vault, context, group)?;
        let result = connection.reach_operation(operation.clone()).await?;
        self.apply_reach_group_kick_result(group, &operation, &result)?;
        Ok(result)
    }
}
