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
    contact_reach::{Decision, OPERATION_HASH_DOMAIN, Operation, Reason, StateRecord, Subject},
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
    fn group_reach_mirror(&self) -> Result<Option<SavedReachState>, SdkError> {
        self.account_db()?
            .client_record("reach", "state")?
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }

    /// Called only after adoption, inside the caller's account writer; performs no signing/RPC.
    pub(crate) fn stage_reach_group_kick(
        &self,
        adopted: &VerifiedGroupState,
        previous: Option<&VerifiedGroupState>,
    ) -> Result<(), SdkError> {
        let Some(mirror) = self.group_reach_mirror()? else {
            return Ok(());
        };
        if mirror.conflict {
            return Err(pending());
        }
        let own = self.owned_device_identity()?;
        let Some(previous) = previous else {
            return Ok(());
        };
        if !matches!(
            adopted.relation_to(previous)?,
            GroupStateRelation::Extension | GroupStateRelation::IncomingPreferred
        ) || adopted
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
            },
        )?;
        Ok(())
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
            db.persist_actor_state(&key(group), &intent)?;
            Ok::<_, SdkError>(())
        })?;
        Ok(operation)
    }
}
