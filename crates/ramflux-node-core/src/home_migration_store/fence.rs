// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authorization-keyed terminal CAS does not depend on a destination disclosing its seal.
use super::{
    Authorization, FENCE_EXPIRES, FENCES, FenceOutcome, HomeRecord, MigrationNode, NodeCoreError,
    NoncommitFence, PROOFS, RECORDS, RecordEvidence, Refusal, RouterCore, RouterRedbStore, Signed,
    auth_error, authorization_key, clock, commit_transition, crypto, maintenance, read, refusal,
    storage, write,
};
impl RouterCore {
    /// Cancel an account-authorized move even when no destination receipt was returned.
    /// The caller authenticates a fresh owner cancellation, or requests expiry only.
    /// # Errors
    /// Rejects another account's authorization, invalid source, and premature expiry queries.
    pub fn fence_home_authorization(
        &self,
        store: &RouterRedbStore,
        node: &MigrationNode,
        authorization: &Signed<Authorization>,
        now: u64,
        cancel: Option<&Signed<ramflux_protocol::home_migration::Control>>,
    ) -> Result<FenceOutcome, NodeCoreError> {
        if let Some(outcome) = store.terminal_migration_authorization(authorization)? {
            return Ok(outcome);
        }
        let now = store.migration_clock_floor(now)?;
        if now > crypto::hard_deadline(&authorization.body).map_err(auth_error)? {
            return fence_authorization(
                store,
                node,
                FenceDecision { authorization, cancel: None, authority: None },
                now,
            );
        }
        self.with_migration_authority(
            &authorization.body.account_anchor,
            now,
            |authority, _publication| {
                fence_authorization(
                    store,
                    node,
                    FenceDecision { authorization, cancel, authority: Some(authority) },
                    now,
                )
            },
        )
    }
}
#[derive(Clone, Copy)]
pub(super) struct FenceDecision<'a> {
    pub authorization: &'a Signed<Authorization>,
    pub cancel: Option<&'a Signed<ramflux_protocol::home_migration::Control>>,
    pub authority: Option<&'a ramflux_crypto::custody::VerifiedRecord>,
}
pub(super) fn fence_authorization(
    store: &RouterRedbStore,
    node: &MigrationNode,
    decision: FenceDecision<'_>,
    now: u64,
) -> Result<FenceOutcome, NodeCoreError> {
    let FenceDecision { authorization: auth, cancel, authority } = decision;
    let a = &auth.body;
    if a.old_node != node.node_id() {
        return Err(refusal(Refusal::BaseMismatch));
    }
    let tx = store.migration_db().begin_write().map_err(storage)?;
    let now = clock(&tx, now)?;
    let key = authorization_key(auth)?;
    // Permanent proof wins even after terminal operation rows were compacted.
    if let Some(hash) = read::<String>(&tx, PROOFS, &key)? {
        let record: RecordEvidence = read(&tx, RECORDS, &hash)?
            .ok_or_else(|| storage("migration permanent proof unavailable"))?;
        return Ok(FenceOutcome::Committed(Box::new(record)));
    }
    if let Some(fence) = read::<Signed<NoncommitFence>>(&tx, FENCES, &key)? {
        return Ok(FenceOutcome::Fenced(fence));
    }
    let deadline = crypto::hard_deadline(a).map_err(auth_error)?;
    if now <= deadline {
        let authority = authority.ok_or_else(|| refusal(Refusal::AuthorityUpdateRequired))?;
        super::authority_evidence::verify(&tx, auth, authority)?;
        if let Some(cancel) = cancel {
            crypto::verify_actor(cancel, authority, now).map_err(auth_error)?;
            let c = &cancel.body;
            if c.action != ramflux_protocol::home_migration::Action::Abort
                || c.audience_node != node.node_id()
                || c.requester.account_anchor != a.account_anchor
                || c.migration_id != a.migration_id
                || c.payload_hash != super::message_hash(auth).map_err(storage)?
            {
                return Err(refusal(Refusal::AuthorityUpdateRequired));
            }
        }
    } else {
        // A permanent proof was checked first. After the signed hard bound, the
        // same trusted clock forbids every first commit, irrespective of whether
        // an old manager record is still retained. This truthful negative result
        // grants no account authority and allocates no new durable state.
        crypto::verify_signatures(auth).map_err(auth_error)?;
    }
    if cancel.is_none() && now <= deadline {
        return Err(refusal(Refusal::CommitOutcomeUnknown));
    }
    let base: RecordEvidence =
        read(&tx, RECORDS, &a.previous_home_hash)?.ok_or_else(|| refusal(Refusal::BaseMismatch))?;
    if base.record.account_anchor() != a.account_anchor
        || base.record.home() != (node.node_id(), node.public_key())
        || base.record.epoch().checked_add(1) != Some(a.next_home_epoch)
        || !matches!(base.record, HomeRecord::Genesis { .. } | HomeRecord::Committed { .. })
    {
        return Err(refusal(Refusal::BaseMismatch));
    }
    let fence = crypto::sign_node(
        NoncommitFence {
            version: 1,
            migration_id: a.migration_id.clone(),
            authorization_hash: super::message_hash(auth).map_err(storage)?,
            seal_hash: None,
            fenced_at: now,
        },
        node.node_id(),
        &node.key,
    )
    .map_err(auth_error)?;
    // Peer-provided operation metadata cannot shorten this signed hard bound.
    if now <= deadline {
        write(&tx, FENCES, &key, &fence)?;
        write(&tx, FENCE_EXPIRES, &maintenance::expiry_key(deadline, &key), &key)?;
    }
    commit_transition(store, tx)?;
    Ok(FenceOutcome::Fenced(fence))
}

impl RouterRedbStore {
    pub(crate) fn terminal_migration_authorization(
        &self,
        auth: &Signed<Authorization>,
    ) -> Result<Option<FenceOutcome>, NodeCoreError> {
        use redb::ReadableDatabase;
        // Neither outcome requires the former home to retain the account's custody registry row.
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let key = authorization_key(auth)?;
        match tx.open_table(PROOFS) {
            Ok(table) => {
                if let Some(value) = table.get(key.as_str()).map_err(storage)? {
                    let hash: String = super::decode(value.value())?;
                    let records = tx.open_table(RECORDS).map_err(storage)?;
                    let value = records
                        .get(hash.as_str())
                        .map_err(storage)?
                        .ok_or_else(|| storage("migration permanent proof unavailable"))?;
                    return Ok(Some(FenceOutcome::Committed(Box::new(super::decode(
                        value.value(),
                    )?))));
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(error) => return Err(storage(error)),
        }
        match tx.open_table(FENCES) {
            Ok(table) => table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| super::decode(value.value()).map(FenceOutcome::Fenced))
                .transpose(),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(error) => Err(storage(error)),
        }
    }
}

impl RouterRedbStore {
    /// Return time clamped to the durable migration clock floor.
    /// # Errors
    /// Returns storage errors without changing the clock.
    pub fn migration_clock_floor(&self, now: u64) -> Result<u64, NodeCoreError> {
        use redb::ReadableDatabase;
        let tx = self.migration_db().begin_read().map_err(storage)?;
        match tx.open_table(super::CLOCK) {
            Ok(table) => {
                Ok(now.max(table.get("floor").map_err(storage)?.map_or(0, |value| value.value())))
            }
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(now),
            Err(error) => Err(storage(error)),
        }
    }
}
