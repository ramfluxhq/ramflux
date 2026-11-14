// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore cannot clear local restrictions or resume positive use before original-proof validation.
use super::{SavedReachState, provenance::store_error, refused};
use crate::SdkError;
use ramflux_protocol::contact_reach::{self as wire, Reason, StateRecord};
use ramflux_storage::AccountDb;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const KEY: &str = "reach/restore-restrictions";
use ramflux_storage::ReachRestoreRestrictions as Restrictions;
pub(super) fn require_ready(db: &AccountDb) -> Result<(), SdkError> {
    if db.actor_state_exists(KEY)? {
        return Err(SdkError::InboundPending(
            "restored reach restrictions require original signer reconciliation".into(),
        ));
    }
    Ok(())
}
pub(super) fn verify(
    db: &AccountDb,
    root: &str,
    home: Option<&ramflux_crypto::home_migration::VerifiedHome>,
) -> Result<Option<Vec<StateRecord>>, SdkError> {
    let (count, bytes) = db.actor_state_usage(KEY)?;
    if count == 0 {
        return Ok(None);
    }
    if count != 1 || bytes > wire::MAX_STATE_BYTES as u64 {
        return Err(refused(Reason::ForeignCapacity));
    }
    let staged: Restrictions =
        db.load_actor_state(KEY)?.ok_or_else(|| refused(Reason::CustodyRefused))?;
    if staged.root != root {
        return Err(refused(Reason::AnchorMismatch));
    }
    if staged.records.len() > 8192
        || staged.records.iter().any(|record| {
            !matches!(
                record,
                StateRecord::Block { .. }
                    | StateRecord::Decline { .. }
                    | StateRecord::Floor { .. }
                    | StateRecord::Conflict { .. }
                    | StateRecord::Retirement { .. }
            )
        })
    {
        return Err(refused(Reason::ForeignSnapshotInvalid));
    }
    verify_originals(db, root, &staged.records, home)?;
    Ok(Some(staged.records))
}
fn verify_originals(
    db: &AccountDb,
    root: &str,
    records: &[StateRecord],
    home: Option<&ramflux_crypto::home_migration::VerifiedHome>,
) -> Result<(), SdkError> {
    let mut signers = BTreeMap::new();
    for record in records {
        for selector in wire::record_signers(record)? {
            let original = db
                .reach_provenance_reference(selector.object_kind, &selector.object_hash)
                .map_err(store_error)?
                .ok_or_else(|| refused(Reason::CustodyRefused))?;
            if original.authority_head_hash != selector.authority_head_hash
                || original.master_certificate_hash != selector.master_certificate_hash
            {
                return Err(refused(Reason::CustodyRefused));
            }
            signers.insert((original.object_kind, original.object_hash.clone()), original);
        }
    }
    let required: BTreeSet<_> =
        signers.values().map(|reference| reference.proof_hash.clone()).collect();
    // This identity describes only the private restored restriction set; it is never a home manifest.
    let state_hash = wire::state_hash(root, 0, 0, 0, records)?;
    let mut builder = ramflux_crypto::contact_reach::ProvenanceStageBuilder::new(
        root,
        0,
        &state_hash,
        signers.into_values().collect(),
    )?;
    for hash in required {
        let proof = db
            .reach_provenance_proof(root, &hash)
            .map_err(store_error)?
            .ok_or_else(|| refused(Reason::CustodyRefused))?;
        builder.push(&proof)?;
    }
    builder.finish()?.verify_originals_with_home(records, home)?;
    Ok(())
}

impl crate::RamfluxClient {
    pub(super) fn saved_reach_state(&self) -> Result<Option<SavedReachState>, SdkError> {
        let db = self.account_db()?;
        require_ready(db)?;
        Ok(db.client_record("reach", "state")?.map(serde_json::from_value).transpose()?)
    }
}
