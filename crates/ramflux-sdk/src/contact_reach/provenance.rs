// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact snapshot catalogue selection, separate from current custody caches and grant use.
use super::{SdkError, refused};
use ramflux_crypto::contact_reach::EncryptedProvenanceStage;
use ramflux_protocol::{
    contact_reach::{self as wire, ProvenanceAuthority, Reason},
    custody::{self, Envelope as Signed},
};

pub(super) fn proof<T: serde::Serialize>(
    catalogue: &EncryptedProvenanceStage,
    object: &Signed<T>,
) -> Result<ProvenanceAuthority, SdkError> {
    let hash = custody::framed_hash(wire::OPERATION_HASH_DOMAIN, object)?;
    let reference = catalogue
        .signers()
        .iter()
        .find(|entry| entry.object_hash == hash)
        .ok_or_else(|| refused(Reason::CustodyRefused))?;
    Ok(catalogue.read_proof(&reference.proof_hash)?)
}
pub(super) fn admission(
    catalogue: &EncryptedProvenanceStage,
    update: &Signed<wire::Admission>,
    home: Option<&ramflux_crypto::home_migration::VerifiedHome>,
) -> Result<(), SdkError> {
    Ok(ramflux_crypto::contact_reach::verify_historical_admission_with_home(
        update,
        &proof(catalogue, update)?,
        home,
    )?)
}
pub(super) fn retirement(
    catalogue: &EncryptedProvenanceStage,
    update: &Signed<wire::Admission>,
    floor: &wire::GroupFloor,
    home: Option<&ramflux_crypto::home_migration::VerifiedHome>,
) -> Result<(), SdkError> {
    floor.validate(update)?;
    admission(catalogue, update, home)?;
    if let Some(grant) = &floor.grant {
        admission(catalogue, grant, home)?;
    }
    if let Some(control) = &floor.block_control {
        admission(catalogue, control, home)?;
    }
    if let Some(header) = &floor.roster_header {
        ramflux_crypto::contact_reach::verify_historical_roster_header_with_home(
            header,
            &proof(catalogue, header.as_ref())?,
            home,
        )?;
    }
    Ok(())
}

pub(super) fn store_error(error: ramflux_storage::StorageError) -> SdkError {
    match error {
        ramflux_storage::StorageError::SegmentResourceCapacity { .. } => {
            refused(Reason::ForeignCapacity)
        }
        ramflux_storage::StorageError::Integrity(_) => refused(Reason::CustodyRefused),
        error => SdkError::from(error),
    }
}
pub(super) fn retain_snapshot(
    db: &ramflux_storage::AccountDb,
    root: &str,
    snapshot: &EncryptedProvenanceStage,
) -> Result<(), SdkError> {
    db.retain_reach_provenance(
        root,
        snapshot.signers(),
        snapshot
            .proof_hashes()
            .map(|hash| snapshot.read_proof(hash).map_err(ramflux_storage::StorageError::from)),
    )
    .map_err(store_error)
}

impl crate::RamfluxClient {
    /// Called inside the same account writer transaction as the signed intent.
    pub(super) fn retain_reach_intent_signer(
        &self,
        operation: &wire::Operation,
        now: u64,
    ) -> Result<(), SdkError> {
        use ramflux_crypto::contact_reach as crypto;
        let root = match operation {
            wire::Operation::Policy { update } => &update.body.account_anchor,
            wire::Operation::Admission { update, .. }
            | wire::Operation::Start { update, .. }
            | wire::Operation::Reply { update, .. } => &update.body.recipient_root,
            wire::Operation::GroupRoster { roster, .. } => &roster.header.body.recipient_root,
            _ => return Err(refused(Reason::ForeignInvalidFrame)),
        };
        let authority = self
            .current_custody_evidence(root, now)?
            .ok_or_else(|| refused(Reason::CustodyRefused))?;
        let mut proof =
            ProvenanceAuthority { proof_hash: String::new(), authority, custodian_history: vec![] };
        proof.proof_hash = proof.content_hash()?;
        let mut references = match operation {
            wire::Operation::Policy { update } => {
                crypto::verify_historical_policy(update, &proof)?;
                wire::record_signers(&wire::StateRecord::Policy {
                    revision: update.body.revision,
                    update: update.clone(),
                })?
            }
            wire::Operation::Admission { update, .. }
            | wire::Operation::Start { update, .. }
            | wire::Operation::Reply { update, .. } => {
                crypto::verify_historical_admission(update, &proof)?;
                wire::record_signers(&wire::StateRecord::AdmissionMeta {
                    revision: update.body.expected_revision,
                    last_update: Some(update.clone()),
                })?
            }
            wire::Operation::GroupRoster { roster, .. } => {
                crypto::verify_historical_roster_header(&roster.header, &proof)?;
                vec![wire::SignerReference {
                    object_hash: custody::framed_hash(wire::OPERATION_HASH_DOMAIN, &roster.header)?,
                    object_kind: wire::ObjectKind::GroupRoster,
                    authority_head_hash: roster.header.body.authority_head_hash.clone(),
                    master_certificate_hash: roster.header.body.master_certificate_hash.clone(),
                    proof_hash: proof.proof_hash.clone(),
                }]
            }
            _ => return Err(refused(Reason::ForeignInvalidFrame)),
        };
        for reference in &mut references {
            reference.proof_hash.clone_from(&proof.proof_hash);
        }
        let db = self.account_db()?;
        db.retain_reach_provenance(root, &references, [Ok(proof)]).map_err(store_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedProofs {
    pub(super) signers: Vec<wire::SignerReference>,
    pub(super) authorities: Vec<ProvenanceAuthority>,
}
#[cfg(test)]
pub(super) fn read_pool_for_tests(
    db: &ramflux_storage::AccountDb,
    root: &str,
) -> Result<Option<RetainedProofs>, SdkError> {
    let signers = db.reach_provenance_references()?;
    let hashes = db.reach_provenance_proof_hashes()?;
    if signers.is_empty() && hashes.is_empty() {
        return Ok(None);
    }
    let authorities = hashes
        .into_iter()
        .map(|hash| {
            db.reach_provenance_proof(root, &hash)?.ok_or_else(|| refused(Reason::CustodyRefused))
        })
        .collect::<Result<Vec<_>, SdkError>>()?;
    Ok(Some(RetainedProofs { signers, authorities }))
}
#[cfg(test)]
pub(super) fn write_pool_for_tests(
    db: &ramflux_storage::AccountDb,
    pool: &RetainedProofs,
) -> Result<(), SdkError> {
    let root = &pool
        .authorities
        .first()
        .ok_or_else(|| refused(Reason::CustodyRefused))?
        .authority
        .publication
        .record
        .body
        .account_anchor;
    db.retain_reach_provenance(root, &pool.signers, pool.authorities.iter().cloned().map(Ok))
        .map_err(store_error)
}
#[cfg(test)]
pub(super) fn clear_pool_for_tests(db: &ramflux_storage::AccountDb) -> Result<(), SdkError> {
    db.write_transaction(|| {
        let prefix = "reach/provenance/";
        let mut removed = 0_usize;
        loop {
            let keys = db.actor_state_key_page_after(prefix, "", 128)?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                removed += 1;
                if removed > wire::MAX_PROVENANCE_OBJECTS + wire::MAX_SIGNER_REFERENCES {
                    return Err(refused(Reason::ForeignCapacity));
                }
                db.remove_actor_state(&key)?;
            }
        }
        Ok(())
    })
}
