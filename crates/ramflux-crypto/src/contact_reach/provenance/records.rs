// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Each original state witness selects its own immutable native proof.
use super::{CryptoError, Signed, custody, reject, wire};
use wire::{ObjectKind, Provenance, ProvenanceAuthority, StateRecord};
pub(in crate::contact_reach) trait HistoricalProofReader {
    fn signers(&self) -> &[wire::SignerReference];
    fn read(&self, hash: &str) -> Result<ProvenanceAuthority, CryptoError>;
}
impl HistoricalProofReader for Provenance {
    fn signers(&self) -> &[wire::SignerReference] {
        &self.signers
    }
    fn read(&self, hash: &str) -> Result<ProvenanceAuthority, CryptoError> {
        self.authorities
            .iter()
            .find(|proof| proof.proof_hash == hash)
            .cloned()
            .ok_or_else(|| reject("original native proof absent"))
    }
}
fn proof<T: serde::Serialize>(
    catalogue: &impl HistoricalProofReader,
    object: &Signed<T>,
    kind: ObjectKind,
) -> Result<ProvenanceAuthority, CryptoError> {
    let hash = custody::framed_hash(wire::OPERATION_HASH_DOMAIN, object)?;
    let reference = catalogue
        .signers()
        .iter()
        .find(|reference| reference.object_kind == kind && reference.object_hash == hash)
        .ok_or_else(|| reject("original signer reference absent"))?;
    let proof = catalogue.read(&reference.proof_hash)?;
    if proof.proof_hash != reference.proof_hash
        || custody::object_hash(&proof.authority.publication.record)?
            != reference.authority_head_hash
        || custody::object_hash(&proof.authority.publication.record.body.master_certificate)?
            != reference.master_certificate_hash
    {
        return Err(reject("original native proof selector mismatch"));
    }
    Ok(proof)
}
fn admission(
    catalogue: &impl HistoricalProofReader,
    update: &Signed<wire::Admission>,
    home: Option<&crate::home_migration::VerifiedHome>,
) -> Result<(), CryptoError> {
    super::verify_historical_admission_with_home(
        update,
        &proof(catalogue, update, ObjectKind::Admission)?,
        home,
    )
}
/// Authenticate every original policy, admission and retirement witness independently.
/// This result is unit only; it cannot satisfy any current management or sender check.
/// # Errors
/// Refuses incomplete catalogues, invalid original native chains, roles or signatures.
pub fn verify_historical_state_records(
    records: &[StateRecord],
    catalogue: &Provenance,
) -> Result<(), CryptoError> {
    catalogue.validate()?;
    verify_records_with_reader(records, catalogue, None)
}
pub(in crate::contact_reach) fn verify_records_with_reader(
    records: &[StateRecord],
    catalogue: &impl HistoricalProofReader,
    home: Option<&crate::home_migration::VerifiedHome>,
) -> Result<(), CryptoError> {
    for record in records {
        match record {
            StateRecord::Policy { update, .. } => super::verify_historical_policy_with_home(
                update,
                &proof(catalogue, update, ObjectKind::Policy)?,
                home,
            )?,
            StateRecord::AdmissionMeta { last_update: Some(update), .. }
            | StateRecord::Grant { update, .. }
            | StateRecord::Block { update, .. }
            | StateRecord::Decline { update, .. } => admission(catalogue, update, home)?,
            StateRecord::Retirement { update, group_floor, .. } => {
                admission(catalogue, update, home)?;
                if let Some(floor) = group_floor {
                    floor.validate(update)?;
                    if let Some(grant) = &floor.grant {
                        admission(catalogue, grant, home)?;
                    }
                    if let Some(control) = &floor.block_control {
                        admission(catalogue, control, home)?;
                    }
                    if let Some(header) = &floor.roster_header {
                        super::verify_historical_roster_header_with_home(
                            header,
                            &proof(catalogue, header.as_ref(), ObjectKind::GroupRoster)?,
                            home,
                        )?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
