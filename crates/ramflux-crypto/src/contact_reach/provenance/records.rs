// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Each original state witness selects its own immutable native proof.
use super::{CryptoError, Signed, custody, reject, wire};
use wire::{ObjectKind, Provenance, ProvenanceAuthority, StateRecord};
fn proof<'a, T: serde::Serialize>(
    catalogue: &'a Provenance,
    object: &Signed<T>,
    kind: ObjectKind,
) -> Result<&'a ProvenanceAuthority, CryptoError> {
    let hash = custody::framed_hash(wire::OPERATION_HASH_DOMAIN, object)?;
    let reference = catalogue
        .signers
        .iter()
        .find(|reference| reference.object_kind == kind && reference.object_hash == hash)
        .ok_or_else(|| reject("original signer reference absent"))?;
    catalogue
        .authorities
        .iter()
        .find(|proof| proof.proof_hash == reference.proof_hash)
        .ok_or_else(|| reject("original native proof absent"))
}
fn admission(catalogue: &Provenance, update: &Signed<wire::Admission>) -> Result<(), CryptoError> {
    super::verify_historical_admission(update, proof(catalogue, update, ObjectKind::Admission)?)
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
    for record in records {
        match record {
            StateRecord::Policy { update, .. } => super::verify_historical_policy(
                update,
                proof(catalogue, update, ObjectKind::Policy)?,
            )?,
            StateRecord::AdmissionMeta { last_update: Some(update), .. }
            | StateRecord::Grant { update, .. }
            | StateRecord::Block { update, .. }
            | StateRecord::Decline { update, .. } => admission(catalogue, update)?,
            StateRecord::Retirement { update, group_floor, .. } => {
                admission(catalogue, update)?;
                if let Some(floor) = group_floor {
                    floor.validate(update)?;
                    if let Some(grant) = &floor.grant {
                        admission(catalogue, grant)?;
                    }
                    if let Some(control) = &floor.block_control {
                        admission(catalogue, control)?;
                    }
                    if let Some(header) = &floor.roster_header {
                        super::verify_historical_roster_header(
                            header,
                            proof(catalogue, header.as_ref(), ObjectKind::GroupRoster)?,
                        )?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
