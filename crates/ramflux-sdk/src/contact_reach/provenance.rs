// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact snapshot catalogue selection, separate from current custody caches and grant use.
use super::{SdkError, refused};
use ramflux_protocol::{
    contact_reach::{self as wire, Provenance, ProvenanceAuthority, Reason},
    custody::{self, Envelope as Signed},
};

pub(super) fn proof<'a, T: serde::Serialize>(
    catalogue: &'a Provenance,
    object: &Signed<T>,
) -> Result<&'a ProvenanceAuthority, SdkError> {
    let hash = custody::framed_hash(wire::OPERATION_HASH_DOMAIN, object)?;
    let reference = catalogue
        .signers
        .iter()
        .find(|entry| entry.object_hash == hash)
        .ok_or_else(|| refused(Reason::CustodyRefused))?;
    catalogue
        .authorities
        .iter()
        .find(|entry| entry.proof_hash == reference.proof_hash)
        .ok_or_else(|| refused(Reason::CustodyRefused))
}
pub(super) fn admission(
    catalogue: &Provenance,
    update: &Signed<wire::Admission>,
) -> Result<(), SdkError> {
    Ok(ramflux_crypto::contact_reach::verify_historical_admission(
        update,
        proof(catalogue, update)?,
    )?)
}
pub(super) fn retirement(
    catalogue: &Provenance,
    update: &Signed<wire::Admission>,
    floor: &wire::GroupFloor,
) -> Result<(), SdkError> {
    floor.validate(update)?;
    admission(catalogue, update)?;
    if let Some(grant) = &floor.grant {
        admission(catalogue, grant)?;
    }
    if let Some(control) = &floor.block_control {
        admission(catalogue, control)?;
    }
    if let Some(header) = &floor.roster_header {
        ramflux_crypto::contact_reach::verify_historical_roster_header(
            header,
            proof(catalogue, header.as_ref())?,
        )?;
    }
    Ok(())
}

/// Local originals may outlive the home's current subset. They are historical data only.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedProofs {
    signers: Vec<wire::SignerReference>,
    authorities: Vec<ProvenanceAuthority>,
}
impl RetainedProofs {
    pub(super) fn merge(previous: Option<&Self>, incoming: &Provenance) -> Result<Self, SdkError> {
        let mut signers = std::collections::BTreeMap::new();
        let mut authorities = std::collections::BTreeMap::new();
        for pool in previous.into_iter().cloned().chain(std::iter::once(Self {
            signers: incoming.signers.clone(),
            authorities: incoming.authorities.clone(),
        })) {
            for reference in pool.signers {
                let key = (reference.object_kind, reference.object_hash.clone());
                if let Some(old) = signers.insert(key, reference.clone())
                    && old != reference
                {
                    return Err(refused(Reason::ForeignSnapshotInvalid));
                }
            }
            for proof in pool.authorities {
                if let Some(old) = authorities.insert(proof.proof_hash.clone(), proof.clone())
                    && old != proof
                {
                    return Err(refused(Reason::CustodyRefused));
                }
            }
        }
        let retained = Self {
            signers: signers.into_values().collect(),
            authorities: authorities.into_values().collect(),
        };
        let mut native = std::collections::BTreeSet::new();
        for proof in &retained.authorities {
            native.extend(proof.native_hashes()?);
        }
        if native.len() > wire::MAX_PROVENANCE_OBJECTS
            || retained.signers.len() > wire::MAX_SIGNER_REFERENCES
            || retained.authorities.len() > wire::MAX_PROVENANCE_OBJECTS
            || ramflux_protocol::canonical_json_bytes(&retained)?.len() > wire::MAX_PROVENANCE_BYTES
        {
            return Err(refused(Reason::ForeignCapacity));
        }
        Ok(retained)
    }
}
