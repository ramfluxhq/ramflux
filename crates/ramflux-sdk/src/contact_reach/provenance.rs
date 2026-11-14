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
    pub(super) signers: Vec<wire::SignerReference>,
    pub(super) authorities: Vec<ProvenanceAuthority>,
}
impl RetainedProofs {
    pub(super) fn merge(previous: Option<&Self>, incoming: &Provenance) -> Result<Self, SdkError> {
        Self::extend(previous, incoming.signers.clone(), incoming.authorities.clone())
    }
    fn extend(
        previous: Option<&Self>,
        incoming_signers: Vec<wire::SignerReference>,
        incoming_authorities: Vec<ProvenanceAuthority>,
    ) -> Result<Self, SdkError> {
        let mut signers = std::collections::BTreeMap::new();
        let mut authorities = std::collections::BTreeMap::new();
        for pool in previous.into_iter().cloned().chain(std::iter::once(Self {
            signers: incoming_signers,
            authorities: incoming_authorities,
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

const POOL_KEY: &str = "reach/provenance";
pub(super) fn retain_snapshot(
    db: &ramflux_storage::AccountDb,
    snapshot: &Provenance,
) -> Result<(), SdkError> {
    let previous = db.load_actor_state::<RetainedProofs>(POOL_KEY)?;
    let retained = RetainedProofs::merge(previous.as_ref(), snapshot)?;
    db.persist_actor_state(POOL_KEY, &retained)?;
    Ok(())
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
        let previous = db.load_actor_state::<RetainedProofs>(POOL_KEY)?;
        let retained = RetainedProofs::extend(previous.as_ref(), references, vec![proof])?;
        db.persist_actor_state(POOL_KEY, &retained)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
