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

/// Local originals may outlive the home's current subset. They are historical data only.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedProofs {
    pub(super) signers: Vec<wire::SignerReference>,
    pub(super) authorities: Vec<ProvenanceAuthority>,
}
impl RetainedProofs {
    pub(super) fn merge(
        previous: Option<Self>,
        incoming: &EncryptedProvenanceStage,
    ) -> Result<Self, SdkError> {
        Self::extend(
            previous,
            incoming.signers().to_vec(),
            incoming.proof_hashes().map(|hash| incoming.read_proof(hash).map_err(SdkError::from)),
        )
    }
    fn extend(
        previous: Option<Self>,
        incoming_signers: Vec<wire::SignerReference>,
        incoming_authorities: impl IntoIterator<Item = Result<ProvenanceAuthority, SdkError>>,
    ) -> Result<Self, SdkError> {
        let previous = previous.unwrap_or_default();
        let mut signers = std::collections::BTreeMap::new();
        let mut authorities = std::collections::BTreeMap::new();
        for reference in previous.signers.into_iter().chain(incoming_signers) {
            let key = (reference.object_kind, reference.object_hash.clone());
            if let Some(old) = signers.insert(key, reference.clone())
                && old != reference
            {
                return Err(refused(Reason::ForeignSnapshotInvalid));
            }
        }
        for proof in previous.authorities.into_iter().map(Ok).chain(incoming_authorities) {
            let proof = proof?;
            if let Some(old) = authorities.insert(proof.proof_hash.clone(), proof.clone())
                && old != proof
            {
                return Err(refused(Reason::CustodyRefused));
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
    snapshot: &EncryptedProvenanceStage,
) -> Result<(), SdkError> {
    let previous = db.load_actor_state::<RetainedProofs>(POOL_KEY)?;
    let retained = RetainedProofs::merge(previous, snapshot)?;
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
        let retained = RetainedProofs::extend(previous, references, [Ok(proof)])?;
        db.persist_actor_state(POOL_KEY, &retained)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
