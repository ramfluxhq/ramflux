// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic original signer retention; no TTL and no substitution from a later current head.
use super::{AccountReach, Reason, Result, account, encoded, key, refuse, row, storage};
use ramflux_protocol::{
    contact_reach::{
        self as wire, ObjectKind, Provenance, ProvenanceAuthority, ProvenanceKind, SignerReference,
    },
    custody::{self, CustodyAuthority, Publication},
};
use redb::{ReadableTable, TableDefinition};
use std::collections::BTreeMap;
const PROOFS: TableDefinition<&str, &[u8]> = TableDefinition::new("contact_reach_provenance_v1");
const REFERENCES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_signer_references_v1");

fn current(tx: &redb::WriteTransaction, root: &str, now: u64) -> Result<ProvenanceAuthority> {
    // Current pins were independently checked by the management owner before this capture.
    let state = account(tx, root)?;
    let cert = &state.publication.record.body.master_certificate.body;
    let custodian_publication = if cert.custody_kind == custody::CustodyKind::ExternalHuman {
        let human = account(tx, &cert.primary_device_ref.account_anchor)?;
        Some(Publication {
            record: human.publication.record,
            compacted_ids: human.publication.compacted_ids,
        })
    } else {
        None
    };
    let authority = CustodyAuthority {
        publication: Publication {
            record: state.publication.record,
            compacted_ids: state.publication.compacted_ids,
        },
        custodian_publication,
    };
    ramflux_crypto::custody::verify_publication(&authority, now)?;
    let mut proof =
        ProvenanceAuthority { proof_hash: String::new(), authority, custodian_history: Vec::new() };
    proof.proof_hash = proof.content_hash()?;
    Ok(proof)
}
fn reference_id(reference: &SignerReference) -> Result<String> {
    serde_json::to_string(&(reference.object_kind, &reference.object_hash)).map_err(storage)
}
/// Retain only the independently verified context for the newly accepted signed object.
/// Existing references are immutable; this never repairs legacy objects from current keys.
pub(super) fn retain(
    tx: &redb::WriteTransaction,
    root: &str,
    state: &AccountReach,
    now: u64,
) -> Result<()> {
    let proof = current(tx, root, now)?;
    let head = custody::object_hash(&proof.authority.publication.record)?;
    let certificate =
        custody::object_hash(&proof.authority.publication.record.body.master_certificate)?;
    let mut signers = BTreeMap::new();
    for record in state.records()? {
        for signer in wire::record_signers(&record)? {
            signers.insert((signer.object_kind, signer.object_hash.clone()), signer);
        }
    }
    for roster in state.rosters.values() {
        let header = &roster.header;
        let signer = SignerReference {
            object_hash: custody::framed_hash(wire::OPERATION_HASH_DOMAIN, header)?,
            object_kind: ObjectKind::GroupRoster,
            authority_head_hash: header.body.authority_head_hash.clone(),
            master_certificate_hash: header.body.master_certificate_hash.clone(),
            proof_hash: String::new(),
        };
        signers.insert((signer.object_kind, signer.object_hash.clone()), signer);
    }
    let mut needed = false;
    for mut signer in signers.into_values() {
        let id = key(root, &reference_id(&signer)?)?;
        let old = tx
            .open_table(REFERENCES)
            .map_err(storage)?
            .get(id.as_str())
            .map_err(storage)?
            .map(|v| row::<SignerReference>(v.value()))
            .transpose()?;
        if let Some(old) = old {
            if old.object_kind != signer.object_kind
                || old.object_hash != signer.object_hash
                || old.authority_head_hash != signer.authority_head_hash
                || old.master_certificate_hash != signer.master_certificate_hash
            {
                return Err(refuse(Reason::CustodyRefused));
            }
            continue;
        }
        if signer.authority_head_hash != head || signer.master_certificate_hash != certificate {
            return Err(refuse(Reason::CustodyRefused));
        }
        signer.proof_hash.clone_from(&proof.proof_hash);
        signer.validate()?;
        tx.open_table(REFERENCES)
            .map_err(storage)?
            .insert(id.as_str(), encoded(&signer)?.as_slice())
            .map_err(storage)?;
        needed = true;
    }
    if needed {
        tx.open_table(PROOFS)
            .map_err(storage)?
            .insert(key(root, &proof.proof_hash)?.as_str(), encoded(&proof)?.as_slice())
            .map_err(storage)?;
    }
    check_caps(tx, root)
}
fn check_caps(tx: &redb::WriteTransaction, root: &str) -> Result<()> {
    let mut global_bytes = 0_usize;
    let mut own_bytes = 0_usize;
    let mut global_objects = 0_usize;
    let mut own_objects = 0_usize;
    let mut global_native = std::collections::BTreeSet::new();
    let mut own_native = std::collections::BTreeSet::new();
    let mut own_refs = 0_usize;
    for (definition, proofs) in [(PROOFS, true), (REFERENCES, false)] {
        let table = tx.open_table(definition).map_err(storage)?;
        for item in table.iter().map_err(storage)? {
            let (k, v) = item.map_err(storage)?;
            let (owner, _): (String, String) = serde_json::from_str(k.value()).map_err(storage)?;
            let bytes = k
                .value()
                .len()
                .checked_add(v.value().len())
                .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
            global_bytes =
                global_bytes.checked_add(bytes).ok_or_else(|| refuse(Reason::ForeignCapacity))?;
            if proofs {
                let proof: ProvenanceAuthority = row(v.value())?;
                let native = proof.native_hashes()?;
                global_native.extend(native.iter().cloned());
                if owner == root {
                    own_native.extend(native);
                }
                global_objects += 1;
            }
            if owner == root {
                own_bytes += bytes;
                own_objects += usize::from(proofs);
                own_refs += usize::from(!proofs);
            }
            if global_bytes > 1024 * 1024 * 1024
                || own_bytes > wire::MAX_PROVENANCE_BYTES
                || global_objects > 65_536
                || own_objects > wire::MAX_PROVENANCE_OBJECTS
                || own_refs > wire::MAX_SIGNER_REFERENCES
                || global_native.len() > 65_536
                || own_native.len() > wire::MAX_PROVENANCE_OBJECTS
            {
                return Err(refuse(Reason::ForeignCapacity));
            }
        }
    }
    Ok(())
}
/// Materialize only the exact references reachable from the canonical state image.
/// Missing originals remain custody-pending; no read-time provenance reconstruction.
pub(in crate::contact_reach) fn catalogue(
    tx: &redb::WriteTransaction,
    root: &str,
    state: &AccountReach,
) -> Result<Provenance> {
    let records = state.records()?;
    let mut signers = BTreeMap::new();
    let mut proofs = BTreeMap::new();
    for record in &records {
        for selected in wire::record_signers(record)? {
            let id = key(root, &reference_id(&selected)?)?;
            let reference: SignerReference = tx
                .open_table(REFERENCES)
                .map_err(storage)?
                .get(id.as_str())
                .map_err(storage)?
                .map(|v| row(v.value()))
                .transpose()?
                .ok_or_else(|| refuse(Reason::CustodyRefused))?;
            if selected.authority_head_hash != reference.authority_head_hash
                || selected.master_certificate_hash != reference.master_certificate_hash
            {
                return Err(refuse(Reason::CustodyRefused));
            }
            let proof: ProvenanceAuthority = tx
                .open_table(PROOFS)
                .map_err(storage)?
                .get(key(root, &reference.proof_hash)?.as_str())
                .map_err(storage)?
                .map(|v| row(v.value()))
                .transpose()?
                .ok_or_else(|| refuse(Reason::CustodyRefused))?;
            proofs.insert(proof.proof_hash.clone(), proof);
            signers.insert((reference.object_kind, reference.object_hash.clone()), reference);
        }
    }
    let catalogue = Provenance {
        kind: ProvenanceKind::ReachProvenance,
        version: 1,
        account_anchor: root.into(),
        revision: state.revision,
        state_hash: wire::state_hash(
            root,
            state.revision,
            state.policy_revision(),
            state.admission_revision,
            &records,
        )?,
        signers: signers.into_values().collect(),
        authorities: proofs.into_values().collect(),
    };
    catalogue.validate().map_err(|_| refuse(Reason::CustodyRefused))?;
    ramflux_crypto::contact_reach::verify_historical_state_records(&records, &catalogue)
        .map_err(|_| refuse(Reason::CustodyRefused))?;
    Ok(catalogue)
}
