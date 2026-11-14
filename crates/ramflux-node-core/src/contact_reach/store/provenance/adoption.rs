// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A new current native tuple stays reach-pending until its complete proof fits durable storage.
use super::{
    AccountReach, ObjectKind, PROOFS, ProvenanceAuthority, REFERENCES, Reason, Result,
    SignerReference, check_caps, current, custody, encoded, index, key, reference_id, refuse, row,
    storage, wire,
};
use redb::ReadableTable;

pub(in crate::contact_reach) fn adopt_current(
    store: &super::super::RouterRedbStore,
    tx: &redb::WriteTransaction,
    root: &str,
    now: u64,
) -> Result<ProvenanceAuthority> {
    let proof = current(store, tx, root, now)?;
    let id = key(root, &proof.proof_hash)?;
    let bytes = encoded(&proof)?;
    let mut table = tx.open_table(PROOFS).map_err(storage)?;
    let old = table.get(id.as_str()).map_err(storage)?.map(|value| value.value().to_vec());
    match old {
        Some(old) if old != bytes => return Err(refuse(Reason::CustodyRefused)),
        Some(_) => return Ok(proof),
        None => {
            table.insert(id.as_str(), bytes.as_slice()).map_err(storage)?;
        }
    }
    drop(table);
    // This write is private to the caller's transaction. Failure cannot acknowledge adoption.
    check_caps(tx, root)?;
    Ok(proof)
}

/// Reads cannot adopt authority. Both current context and exact original references must exist.
pub(in crate::contact_reach) fn require_ready(
    store: &super::super::RouterRedbStore,
    tx: &redb::WriteTransaction,
    root: &str,
    state: &AccountReach,
    now: u64,
) -> Result<()> {
    let current = current(store, tx, root, now)?;
    let table = tx.open_table(PROOFS).map_err(storage)?;
    let retained = table.get(key(root, &current.proof_hash)?.as_str()).map_err(storage)?;
    let expected = encoded(&current)?;
    if retained.is_none_or(|value| value.value() != expected) {
        return Err(refuse(Reason::CustodyRefused));
    }
    let mut signers = index(tx, root, state)?.signers;
    for roster in state.rosters.values() {
        let header = &roster.header;
        let id = reference_id(&SignerReference {
            object_hash: custody::framed_hash(wire::OPERATION_HASH_DOMAIN, header)?,
            object_kind: ObjectKind::GroupRoster,
            authority_head_hash: header.body.authority_head_hash.clone(),
            master_certificate_hash: header.body.master_certificate_hash.clone(),
            proof_hash: String::new(),
        })?;
        let reference: SignerReference = tx
            .open_table(REFERENCES)
            .map_err(storage)?
            .get(key(root, &id)?.as_str())
            .map_err(storage)?
            .map(|value| row(value.value()))
            .transpose()?
            .ok_or_else(|| refuse(Reason::CustodyRefused))?;
        reference.validate().map_err(|_| refuse(Reason::CustodyRefused))?;
        if reference.authority_head_hash != header.body.authority_head_hash
            || reference.master_certificate_hash != header.body.master_certificate_hash
        {
            return Err(refuse(Reason::CustodyRefused));
        }
        signers.push(reference);
    }
    for reference in signers {
        let raw = table
            .get(key(root, &reference.proof_hash)?.as_str())
            .map_err(storage)?
            .ok_or_else(|| refuse(Reason::CustodyRefused))?;
        if raw.value().len() > 1024 * 1024 + 1024 {
            return Err(refuse(Reason::ForeignCapacity));
        }
        let proof: ProvenanceAuthority = row(raw.value())?;
        proof.validate().map_err(|_| refuse(Reason::CustodyRefused))?;
        if proof.proof_hash != reference.proof_hash
            || custody::object_hash(&proof.authority.publication.record)?
                != reference.authority_head_hash
            || custody::object_hash(&proof.authority.publication.record.body.master_certificate)?
                != reference.master_certificate_hash
        {
            return Err(refuse(Reason::CustodyRefused));
        }
    }
    Ok(())
}
