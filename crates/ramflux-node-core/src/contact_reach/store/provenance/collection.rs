// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Collect superseded originals only while the owner holds an empty snapshot-lease set.
use super::{
    AccountReach, PROOFS, REFERENCES, Reason, Result, SignerReference, check_caps, current, index,
    key, reference_id, refuse, row, storage, wire,
};
use redb::ReadableTable;
use std::collections::BTreeSet;

/// Caller holds the snapshot mutex and has removed every expired lease for this recipient.
/// It must not call while any unexpired lease or a not-yet-encrypted read index exists.
pub(in crate::contact_reach) fn collect_without_leases(
    store: &super::super::RouterRedbStore,
    tx: &redb::WriteTransaction,
    root: &str,
    state: &AccountReach,
    now: u64,
) -> Result<()> {
    let mut live = BTreeSet::new();
    let mut proofs = BTreeSet::new();
    for reference in index(tx, root, state)?.signers {
        live.insert(key(root, &reference_id(&reference)?)?);
        proofs.insert(key(root, &reference.proof_hash)?);
    }
    // Live roster headers are intentionally excluded from the state pages, but still own proofs.
    for roster in state.rosters.values() {
        let header = &roster.header;
        let selected = SignerReference {
            object_kind: wire::ObjectKind::GroupRoster,
            object_hash: super::custody::framed_hash(wire::OPERATION_HASH_DOMAIN, header)?,
            authority_head_hash: header.body.authority_head_hash.clone(),
            master_certificate_hash: header.body.master_certificate_hash.clone(),
            proof_hash: String::new(),
        };
        let id = key(root, &reference_id(&selected)?)?;
        let reference: SignerReference = tx
            .open_table(REFERENCES)
            .map_err(storage)?
            .get(id.as_str())
            .map_err(storage)?
            .map(|value| row(value.value()))
            .transpose()?
            .ok_or_else(|| refuse(Reason::CustodyRefused))?;
        reference.validate()?;
        if reference.object_kind != selected.object_kind
            || reference.object_hash != selected.object_hash
            || reference.authority_head_hash != selected.authority_head_hash
            || reference.master_certificate_hash != selected.master_certificate_hash
        {
            return Err(refuse(Reason::CustodyRefused));
        }
        live.insert(id);
        proofs.insert(key(root, &reference.proof_hash)?);
    }
    // The admitted current tuple remains available for future negative commands even before
    // any signed state record refers to it. A newly observed tuple may not yet have a row.
    proofs.insert(key(root, &current(store, tx, root, now)?.proof_hash)?);
    remove_unreferenced(tx, root, REFERENCES, &live, wire::MAX_SIGNER_REFERENCES)?;
    remove_unreferenced(tx, root, PROOFS, &proofs, wire::MAX_PROVENANCE_OBJECTS)?;
    check_caps(tx, root)
}

fn remove_unreferenced(
    tx: &redb::WriteTransaction,
    root: &str,
    definition: redb::TableDefinition<&str, &[u8]>,
    live: &BTreeSet<String>,
    limit: usize,
) -> Result<()> {
    let prefix = format!("[{},", serde_json::to_string(root).map_err(storage)?);
    let mut table = tx.open_table(definition).map_err(storage)?;
    let mut remove = Vec::new();
    let mut count = 0;
    for entry in table.range(prefix.as_str()..).map_err(storage)? {
        let (key, _) = entry.map_err(storage)?;
        if !key.value().starts_with(&prefix) {
            break;
        }
        count += 1;
        if count > limit {
            return Err(refuse(Reason::ForeignCapacity));
        }
        if !live.contains(key.value()) {
            remove.push(key.value().to_owned());
        }
    }
    for id in remove {
        table.remove(id.as_str()).map_err(storage)?;
    }
    Ok(())
}
