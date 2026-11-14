// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Canonical state pages place each original signer reference on its first occurrence only.
use super::{Reason, Result, StatePage, refuse, storage};
use ramflux_protocol::contact_reach::{SignerReference, StateRecord, record_signers};
use std::collections::{BTreeMap, BTreeSet};
pub(super) fn pack(
    records: &[StateRecord],
    snapshot_id: &str,
    signers: &[SignerReference],
) -> Result<Vec<StatePage>> {
    let by_object: BTreeMap<_, _> = signers
        .iter()
        .map(|reference| ((reference.object_kind, reference.object_hash.as_str()), reference))
        .collect();
    let mut pages = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, chunk) in records.chunks(32).enumerate() {
        let mut selected = Vec::new();
        for record in chunk {
            for reference in record_signers(record)? {
                if seen.insert((reference.object_kind, reference.object_hash.clone())) {
                    selected.push(
                        (*by_object
                            .get(&(reference.object_kind, reference.object_hash.as_str()))
                            .ok_or_else(|| refuse(Reason::CustodyRefused))?)
                        .clone(),
                    );
                }
            }
        }
        selected.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
        let page = StatePage {
            version: 1,
            snapshot_id: snapshot_id.into(),
            page: u64::try_from(index).map_err(storage)?,
            records: chunk.to_vec(),
            signers: selected,
        };
        if super::super::store::encoded(&page)?.len() > 1024 * 1024 {
            return Err(refuse(Reason::ForeignCapacity));
        }
        pages.push(page);
    }
    Ok(pages)
}
