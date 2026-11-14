// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reuse the native M4 verifier with independently authenticated home evidence.
use super::{CryptoError, reject, wire};
use crate::home_migration::{VerifiedHome, verify_home_chain_with_custodians};
use ramflux_protocol::home_migration::{HomeRecord, ResolveResult};

pub(super) fn verify_original_home(
    proof: &wire::ProvenanceAuthority,
    root: &str,
    issued_at: u64,
    home: Option<&VerifiedHome>,
) -> Result<(), CryptoError> {
    let home = home.ok_or_else(|| reject("original external signer requires verified home"))?;
    if home.evidence().record.account_anchor() != root {
        return Err(reject("original home account mismatch"));
    }
    let records = home.records();
    let base = records.first().ok_or_else(|| reject("original home evidence absent"))?;
    if records.len() > 64
        || ramflux_protocol::canonical_json_bytes(&(records, &proof.custodian_history))?.len()
            > 1024 * 1024
    {
        return Err(reject("original home closure capacity"));
    }
    for record in records {
        let committed = match &record.record {
            HomeRecord::Genesis { genesis } => genesis.body.registered_at,
            HomeRecord::Committed { commit_proof, .. } => commit_proof.body.committed_at,
        };
        if committed > issued_at {
            return Err(reject("home was committed after original object"));
        }
    }
    let result = ResolveResult {
        home: home.evidence().clone(),
        predecessors: records.iter().take(records.len().saturating_sub(1)).cloned().collect(),
    };
    let original =
        verify_home_chain_with_custodians(&result, base, &proof.custodian_history, issued_at)?;
    if original.hash() != home.hash() {
        return Err(reject("original home closure mismatch"));
    }
    Ok(())
}
