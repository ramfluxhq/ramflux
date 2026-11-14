// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A retained historical node key reaches current discovery only through original signed rotations.
use super::{CryptoError, reject, wire};
use std::collections::BTreeSet;
/// Previously authenticated node key and its independent retained rotation-time floor.
#[derive(Clone, Copy)]
pub struct NodeContinuityContext<'a> {
    pub node: &'a str,
    pub old_key: &'a str,
    pub current_key: &'a str,
    pub minimum_rotated_at: u64,
    pub now: u64,
}
/// Verify the original old-key signatures and the suffix beginning at the retained key.
/// Current discovery signature and TLS new-key possession must be verified separately.
/// # Errors
/// Refuses forks, retired-key reuse, wrong nodes, missing links and nonincreasing times.
pub fn verify_node_continuity(
    proofs: &[serde_json::Value],
    context: NodeContinuityContext<'_>,
) -> Result<(), CryptoError> {
    wire::original_document(&proofs, 1024 * 1024)?;
    if proofs.len() > 32
        || context.now > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        || context.minimum_rotated_at > ramflux_protocol::MAX_SAFE_JSON_INTEGER
    {
        return Err(reject("node rotation proof budget or clock"));
    }
    let mut key = context.old_key.to_owned();
    let mut at = context.minimum_rotated_at;
    let mut active = false;
    let mut used = BTreeSet::new();
    let mut previous: Option<wire::NodeKeyRotation> = None;
    for proof in proofs {
        let rotation: wire::NodeKeyRotation =
            wire::decode(&ramflux_protocol::canonical_json_bytes(proof)?, 1024 * 1024)?;
        rotation.validate()?;
        if rotation.node_id != context.node
            || rotation.rotated_at > context.now
            || previous.as_ref().is_some_and(|prior| {
                prior.new_node_public_key != rotation.old_node_public_key
                    || prior.rotated_at >= rotation.rotated_at
            })
        {
            return Err(reject("node rotation chain mismatch"));
        }
        if previous.is_none() {
            used.insert(rotation.old_node_public_key.clone());
        }
        if !used.insert(rotation.new_node_public_key.clone()) {
            return Err(reject("node rotation reuses a retired active key"));
        }
        crate::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&rotation)?,
            &rotation.signature,
            &rotation.old_node_public_key,
        )?;
        active |= rotation.old_node_public_key == context.old_key;
        if active {
            if rotation.old_node_public_key != key || rotation.rotated_at <= at {
                return Err(reject("node rotation rollback or competing successor"));
            }
            key.clone_from(&rotation.new_node_public_key);
            at = rotation.rotated_at;
        }
        previous = Some(rotation);
    }
    if key != context.current_key
        || previous.as_ref().is_some_and(|last| last.new_node_public_key != context.current_key)
    {
        return Err(reject("node key changed without verified continuity"));
    }
    Ok(())
}
#[cfg(test)]
mod tests;
