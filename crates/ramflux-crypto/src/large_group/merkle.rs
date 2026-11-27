// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! RFC 9162 section 2.1.1 Merkle tree hash over key slots (any leaf count), with the leaf/node
//! domain separation of design section 2.4.1.

use super::LgError;

const LEAF_DOMAIN: &[u8] = b"rf-lg-slot-leaf-v1";
const NODE_DOMAIN: &[u8] = b"rf-lg-slot-node-v1";

/// `leaf = BLAKE3("rf-lg-slot-leaf-v1" ‖ P ‖ BLAKE3(slot_ct))`.
#[must_use]
pub fn leaf_hash(p: &[u8; 32], slot_ct: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(p);
    hasher.update(blake3::hash(slot_ct).as_bytes());
    *hasher.finalize().as_bytes()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Largest power of two strictly less than `n` (`n > 1`).
fn split_point(n: usize) -> usize {
    let mut k = 1_usize;
    while k.saturating_mul(2) < n {
        k = k.saturating_mul(2);
    }
    k
}

fn mth(leaves: &[[u8; 32]]) -> Result<[u8; 32], LgError> {
    match leaves {
        [] => Err(LgError::Format("empty slot tree")),
        [only] => Ok(*only),
        _ => {
            let k = split_point(leaves.len());
            let (left, right) = leaves.split_at(k);
            Ok(node_hash(&mth(left)?, &mth(right)?))
        }
    }
}

/// Merkle root over already-hashed leaves in strictly increasing `P` order.
///
/// # Errors
/// Refuses an empty leaf list.
pub fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], LgError> {
    mth(leaves)
}

/// Audit path for leaf `index` (RFC 6962/9162 `PATH`), leaf-to-root order.
///
/// # Errors
/// Refuses an empty tree or an index outside it.
pub fn audit_path(leaves: &[[u8; 32]], index: usize) -> Result<Vec<[u8; 32]>, LgError> {
    if index >= leaves.len() {
        return Err(LgError::Format("slot index"));
    }
    let mut path = Vec::new();
    path_into(leaves, index, &mut path)?;
    Ok(path)
}

fn path_into(leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) -> Result<(), LgError> {
    if leaves.len() <= 1 {
        return Ok(());
    }
    let k = split_point(leaves.len());
    let (left, right) = leaves.split_at(k);
    if index < k {
        path_into(left, index, out)?;
        out.push(mth(right)?);
    } else {
        path_into(right, index - k, out)?;
        out.push(mth(left)?);
    }
    Ok(())
}

/// RFC 9162 section 2.1.3.2 inclusion verification with leaf index and signed `slot_count`.
#[must_use]
pub fn verify_audit_path(
    leaf: &[u8; 32],
    index: u64,
    slot_count: u64,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if index >= slot_count {
        return false;
    }
    let mut fnode = index;
    let mut snode = slot_count - 1;
    let mut hash = *leaf;
    for sibling in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            hash = node_hash(sibling, &hash);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            hash = node_hash(&hash, sibling);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && hash == *root
}
