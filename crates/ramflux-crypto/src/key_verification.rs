// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ramflux_protocol::{decode_base64url, encode_base64url};
use serde::{Deserialize, Serialize};

use crate::{CryptoError, blake3_256, verify_canonical_signature, write_len_prefixed};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSafetyMaterial {
    pub device_id_hash: Vec<u8>,
    pub device_identity_key_hash: Vec<u8>,
    pub device_signing_key_hash: Vec<u8>,
    pub device_x25519_identity_key_hash: Vec<u8>,
    pub device_epoch: u64,
    pub branch_authorized_event_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactSafetyMaterial {
    pub identity_commitment: Vec<u8>,
    pub identity_key_hash: Vec<u8>,
    pub lineage_head: Vec<u8>,
    pub devices: Vec<DeviceSafetyMaterial>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KtLeafInput<'a> {
    pub identity_commitment: &'a str,
    pub lineage_head: &'a str,
    pub device_set_hash: &'a str,
    pub home_node: &'a str,
    pub sequence: u64,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KtLeaf {
    pub schema: String,
    pub identity_commitment: String,
    pub lineage_head: String,
    pub device_set_hash: String,
    pub home_node: String,
    pub sequence: u64,
    pub created_at: i64,
    pub signature_by_identity_device: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct KtLeafSigningBody<'a> {
    schema: &'a str,
    identity_commitment: &'a str,
    lineage_head: &'a str,
    device_set_hash: &'a str,
    home_node: &'a str,
    sequence: u64,
    created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KtSignedTreeHead {
    pub tree_size: u64,
    pub root_hash: String,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct KtTreeHeadSigningBody<'a> {
    tree_size: u64,
    root_hash: &'a str,
    timestamp: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KtInclusionProof {
    pub leaf_index: usize,
    pub tree_size: usize,
    pub audit_path: Vec<[u8; 32]>,
    pub tree_head: KtSignedTreeHead,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KtConsistencyProof {
    pub old_leaf_hashes: Vec<[u8; 32]>,
    pub appended_leaf_hashes: Vec<[u8; 32]>,
    pub old_tree_head: KtSignedTreeHead,
    pub new_tree_head: KtSignedTreeHead,
}

#[must_use]
pub fn device_set_hash(devices: &[DeviceSafetyMaterial]) -> [u8; 32] {
    let mut tuples = devices.iter().map(device_safety_tuple).collect::<Vec<(Vec<u8>, Vec<u8>)>>();
    tuples.sort_by(|(left_key, _left_tuple), (right_key, _right_tuple)| left_key.cmp(right_key));
    let mut bytes = Vec::new();
    for (_key, tuple) in tuples {
        bytes.extend_from_slice(&tuple);
    }
    blake3_256(ramflux_protocol::domain::KEY_VERIFICATION_DEVICE_SET, &bytes)
}

#[must_use]
pub fn safety_fingerprint(
    first: &ContactSafetyMaterial,
    second: &ContactSafetyMaterial,
) -> [u8; 32] {
    let first_bytes = contact_safety_bytes(first);
    let second_bytes = contact_safety_bytes(second);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ramflux_protocol::domain::KEY_VERIFICATION_SAFETY_NUMBER.as_bytes());
    if first.identity_commitment <= second.identity_commitment {
        bytes.extend_from_slice(&first_bytes);
        bytes.extend_from_slice(&second_bytes);
    } else {
        bytes.extend_from_slice(&second_bytes);
        bytes.extend_from_slice(&first_bytes);
    }
    blake3_256(ramflux_protocol::domain::KEY_VERIFICATION_SAFETY_NUMBER, &bytes)
}

#[must_use]
pub fn safety_number(first: &ContactSafetyMaterial, second: &ContactSafetyMaterial) -> Vec<String> {
    let fingerprint = safety_fingerprint(first, second);
    let unbiased_limit = (u64::from(u32::MAX) + 1) / 100_000 * 100_000;
    let mut groups = Vec::with_capacity(12);
    for index in 0..12 {
        let mut attempt = 0_u32;
        loop {
            let mut bytes = Vec::with_capacity(37);
            bytes.extend_from_slice(&fingerprint);
            bytes.push(index);
            bytes.extend_from_slice(&attempt.to_be_bytes());
            let candidate_hash = blake3_256("ramflux.safety_number.group.v1", &bytes);
            let candidate = u32::from_be_bytes([
                candidate_hash[0],
                candidate_hash[1],
                candidate_hash[2],
                candidate_hash[3],
            ]);
            if u64::from(candidate) < unbiased_limit {
                groups.push(format!("{:05}", candidate % 100_000));
                break;
            }
            attempt = attempt.saturating_add(1);
        }
    }
    groups
}

#[must_use]
pub fn registration_pow_digest(identity_commitment: &str, nonce: u64) -> [u8; 32] {
    let mut bytes = Vec::new();
    write_len_prefixed(&mut bytes, identity_commitment.as_bytes());
    bytes.extend_from_slice(&nonce.to_be_bytes());
    blake3_256(ramflux_protocol::domain::REGISTRATION_POW, &bytes)
}

#[must_use]
pub fn registration_pow_meets_difficulty(
    identity_commitment: &str,
    nonce: u64,
    difficulty_bits: u8,
) -> bool {
    leading_zero_bits(&registration_pow_digest(identity_commitment, nonce))
        >= u32::from(difficulty_bits)
}

#[must_use]
pub fn solve_registration_pow(identity_commitment: &str, difficulty_bits: u8) -> u64 {
    let mut nonce = 0_u64;
    while !registration_pow_meets_difficulty(identity_commitment, nonce, difficulty_bits) {
        nonce = nonce.saturating_add(1);
    }
    nonce
}

#[must_use]
pub fn kt_leaf_hash(leaf_bytes: &[u8]) -> [u8; 32] {
    blake3_256("ramflux.kt.leaf.v1", leaf_bytes)
}

/// # Errors
/// Returns an error when the KT leaf signing body cannot be canonicalized.
pub fn sign_kt_leaf(
    input: KtLeafInput<'_>,
    identity_device_signing_key: &SigningKey,
) -> Result<KtLeaf, CryptoError> {
    let body = kt_leaf_signing_body(&input);
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    let signature = identity_device_signing_key.sign(&canonical);
    Ok(KtLeaf {
        schema: "ramflux.kt_leaf.v1".to_owned(),
        identity_commitment: input.identity_commitment.to_owned(),
        lineage_head: input.lineage_head.to_owned(),
        device_set_hash: input.device_set_hash.to_owned(),
        home_node: input.home_node.to_owned(),
        sequence: input.sequence,
        created_at: input.created_at,
        signature_by_identity_device: encode_base64url(signature.to_bytes()),
    })
}

/// # Errors
/// Returns an error when the KT leaf signature cannot be verified.
pub fn verify_kt_leaf_signature(
    leaf: &KtLeaf,
    identity_device_public_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let input = KtLeafInput {
        identity_commitment: &leaf.identity_commitment,
        lineage_head: &leaf.lineage_head,
        device_set_hash: &leaf.device_set_hash,
        home_node: &leaf.home_node,
        sequence: leaf.sequence,
        created_at: leaf.created_at,
    };
    let body = kt_leaf_signing_body(&input);
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    verify_canonical_signature(
        &canonical,
        &leaf.signature_by_identity_device,
        &encode_base64url(identity_device_public_key.to_bytes()),
    )
}

/// # Errors
/// Returns an error when the KT leaf cannot be canonicalized.
pub fn kt_leaf_canonical_hash(leaf: &KtLeaf) -> Result<[u8; 32], CryptoError> {
    let canonical = ramflux_protocol::canonical_json_bytes(leaf)?;
    Ok(kt_leaf_hash(&canonical))
}

#[must_use]
pub fn kt_parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    blake3_256("ramflux.kt.node.v1", &bytes)
}

#[must_use]
pub fn kt_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return blake3_256("ramflux.kt.empty.v1", b"");
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let right = if chunk.len() == 2 { &chunk[1] } else { &chunk[0] };
            next.push(kt_parent_hash(&chunk[0], right));
        }
        level = next;
    }
    level[0]
}

/// # Errors
/// Returns an error when the leaf index is outside the tree.
pub fn kt_inclusion_proof(
    leaves: &[[u8; 32]],
    leaf_index: usize,
) -> Result<Vec<[u8; 32]>, CryptoError> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return Err(CryptoError::TransparencyProofFailed);
    }
    let mut proof = Vec::new();
    let mut index = leaf_index;
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let sibling_index =
            if index.is_multiple_of(2) { (index + 1).min(level.len() - 1) } else { index - 1 };
        proof.push(level[sibling_index]);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let right = if chunk.len() == 2 { &chunk[1] } else { &chunk[0] };
            next.push(kt_parent_hash(&chunk[0], right));
        }
        level = next;
        index /= 2;
    }
    Ok(proof)
}

/// # Errors
/// Returns an error when the tree head signing body cannot be canonicalized.
pub fn sign_kt_tree_head(
    tree_size: u64,
    root_hash: [u8; 32],
    timestamp: i64,
    log_signing_key: &SigningKey,
) -> Result<KtSignedTreeHead, CryptoError> {
    let root_hash = encode_base64url(root_hash);
    let body = KtTreeHeadSigningBody { tree_size, root_hash: &root_hash, timestamp };
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    let signature = log_signing_key.sign(&canonical);
    Ok(KtSignedTreeHead {
        tree_size,
        root_hash,
        timestamp,
        signature: encode_base64url(signature.to_bytes()),
    })
}

/// # Errors
/// Returns an error when the tree head signature or root encoding is invalid.
pub fn verify_kt_tree_head(
    tree_head: &KtSignedTreeHead,
    log_public_key: &VerifyingKey,
) -> Result<[u8; 32], CryptoError> {
    let root_hash = decode_hash32(&tree_head.root_hash)?;
    let body = KtTreeHeadSigningBody {
        tree_size: tree_head.tree_size,
        root_hash: &tree_head.root_hash,
        timestamp: tree_head.timestamp,
    };
    let canonical = ramflux_protocol::canonical_json_bytes(&body)?;
    verify_canonical_signature(
        &canonical,
        &tree_head.signature,
        &encode_base64url(log_public_key.to_bytes()),
    )?;
    Ok(root_hash)
}

/// # Errors
/// Returns an error when the inclusion proof is outside tree bounds or does not match the root.
pub fn verify_kt_inclusion(
    leaf_hash: [u8; 32],
    leaf_index: usize,
    tree_size: usize,
    proof: &[[u8; 32]],
    expected_root: [u8; 32],
) -> Result<(), CryptoError> {
    if tree_size == 0 || leaf_index >= tree_size {
        return Err(CryptoError::TransparencyProofFailed);
    }
    let mut node = leaf_hash;
    let mut index = leaf_index;
    let mut width = tree_size;
    for sibling in proof {
        if index.is_multiple_of(2) {
            node = kt_parent_hash(&node, sibling);
        } else {
            node = kt_parent_hash(sibling, &node);
        }
        index /= 2;
        width = width.div_ceil(2);
    }
    if width == 1 && node == expected_root {
        Ok(())
    } else {
        Err(CryptoError::TransparencyProofFailed)
    }
}

/// # Errors
/// Returns an error when the signed tree head, bounds, or inclusion path is invalid.
pub fn verify_kt_inclusion_proof(
    leaf_hash: [u8; 32],
    proof: &KtInclusionProof,
    log_public_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let root_hash = verify_kt_tree_head(&proof.tree_head, log_public_key)?;
    let head_tree_size = usize::try_from(proof.tree_head.tree_size)
        .map_err(|_err| CryptoError::TransparencyProofFailed)?;
    if head_tree_size != proof.tree_size {
        return Err(CryptoError::TransparencyProofFailed);
    }
    verify_kt_inclusion(leaf_hash, proof.leaf_index, proof.tree_size, &proof.audit_path, root_hash)
}

/// # Errors
/// Returns an error when the new leaf list is not a prefix extension or roots do not match.
pub fn verify_kt_consistency_prefix(
    old_leaves: &[[u8; 32]],
    new_leaves: &[[u8; 32]],
    old_root: [u8; 32],
    new_root: [u8; 32],
) -> Result<(), CryptoError> {
    if old_leaves.len() > new_leaves.len() || new_leaves[..old_leaves.len()] != *old_leaves {
        return Err(CryptoError::TransparencyProofFailed);
    }
    if kt_merkle_root(old_leaves) == old_root && kt_merkle_root(new_leaves) == new_root {
        Ok(())
    } else {
        Err(CryptoError::TransparencyProofFailed)
    }
}

/// # Errors
/// Returns an error when tree heads are invalid, rolled back, or not append-only.
pub fn verify_kt_consistency_proof(
    proof: &KtConsistencyProof,
    log_public_key: &VerifyingKey,
) -> Result<(), CryptoError> {
    let old_root = verify_kt_tree_head(&proof.old_tree_head, log_public_key)?;
    let new_root = verify_kt_tree_head(&proof.new_tree_head, log_public_key)?;
    let old_size = usize::try_from(proof.old_tree_head.tree_size)
        .map_err(|_err| CryptoError::TransparencyProofFailed)?;
    let new_size = usize::try_from(proof.new_tree_head.tree_size)
        .map_err(|_err| CryptoError::TransparencyProofFailed)?;
    if old_size != proof.old_leaf_hashes.len()
        || new_size != old_size + proof.appended_leaf_hashes.len()
        || new_size < old_size
    {
        return Err(CryptoError::TransparencyProofFailed);
    }
    let mut new_leaves = proof.old_leaf_hashes.clone();
    new_leaves.extend_from_slice(&proof.appended_leaf_hashes);
    verify_kt_consistency_prefix(&proof.old_leaf_hashes, &new_leaves, old_root, new_root)
}

fn contact_safety_bytes(material: &ContactSafetyMaterial) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_len_prefixed(&mut bytes, &material.identity_commitment);
    write_len_prefixed(&mut bytes, &material.identity_key_hash);
    bytes.extend_from_slice(&device_set_hash(&material.devices));
    write_len_prefixed(&mut bytes, &material.lineage_head);
    bytes
}

fn kt_leaf_signing_body<'a>(input: &'a KtLeafInput<'a>) -> KtLeafSigningBody<'a> {
    KtLeafSigningBody {
        schema: "ramflux.kt_leaf.v1",
        identity_commitment: input.identity_commitment,
        lineage_head: input.lineage_head,
        device_set_hash: input.device_set_hash,
        home_node: input.home_node,
        sequence: input.sequence,
        created_at: input.created_at,
    }
}

fn decode_hash32(value: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = decode_base64url(value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| CryptoError::InvalidPublicKeyLength(bytes.len()))
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0_u32;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

fn device_safety_tuple(device: &DeviceSafetyMaterial) -> (Vec<u8>, Vec<u8>) {
    let mut tuple = Vec::new();
    write_len_prefixed(&mut tuple, &device.device_id_hash);
    write_len_prefixed(&mut tuple, &device.device_identity_key_hash);
    write_len_prefixed(&mut tuple, &device.device_signing_key_hash);
    write_len_prefixed(&mut tuple, &device.device_x25519_identity_key_hash);
    tuple.extend_from_slice(&device.device_epoch.to_be_bytes());
    write_len_prefixed(&mut tuple, &device.branch_authorized_event_id);

    let mut key = Vec::new();
    key.extend_from_slice(&device.device_id_hash);
    key.extend_from_slice(&device.device_identity_key_hash);
    key.extend_from_slice(&device.device_epoch.to_be_bytes());
    (key, tuple)
}
