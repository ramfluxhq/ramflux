// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Content encryption (design section 2.6, L6/R2-L3/R2-L5): XChaCha20-Poly1305 under `k_content`
//! with a random 192-bit nonce, padded to a size bucket. `AD = "rf-lg-post-v1" ‖ group_id ‖
//! I2OSP(key_epoch, 8) ‖ post_id ‖ hdr_hash`. `appended_at` and `log_seq` are host-written and
//! therefore outside `hdr_hash` (R3-L1); the head chain binds them.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::codec::{Dec, Enc};
use super::{EpochKey, LgError, random_array};

/// Padded ciphertext size buckets (nonce and tag included).
pub const SIZE_BUCKETS: [usize; 3] = [256, 1024, 4096];
/// Largest bucket.
pub const MAX_BUCKET: usize = 4096;
/// Mention tag slots per entry.
pub const TAG_SLOTS: usize = 8;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const POST_DOMAIN: &[u8] = b"rf-lg-post-v1";
const HDR_DOMAIN: &[u8] = b"rf-lg-hdr-v1";
const INNER_DOMAIN: &[u8] = b"rf-lg-inner-v1";
const BIND_DOMAIN: &[u8] = b"rf-lg-entry-v1";
const CHAIN_DOMAIN: &[u8] = b"rf-lg-entry-chain-v1";
const MAX_SEEN: usize = 256;

/// Encrypted entry kinds (host-visible `kind`).
pub struct EntryKind;

impl EntryKind {
    pub const POST: u8 = 1;
    pub const REACTION: u8 = 2;
    pub const EDIT: u8 = 3;
    pub const KEY_W: u8 = 4;
    pub const KEY_W_PRIME: u8 = 5;
    pub const KEY_REDELIVER: u8 = 6;
    pub const KEY_R: u8 = 7;
}

/// Host-visible header fields that `hdr_hash` covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryHeader {
    pub kind: u8,
    pub post_id: [u8; 16],
    pub key_epoch: u64,
    pub bucket: u32,
    pub del_secret_hash: [u8; 32],
    pub tags: [[u8; 16]; TAG_SLOTS],
}

/// `hdr_hash = BLAKE3(canonical header without token and without H(ciphertext))`.
#[must_use]
pub fn header_hash(header: &EntryHeader) -> [u8; 32] {
    let mut enc = Enc::new(HDR_DOMAIN);
    enc.u8(header.kind)
        .fixed(&header.post_id)
        .u64(header.key_epoch)
        .u32(header.bucket)
        .fixed(&header.del_secret_hash);
    for tag in &header.tags {
        enc.fixed(tag);
    }
    *blake3::hash(&enc.finish()).as_bytes()
}

/// The `H(entry_header)` a token tag binds: header hash plus `H(ciphertext)` (the token itself is
/// excluded, it is computed after encryption).
#[must_use]
pub fn entry_bind_hash(hdr_hash: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BIND_DOMAIN);
    hasher.update(hdr_hash);
    hasher.update(blake3::hash(ciphertext).as_bytes());
    *hasher.finalize().as_bytes()
}

/// The entry hash the head chain covers: the bind hash plus token, `appended_at` and `log_seq`.
#[must_use]
pub fn entry_chain_hash(
    bind_hash: &[u8; 32],
    token: &[u8],
    appended_at_ms: u64,
    log_seq: u64,
) -> [u8; 32] {
    let mut enc = Enc::new(CHAIN_DOMAIN);
    enc.fixed(bind_hash).var(token).u64(appended_at_ms).u64(log_seq);
    *blake3::hash(&enc.finish()).as_bytes()
}

/// A sealed entry body (what the host stores) and the decrypted view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEntry {
    pub ciphertext: Vec<u8>,
}

/// Smallest bucket that holds the inner structure.
///
/// # Errors
/// Refuses content that does not fit the largest bucket.
pub fn bucket_for(seen_len: usize, body_len: usize) -> Result<usize, LgError> {
    let inner = 4 + 32 + 64 + 4 + seen_len + 4 + body_len;
    let need = NONCE_LEN + TAG_LEN + inner;
    SIZE_BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= need)
        .ok_or(LgError::Format("entry too large for the largest bucket"))
}

fn associated_data(group_id: &[u8; 32], header: &EntryHeader) -> Vec<u8> {
    let mut ad = Vec::with_capacity(POST_DOMAIN.len() + 32 + 8 + 16 + 32);
    ad.extend_from_slice(POST_DOMAIN);
    ad.extend_from_slice(group_id);
    ad.extend_from_slice(&header.key_epoch.to_be_bytes());
    ad.extend_from_slice(&header.post_id);
    ad.extend_from_slice(&header_hash(header));
    ad
}

fn inner_signing_bytes(ad: &[u8], seen: &[u8], body: &[u8]) -> Vec<u8> {
    let mut enc = Enc::new(INNER_DOMAIN);
    enc.var(ad).var(seen).var(body);
    enc.finish()
}

/// Seals one entry: the inner device signature covers the AD fields plus `seen` and the body.
///
/// # Errors
/// Refuses content that does not fit the header's bucket, or an AEAD/randomness failure.
pub fn seal_entry(
    k_content: &EpochKey,
    group_id: &[u8; 32],
    header: &EntryHeader,
    author_seed: &[u8; 32],
    seen: &[u8],
    body: &[u8],
) -> Result<SealedEntry, LgError> {
    if seen.len() > MAX_SEEN {
        return Err(LgError::Format("seen too long"));
    }
    let bucket = usize::try_from(header.bucket).map_err(|_| LgError::Format("bucket"))?;
    if !SIZE_BUCKETS.contains(&bucket) || bucket_for(seen.len(), body.len())? > bucket {
        return Err(LgError::Format("bucket does not fit the entry"));
    }
    let ad = associated_data(group_id, header);
    let signing = SigningKey::from_bytes(author_seed);
    let signature = signing.sign(&inner_signing_bytes(&ad, seen, body)).to_bytes();
    let mut structured = Enc::default();
    structured.fixed(&signing.verifying_key().to_bytes()).fixed(&signature).var(seen).var(body);
    let structured = structured.finish();
    let plain_len = bucket - NONCE_LEN - TAG_LEN;
    let mut plain = Vec::with_capacity(plain_len);
    let structured_len = u32::try_from(structured.len()).map_err(|_| LgError::Format("length"))?;
    plain.extend_from_slice(&structured_len.to_be_bytes());
    plain.extend_from_slice(&structured);
    plain.resize(plain_len, 0);
    let nonce = random_array::<NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new(k_content.expose().into());
    let sealed = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &ad })
        .map_err(|_| LgError::Crypto("content seal"))?;
    let mut ciphertext = Vec::with_capacity(bucket);
    ciphertext.extend_from_slice(&nonce);
    ciphertext.extend_from_slice(&sealed);
    Ok(SealedEntry { ciphertext })
}

/// Decrypted entry: the author device key, `seen` and the body, after the inner signature check.
pub struct OpenedEntry {
    pub author_pub: [u8; 32],
    pub seen: Vec<u8>,
    pub body: Vec<u8>,
}

/// Opens one entry. A header altered by the host (including `H(del_secret)`) fails the AD check.
///
/// # Errors
/// Refuses a malformed entry, an AEAD failure or a bad inner signature.
pub fn open_entry(
    k_content: &EpochKey,
    group_id: &[u8; 32],
    header: &EntryHeader,
    ciphertext: &[u8],
) -> Result<OpenedEntry, LgError> {
    let (nonce, sealed) =
        ciphertext.split_at_checked(NONCE_LEN).ok_or(LgError::Format("entry length"))?;
    let ad = associated_data(group_id, header);
    let cipher = XChaCha20Poly1305::new(k_content.expose().into());
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: sealed, aad: &ad })
        .map_err(|_| LgError::Verify("content aead"))?;
    let mut outer = Dec::new(&plain);
    let structured_len =
        usize::try_from(outer.u32()?).map_err(|_| LgError::Format("inner length"))?;
    let structured = plain
        .get(4..4_usize.saturating_add(structured_len))
        .ok_or(LgError::Format("inner length"))?;
    let mut dec = Dec::new(structured);
    let author_pub: [u8; 32] = dec.fixed()?;
    let signature: [u8; 64] = dec.fixed()?;
    let seen = dec.var(MAX_SEEN)?.to_vec();
    let body = dec.var(MAX_BUCKET)?.to_vec();
    dec.finish()?;
    let key = VerifyingKey::from_bytes(&author_pub).map_err(|_| LgError::Verify("author key"))?;
    key.verify(&inner_signing_bytes(&ad, &seen, &body), &Signature::from_bytes(&signature))
        .map_err(|_| LgError::Verify("inner signature"))?;
    Ok(OpenedEntry { author_pub, seen, body })
}
