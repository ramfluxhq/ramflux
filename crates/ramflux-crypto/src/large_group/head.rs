// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host-signed head chain and `seen` (design section 2.6, H3):
//! `head_n = BLAKE3(head_{n-1} ‖ I2OSP(n, 8) ‖ H(entry_header_n))`,
//! `host_sig_n = Ed25519(host_head_sk, "rf-lg-head-v1" ‖ group_id ‖ I2OSP(n, 8) ‖ head_n)`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::LgError;
use super::codec::{Dec, Enc};

const HEAD_DOMAIN: &[u8] = b"rf-lg-head-v1";
const SEEN_DOMAIN: &[u8] = b"rf-lg-seen-v1";

/// `head_n` from the previous head, the position and the entry-chain hash.
#[must_use]
pub fn next_head(prev_head: &[u8; 32], n: u64, entry_chain_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_head);
    hasher.update(&n.to_be_bytes());
    hasher.update(entry_chain_hash);
    *hasher.finalize().as_bytes()
}

fn head_message(group_id: &[u8; 32], n: u64, head: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(HEAD_DOMAIN.len() + 32 + 8 + 32);
    message.extend_from_slice(HEAD_DOMAIN);
    message.extend_from_slice(group_id);
    message.extend_from_slice(&n.to_be_bytes());
    message.extend_from_slice(head);
    message
}

/// Host signature over one head.
#[must_use]
pub fn host_head_sign(seed: &[u8; 32], group_id: &[u8; 32], n: u64, head: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(&head_message(group_id, n, head)).to_bytes()
}

/// # Errors
/// Refuses a malformed key or a signature that does not verify over the caller's own `head`.
pub fn host_head_verify(
    host_head_pk: &[u8; 32],
    group_id: &[u8; 32],
    n: u64,
    head: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), LgError> {
    let key = VerifyingKey::from_bytes(host_head_pk).map_err(|_| LgError::Verify("host key"))?;
    key.verify(&head_message(group_id, n, head), &Signature::from_bytes(signature))
        .map_err(|_| LgError::Verify("host head signature"))
}

/// `seen = (log_seq, head_hash, host_sig)` an author puts under its inner signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub log_seq: u64,
    pub head: [u8; 32],
    pub host_sig: [u8; 64],
}

impl Seen {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::new(SEEN_DOMAIN);
        enc.u64(self.log_seq).fixed(&self.head).fixed(&self.host_sig);
        enc.finish()
    }

    /// # Errors
    /// Refuses malformed bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        if dec.var(SEEN_DOMAIN.len())? != SEEN_DOMAIN {
            return Err(LgError::Format("seen domain"));
        }
        let seen = Self { log_seq: dec.u64()?, head: dec.fixed()?, host_sig: dec.fixed()? };
        dec.finish()?;
        Ok(seen)
    }
}

/// Reader-side verdict on a `seen` (H3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeenVerdict {
    /// Consistent with the reader's own chain (or ahead of it: nothing to compare yet).
    Consistent,
    /// Invalid host signature: ignored, author flagged locally, no alarm and no posting stop.
    FlagAuthor,
    /// Two valid host signatures for one `n` over different heads: transferable proof, alarm.
    Equivocation { n: u64, own_head: [u8; 32], other_head: [u8; 32], other_sig: [u8; 64] },
}

/// Classifies a `seen` against the reader's own head at the same position (`None` when the reader
/// has not reached `n`).
#[must_use]
pub fn classify_seen(
    host_head_pk: &[u8; 32],
    group_id: &[u8; 32],
    seen: &Seen,
    own_head_at_n: Option<&[u8; 32]>,
) -> SeenVerdict {
    if host_head_verify(host_head_pk, group_id, seen.log_seq, &seen.head, &seen.host_sig).is_err() {
        return SeenVerdict::FlagAuthor;
    }
    match own_head_at_n {
        Some(own) if own != &seen.head => SeenVerdict::Equivocation {
            n: seen.log_seq,
            own_head: *own,
            other_head: seen.head,
            other_sig: seen.host_sig,
        },
        _ => SeenVerdict::Consistent,
    }
}
