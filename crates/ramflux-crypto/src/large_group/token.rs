// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Client side of posting tokens (spec 2.6) and host-side redemption checks.
//! `token = te ‖ input ‖ tag` (68 B); `tag = BLAKE3-keyed(k_bind, H(header without token ‖ mls bytes))`,
//! `k_bind = BLAKE3-derive_key("rf-lg-token-bind-v1", output)`. A token is issued for one of three
//! buckets (`post`, `commit`, `open`); the bucket is part of the POPRF `info`.

use subtle::ConstantTimeEq;
use voprf::{EvaluationElement, PoprfClient, Proof, Ristretto255};
use zeroize::Zeroizing;

use super::LgError;
use super::ids::{BATCH_SIZE, token_info};
use super::poprf_host::{LgTokenRootKey, decompress_public};
use super::rng::FallibleOsRng;

/// Wire size of a token.
pub const TOKEN_LEN: usize = 68;
/// Spent-set key size `BLAKE3(te ‖ input)[..16]`.
pub const SPENT_KEY_LEN: usize = 16;
const BIND_CONTEXT: &str = "rf-lg-token-bind-v1";
/// Tokens a commit spends (spec 2.6).
pub const COMMIT_TOKEN_COST: u32 = 4;

/// Token bucket (spec 2.6): what a token may be spent on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenBucket {
    /// Posts and tombstones.
    Post,
    /// Commits (4 tokens), proposals, state, join requests, member invite ops, their blobs.
    Commit,
    /// One member session open.
    Open,
}

/// Daily token quota of one bucket per device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketQuota {
    pub per_day: u32,
    pub first_day: u32,
}

impl TokenBucket {
    /// Wire code (also the `info` byte).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Post => 1,
            Self::Commit => 2,
            Self::Open => 3,
        }
    }

    /// # Errors
    /// Refuses an unknown code.
    pub fn from_code(code: u8) -> Result<Self, LgError> {
        match code {
            1 => Ok(Self::Post),
            2 => Ok(Self::Commit),
            3 => Ok(Self::Open),
            _ => Err(LgError::Format("token bucket")),
        }
    }

    /// Quota per `P` per 24 h. `post` 500 (20 on the first day) and `commit` 96 (16) are decided;
    /// the `open` quota is a configuration value from TBD-MEAS-8 (`2 × p95` phone reconnects),
    /// first day a third of it, rounded up.
    #[must_use]
    pub const fn quota(self, open_per_day: u32) -> BucketQuota {
        match self {
            Self::Post => BucketQuota { per_day: 500, first_day: 20 },
            Self::Commit => BucketQuota { per_day: 96, first_day: 16 },
            Self::Open => {
                BucketQuota { per_day: open_per_day, first_day: open_per_day.div_ceil(3) }
            }
        }
    }
}

/// A redeemable token bound to one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub te: u32,
    pub input: [u8; 32],
    pub tag: [u8; 32],
}

impl Token {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; TOKEN_LEN] {
        let mut out = [0_u8; TOKEN_LEN];
        let (te, rest) = out.split_at_mut(4);
        te.copy_from_slice(&self.te.to_be_bytes());
        let (input, tag) = rest.split_at_mut(32);
        input.copy_from_slice(&self.input);
        tag.copy_from_slice(&self.tag);
        out
    }

    /// # Errors
    /// Refuses any length other than 68.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LgError> {
        let array: [u8; TOKEN_LEN] =
            bytes.try_into().map_err(|_| LgError::Format("token length"))?;
        let (te, rest) = array.split_at(4);
        let (input, tag) = rest.split_at(32);
        Ok(Self {
            te: u32::from_be_bytes(te.try_into().map_err(|_| LgError::Format("token epoch"))?),
            input: input.try_into().map_err(|_| LgError::Format("token input"))?,
            tag: tag.try_into().map_err(|_| LgError::Format("token tag"))?,
        })
    }
}

/// A finalized token whose raw output never leaves the client.
pub struct TokenSecret {
    pub te: u32,
    bucket: TokenBucket,
    input: [u8; 32],
    output: Zeroizing<[u8; 64]>,
}

impl TokenSecret {
    /// The bucket this token may be spent in.
    #[must_use]
    pub const fn bucket(&self) -> TokenBucket {
        self.bucket
    }

    /// Client-state export `(te, bucket, input, output)` for the encrypted account checkpoint.
    #[must_use]
    pub fn to_parts(&self) -> (u32, TokenBucket, [u8; 32], [u8; 64]) {
        (self.te, self.bucket, self.input, *self.output)
    }

    /// Restores a token from [`Self::to_parts`].
    #[must_use]
    pub fn from_parts(te: u32, bucket: TokenBucket, input: [u8; 32], output: [u8; 64]) -> Self {
        Self { te, bucket, input, output: Zeroizing::new(output) }
    }

    /// Binds the token to the entry hash (`H(header without token ‖ mls bytes)`).
    #[must_use]
    pub fn bind(&self, entry_hash: &[u8; 32]) -> Token {
        Token { te: self.te, input: self.input, tag: bind_tag(&self.output, entry_hash) }
    }
}

fn bind_tag(output: &[u8; 64], entry_hash: &[u8; 32]) -> [u8; 32] {
    let k_bind = Zeroizing::new(blake3::derive_key(BIND_CONTEXT, output));
    *blake3::keyed_hash(&k_bind, entry_hash).as_bytes()
}

/// `BLAKE3(te ‖ input)[..16]`.
#[must_use]
pub fn spent_key(te: u32, input: &[u8; 32]) -> [u8; SPENT_KEY_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&te.to_be_bytes());
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = [0_u8; SPENT_KEY_LEN];
    for (dst, src) in out.iter_mut().zip(digest.as_bytes().iter()) {
        *dst = *src;
    }
    out
}

/// Host redemption check: recompute `output = evaluate(input, info(te))`, recompute the binding
/// tag, compare in constant time. Returns the spent-set key; the caller inserts it in the same
/// transaction as the log append.
///
/// # Errors
/// Refuses a wrong tag (token moved onto another entry) or a POPRF failure.
pub fn verify_token_binding(
    root: &LgTokenRootKey,
    group_id: &[u8; 32],
    bucket: TokenBucket,
    token: &Token,
    entry_hash: &[u8; 32],
) -> Result<[u8; SPENT_KEY_LEN], LgError> {
    let info = token_info(group_id, token.te, bucket);
    let output = Zeroizing::new(root.evaluate(&token.input, &info)?);
    let expected = bind_tag(&output, entry_hash);
    if bool::from(expected.ct_eq(&token.tag)) {
        Ok(spent_key(token.te, &token.input))
    } else {
        Err(LgError::Verify("token binding tag"))
    }
}

/// Client state of one issuance request: blinding states, inputs and the 20 blinded elements.
pub struct TokenBatchRequest {
    bucket: TokenBucket,
    clients: Vec<PoprfClient<Ristretto255>>,
    inputs: Vec<[u8; 32]>,
    pub blinded: Vec<[u8; 32]>,
}

/// Blinds a full batch of 20 fresh random inputs for `bucket`.
///
/// # Errors
/// Returns a typed error when randomness or blinding fails.
pub fn begin_token_batch(bucket: TokenBucket) -> Result<TokenBatchRequest, LgError> {
    begin_token_batch_sized(bucket, BATCH_SIZE)
}

/// Blinds a batch of `count` (1 to 20) fresh random inputs for `bucket`. A batch never exceeds the
/// remaining daily quota of its bucket (first-day commit quota 16: one batch of 16), so the client
/// asks for fewer than 20 when the quota left is smaller.
///
/// # Errors
/// Refuses a `count` outside 1 to 20; returns a typed error when randomness or blinding fails.
pub fn begin_token_batch_sized(
    bucket: TokenBucket,
    count: usize,
) -> Result<TokenBatchRequest, LgError> {
    if count == 0 || count > BATCH_SIZE {
        return Err(LgError::Format("batch size"));
    }
    let mut clients = Vec::with_capacity(count);
    let mut inputs = Vec::with_capacity(count);
    let mut blinded = Vec::with_capacity(count);
    for _ in 0..count {
        let input = super::random_array::<32>()?;
        let mut rng = FallibleOsRng;
        let result = PoprfClient::<Ristretto255>::blind(&input, &mut rng)
            .map_err(|_| LgError::Poprf("blind"))?;
        let message: [u8; 32] = result
            .message
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| LgError::Format("blinded length"))?;
        clients.push(result.state);
        inputs.push(input);
        blinded.push(message);
    }
    Ok(TokenBatchRequest { bucket, clients, inputs, blinded })
}

/// Verifies the batched DLEQ proof against the attested `pkS` and `info(te, bucket)` and returns the
/// finalized tokens (audit L2: the attested `pkS` goes to `batch_finalize`, never a tweaked key).
///
/// # Errors
/// A proof or element failure discards the whole batch (`VerifyError`, warn).
pub fn finish_token_batch(
    request: &TokenBatchRequest,
    evaluated: &[[u8; 32]],
    proof: &[u8; 64],
    pk_s: &[u8; 32],
    group_id: &[u8; 32],
    te: u32,
) -> Result<Vec<TokenSecret>, LgError> {
    if evaluated.len() != request.clients.len() {
        return Err(LgError::Verify("batch size"));
    }
    let mut messages = Vec::with_capacity(evaluated.len());
    for raw in evaluated {
        messages.push(
            EvaluationElement::<Ristretto255>::deserialize(raw)
                .map_err(|_| LgError::Verify("evaluation element"))?,
        );
    }
    let proof = Proof::<Ristretto255>::deserialize(proof).map_err(|_| LgError::Verify("proof"))?;
    let pk = decompress_public(pk_s)?;
    let info = token_info(group_id, te, request.bucket);
    let finalized = PoprfClient::<Ristretto255>::batch_finalize(
        request.inputs.iter().map(<[u8; 32]>::as_slice),
        &request.clients,
        &messages,
        &proof,
        pk,
        Some(&info),
    )
    .map_err(|_| LgError::Verify("batch proof"))?;
    let mut tokens = Vec::with_capacity(request.inputs.len());
    for (output, input) in finalized.zip(request.inputs.iter()) {
        let output = output.map_err(|_| LgError::Verify("finalize"))?;
        let bytes: [u8; 64] =
            output.as_slice().try_into().map_err(|_| LgError::Format("output length"))?;
        tokens.push(TokenSecret {
            te,
            bucket: request.bucket,
            input: *input,
            output: Zeroizing::new(bytes),
        });
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_batch_issues_and_finishes() {
        let root = LgTokenRootKey::from_seed(&[8; 32]).expect("test: root key");
        let group_id = [4_u8; 32];
        let request = begin_token_batch_sized(TokenBucket::Commit, 16).expect("test: blind 16");
        let info = token_info(&group_id, 0, TokenBucket::Commit);
        let issued = root.issue_batch(&request.blinded, &info).expect("test: issue 16");
        let secrets = finish_token_batch(
            &request,
            &issued.evaluated,
            &issued.proof,
            &root.public_key(),
            &group_id,
            0,
        )
        .expect("test: finish 16");
        assert_eq!(secrets.len(), 16, "a batch of 16 yields 16 tokens");
        assert!(begin_token_batch_sized(TokenBucket::Post, 0).is_err(), "empty batch refused");
        assert!(begin_token_batch_sized(TokenBucket::Post, 21).is_err(), "over 20 refused");
    }

    #[test]
    fn issued_token_redeems_in_its_bucket_only() {
        let root = LgTokenRootKey::from_seed(&[7; 32]).expect("test: root key");
        let group_id = [3_u8; 32];
        let te = 1;
        let request = begin_token_batch(TokenBucket::Post).expect("test: blind batch");
        let info = token_info(&group_id, te, TokenBucket::Post);
        let issued = root.issue_batch(&request.blinded, &info).expect("test: issue batch");
        let secrets = finish_token_batch(
            &request,
            &issued.evaluated,
            &issued.proof,
            &root.public_key(),
            &group_id,
            te,
        )
        .expect("test: finish batch");
        assert_eq!(secrets.len(), BATCH_SIZE, "one batch holds {BATCH_SIZE} tokens");
        let entry_hash = [9_u8; 32];
        let token = secrets.first().expect("test: first token").bind(&entry_hash);
        verify_token_binding(&root, &group_id, TokenBucket::Post, &token, &entry_hash)
            .expect("test: token redeems in its bucket");
        assert!(
            verify_token_binding(&root, &group_id, TokenBucket::Commit, &token, &entry_hash)
                .is_err(),
            "a post token must not redeem in the commit bucket"
        );
        assert!(
            verify_token_binding(&root, &group_id, TokenBucket::Post, &token, &[1; 32]).is_err(),
            "a token must not move onto another entry"
        );
    }
}
