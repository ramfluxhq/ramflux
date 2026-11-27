// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The only file that names `PoprfServer` (design section 2.7). The newtype implements neither
//! `Debug`, `Display` nor `Clone`, so a `{:?}` on a root key fails to compile. Host calls are
//! limited to `new`, `batch_blind_evaluate_prepare`, `batch_blind_evaluate_finish` and `evaluate`;
//! the RNG-unwrapping `blind_evaluate` / `batch_blind_evaluate` are never used (audit M1).

use curve25519_dalek::ristretto::CompressedRistretto;
use voprf::{BlindedElement, PoprfServer, PreparedEvaluationElement, Ristretto255};

use super::LgError;
use super::rng::{FallibleOsRng, SeedRng};

/// POPRF root key `skS` of one large group (not `Clone`, no `Debug`/`Display`).
pub struct LgTokenRootKey {
    server: PoprfServer<Ristretto255>,
}

/// One issuance reply: 20 evaluation elements and the batched DLEQ proof.
pub struct IssuedBatch {
    pub evaluated: Vec<[u8; 32]>,
    pub proof: [u8; 64],
}

fn map_error(error: &voprf::Error, context: &'static str) -> LgError {
    if matches!(error, voprf::Error::Protocol) {
        LgError::PoprfProtocol
    } else {
        LgError::Poprf(context)
    }
}

fn to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], LgError> {
    bytes.try_into().map_err(|_| LgError::Format("poprf element length"))
}

impl LgTokenRootKey {
    /// Derives the root key from the 32-byte seed stored in the group key file, through the
    /// allowed `PoprfServer::new` call (it fills exactly one scalar length from the RNG).
    ///
    /// # Errors
    /// `Error::Protocol` maps to [`LgError::PoprfProtocol`].
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, LgError> {
        let mut rng = SeedRng::new(seed);
        let server =
            PoprfServer::<Ristretto255>::new(&mut rng).map_err(|e| map_error(&e, "new"))?;
        Ok(Self { server })
    }

    /// RFC 9497 DeriveKeyPair with an explicit `info` (known-answer check only).
    ///
    /// # Errors
    /// Returns a typed POPRF error.
    pub(crate) fn kat_from_seed(seed: &[u8], key_info: &[u8]) -> Result<Self, LgError> {
        let server = PoprfServer::<Ristretto255>::new_from_seed(seed, key_info)
            .map_err(|e| map_error(&e, "derive key pair"))?;
        Ok(Self { server })
    }

    /// Compressed `pkS`.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.server.get_public_key().compress().to_bytes()
    }

    /// Issues one batch with `batch_blind_evaluate_prepare` + `_finish` (one DLEQ proof).
    ///
    /// # Errors
    /// `Error::Protocol` from `prepare` maps to [`LgError::PoprfProtocol`] (the rotation path,
    /// audit L2); a malformed element or an RNG failure is a typed refusal.
    pub fn issue_batch(&self, blinded: &[[u8; 32]], info: &[u8]) -> Result<IssuedBatch, LgError> {
        let mut elements = Vec::with_capacity(blinded.len());
        for raw in blinded {
            elements.push(
                BlindedElement::<Ristretto255>::deserialize(raw)
                    .map_err(|e| map_error(&e, "blinded element"))?,
            );
        }
        let prepared = self
            .server
            .batch_blind_evaluate_prepare(elements.iter(), Some(info))
            .map_err(|e| map_error(&e, "prepare"))?;
        let tweak = prepared.prepared_tweak;
        let evaluations: Vec<PreparedEvaluationElement<Ristretto255>> =
            prepared.prepared_evaluation_elements.collect();
        let mut rng = FallibleOsRng;
        let finished = PoprfServer::<Ristretto255>::batch_blind_evaluate_finish(
            &mut rng,
            elements.iter(),
            &evaluations,
            &tweak,
        )
        .map_err(|e| map_error(&e, "finish"))?;
        let mut evaluated = Vec::with_capacity(elements.len());
        for message in finished.messages {
            evaluated.push(to_array::<32>(message.serialize().as_slice())?);
        }
        let proof = to_array::<64>(finished.proof.serialize().as_slice())?;
        Ok(IssuedBatch { evaluated, proof })
    }

    /// Server-side `Evaluate(input, info)`: the 64-byte token output used at redemption.
    ///
    /// # Errors
    /// Returns a typed POPRF error.
    pub fn evaluate(&self, input: &[u8], info: &[u8]) -> Result<[u8; 64], LgError> {
        let output =
            self.server.evaluate(input, Some(info)).map_err(|e| map_error(&e, "evaluate"))?;
        to_array::<64>(output.as_slice())
    }
}

/// Decompresses an attested `pkS`, refusing the identity element.
pub(crate) fn decompress_public(
    bytes: &[u8; 32],
) -> Result<curve25519_dalek::ristretto::RistrettoPoint, LgError> {
    let point = CompressedRistretto(*bytes)
        .decompress()
        .ok_or(LgError::Format("pkS is not a ristretto point"))?;
    if point == <curve25519_dalek::ristretto::RistrettoPoint as curve25519_dalek::traits::Identity>::identity() {
        return Err(LgError::Format("pkS is the identity"));
    }
    Ok(point)
}
