// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! RFC 9497 Appendix A.1.3 (ristretto255-SHA512, POPRF mode) known-answer check, driven by the
//! hidden `rf debug kat poprf` command. The crate cannot take a fixed blind without its `danger`
//! feature (never enabled), so the check runs the full client/server round trip with a random
//! blind: the key derived from the RFC seed must match `pkSm`, and the finalized and
//! server-evaluated outputs must equal the RFC `Output` values (the output does not depend on the
//! blind).

use curve25519_dalek::ristretto::CompressedRistretto;
use voprf::{EvaluationElement, PoprfClient, Proof, Ristretto255};

use super::LgError;
use super::poprf_host::LgTokenRootKey;
use super::rng::FallibleOsRng;

const KEY_INFO_HEX: &str = "74657374206b6579";
const PK_HEX: &str = "c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631";
const INFO_HEX: &str = "7465737420696e666f";
const INPUT_1: &str = "00";
const INPUT_2: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const OUTPUT_1: &str = "ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221";
const OUTPUT_2: &str = "7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507";

type KatCase = (&'static str, Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Result of the known-answer check: one line per vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KatReport {
    pub lines: Vec<String>,
    pub all_match: bool,
}

fn hex_vec(value: &str) -> Result<Vec<u8>, LgError> {
    hex::decode(value).map_err(|_| LgError::Format("kat hex"))
}

/// Round trip over `inputs` (batch) with the RFC key; returns the finalized outputs.
fn round_trip(
    root: &LgTokenRootKey,
    inputs: &[Vec<u8>],
    info: &[u8],
) -> Result<Vec<Vec<u8>>, LgError> {
    let mut clients = Vec::with_capacity(inputs.len());
    let mut blinded = Vec::with_capacity(inputs.len());
    for input in inputs {
        let mut rng = FallibleOsRng;
        let result = PoprfClient::<Ristretto255>::blind(input, &mut rng)
            .map_err(|_| LgError::Poprf("kat blind"))?;
        let message: [u8; 32] = result
            .message
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| LgError::Format("kat blinded length"))?;
        clients.push(result.state);
        blinded.push(message);
    }
    let issued = root.issue_batch(&blinded, info)?;
    let mut messages = Vec::with_capacity(issued.evaluated.len());
    for raw in &issued.evaluated {
        messages.push(
            EvaluationElement::<Ristretto255>::deserialize(raw)
                .map_err(|_| LgError::Verify("kat evaluation element"))?,
        );
    }
    let proof = Proof::<Ristretto255>::deserialize(&issued.proof)
        .map_err(|_| LgError::Verify("kat proof"))?;
    let pk =
        CompressedRistretto(root.public_key()).decompress().ok_or(LgError::Format("kat pk"))?;
    let finalized = PoprfClient::<Ristretto255>::batch_finalize(
        inputs.iter().map(Vec::as_slice),
        &clients,
        &messages,
        &proof,
        pk,
        Some(info),
    )
    .map_err(|_| LgError::Verify("kat batch proof"))?;
    let mut outputs = Vec::with_capacity(inputs.len());
    for output in finalized {
        outputs.push(output.map_err(|_| LgError::Verify("kat finalize"))?.as_slice().to_vec());
    }
    Ok(outputs)
}

/// Runs vectors 1 to 3 of RFC 9497 A.1.3.
///
/// # Errors
/// Returns a typed error only when the check itself cannot run; a mismatch is reported in
/// [`KatReport::all_match`].
pub fn kat_poprf() -> Result<KatReport, LgError> {
    let seed = [0xa3_u8; 32];
    let root = LgTokenRootKey::kat_from_seed(&seed, &hex_vec(KEY_INFO_HEX)?)?;
    let info = hex_vec(INFO_HEX)?;
    let mut lines = Vec::new();
    let mut all = true;
    let pk_ok = root.public_key().as_slice() == hex_vec(PK_HEX)?.as_slice();
    lines.push(format!("pkSm {}", if pk_ok { "match" } else { "MISMATCH" }));
    all &= pk_ok;
    let (in1, in2) = (hex_vec(INPUT_1)?, hex_vec(INPUT_2)?);
    let (out1, out2) = (hex_vec(OUTPUT_1)?, hex_vec(OUTPUT_2)?);
    let cases: [KatCase; 3] = [
        ("vector 1", vec![in1.clone()], vec![out1.clone()]),
        ("vector 2", vec![in2.clone()], vec![out2.clone()]),
        ("vector 3", vec![in1, in2], vec![out1, out2]),
    ];
    for (name, inputs, expected) in cases {
        let got = round_trip(&root, &inputs, &info)?;
        let ok = got == expected;
        lines.push(format!("{name} {}", if ok { "match" } else { "MISMATCH" }));
        all &= ok;
    }
    Ok(KatReport { lines, all_match: all })
}
