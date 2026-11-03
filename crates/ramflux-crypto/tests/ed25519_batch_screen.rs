// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use curve25519_dalek::{constants::EIGHT_TORSION, scalar::Scalar};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, verify_batch};
use ramflux_crypto::{
    CanonicalSignatureBatchItem, CanonicalSignatureSingleKeyBatchItem, verify_canonical_signature,
    verify_canonical_signatures_batch, verify_canonical_signatures_batch_single_key,
};
use ramflux_protocol::encode_base64url;
use sha2::{Digest, Sha512};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signature(r: [u8; 32], s: Scalar) -> [u8; 64] {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&r);
    bytes[32..].copy_from_slice(&s.to_bytes());
    bytes
}

fn challenge(r: &[u8; 32], a: &[u8; 32], message: &[u8]) -> Scalar {
    let hash = Sha512::new().chain_update(r).chain_update(a).chain_update(message).finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

fn identity() -> [u8; 32] {
    EIGHT_TORSION[0].compress().to_bytes()
}

fn raw_accepts(key: &[u8; 32], messages: &[&[u8]], signatures: &[[u8; 64]]) -> TestResult<bool> {
    let key = VerifyingKey::from_bytes(key)?;
    let signatures = signatures.iter().map(Signature::from_bytes).collect::<Vec<_>>();
    Ok(verify_batch(messages, &signatures, &vec![key; messages.len()]).is_ok())
}

fn assert_wrappers(
    key: &[u8; 32],
    messages: &[&[u8]],
    signatures: &[[u8; 64]],
    failures: &[usize],
) {
    let single = messages
        .iter()
        .zip(signatures)
        .map(|(canonical, signature_bytes)| CanonicalSignatureSingleKeyBatchItem {
            canonical,
            signature_bytes,
        })
        .collect::<Vec<_>>();
    let multi = messages
        .iter()
        .zip(signatures)
        .map(|(canonical, signature_bytes)| CanonicalSignatureBatchItem {
            public_key_bytes: key,
            canonical,
            signature_bytes,
        })
        .collect::<Vec<_>>();
    let expected = if failures.is_empty() { Ok(()) } else { Err(failures.to_vec()) };
    assert_eq!(
        verify_canonical_signatures_batch_single_key(key, &single),
        expected,
        "single-key strict indices"
    );
    assert_eq!(verify_canonical_signatures_batch(&multi), expected, "multi-key strict indices");
}

#[test]
fn batch_wrappers_reject_identity_key_identity_r_zero_s_forgery() -> TestResult {
    let key = identity();
    let forged = signature(identity(), Scalar::ZERO);
    let message = b"ramflux-batch-weak-key-probe";
    assert!(raw_accepts(&key, &[message], &[forged])?);
    assert!(
        verify_canonical_signature(message, &encode_base64url(forged), &encode_base64url(key))
            .is_err()
    );
    // RFC 8032 section 7.1 TEST 1, 2 and 3 (frozen bytes, not generated signatures).
    let publics = [
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    ]
    .map(|v| hex::decode(v).map(|v| v.try_into().map_err(|_| "key length")))
    .into_iter()
    .collect::<Result<Result<Vec<[u8; 32]>, _>, _>>()??;
    let signatures = [
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ].map(|v| hex::decode(v).map(|v| v.try_into().map_err(|_| "signature length"))).into_iter()
        .collect::<Result<Result<Vec<[u8; 64]>, _>, _>>()??;
    let items = [
        CanonicalSignatureBatchItem {
            public_key_bytes: &publics[0],
            canonical: b"",
            signature_bytes: &signatures[0],
        },
        CanonicalSignatureBatchItem {
            public_key_bytes: &publics[1],
            canonical: &[0x72],
            signature_bytes: &signatures[1],
        },
        CanonicalSignatureBatchItem {
            public_key_bytes: &key,
            canonical: message,
            signature_bytes: &forged,
        },
        CanonicalSignatureBatchItem {
            public_key_bytes: &publics[2],
            canonical: &[0xaf, 0x82],
            signature_bytes: &signatures[2],
        },
    ];
    assert_eq!(
        verify_canonical_signatures_batch(&items),
        Err(vec![2]),
        "mixed RFC/identity multi-key indices"
    );
    assert_wrappers(&key, &[message.as_slice(); 4], &[forged; 4], &[0, 1, 2, 3]);
    Ok(())
}

#[test]
fn batch_wrappers_reject_every_small_order_public_key() -> TestResult {
    let forged = signature(identity(), Scalar::ZERO);
    for point in EIGHT_TORSION {
        let key = point.compress().to_bytes();
        let mut found = false;
        for counter in 0..4096_u32 {
            let message = format!("ramflux-small-order-key-{counter}");
            let messages = [message.as_bytes(); 2];
            if raw_accepts(&key, &messages, &[forged; 2])? {
                assert!(
                    VerifyingKey::from_bytes(&key)?
                        .verify_strict(message.as_bytes(), &Signature::from_bytes(&forged))
                        .is_err()
                );
                assert_wrappers(&key, &messages, &[forged; 2], &[0, 1]);
                found = true;
                break;
            }
        }
        assert!(found, "no raw-batch witness in 4096 tries for {key:?}");
    }
    Ok(())
}

#[test]
fn single_key_batch_rejects_small_order_r_under_an_honest_key() -> TestResult {
    holder_crafted_r_probe(false)
}

#[test]
fn wrappers_reject_mixed_order_r_under_torsion_free_key() -> TestResult {
    holder_crafted_r_probe(true)
}

fn holder_crafted_r_probe(mixed: bool) -> TestResult {
    let signing = SigningKey::from_bytes(&[0x5a; 32]);
    let key = signing.verifying_key().to_bytes();
    assert!(signing.verifying_key().to_edwards().is_torsion_free());
    let r = if mixed { Scalar::from(42_u64) } else { Scalar::ZERO };
    let point =
        (curve25519_dalek::EdwardsPoint::mul_base(&r) + EIGHT_TORSION[1]).compress().to_bytes();
    let honest_message = b"honest-neighbor";
    let honest = signing.sign(honest_message).to_bytes();
    for counter in 0..4096_u32 {
        let message = format!("ramflux-holder-r-{mixed}-{counter}");
        let forged =
            signature(point, r + challenge(&point, &key, message.as_bytes()) * signing.to_scalar());
        let messages = [honest_message.as_slice(), message.as_bytes()];
        let signatures = [honest, forged];
        if signing
            .verifying_key()
            .verify_strict(message.as_bytes(), &Signature::from_bytes(&forged))
            .is_err()
            && raw_accepts(&key, &messages, &signatures)?
        {
            // The raw equation and both wrappers see exactly the same multi-item batch.
            assert_wrappers(&key, &messages, &signatures, &[1]);
            return Ok(());
        }
    }
    Err("no holder-crafted R witness in 4096 tries".into())
}

#[test]
fn single_key_batch_routes_a_mixed_order_key_to_strict() -> TestResult {
    let signing = SigningKey::from_bytes(&[0x5a; 32]);
    let key = (signing.verifying_key().to_edwards() + EIGHT_TORSION[1]).compress().to_bytes();
    let verifying = VerifyingKey::from_bytes(&key)?;
    assert!(!verifying.is_weak());
    assert!(!verifying.to_edwards().is_torsion_free());
    let r = Scalar::from(42_u64);
    let point = curve25519_dalek::EdwardsPoint::mul_base(&r).compress().to_bytes();
    for counter in 0..4096_u32 {
        let message = format!("ramflux-mixed-key-{counter}");
        let k = challenge(&point, &key, message.as_bytes());
        if k.to_bytes()[0] & 7 == 0 {
            continue;
        }
        let forged = signature(point, r + k * signing.to_scalar());
        if verifying.verify_strict(message.as_bytes(), &Signature::from_bytes(&forged)).is_err()
            && raw_accepts(&key, &[message.as_bytes(); 2], &[forged; 2])?
        {
            assert_wrappers(&key, &[message.as_bytes(); 2], &[forged; 2], &[0, 1]);
            return Ok(());
        }
    }
    Err("no mixed-order key witness in 4096 tries".into())
}

#[test]
fn wrappers_reject_identity_r_under_nonweak_key() -> TestResult {
    let signing = SigningKey::from_bytes(&[0x5a; 32]);
    let key = signing.verifying_key();
    assert!(!key.is_weak());
    let message = b"ramflux-identity-r";
    let forged = signature(
        identity(),
        challenge(&identity(), &key.to_bytes(), message) * signing.to_scalar(),
    );
    key.verify(message, &Signature::from_bytes(&forged))?;
    assert!(key.verify_strict(message, &Signature::from_bytes(&forged)).is_err());
    assert_wrappers(&key.to_bytes(), &[message.as_slice(); 2], &[forged; 2], &[0, 1]);
    Ok(())
}

#[test]
fn single_item_batch_is_strict() {
    let forged = signature(identity(), Scalar::ZERO);
    assert_wrappers(&identity(), &[b"ramflux-batch-weak-key-probe"], &[forged], &[0]);
    let signing = SigningKey::from_bytes(&[0x5a; 32]);
    let message = b"honest-single-item";
    assert_wrappers(
        &signing.verifying_key().to_bytes(),
        &[message],
        &[signing.sign(message).to_bytes()],
        &[],
    );
}
