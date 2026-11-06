// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::hkdf;
use super::{NativeHkdfError, native_hkdf};
use serde_json::Value;
use std::{cell::RefCell, collections::BTreeMap};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
enum State {
    Bytes(Vec<u8>),
    Words(Vec<u32>),
    Meta(u64, usize),
}
struct Observation {
    slot: &'static str,
    state: State,
}
thread_local! { static OBSERVATIONS:RefCell<Option<Vec<Observation>>>=const {RefCell::new(None)}; }
pub(super) fn observe_bytes(slot: &'static str, bytes: &[u8]) {
    OBSERVATIONS.with(|events| {
        if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Observation { slot, state: State::Bytes(bytes.to_vec()) });
        }
    });
}
pub(super) fn observe_words(slot: &'static str, words: &[u32]) {
    OBSERVATIONS.with(|events| {
        if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Observation { slot, state: State::Words(words.to_vec()) });
        }
    });
}
pub(super) fn observe_meta(total: u64, used: usize) {
    OBSERVATIONS.with(|events| {
        if let Some(events) = events.borrow_mut().as_mut() {
            events.push(Observation { slot: "sha_meta", state: State::Meta(total, used) });
        }
    });
}
fn capture(run: impl FnOnce() -> Result) -> Result<Vec<Observation>> {
    struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            OBSERVATIONS.with(|events| {
                events.replace(None);
            });
        }
    }
    OBSERVATIONS.with(|events| {
        assert!(events.borrow().is_none());
        events.replace(Some(Vec::new()));
    });
    let scope = Scope;
    run()?;
    let observations = OBSERVATIONS.with(RefCell::take).ok_or("observer missing")?;
    drop(scope);
    Ok(observations)
}
// Independent inventory from the SHA/HMAC wire lengths, not production counters.
fn expected(ikm: usize, salt: usize, info: usize, steps: usize) -> BTreeMap<&'static str, usize> {
    let hmacs = 1 + steps;
    let normalized = usize::from(salt > 64);
    let shas = 2 * hmacs + normalized;
    let padded = |n: usize| (n + 9).div_ceil(64);
    let mut compressed = padded(64 + ikm) + padded(96);
    if salt > 64 {
        compressed += padded(salt);
    }
    for block in 0..steps {
        compressed += padded(64 + if block == 0 { 0 } else { 32 } + info + 1) + padded(96);
    }
    let mut map = BTreeMap::from([
        ("normalized_key", hmacs),
        ("hmac_key", hmacs),
        ("ipad", hmacs),
        ("opad", hmacs),
        ("inner_digest", hmacs),
        ("inner_state", hmacs),
        ("outer_state", hmacs),
        ("sha_final", shas),
        ("sha_meta", shas),
        ("sha_block", compressed + shas),
        ("sha_schedule", compressed + shas),
        ("sha_work", compressed + shas),
        ("sha_round", compressed + shas),
        ("prk", 1),
        ("previous", 1),
        ("output", 1),
    ]);
    if normalized > 0 {
        map.insert("normalize_state", normalized);
    }
    if steps > 0 {
        map.insert("current_block", steps);
        map.insert("previous_replaced", steps);
    }
    map
}
fn assert_erased(events: Vec<Observation>, expected: &BTreeMap<&'static str, usize>) {
    let mut observed = BTreeMap::new();
    for event in events {
        let zero = match event.state {
            State::Bytes(bytes) => bytes.iter().all(|b| *b == 0),
            State::Words(words) => words.iter().all(|w| *w == 0),
            State::Meta(total, used) => total == 0 && used == 0,
        };
        assert!(zero, "owned secret slot was not wiped: {}", event.slot);
        *observed.entry(event.slot).or_insert(0) += 1;
    }
    assert_eq!(&observed, expected, "missing or extra cleanup observations");
}
fn fixture_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(value.as_str().ok_or("hex")?)?)
}
#[test]
fn dm_fs_v3_hkdf_secret_cleanup_every_exit() -> Result {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../ramflux-protocol/fixtures/dm_fs_v3/crypto_vectors.json"
    ))?;
    let kat = &vectors["known_answers"]["hkdf"];
    let ikm = fixture_bytes(&kat["ikm"])?;
    let salt = fixture_bytes(&kat["salt"])?;
    let info = fixture_bytes(&kat["info"])?;
    let golden = fixture_bytes(&kat["output"])?;
    let events = capture(|| {
        let output = native_hkdf::<42>(&ikm, &salt, &info)?;
        assert!(output.as_ref() == golden, "RFC5869 A.1 mismatch");
        drop(output);
        Ok(())
    })?;
    assert_erased(events, &expected(ikm.len(), salt.len(), info.len(), 2));
    // Error after extract, after one block and after replacing a previous block.
    for steps in [0, 1, 2] {
        let events = capture(|| {
            assert!(matches!(
                hkdf::exercise::<42>(&ikm, &salt, &info, steps),
                Err(NativeHkdfError::Injected)
            ));
            Ok(())
        })?;
        assert_erased(events, &expected(ikm.len(), salt.len(), info.len(), steps));
    }
    // The scoped owner contains a live PRK, previous block and partial output.
    let events = capture(|| {
        hkdf::scoped_drop::<42>(&ikm, &salt, &info)?;
        Ok(())
    })?;
    assert_erased(events, &expected(ikm.len(), salt.len(), info.len(), 1));
    // RFC5869 A.2: long salt exercises HMAC key normalization and extra SHA blocks.
    let ikm: Vec<u8> = (0..80).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    let golden = hex::decode(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    )?;
    let events = capture(|| {
        let output = native_hkdf::<82>(&ikm, &salt, &info)?;
        assert!(output.as_ref() == golden, "RFC5869 A.2 mismatch");
        drop(output);
        Ok(())
    })?;
    assert_erased(events, &expected(80, 80, 80, 3));
    for vector in vectors["bootstrap"].as_array().ok_or("bootstrap")? {
        let v = &vector["kdf"];
        let ikm = fixture_bytes(&v["ikm"])?;
        let salt = fixture_bytes(&v["salt"])?;
        let info = fixture_bytes(&v["info"])?;
        let prk = fixture_bytes(&v["prk"])?;
        let golden = fixture_bytes(&v["output"])?;
        let events = capture(|| {
            let output = native_hkdf::<32>(&ikm, &salt, &info)?;
            assert!(output.as_ref() == golden, "P01 HKDF mismatch");
            drop(output);
            Ok(())
        })?;
        assert_erased(events, &expected(ikm.len(), salt.len(), info.len(), 1));
        let blocks: Vec<[u8; 32]> = v["blocks"]
            .as_array()
            .ok_or("blocks")?
            .iter()
            .map(|value| fixture_bytes(value)?.try_into().map_err(|_| "block width".into()))
            .collect::<Result<_>>()?;
        assert!(
            hkdf::test_intermediates::<32>(&ikm, &salt, &info, &prk, &blocks, &golden)?,
            "P01 extract/expand mismatch"
        );
    }
    Ok(())
}
#[test]
fn dm_fs_v3_hkdf_padding_and_output_bounds() -> Result {
    use sha2::{Digest, Sha256};
    for length in [0, 1, 55, 56, 63, 64, 65, 112, 127, 128, 129] {
        let data = vec![0xa5; length];
        let expected = Sha256::digest(&data);
        let actual = hkdf::test_sha(&data)?;
        assert!(actual.as_ref() == &expected[..], "SHA256 boundary mismatch at {length}");
    }
    assert!(matches!(
        native_hkdf::<0>(b"input", b"salt", b"info"),
        Err(NativeHkdfError::OutputLength)
    ));
    assert!(matches!(
        native_hkdf::<8161>(b"input", b"salt", b"info"),
        Err(NativeHkdfError::OutputLength)
    ));
    let maximum = native_hkdf::<8160>(b"input", b"salt", b"info")?;
    assert_eq!(maximum.as_ref().len(), 8160);
    drop(maximum);
    Ok(())
}

// RFC 4231 sections 4.2-4.8; TC5 specifies a 128-bit truncated tag.
#[test]
fn dm_fs_v3_hkdf_rfc4231_and_empty_salt_kats() -> Result {
    let cases = [
        (vec![0x0b;20], b"Hi There".to_vec(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (vec![0xaa;20],vec![0xdd;50],"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        ((1..=25).collect::<Vec<u8>>(),vec![0xcd;50],"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (vec![0x0c;20],b"Test With Truncation".to_vec(),"a3b6167473100ee06e0c796c2955552b"),
        (vec![0xaa;131],b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (vec![0xaa;131],b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    ];
    for (index, (key, data, golden)) in cases.into_iter().enumerate() {
        let split = data.len() / 2;
        let actual = hkdf::test_hmac(&key, &[&data[..split], &data[split..]])?;
        let expected = hex::decode(golden)?;
        assert!(actual.as_ref()[..expected.len()] == expected, "RFC4231 TC{} mismatch", index + 1);
    }
    let expected = hex::decode(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    )?;
    let prk = hex::decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")?;
    let actual = native_hkdf::<42>(&[0x0b; 22], &[], &[])?;
    assert!(actual.as_ref() == expected, "RFC5869 A.3 mismatch");
    // Explicit independent extract check for the empty-key case.
    let extracted = hkdf::test_hmac(&[], &[&[0x0b; 22]])?;
    assert!(extracted.as_ref() == prk, "RFC5869 A.3 PRK mismatch");
    Ok(())
}
fn seeded_next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
fn seeded_bytes(state: &mut u64, length: usize) -> Vec<u8> {
    (0..length).map(|_| seeded_next(state).to_le_bytes()[0]).collect()
}
fn compare_hkdf<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result {
    let expected = ::hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut reference = vec![0; N];
    expected.expand(info, &mut reference)?;
    let actual = native_hkdf::<N>(ikm, salt, info)?;
    assert!(actual.as_ref() == reference, "seeded HKDF mismatch at L={N}");
    Ok(())
}
#[test]
fn dm_fs_v3_hkdf_seeded_differential_primitives() -> Result {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    let mut seed = 0x7a02_5a17_d1ff_4231u64;
    let boundaries = [0, 1, 55, 56, 63, 64, 119, 120, 127, 128, 129, 300];
    let keys = [0, 1, 20, 32, 63, 64, 65, 119, 120, 131, 300];
    for case in 0..48 {
        let random_length = usize::try_from(seeded_next(&mut seed) % 301)?;
        let length = boundaries.get(case).copied().unwrap_or(random_length);
        let data = seeded_bytes(&mut seed, length);
        let expected = Sha256::digest(&data);
        let actual = hkdf::test_sha(&data)?;
        assert!(actual.as_ref() == &expected[..], "seeded SHA mismatch at {length}");
        let random_key = usize::try_from(seeded_next(&mut seed) % 301)?;
        let key = seeded_bytes(&mut seed, keys.get(case).copied().unwrap_or(random_key));
        let split = usize::try_from(seeded_next(&mut seed))? % (data.len() + 1);
        let mut expected = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)?;
        expected.update(&data[..split]);
        expected.update(&data[split..]);
        let expected = expected.finalize().into_bytes();
        let actual = hkdf::test_hmac(&key, &[&data[..split], &data[split..]])?;
        assert!(
            actual.as_ref() == &expected[..],
            "seeded HMAC mismatch at key length {}",
            key.len()
        );
    }
    for case in 0..16 {
        let ikm_length = usize::try_from(seeded_next(&mut seed) % 301)?;
        let salt_length =
            if case % 3 == 0 { 0 } else { usize::try_from(seeded_next(&mut seed) % 301)? };
        let info_length =
            if case % 4 == 0 { 0 } else { usize::try_from(seeded_next(&mut seed) % 301)? };
        let ikm = seeded_bytes(&mut seed, ikm_length);
        let salt = seeded_bytes(&mut seed, salt_length);
        let info = seeded_bytes(&mut seed, info_length);
        compare_hkdf::<1>(&ikm, &salt, &info)?;
        compare_hkdf::<31>(&ikm, &salt, &info)?;
        compare_hkdf::<32>(&ikm, &salt, &info)?;
        compare_hkdf::<33>(&ikm, &salt, &info)?;
        compare_hkdf::<64>(&ikm, &salt, &info)?;
        compare_hkdf::<65>(&ikm, &salt, &info)?;
        compare_hkdf::<255>(&ikm, &salt, &info)?;
        compare_hkdf::<8160>(&ikm, &salt, &info)?;
    }
    Ok(())
}

/// Reuse the actual-state HKDF observer for both native bootstrap callers.
pub(super) fn native_cleanup_contract(
    ikm: usize,
    info: usize,
    steps: usize,
    run: impl FnOnce() -> Result,
) -> Result {
    let events = capture(run)?;
    assert_erased(events, &expected(ikm, 32, info, steps));
    Ok(())
}
