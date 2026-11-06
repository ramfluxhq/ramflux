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
    assert_eq!(maximum.len(), 8160);
    drop(maximum);
    Ok(())
}
