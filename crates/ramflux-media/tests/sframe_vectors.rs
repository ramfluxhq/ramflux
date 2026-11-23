// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

// Moved tests keep their original numeric casts and assertions.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

//! `SFrame` against the RFC 9605 test vectors (Appendix C.1 headers, C.3
//! encryption for the two GCM suites), and its refusals.

use ramflux_media::sframe::{
    AES_128_GCM_SHA256_128, AES_256_GCM_SHA512_128, Header, Receiver, Sender, SframeError, suite,
};

fn hex(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("hex"))
        .collect()
}

fn number(text: &str) -> u64 {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).expect("number")
}

#[test]
fn every_header_vector_encodes_and_decodes() {
    let vectors = include_str!("vectors/rfc9605_c1_headers.txt");
    let mut count = 0;
    for line in vectors.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let mut parts = line.split(' ');
        let (kid, ctr) = (number(parts.next().unwrap()), number(parts.next().unwrap()));
        let encoded = hex(parts.next().unwrap());
        let header = Header { kid, ctr };
        assert_eq!(header.encode(), encoded, "encode {line}");
        assert_eq!(Header::decode(&encoded), Ok((header, encoded.len())), "decode {line}");
        count += 1;
    }
    assert_eq!(count, 289, "every case of Appendix C.1");
}

#[test]
fn non_minimal_and_truncated_headers_are_refused() {
    // CTR 5 written in an extended byte; KID 0x10 in two bytes.
    for bad in [&[0x08, 0x05][..], &[0x90, 0x00, 0x10], &[], &[0x09, 0x01], &[0x80]] {
        assert_eq!(Header::decode(bad), Err(SframeError::Header), "{bad:02x?}");
    }
}

struct Case {
    suite: u16,
    ct: &'static str,
}

const KID: u64 = 0x123;
const CTR: u64 = 0x4567;
const BASE_KEY: &str = "000102030405060708090a0b0c0d0e0f";
const METADATA: &str = "4945544620534672616d65205747";
const PT: &str = "64726166742d696574662d736672616d652d656e63";

const CASES: [Case; 2] = [
    Case {
        suite: AES_128_GCM_SHA256_128,
        ct: "9901234567b7412c2513a1b66dbb48841bbaf17f598751176ad847681a69c6d0b091c07018ce4adb34eb",
    },
    Case {
        suite: AES_256_GCM_SHA512_128,
        ct: "990123456794f509d36e9beacb0e261d99c7d1e972f1fed787d4049f17ca21353c1cc24d56ceabced279",
    },
];

/// A sender whose next counter is `CTR`: the vectors encrypt at 0x4567.
fn sender_at_ctr(suite_id: u16) -> Sender {
    let mut sender = Sender::new(suite(suite_id).unwrap(), KID, &hex(BASE_KEY)).unwrap();
    for _ in 0..CTR {
        sender.encrypt(&[], &[]).unwrap();
    }
    sender
}

#[test]
fn encryption_vectors_of_the_gcm_suites() {
    for case in &CASES {
        let mut sender = sender_at_ctr(case.suite);
        let ct = sender.encrypt(&hex(METADATA), &hex(PT)).unwrap();
        assert_eq!(ct, hex(case.ct), "encrypt, suite {:#06x}", case.suite);

        let mut receiver = Receiver::new();
        receiver.add_key(suite(case.suite).unwrap(), KID, &hex(BASE_KEY)).unwrap();
        assert_eq!(receiver.decrypt(&hex(METADATA), &hex(case.ct)), Ok(hex(PT)));
        // The same ciphertext again is a replay.
        assert_eq!(receiver.decrypt(&hex(METADATA), &hex(case.ct)), Err(SframeError::Replay));
    }
}

#[test]
fn altered_ciphertext_metadata_or_header_fail_closed() {
    let case = &CASES[1];
    let fresh = || {
        let mut receiver = Receiver::new();
        receiver.add_key(suite(case.suite).unwrap(), KID, &hex(BASE_KEY)).unwrap();
        receiver
    };
    let good = hex(case.ct);
    let mut flipped = good.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert_eq!(fresh().decrypt(&hex(METADATA), &flipped), Err(SframeError::Decrypt));
    assert_eq!(fresh().decrypt(b"other metadata", &good), Err(SframeError::Decrypt));
    // Another counter in the header: the nonce and AAD change.
    let mut other_ctr = good.clone();
    other_ctr[4] ^= 1;
    assert_eq!(fresh().decrypt(&hex(METADATA), &other_ctr), Err(SframeError::Decrypt));
    // Unknown key id.
    let mut receiver = Receiver::new();
    receiver.add_key(suite(case.suite).unwrap(), KID + 1, &hex(BASE_KEY)).unwrap();
    assert_eq!(receiver.decrypt(&hex(METADATA), &good), Err(SframeError::UnknownKid));
    // A failure leaves the window open: the genuine one still decrypts.
    let mut receiver = fresh();
    assert!(receiver.decrypt(&hex(METADATA), &flipped).is_err());
    assert_eq!(receiver.decrypt(&hex(METADATA), &good), Ok(hex(PT)));
}

#[test]
fn unsupported_suites_and_empty_keys_are_refused() {
    for id in [0x0000, 0x0001, 0x0003, 0xf000] {
        assert_eq!(suite(id).err(), Some(SframeError::UnsupportedSuite(id)));
    }
    let suite = suite(AES_256_GCM_SHA512_128).unwrap();
    assert_eq!(suite.id(), AES_256_GCM_SHA512_128);
    assert_eq!(suite.overhead(), 16);
    assert_eq!(Sender::new(suite, 1, &[]).err(), Some(SframeError::EmptyKey));
}

#[test]
fn counters_rise_and_differ_per_payload() {
    let suite = suite(AES_256_GCM_SHA512_128).unwrap();
    let mut sender = Sender::new(suite, 7, &[9; 32]).unwrap();
    let a = sender.encrypt(b"m", b"same").unwrap();
    let b = sender.encrypt(b"m", b"same").unwrap();
    assert_ne!(a, b, "a fresh nonce per payload");
    assert_eq!(Header::decode(&a).unwrap().0, Header { kid: 7, ctr: 0 });
    assert_eq!(Header::decode(&b).unwrap().0, Header { kid: 7, ctr: 1 });
    let mut receiver = Receiver::new();
    receiver.add_key(suite, 7, &[9; 32]).unwrap();
    // Out of order is fine; each once.
    assert_eq!(receiver.decrypt(b"m", &b), Ok(b"same".to_vec()));
    assert_eq!(receiver.decrypt(b"m", &a), Ok(b"same".to_vec()));
    assert_eq!(receiver.decrypt(b"m", &a), Err(SframeError::Replay));
}
