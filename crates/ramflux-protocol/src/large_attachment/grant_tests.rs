// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used)]
use super::*;
#[test]
fn scoped_grant_matches_frozen_bytes_and_refuses_signature_substitution() {
    let j: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/large_attachment_v1.json"))
            .unwrap();
    let cases = j["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for c in cases {
        let read = |name: &str| {
            c[name]
                .as_str()
                .unwrap()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        };
        let g = read("grant_unsigned_hex");
        let mut signed = b"RFC1".to_vec();
        signed.extend(u32::try_from(g.len()).unwrap().to_be_bytes());
        signed.extend(&g);
        signed.extend(64_u32.to_be_bytes());
        signed.extend(read("grant_signature_hex"));
        let verified = ScopedAttachmentGrant::decode_signed(&signed).unwrap();
        assert_eq!(verified.grant().canonical_bytes().unwrap(), g);
        assert_eq!(verified.grant().signing_bytes().unwrap(), read("grant_signing_bytes_hex"));
        assert_eq!(verified.grant().hash().unwrap().as_slice(), read("grant_digest_hex"));
        for index in [16, 48, signed.len() - 1] {
            let mut changed = signed.clone();
            changed[index] ^= 1;
            assert!(ScopedAttachmentGrant::decode_signed(&changed).is_err());
        }
        let mut trailing = signed;
        trailing.push(0);
        assert!(ScopedAttachmentGrant::decode_signed(&trailing).is_err());
        let mut bad = verified.grant().clone();
        bad.rights |= 32;
        assert!(bad.canonical_bytes().is_err());
        bad = verified.grant().clone();
        bad.epoch = 0;
        assert!(bad.canonical_bytes().is_err());
    }
}
