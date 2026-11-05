// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn data(v: &Value, name: &str) -> Vec<u8> {
    unhex(v[name].as_str().unwrap())
}

#[test]
fn large_manifest_matches_s0_layer4_vectors() {
    let fixtures: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/large_attachment_v1.json"))
            .unwrap();
    let public: [u8; 32] = data(&fixtures, "owner_public_key_hex").try_into().unwrap();
    for case in fixtures["cases"].as_array().unwrap() {
        let exact = data(case, "media_manifest_codec_hex");
        let inner = MediaManifest::decode(&exact).unwrap();
        assert_eq!(inner.canonical_bytes().unwrap(), exact);
        assert_eq!(inner.hash().unwrap().as_slice(), data(case, "hinner_hex"));
        let native = ContentManifest {
            object_id: data(case, "object_id_hex").try_into().unwrap(),
            owner: QualifiedOwner {
                account_anchor: "owner-anchor".into(),
                device_id: "owner-device".into(),
                device_epoch: 7,
                signing_public_key: public,
                home_node_id: "node-owner".into(),
            },
            layout: inner.layout(),
            segment_digests: inner.segment_digests.clone(),
        };
        let mc = native.canonical_bytes().unwrap();
        assert_eq!(ContentManifest::decode(&mc).unwrap(), native);
        for bad in [mc[..mc.len() - 1].to_vec(), [mc.as_slice(), &[0]].concat()] {
            assert!(ContentManifest::decode(&bad).is_err());
        }
        assert_eq!(native.canonical_bytes().unwrap(), data(case, "content_manifest_unsigned_hex"));
        assert_eq!(native.signing_bytes().unwrap(), data(case, "content_signing_bytes_hex"));
        assert_eq!(native.hash().unwrap().as_slice(), data(case, "hrelay_hex"));
        let signature: [u8; 64] = data(case, "content_signature_hex").try_into().unwrap();
        assert_eq!(
            ContentManifest::decode_signed(&native.signed_bytes(&signature).unwrap()).unwrap(),
            (native.clone(), signature)
        );
        let mut bad_signature = signature;
        bad_signature[0] ^= 1;
        assert!(native.signed_bytes(&bad_signature).is_err());
        let sig = Signature::from_slice(&data(case, "content_signature_hex")).unwrap();
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify(&native.signing_bytes().unwrap(), &sig)
            .unwrap();
        let seed: [u8; 32] = data(&fixtures, "public_fixture_owner_seed_hex").try_into().unwrap();
        assert_eq!(SigningKey::from_bytes(&seed).sign(&native.signing_bytes().unwrap()), sig);
        assert!(
            !native.canonical_bytes().unwrap().windows(32).any(|w| w == inner.plaintext_digest)
        );
        let mut reference = MediaRef {
            mime_type: "application/octet-stream".into(),
            file_name: Some("fixture.bin".into()),
            inline_thumbnail: None,
            object_id: case["object_id_base64url"].as_str().unwrap().into(),
            manifest_digest: inner.hash().unwrap(),
            size: inner.plaintext_length,
            key_slots: inner.key_slots.clone(),
            large_manifest: inner.clone(),
        };
        reference.validate_binding(&native).unwrap();
        assert_eq!(MediaRef::decode(&reference.canonical_bytes().unwrap()).unwrap(), reference);
        for layer in 1..4 {
            assert_eq!(
                reference.for_peer(layer, "caption"),
                PeerMedia::CaptionWithUpgradeRequired { caption: "caption", required_layer: 4 }
            );
        }
        assert!(matches!(reference.for_peer(4, "caption"), PeerMedia::Large(_)));
        reference.manifest_digest[0] ^= 1;
        assert!(reference.validate_binding(&native).is_err());
        reference.manifest_digest = inner.hash().unwrap();
        reference.large_manifest.manifest_id[0] ^= 1;
        reference.manifest_digest = reference.large_manifest.hash().unwrap();
        assert!(reference.validate_binding(&native).is_err());
        for mutation in [vec![0x68, 1], vec![0x18, 0], exact[..exact.len() - 1].to_vec()] {
            let mut invalid = exact.clone();
            invalid.extend(mutation);
            assert!(MediaManifest::decode(&invalid).is_err());
        }
    }
    let a = &fixtures["cases"][1];
    let b = &fixtures["cases"][6];
    assert_eq!(a["plaintext_digest_hex"], b["plaintext_digest_hex"]);
    for field in ["content_manifest_unsigned_hex", "hrelay_hex", "content_signature_hex"] {
        assert_ne!(a[field], b[field]);
    }
    assert!(
        SegmentLayout { plaintext_length: u64::MAX, network_chunk_bytes: 524_288 }
            .dimensions()
            .is_err()
    );
}
