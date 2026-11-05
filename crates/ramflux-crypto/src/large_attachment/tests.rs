// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use ramflux_protocol::large_attachment::{
    ContentManifest, MediaManifest, MediaRef, VerifiedContentManifest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn data(v: &Value, name: &str) -> Vec<u8> {
    hex::decode(v[name].as_str().unwrap()).unwrap()
}

fn manifests(case: &Value) -> (MediaRef, VerifiedContentManifest) {
    let mc = data(case, "content_manifest_unsigned_hex");
    let signature = data(case, "content_signature_hex");
    let mut signed = Vec::new();
    signed.extend_from_slice(&u32::try_from(mc.len()).unwrap().to_be_bytes());
    signed.extend_from_slice(&mc);
    signed.extend_from_slice(&64_u32.to_be_bytes());
    signed.extend_from_slice(&signature);
    let native = ContentManifest::decode_signed(&signed).unwrap();
    let inner = MediaManifest::decode(&data(case, "media_manifest_codec_hex")).unwrap();
    let reference = MediaRef {
        object_id: case["object_id_base64url"].as_str().unwrap().into(),
        manifest_digest: inner.hash().unwrap(),
        mime_type: "application/octet-stream".into(),
        size: inner.plaintext_length,
        key_slots: inner.key_slots.clone(),
        file_name: None,
        inline_thumbnail: None,
        large_manifest: inner,
    };
    (reference, native)
}

#[test]
fn large_segments_reject_reorder_truncation_and_nonce_reuse() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../ramflux-protocol/tests/fixtures/large_attachment_v1.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let layout = SegmentLayout {
            plaintext_length: case["plaintext_length"].as_u64().unwrap(),
            network_chunk_bytes: u32::try_from(case["network_chunk_bytes"].as_u64().unwrap())
                .unwrap(),
        };
        let key: [u8; 32] = data(case, "file_key_hex").try_into().unwrap();
        let object_id: [u8; 32] = data(case, "object_id_hex").try_into().unwrap();
        let mut sealer =
            SegmentSealer { key: Zeroizing::new(key), object_id, layout, next_index: 0 };
        let (reference, native) = manifests(case);
        let mut verifier = PlaintextVerifier::new(&reference, &native).unwrap();
        let mut changed = reference.clone();
        changed.large_manifest.plaintext_digest = [0; 32];
        changed.manifest_digest = changed.large_manifest.hash().unwrap();
        let mut wrong_digest = PlaintextVerifier::new(&changed, &native).unwrap();
        let mut offset = 0;
        let mut ciphertexts = Vec::new();
        for segment in case["segments"].as_array().unwrap() {
            let index = segment["index"].as_u64().unwrap();
            let length = usize::try_from(segment["plaintext_length"].as_u64().unwrap()).unwrap();
            let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
                (offset..offset + length).map(|j| u8::try_from(j % 251).unwrap()).collect(),
            );
            offset += length;
            assert_eq!(nonce(index).as_slice(), data(segment, "nonce_hex"));
            assert_eq!(layout.associated_data(&object_id, index).unwrap(), data(segment, "ad_hex"));
            assert!(sealer.seal(index + 1, &plaintext).is_err());
            let ciphertext = sealer.seal(index, &plaintext).unwrap();
            assert!(matches!(sealer.seal(index, &plaintext), Err(SegmentError::NonceReuse)));
            assert_eq!(
                hex::encode(Sha256::digest(&ciphertext)),
                segment["ciphertext_sha256"].as_str().unwrap()
            );
            assert_eq!(
                segment_digest(&ciphertext).unwrap().as_slice(),
                data(segment, "segment_digest_hex")
            );
            if let Some(exact) = segment["ciphertext_hex"].as_str() {
                assert_eq!(hex::encode(&ciphertext), exact);
            }
            let reopened = open_segment(&key, &object_id, layout, index, &ciphertext).unwrap();
            assert_eq!(reopened.as_staging_bytes(), plaintext.as_slice());
            verifier.update_segment(index, &reopened).unwrap();
            wrong_digest.update_segment(index, &reopened).unwrap();
            let mut false_final_ad = layout.associated_data(&object_id, index).unwrap();
            *false_final_ad.last_mut().unwrap() ^= 1;
            let primitive = ChaCha20Poly1305::new_from_slice(&key).unwrap();
            let false_final_ciphertext = primitive
                .encrypt(
                    Nonce::from_slice(&nonce(index)),
                    Payload { msg: &plaintext, aad: &false_final_ad },
                )
                .unwrap();
            assert!(
                open_segment(&key, &object_id, layout, index, &false_final_ciphertext).is_err()
            );
            let mut corrupt = ciphertext.clone();
            corrupt[0] ^= 1;
            assert!(open_segment(&key, &object_id, layout, index, &corrupt).is_err());
            assert!(
                open_segment(&key, &object_id, layout, index, &ciphertext[..ciphertext.len() - 1])
                    .is_err()
            );
            assert!(
                open_segment(&key, &object_id, layout, index, &ciphertext[..ciphertext.len() - 16])
                    .is_err()
            );
            assert!(open_segment(&key, &object_id, layout, index + 1, &ciphertext).is_err());
            let mut other = object_id;
            other[0] ^= 1;
            assert!(open_segment(&key, &other, layout, index, &ciphertext).is_err());
            let changed_final = SegmentLayout {
                plaintext_length: layout.plaintext_length
                    + ramflux_protocol::large_attachment::PLAINTEXT_SEGMENT_BYTES,
                ..layout
            };
            assert!(open_segment(&key, &object_id, changed_final, index, &ciphertext).is_err());
            ciphertexts.push(ciphertext);
        }
        let token = verifier.finish().unwrap();
        assert_eq!(token.object_id(), &object_id);
        assert_eq!(token.inner_digest(), &reference.manifest_digest);
        assert_eq!(token.length(), layout.plaintext_length);
        assert!(wrong_digest.finish().is_err());
        let prefix_verifier = PlaintextVerifier::new(&reference, &native).unwrap();
        if layout.plaintext_length > 0 {
            assert_eq!(
                prefix_verifier.finish().err(),
                Some(FormatError("incomplete plaintext length"))
            );
        }
        for index in 1..ciphertexts.len() {
            assert!(open_segment(&key, &object_id, layout, 0, &ciphertexts[index]).is_err());
            assert!(open_segment(&key, &object_id, layout, index as u64, &ciphertexts[0]).is_err());
        }
    }
    let layout = SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 };
    let a = SegmentSealer::new(layout).unwrap();
    let b = SegmentSealer::new(layout).unwrap();
    assert_ne!(a.object_id(), b.object_id());
    assert_ne!(a.file_key(), b.file_key());
    let a = &fixture["cases"][1];
    let b = &fixture["cases"][6];
    assert_eq!(a["plaintext_digest_hex"], b["plaintext_digest_hex"]);
    assert_ne!(a["segments"][0]["ciphertext_hex"], b["segments"][0]["ciphertext_hex"]);
}

#[test]
fn large_final_verifier_requires_ordered_complete_authenticated_segments() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../ramflux-protocol/tests/fixtures/large_attachment_v1.json"
    ))
    .unwrap();
    let case = &fixture["cases"][5];
    let (reference, native) = manifests(case);
    let layout = reference.large_manifest.layout();
    let capacity =
        usize::try_from(ramflux_protocol::large_attachment::PLAINTEXT_SEGMENT_BYTES).unwrap();
    // These private staging values model the output of the separately tested AEAD opener.
    let mut first = UnverifiedStaging {
        bytes: Zeroizing::new((0..capacity).map(|j| u8::try_from(j % 251).unwrap()).collect()),
        object_id: native.manifest().object_id,
        layout,
        index: 0,
    };
    let mut verifier = PlaintextVerifier::new(&reference, &native).unwrap();
    first.index = 1;
    assert!(verifier.update_segment(1, &first).is_err());
    first.index = 0;
    first.object_id[0] ^= 1;
    assert!(verifier.update_segment(0, &first).is_err());
    first.object_id[0] ^= 1;
    first.bytes.pop();
    assert_eq!(
        verifier.update_segment(0, &first).err(),
        Some(FormatError("plaintext segment length"))
    );
    first.bytes.push(u8::try_from((capacity - 1) % 251).unwrap());
    verifier.update_segment(0, &first).unwrap();
    assert!(verifier.update_segment(0, &first).is_err());
    // Correct full-file digest is retained. Assert the length refusal itself,
    // independently of the later digest mismatch for this valid prefix.
    assert_eq!(verifier.finish().err(), Some(FormatError("incomplete plaintext length")));
    let empty_case = &fixture["cases"][0];
    let (empty_ref, empty_native) = manifests(empty_case);
    assert_eq!(
        PlaintextVerifier::new(&empty_ref, &empty_native).unwrap().finish().err(),
        Some(FormatError("incomplete plaintext segment count"))
    );
}
