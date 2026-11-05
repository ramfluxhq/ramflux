// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn data(v: &Value, name: &str) -> Vec<u8> {
    hex::decode(v[name].as_str().unwrap()).unwrap()
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
        let expected: [u8; 32] = data(case, "plaintext_digest_hex").try_into().unwrap();
        let mut verifier = PlaintextVerifier::new(layout.plaintext_length);
        let mut wrong_digest = PlaintextVerifier::new(layout.plaintext_length);
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
            assert_eq!(*reopened, *plaintext);
            verifier.update(&reopened).unwrap();
            wrong_digest.update(&reopened).unwrap();
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
        verifier.finish(&expected).unwrap();
        assert!(wrong_digest.finish(&[0; 32]).is_err());
        let mut wrong = PlaintextVerifier::new(layout.plaintext_length);
        if layout.plaintext_length > 0 {
            wrong.update(&[0]).unwrap();
        }
        assert!(wrong.finish(&[0; 32]).is_err());
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
