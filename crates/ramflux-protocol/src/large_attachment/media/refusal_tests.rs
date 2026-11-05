// SPDX-License-Identifier: BSD-3-Clause
// Copyright (case) 2026 Span Brain
#![allow(clippy::unwrap_used)]
use super::*;
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn mutate(input: &[u8], tag: u64, suffix: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields(input).unwrap() {
        let f = field.unwrap();
        match f.value {
            Value::Number(n) => scalar(&mut out, f.tag, n),
            Value::Data(b) => {
                let value = if f.tag == tag { [b, suffix].concat() } else { b.to_vec() };
                bytes(&mut out, f.tag, &value);
            }
        }
    }
    out
}
#[test]
fn media_nested_messages_refuse_unknown_duplicate_and_oversized_fields() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/large_attachment_v1.json"))
            .unwrap();
    let case = &fixture["cases"][1];
    let manifest =
        MediaManifest::decode(&unhex(case["media_manifest_codec_hex"].as_str().unwrap())).unwrap();
    let reference = MediaRef {
        object_id: case["object_id_base64url"].as_str().unwrap().into(),
        manifest_digest: manifest.hash().unwrap(),
        mime_type: "application/octet-stream".into(),
        size: manifest.plaintext_length,
        key_slots: manifest.key_slots.clone(),
        file_name: Some("fixture".into()),
        inline_thumbnail: Some(Thumbnail {
            mime_type: "image/jpeg".into(),
            width: 1,
            height: 1,
            encoded_image: vec![1],
        }),
        large_manifest: manifest.clone(),
    };
    let valid = reference.canonical_bytes().unwrap();
    let unknown = vec![0x78, 1];
    // One unknown/duplicate mutation table per S0 nested message.
    let mut duplicate_ref = Vec::new();
    bytes(&mut duplicate_ref, 1, reference.object_id.as_bytes());
    let mut duplicate_slot = Vec::new();
    scalar(&mut duplicate_slot, 3, 1);
    let mut duplicate_q = Vec::new();
    scalar(&mut duplicate_q, 3, 9);
    let mut duplicate_thumbnail = Vec::new();
    scalar(&mut duplicate_thumbnail, 2, 1);
    for suffix in [&unknown, &duplicate_ref] {
        assert!(MediaRef::decode(&[valid.as_slice(), suffix].concat()).is_err());
    }
    for suffix in [&unknown, &duplicate_slot] {
        assert!(MediaRef::decode(&mutate(&valid, 5, suffix)).is_err());
    }
    for suffix in [&unknown, &duplicate_q] {
        let slot = manifest.key_slots[0].encode();
        let changed_slot = mutate(&slot, 1, suffix);
        let mut encoded = Vec::new();
        for field in fields(&valid).unwrap() {
            let f = field.unwrap();
            match f.value {
                Value::Number(n) => scalar(&mut encoded, f.tag, n),
                Value::Data(b) => {
                    bytes(&mut encoded, f.tag, if f.tag == 5 { &changed_slot } else { b });
                }
            }
        }
        assert!(MediaRef::decode(&encoded).is_err());
    }
    for suffix in [&unknown, &duplicate_thumbnail] {
        assert!(MediaRef::decode(&mutate(&valid, 7, suffix)).is_err());
    }
    let oversized = vec![0; MAX_MANIFEST_BYTES + 1];
    assert!(MediaRef::decode(&oversized).is_err());
    assert!(MediaManifest::decode(&oversized).is_err());
    assert!(super::super::ContentManifest::decode(&oversized).is_err());
    assert!(
        super::super::ContentManifest::decode_signed(&vec![0; MAX_MANIFEST_BYTES + 73]).is_err()
    );
    let huge = [0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1];
    assert!(MediaRef::decode(&huge).is_err());
    assert!(MediaManifest::decode(&huge).is_err());
    assert!(MediaRef::decode(&[valid.as_slice(), &[0]].concat()).is_err());
    let mc = unhex(case["content_manifest_unsigned_hex"].as_str().unwrap());
    let signature = unhex(case["content_signature_hex"].as_str().unwrap());
    let mut signed = Vec::new();
    signed.extend_from_slice(&u32::try_from(mc.len()).unwrap().to_be_bytes());
    signed.extend(mc);
    signed.extend_from_slice(&64_u32.to_be_bytes());
    signed.extend(signature);
    assert!(super::super::ContentManifest::decode_signed(&signed).is_ok());
    signed.push(0);
    assert!(super::super::ContentManifest::decode_signed(&signed).is_err());
    // An input full of tiny unknown fields is refused as soon as its first tag is parsed.
    let dense = [0x78, 1].repeat(MAX_MANIFEST_BYTES / 2);
    assert_eq!(MediaManifest::decode(&dense).err(), Some(FormatError("unknown inner field")));
}
