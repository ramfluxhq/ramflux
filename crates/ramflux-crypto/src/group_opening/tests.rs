// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;

const MESSAGE: &[u8] = b"\x0a\x05hello\x8a\x01\x20*******************************\x2a";
fn fixture() -> Result<g::GroupSealedContent, Box<dyn std::error::Error>> {
    let vectors: serde_json::Value = serde_json::from_str(include_str!("golden.json"))?;
    let bytes = |field: &str| {
        ramflux_protocol::decode_base64url(vectors[field].as_str().ok_or("golden field")?)
            .map_err(Into::<Box<dyn std::error::Error>>::into)
    };
    Ok(g::GroupSealedContent {
        group_id: "fixture-group".into(),
        key_epoch: 7,
        group_state_hash: vec![8; 32],
        author: Some(g::QualifiedDevice {
            account_anchor: ramflux_protocol::encode_base64url([0; 32]),
            device_id: "alice".into(),
            device_epoch: 1,
        }),
        session_id: vec![9; 32],
        counter: 1,
        nonce: vec![3; 12],
        ciphertext: vec![4; 32],
        sender_device_hash: vec![5; 32],
        recipient_device_hash: vec![6; 32],
        device_epoch: 1,
        event_id: vectors["native_event_id"].as_str().ok_or("event")?.as_bytes().to_vec(),
        canonical_crypto_header: bytes("canonical_header")?,
        header_hash: bytes("header_hash")?,
        ciphertext_hash: bytes("ciphertext_hash")?,
        key_commitment: bytes("key_commitment")?,
        franking_commitment: bytes("franking_commitment")?,
        commitment: bytes("commitment")?,
        content_commitment: bytes("commitment")?,
        ..Default::default()
    })
}
fn opening() -> Vec<u8> {
    [[1; 32], [2; 32]].concat()
}
#[test]
fn group_opening_independent_golden_vector_strict_lengths_and_zeroization()
-> Result<(), Box<dyn std::error::Error>> {
    let sealed = fixture()?;
    for len in [0, 63, 65, 128] {
        let mut key = vec![7; len];
        assert!(verify_group_message_opening(&mut key, MESSAGE, &sealed).is_err());
        assert!(key.iter().all(|byte| *byte == 0), "opening survived a length refusal");
    }
    let mut key = opening();
    assert!(verify_group_message_opening(&mut key, MESSAGE, &sealed).is_ok());
    assert!(key.iter().all(|byte| *byte == 0), "opening survived successful verification");
    Ok(())
}
#[test]
fn group_opening_recomputes_commitment_for_exact_message_header_ciphertext_and_aad()
-> Result<(), Box<dyn std::error::Error>> {
    let sealed = fixture()?;
    for change in [
        "message",
        "aad",
        "group",
        "header",
        "ciphertext",
        "swapped",
        "sender",
        "event",
        "application_id",
        "key",
        "franking",
        "commitment",
        "content",
        "epoch",
        "author",
        "author_root",
        "recursive",
    ] {
        let mut modified = sealed.clone();
        let mut key = opening();
        let mut plain = MESSAGE.to_vec();
        match change {
            "message" => plain[6] ^= 1,
            "aad" => modified.group_state_hash[0] ^= 1,
            "group" => modified.group_id.push('x'),
            "header" => modified.canonical_crypto_header.push(1),
            "ciphertext" => modified.ciphertext.push(1),
            "swapped" => key.rotate_left(32),
            "sender" => modified.sender_device_hash[0] ^= 1,
            "event" => modified.event_id.push(b'x'),
            "application_id" => {
                modified.event_id = ramflux_protocol::encode_base64url([11; 32]).into_bytes();
            }
            "key" => modified.key_commitment[0] ^= 1,
            "franking" => modified.franking_commitment[0] ^= 1,
            "commitment" => modified.commitment[0] ^= 1,
            "content" => modified.content_commitment[0] ^= 1,
            "epoch" => modified.key_epoch += 1,
            "author" => modified.author.as_mut().ok_or("author")?.device_id.push('x'),
            "author_root" => {
                modified.author.as_mut().ok_or("author")?.account_anchor =
                    ramflux_protocol::encode_base64url([1; 32]);
            }
            "recursive" => {
                plain = g::Message {
                    sealed_group: Some(g::GroupSealedContent::default()),
                    ..Default::default()
                }
                .encode_to_vec();
            }
            _ => return Err(format!("test: unknown group opening tamper case {change}").into()),
        }
        assert!(
            verify_group_message_opening(&mut key, &plain, &modified).is_err(),
            "tampered group opening row {change} verified"
        );
        assert!(key.iter().all(|byte| *byte == 0), "opening survived a commitment refusal");
    }
    Ok(())
}
