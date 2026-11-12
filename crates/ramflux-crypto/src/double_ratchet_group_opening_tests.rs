// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independently pinned native KDF schedule and sender/receiver openings across counters.
use super::*;
use prost::Message as _;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn native_group_openings_match_two_counter_independent_kdf_vectors() -> TestResult {
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("group_opening/native_kdf_golden.json"))?;
    let mut sender = DmSession::initiator([1; 32], [2; 32], [3; 32], [4; 32])?;
    let mut receiver = DmSession::recipient([1; 32], [3; 32], [2; 32], [4; 32])?;
    let plaintext =
        ramflux_protocol::message::Message { text: "native opening".into(), ..Default::default() }
            .encode_to_vec();
    for vector in vectors {
        let aad = ramflux_protocol::decode_base64url(vector["aad"].as_str().ok_or("aad")?)?;
        let counter = sender.send_counter;
        let direction = sender.direction_context(DIRECTION_SEND, &[0; 32], counter, 0);
        let (_, secret) = kdf_ck(sender.sending_chain_key.expose(), &direction)?;
        let encrypted = sender.encrypt_with_franking_keys(&plaintext, &aad)?;
        let cipher = &encrypted.ciphertext;
        assert_eq!(vector["counter"].as_u64(), Some(cipher.counter));
        assert_eq!(vector["session"].as_str(), Some(cipher.session_id.as_str()));
        assert_eq!(vector["native_id"].as_str(), Some(cipher.message_event_id.as_str()));
        assert_eq!(
            vector["header"].as_str(),
            Some(encode_base64url(&cipher.canonical_header_bytes).as_str())
        );
        assert_eq!(vector["nonce"].as_str(), Some(encode_base64url(cipher.nonce).as_str()));
        let context =
            sender.message_context(DIRECTION_SEND, counter, &cipher.canonical_header_bytes, &aad);
        let keys = derive_message_keys(&secret, &context)?;
        let mut schedule = Zeroizing::new(Vec::with_capacity(108));
        schedule.extend_from_slice(&keys.aead_key);
        schedule.extend_from_slice(&keys.nonce);
        schedule.extend_from_slice(&keys.commitment_key);
        schedule.extend_from_slice(&keys.opening_key);
        assert_eq!(
            vector["schedule_hash"].as_str(),
            Some(encode_base64url(blake3::hash(&schedule).as_bytes()).as_str()),
            "native schedule drift at {counter}"
        );
        let mut opening = Zeroizing::new(Vec::with_capacity(64));
        opening.extend_from_slice(encrypted.opening_key.as_slice());
        opening.extend_from_slice(encrypted.commitment_key.as_slice());
        assert_eq!(
            vector["opening_hash"].as_str(),
            Some(encode_base64url(blake3::hash(&opening).as_bytes()).as_str()),
            "opening drift at {counter}"
        );
        assert!(*encrypted.opening_key == keys.opening_key, "sender opening differs from KDF");
        assert!(
            *encrypted.commitment_key == keys.commitment_key,
            "sender commitment key differs from KDF"
        );
        let decrypted = receiver.decrypt_with_franking_keys(cipher, &aad)?;
        assert_eq!(decrypted.plaintext, plaintext);
        assert!(
            decrypted.opening_key == *encrypted.opening_key,
            "sender/receiver opening mismatch"
        );
        assert!(
            decrypted.commitment_key == *encrypted.commitment_key,
            "sender/receiver commitment key mismatch"
        );
    }
    Ok(())
}
