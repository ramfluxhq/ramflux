// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Complete original signatures and protobuf bytes calculated independently in Python.
use super::*;
use crate::client::native_test_support::TestResult;

#[test]
fn group_history_independent_complete_signed_vectors_match_native_receive() -> TestResult {
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("group_history_golden.json"))?;
    let mut receiver = ramflux_crypto::DmSession::recipient([1; 32], [3; 32], [2; 32], [4; 32])?;
    assert_eq!(vectors.len(), 2);
    for vector in vectors {
        let wire =
            ramflux_protocol::decode_base64url(vector["history_item"].as_str().ok_or("wire")?)?;
        assert_eq!(
            vector["history_item_hash"].as_str(),
            Some(ramflux_protocol::encode_base64url(blake3::hash(&wire).as_bytes()).as_str())
        );
        let item = g::HistoryItem::decode(wire.as_slice())?;
        verify_golden_phases(&item)?;
        assert!(item.encode_to_vec() == wire, "independent HistoryItem protobuf bytes drifted");
        let (identity, origin, verified) = RamfluxClient::verify_history_message_origin(&item)?;
        assert_eq!(
            vector["event_id"].as_str(),
            Some(ramflux_protocol::encode_base64url(&identity.id).as_str())
        );
        assert_eq!(verified.author.root, identity.author.as_ref().ok_or("author")?.account_anchor);
        let outer: serde_json::Value =
            ramflux_protocol::parse_i_json(&origin.evidence.canonical_sender_envelope)?;
        assert!(
            outer.get("encrypted_payload").is_none(),
            "history required the original pair ciphertext"
        );
        let inner = g::Inner::decode(item.exact_inner.as_slice())?;
        let message = g::Message::decode(inner.body.as_slice())?;
        let sealed = message.sealed_group.as_ref().ok_or("sealed")?;
        let native = crate::client::generated_group::to_native(sealed)?;
        assert_eq!(vector["counter"].as_u64(), Some(native.ciphertext.counter));
        let aad = crate::group::group_key_associated_data(
            &sealed.group_id,
            &verified.author.device,
            sealed.key_epoch,
            native.group_state_hash.as_deref(),
        )?;
        let decrypted = receiver.decrypt_with_franking_keys(&native.ciphertext, &aad)?;
        assert!(
            decrypted.plaintext == origin.evidence.group_plaintext,
            "independent native AEAD plaintext differs"
        );
        let mut opening = zeroize::Zeroizing::new(Vec::with_capacity(64));
        opening.extend_from_slice(&decrypted.opening_key);
        opening.extend_from_slice(&decrypted.commitment_key);
        assert!(
            *opening == origin.evidence.group_opening,
            "independent sender/receiver opening differs"
        );
    }
    Ok(())
}

#[test]
fn group_history_forwarder_cannot_replace_commitments_without_original_signature() -> TestResult {
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("group_history_golden.json"))?;
    let wire =
        ramflux_protocol::decode_base64url(vectors[0]["history_item"].as_str().ok_or("wire")?)?;
    let item = g::HistoryItem::decode(wire.as_slice())?;
    let (identity, mut origin, verified) = RamfluxClient::verify_history_message_origin(&item)?;
    let mut inner = g::Inner::decode(item.exact_inner.as_slice())?;
    let mut message = g::Message::decode(inner.body.as_slice())?;
    let sealed = message.sealed_group.as_mut().ok_or("sealed")?;
    let plaintext =
        g::Message { text: "forwarder replacement".into(), ..Default::default() }.encode_to_vec();
    let aad = crate::group::group_key_associated_data(
        &sealed.group_id,
        &verified.author.device,
        sealed.key_epoch,
        Some(&ramflux_protocol::encode_base64url(&sealed.group_state_hash)),
    )?;
    let opening_key = origin.evidence.group_opening[..32].try_into()?;
    let commitment_key = origin.evidence.group_opening[32..].try_into()?;
    let event = String::from_utf8(sealed.event_id.clone())?;
    let forged = ramflux_crypto::franking_commitment(&ramflux_crypto::FrankingCommitmentInput {
        plaintext: &plaintext,
        sender_device_id_hash: &sealed.sender_device_hash,
        message_event_id: &event,
        canonical_header_bytes: &sealed.canonical_crypto_header,
        associated_data: &aad,
        ciphertext: &sealed.ciphertext,
        opening_key,
        commitment_key,
    });
    sealed.franking_commitment = ramflux_protocol::decode_base64url(&forged.franking_commitment)?;
    sealed.commitment = ramflux_protocol::decode_base64url(&forged.commitment)?;
    sealed.content_commitment.clone_from(&sealed.commitment);
    inner.body = message.encode_to_vec();
    origin.evidence.group_plaintext = plaintext;
    let exact = inner.encode_to_vec();
    let a0 = g::outer::encode_candidate_report_a0(&g::outer::candidate_report_a0_from_envelope(
        &verified.outer,
    )?)?;
    let kf = origin.evidence.report_opening.as_slice().try_into()?;
    let mut outer: serde_json::Value =
        ramflux_protocol::parse_i_json(&origin.evidence.canonical_sender_envelope)?;
    outer["report_commitment"] = serde_json::json!(ramflux_protocol::encode_base64url(
        ramflux_crypto::report_commitment(kf, &exact, &a0)?
    ));
    // A forwarder knows both disclosed openings and can rebuild C/MACs, but not this signature.
    origin.evidence.canonical_sender_envelope = ramflux_protocol::canonical_json_bytes(&outer)?;
    assert!(
        origin.verify(&identity, &exact).is_err(),
        "forwarder replaced the original signed commitment"
    );
    Ok(())
}

fn verify_golden_phases(item: &g::HistoryItem) -> TestResult {
    let evidence = item.source_evidence.as_ref().ok_or("evidence")?;
    let snapshot = ramflux_protocol::group_state::GroupStateSnapshot::from_wire_bytes(
        &evidence.group_membership.as_ref().ok_or("snapshot")?.canonical,
    )?;
    ramflux_crypto::verify_group_state_snapshot(snapshot)
        .map_err(|error| format!("golden snapshot: {error}"))?;
    let inner = g::Inner::decode(item.exact_inner.as_slice())?;
    let identity = inner.identity.as_ref().ok_or("identity")?;
    let outer: serde_json::Value =
        ramflux_protocol::parse_i_json(&evidence.canonical_sender_envelope)?;
    crate::client::generated_history::authority(
        &outer,
        evidence.source_authority.as_ref().ok_or("authority")?,
        identity,
    )
    .map_err(|error| format!("golden authority/signature: {error}"))?;
    let mut a0_outer = outer.clone();
    a0_outer["encrypted_payload"] = serde_json::json!("");
    let envelope: ramflux_protocol::Envelope = serde_json::from_value(a0_outer)?;
    let a0 = g::outer::encode_candidate_report_a0(&g::outer::candidate_report_a0_from_envelope(
        &envelope,
    )?)?;
    let kf = evidence.report_opening.as_slice().try_into()?;
    let commitment =
        ramflux_protocol::decode_base64url(envelope.report_commitment.as_ref().ok_or("C")?)?;
    ramflux_crypto::verify_report_opening(
        kf,
        &item.exact_inner,
        &a0,
        commitment.as_slice().try_into()?,
    )
    .map_err(|error| format!("golden outer C: {error}"))?;
    let issued = u64::try_from(envelope.created_at)?;
    g::original_header::verify_inner_extension(
        &envelope.ext,
        &item.exact_inner,
        issued,
        issued + u64::from(envelope.ttl),
    )
    .map_err(|error| format!("golden header: {error}"))?;
    let message = g::Message::decode(inner.body.as_slice())?;
    let mut opening = zeroize::Zeroizing::new(evidence.group_opening.clone());
    ramflux_crypto::verify_group_message_opening(
        &mut opening,
        &evidence.group_plaintext,
        message.sealed_group.as_ref().ok_or("sealed")?,
    )
    .map_err(|error| format!("golden native commitment: {error}"))?;
    Ok(())
}
