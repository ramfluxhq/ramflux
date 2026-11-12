// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::message::{
    Forward, GroupSealedContent, MediaRef, Message, MessageRef, QualifiedDevice, Receipt,
    ReceiptState, Service, ServiceAction, content,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn author() -> QualifiedDevice {
    QualifiedDevice { account_anchor: "anchor".into(), device_id: "device".into(), device_epoch: 1 }
}

fn named_ref() -> MessageRef {
    MessageRef { id: vec![7; 32], conversation_id: "c".into(), author_anchor: "a".into() }
}

fn stream() -> GeneratedEventStream {
    GeneratedEventStream::new("c1", author())
}

fn identity_of(bytes: &[u8]) -> Result<g::EventIdentity, SdkError> {
    Ok(RamfluxClient::decode_generated_inner(bytes)?.0)
}

#[test]
fn message_service_share_sequence_and_order() -> TestResult {
    let mut stream = stream();
    let message = RamfluxClient::encode_generated_message(
        &mut stream,
        b"msg-1".to_vec(),
        Message { text: "hello".into(), ..Default::default() },
    )?;
    let service = RamfluxClient::encode_generated_service(
        &mut stream,
        b"svc-1".to_vec(),
        Service { action: ServiceAction::ServiceMemberAdded as i32, ..Default::default() },
    )?;
    let message_id = identity_of(&message)?;
    let service_id = identity_of(&service)?;
    assert_eq!(message_id.conversation_id, service_id.conversation_id);
    assert_eq!(message_id.author, service_id.author);
    assert_eq!(message_id.device_sequence, 1);
    assert_eq!(service_id.device_sequence, 2);
    assert_eq!(message_id.hlc + 1, service_id.hlc);
    assert_eq!(message_id.id, g::identity::derive(&author(), "c1", 1)?);
    assert_eq!(service_id.id, g::identity::derive(&author(), "c1", 2)?);
    assert_ne!(message_id.id, service_id.id);
    let (decoded_message_id, decoded_message) = RamfluxClient::decode_generated_inner(&message)?;
    let (decoded_service_id, decoded_service) = RamfluxClient::decode_generated_inner(&service)?;
    assert_eq!(decoded_message_id.device_sequence, 1);
    assert_eq!(decoded_service_id.device_sequence, 2);
    assert!(matches!(decoded_message.value, Some(content::Value::Message(_))));
    assert!(matches!(decoded_service.value, Some(content::Value::Service(_))));
    assert_eq!(
        RamfluxClient::encode_generated_inner(decoded_message_id, &decoded_message)?,
        message
    );
    assert_eq!(
        RamfluxClient::encode_generated_inner(decoded_service_id, &decoded_service)?,
        service
    );
    Ok(())
}

#[test]
fn generated_message_media_group_and_receipt_paths_round_trip() -> TestResult {
    let mut stream = stream();
    let media = MediaRef {
        object_id: "obj-1".into(),
        manifest_digest: vec![9; 32],
        mime_type: "image/png".into(),
        size: 64,
        file_name: Some("pic.png".into()),
        ..Default::default()
    };
    let with_media = RamfluxClient::encode_generated_message(
        &mut stream,
        b"media-1".to_vec(),
        Message { text: "pic".into(), media: vec![media.clone()], ..Default::default() },
    )?;
    let (_, media_content) = RamfluxClient::decode_generated_inner(&with_media)?;
    match media_content.value {
        Some(content::Value::Message(decoded)) => {
            assert_eq!(decoded.media, vec![media]);
            assert_eq!(decoded.text, "pic");
        }
        other => return Err(format!("expected message, got {other:?}").into()),
    }

    let mut group_stream = GeneratedEventStream::new("c1", author()).with_group("g1", 3);
    let sealed = GroupSealedContent {
        group_id: "g1".into(),
        ciphertext: vec![1, 2, 3],
        event_id: g::identity::derive(&author(), "c1", 1)?.to_vec(),
        author: Some(author()),
        key_epoch: 3,
        group_state_hash: vec![7; 32],
        native_authority_proof: Vec::new(),
        ..Default::default()
    };
    let group_bytes = RamfluxClient::encode_generated_message(
        &mut group_stream,
        b"group-1".to_vec(),
        Message { sealed_group: Some(sealed.clone()), ..Default::default() },
    )?;
    let (group_identity, group_content) = RamfluxClient::decode_generated_inner(&group_bytes)?;
    assert_eq!(group_identity.group_id.as_deref(), Some("g1"));
    assert_eq!(group_identity.group_epoch, Some(3));
    match group_content.value {
        Some(content::Value::Message(decoded)) => {
            assert_eq!(decoded.sealed_group, Some(sealed));
            assert_eq!(decoded.text, "");
        }
        other => return Err(format!("expected sealed group, got {other:?}").into()),
    }

    let forward = Forward {
        original: Some(named_ref()),
        original_display_name: Some("Alice".into()),
        origin_assertion: Vec::new(),
    };
    let forwarded = RamfluxClient::encode_generated_message(
        &mut stream,
        b"fwd-1".to_vec(),
        Message { text: "fwd".into(), forward: Some(forward.clone()), ..Default::default() },
    )?;
    let (_, forward_content) = RamfluxClient::decode_generated_inner(&forwarded)?;
    match forward_content.value {
        Some(content::Value::Message(decoded)) => assert_eq!(decoded.forward, Some(forward)),
        other => return Err(format!("expected forward, got {other:?}").into()),
    }

    let receipt = Receipt {
        targets: vec![named_ref()],
        state: ReceiptState::ReceiptDelivered as i32,
        at: 1_700_000_000,
        receiver: Some(author()),
    };
    let receipt_bytes =
        RamfluxClient::encode_generated_receipt(&mut stream, b"rcpt-1".to_vec(), receipt.clone())?;
    let scanned = validation::scan_inner(&receipt_bytes)?;
    assert_eq!(scanned.kind, g::KindId::KindReceipt as u32);
    assert_ne!(scanned.kind, g::KindId::KindMessage as u32);
    let (receipt_identity, receipt_content) =
        RamfluxClient::decode_generated_inner(&receipt_bytes)?;
    assert_eq!(
        receipt_identity.id,
        g::identity::derive(&author(), "c1", receipt_identity.device_sequence)?
    );
    match receipt_content.value {
        Some(content::Value::Receipt(ref decoded)) => {
            assert_eq!(decoded, &receipt);
            assert_eq!(decoded.state, ReceiptState::ReceiptDelivered as i32);
        }
        other => return Err(format!("expected user receipt, got {other:?}").into()),
    }
    assert_eq!(
        RamfluxClient::encode_generated_inner(receipt_identity, &receipt_content)?,
        receipt_bytes
    );
    Ok(())
}

#[test]
fn empty_message_ref_and_empty_event_id_are_refused() {
    let mut stream = stream();
    let empty = MessageRef { id: vec![], conversation_id: "c".into(), author_anchor: "a".into() };
    assert!(
        RamfluxClient::encode_generated_message(
            &mut stream,
            b"reply".to_vec(),
            Message { reply_to: Some(empty.clone()), ..Default::default() },
        )
        .is_err()
    );
    assert!(
        RamfluxClient::encode_generated_service(
            &mut stream,
            b"pin".to_vec(),
            Service {
                action: ServiceAction::ServicePinAdded as i32,
                target: Some(empty),
                ..Default::default()
            },
        )
        .is_err()
    );
    assert!(stream.next(vec![]).is_err());
}

#[test]
fn private_revision_nonce_blocks_erased_text_guessing_and_preserves_fanout() -> TestResult {
    let mut stream = stream();
    let original = RamfluxClient::encode_generated_message(
        &mut stream,
        b"revision".to_vec(),
        Message { text: "yes".into(), ..Default::default() },
    )?;
    let (identity, content) = RamfluxClient::decode_generated_inner(&original)?;
    let Some(content::Value::Message(message)) = content.value.as_ref() else {
        return Err("message missing".into());
    };
    assert_eq!(message.erasure_nonce.len(), 32);
    assert_ne!(message.erasure_nonce, vec![0; 32]);
    // Recipient fan-out reuses prepared content/exact Inner and its private entropy.
    assert_eq!(RamfluxClient::encode_generated_inner(identity.clone(), &content)?, original);
    let target = MessageRef {
        id: identity.id.clone(),
        conversation_id: identity.conversation_id.clone(),
        author_anchor: "anchor".into(),
    };
    let retained = crate::client::message_mutations::previous_content_digest(&target, &original)?;
    let mut confirmed_with_nonce = Vec::new();
    let mut confirmed_without_nonce = Vec::new();
    for guess in ["no", "yes", "maybe"] {
        let known = Message {
            text: guess.into(),
            erasure_nonce: message.erasure_nonce.clone(),
            ..Default::default()
        };
        if crate::client::message_mutations::digest_exact_content(&target, &known.encode_to_vec())?
            == retained
        {
            confirmed_with_nonce.push(guess);
        }
        let unknown = Message { text: guess.into(), ..Default::default() };
        if crate::client::message_mutations::digest_exact_content(
            &target,
            &unknown.encode_to_vec(),
        )? == retained
        {
            confirmed_without_nonce.push(guess);
        }
    }
    assert_eq!(confirmed_with_nonce, ["yes"], "known-nonce calibration must recover the old body");
    assert!(
        confirmed_without_nonce.is_empty(),
        "retained digest must not confirm a guess without erased entropy"
    );
    assert!(
        RamfluxClient::encode_generated_message(
            &mut stream,
            b"chosen-nonce".to_vec(),
            message.clone()
        )
        .is_err()
    );
    assert!(
        RamfluxClient::encode_generated_edit(
            &mut stream,
            b"chosen-replacement-nonce".to_vec(),
            g::Edit {
                target: Some(target.clone()),
                revision: 1,
                previous_content_digest: retained.to_vec(),
                replacement: Some(message.clone()),
            }
        )
        .is_err()
    );
    let replacement = RamfluxClient::encode_generated_message(
        &mut stream,
        b"replacement".to_vec(),
        Message { text: "yes".into(), ..Default::default() },
    )?;
    let (_, replacement) = RamfluxClient::decode_generated_inner(&replacement)?;
    let Some(content::Value::Message(replacement)) = replacement.value else {
        return Err("replacement missing".into());
    };
    assert_ne!(message.erasure_nonce, replacement.erasure_nonce);
    let mut public = content.clone();
    g::private_revision::redact_content(&mut public);
    let Some(content::Value::Message(public)) = public.value else {
        return Err("public message missing".into());
    };
    assert_eq!(public.erasure_nonce, [] as [u8; 0]);
    assert_eq!(public.text, "yes");
    let header = g::original_header::for_inner(&original, 10, 20)?;
    let mut changed = content.clone();
    if let Some(content::Value::Message(message)) = changed.value.as_mut() {
        message.erasure_nonce = vec![9; 32];
    }
    let changed = RamfluxClient::encode_generated_inner(identity, &changed)?;
    assert_eq!(
        g::original_header::for_inner(&changed, 10, 20)?,
        header,
        "retained header must not commit to erased entropy"
    );
    Ok(())
}

#[test]
fn private_revision_dm_and_group_digests_match_independent_vectors() -> TestResult {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("edit_digest_golden.json"))?;
    assert_eq!(rows.len(), 2);
    for row in rows {
        let target = MessageRef {
            id: ramflux_protocol::decode_base64url(row["target"].as_str().ok_or("target")?)?,
            conversation_id: row["conversation"].as_str().ok_or("conversation")?.into(),
            author_anchor: row["author"].as_str().ok_or("author")?.into(),
        };
        let exact =
            ramflux_protocol::decode_base64url(row["exact_message"].as_str().ok_or("message")?)?;
        let expected = ramflux_protocol::decode_base64url(row["digest"].as_str().ok_or("digest")?)?;
        assert_eq!(
            crate::client::message_mutations::digest_exact_content(&target, &exact)?.as_slice(),
            expected
        );
        let transcript =
            ramflux_protocol::decode_base64url(row["transcript"].as_str().ok_or("transcript")?)?;
        assert_eq!(blake3::hash(&transcript).as_bytes().as_slice(), expected);
    }
    Ok(())
}
