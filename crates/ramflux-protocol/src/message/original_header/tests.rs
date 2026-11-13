// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::message as g;
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn original() -> Result<g::Inner, validation::ValidationError> {
    let author = g::QualifiedDevice {
        account_anchor: "root".into(),
        device_id: "device".into(),
        device_epoch: 7,
    };
    Ok(g::Inner {
        layer: 2,
        kind: 1,
        identity: Some(g::EventIdentity {
            id: g::identity::derive(&author, "conversation", 3)?.to_vec(),
            conversation_id: "conversation".into(),
            author: Some(author),
            device_sequence: 3,
            hlc: 9,
            ..Default::default()
        }),
        body: g::Message { text: "erased body".into(), ..Default::default() }.encode_to_vec(),
    })
}

#[test]
fn message_receipt_requires_matching_metadata_commitment() -> TestResult {
    let inner = original()?.encode_to_vec();
    let mut ext = crate::Ext::default();
    assert_eq!(
        verify_inner_extension(&ext, &inner, 100, 400),
        Err(EvidenceError::OriginEvidenceMissing)
    );
    ext.ext.insert(EXT_KEY.into(), serde_json::json!(crate::encode_base64url([0; 32])));
    assert_eq!(
        verify_inner_extension(&ext, &inner, 100, 400),
        Err(EvidenceError::OriginCommitmentMismatch)
    );
    ext.ext.insert(
        EXT_KEY.into(),
        serde_json::json!(for_inner(&inner, 100, 400)?.ok_or("Message required")?),
    );
    verify_inner_extension(&ext, &inner, 100, 400)?;
    assert_eq!(
        verify_inner_extension(&ext, &inner, 101, 400),
        Err(EvidenceError::OriginCommitmentMismatch)
    );
    let mut reaction = original()?;
    reaction.kind = 5;
    reaction.body.clear();
    assert_eq!(
        verify_inner_extension(&ext, &reaction.encode_to_vec(), 100, 400),
        Err(EvidenceError::OriginCommitmentMismatch)
    );
    Ok(())
}

#[test]
fn original_header_never_commits_body_fields() -> TestResult {
    let mut inner = original()?;
    let first = for_inner(&inner.encode_to_vec(), 100, 400)?;
    inner.body = g::Message {
        text: "replacement body".into(),
        reply_to: Some(g::MessageRef {
            id: vec![9; 32],
            conversation_id: "another".into(),
            author_anchor: "another".into(),
        }),
        ..Default::default()
    }
    .encode_to_vec();
    assert_eq!(first, for_inner(&inner.encode_to_vec(), 100, 400)?);
    assert!(first.is_some());
    let identity = inner.identity.ok_or("identity")?.encode_to_vec();
    let transcript = transcript(&Header {
        layer: 2,
        kind: 1,
        exact_identity: &identity,
        issued_at: 100,
        expires_at: 400,
        group: None,
    })?;
    let vector: serde_json::Value = serde_json::from_str(include_str!("vectors.json"))?;
    assert_eq!(crate::encode_base64url(&transcript), vector["transcript_b64"]);
    assert_eq!(first.ok_or("commitment")?, vector["commitment"]);
    Ok(())
}

#[test]
fn retained_identity_refuses_unknown_alternate_and_oversized_bytes() -> TestResult {
    let identity = original()?.identity.ok_or("identity")?.encode_to_vec();
    decode_identity(&identity)?;
    let mut unknown = identity.clone();
    unknown.extend([0x80, 0x01, 0x01]);
    assert_eq!(decode_identity(&unknown), Err(EvidenceError::OriginCommitmentMismatch));
    let mut alternate = identity;
    alternate.splice(1..2, [0xa0, 0x00]);
    assert_eq!(decode_identity(&alternate), Err(EvidenceError::OriginCommitmentMismatch));
    assert_eq!(
        decode_identity(&vec![1; MAX_IDENTITY_BYTES + 1]),
        Err(EvidenceError::OriginCommitmentMismatch)
    );
    Ok(())
}

#[test]
fn edited_group_header_requires_exact_redacted_group_binding() -> TestResult {
    let mut identity = original()?.identity.ok_or("identity")?;
    identity.group_id = Some("group".into());
    identity.group_epoch = Some(8);
    let mut group = g::OriginalGroupBinding {
        group_id: "group".into(),
        author: identity.author.clone(),
        key_epoch: 8,
        group_state_hash: vec![5; 32],
    };
    let exact = identity.encode_to_vec();
    let first = commitment(&Header {
        layer: 2,
        kind: 1,
        exact_identity: &exact,
        issued_at: 100,
        expires_at: 400,
        group: Some(&group),
    })?;
    group.group_state_hash[0] ^= 1;
    assert_ne!(
        first,
        commitment(&Header {
            layer: 2,
            kind: 1,
            exact_identity: &exact,
            issued_at: 100,
            expires_at: 400,
            group: Some(&group)
        })?
    );
    group.author.as_mut().ok_or("author")?.device_epoch = 9;
    assert_eq!(
        commitment(&Header {
            layer: 2,
            kind: 1,
            exact_identity: &exact,
            issued_at: 100,
            expires_at: 400,
            group: Some(&group)
        }),
        Err(EvidenceError::OriginCommitmentMismatch)
    );
    Ok(())
}

#[test]
fn edited_history_evidence_fields_have_permanent_layer_bindings() -> TestResult {
    let item = g::HistoryItem {
        exact_inner: vec![1],
        exact_original_identity: vec![2],
        source_evidence: Some(g::HistoryOriginEvidence {
            canonical_sender_envelope: vec![3],
            report_opening: vec![4],
            group_plaintext: vec![5],
            group_opening: vec![6],
            ..Default::default()
        }),
        original_metadata_evidence: Some(g::HistoryOriginalMetadataEvidence {
            canonical_sender_envelope: vec![7],
            source_authority: Some(g::NativeCustodyManifest { canonical: vec![8] }),
            group_membership: Some(g::NativeGroupSnapshot { canonical: vec![9] }),
            group_binding: Some(g::OriginalGroupBinding {
                group_id: "group".into(),
                author: Some(g::QualifiedDevice {
                    account_anchor: "root".into(),
                    device_id: "device".into(),
                    device_epoch: 1,
                }),
                key_epoch: 2,
                group_state_hash: vec![3; 32],
            }),
            layer: 2,
        }),
        ..Default::default()
    };
    assert_eq!(
        g::validation::scan_message("HistoryItem", &item.encode_to_vec(), 2)?,
        g::validation::ScanOutcome::Supported
    );
    Ok(())
}

#[test]
fn edited_group_history_item_drops_wrapper_commitments() -> TestResult {
    let mut identity = original()?.identity.ok_or("identity")?;
    identity.group_id = Some("group".into());
    identity.group_epoch = Some(8);
    let group = g::GroupSealedContent {
        group_id: "group".into(),
        author: identity.author.clone(),
        key_epoch: 8,
        group_state_hash: vec![1; 32],
        content_commitment: b"retired-content-commitment".to_vec(),
        ciphertext_hash: b"retired-ciphertext-hash".to_vec(),
        key_commitment: b"retired-key-commitment".to_vec(),
        franking_commitment: b"retired-franking-commitment".to_vec(),
        nonce: b"retired-nonce".to_vec(),
        ratchet_public_key: b"retired-ratchet-key".to_vec(),
        ciphertext: b"retired-ciphertext".to_vec(),
        ..Default::default()
    };
    let mut retained = group_binding(&group);
    let retained_bytes = retained.encode_to_vec();
    for erased in [
        &group.content_commitment,
        &group.ciphertext_hash,
        &group.key_commitment,
        &group.franking_commitment,
        &group.nonce,
        &group.ratchet_public_key,
        &group.ciphertext,
    ] {
        assert!(
            !retained_bytes.windows(erased.len()).any(|bytes| bytes == erased),
            "retained erased wrapper bytes"
        );
    }
    let encoded = serde_json::to_value(&retained)?;
    assert_eq!(encoded.as_object().ok_or("object")?.len(), 4);
    for forbidden in [
        "contentCommitment",
        "ciphertextHash",
        "keyCommitment",
        "frankingCommitment",
        "nonce",
        "ratchetPublicKey",
        "ciphertext",
    ] {
        assert!(encoded.get(forbidden).is_none(), "retained {forbidden}");
    }
    let exact = identity.encode_to_vec();
    let mut ext = crate::Ext::default();
    ext.ext.insert(
        EXT_KEY.into(),
        serde_json::json!(commitment(&Header {
            layer: 2,
            kind: 1,
            exact_identity: &exact,
            issued_at: 100,
            expires_at: 400,
            group: Some(&retained)
        })?),
    );
    retained.group_state_hash[0] ^= 1;
    assert_eq!(
        verify_extension(
            &ext,
            1,
            Some(&Header {
                layer: 2,
                kind: 1,
                exact_identity: &exact,
                issued_at: 100,
                expires_at: 400,
                group: Some(&retained)
            })
        ),
        Err(EvidenceError::OriginCommitmentMismatch)
    );
    Ok(())
}
