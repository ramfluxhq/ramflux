// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native signatures exercise the shared storage-facing version verifier.
use super::*;
use ramflux_crypto::native_origin::{DirectEvidence, DirectVersion, Kind, RetainedOrigin, Routing};

fn scoped(
    sender: &HistorySenderFixture,
    peer: &str,
    sequence: u64,
    content: g::content::Value,
) -> TestResult<g::Inner> {
    let mut value = inner(sender, sequence, content)?;
    let identity = value.identity.as_mut().ok_or("identity")?;
    identity.conversation_id = g::dm_scope::derive(&sender.author.account_anchor, peer)?;
    identity.id =
        g::identity::derive(&sender.author, &identity.conversation_id, sequence)?.to_vec();
    Ok(value)
}
fn retained(
    sender: &HistorySenderFixture,
    value: &g::Inner,
    now: u64,
) -> TestResult<RetainedOrigin> {
    let id = value.identity.as_ref().ok_or("identity")?;
    Ok(RetainedOrigin {
        evidence: evidence(sender, value, now)?,
        reported_inner: Vec::new(),
        routing: Routing {
            kind: Kind::Direct,
            conversation_id: id.conversation_id.clone(),
            message_id: ramflux_protocol::encode_base64url(&id.id),
            group_id: None,
            group_message_id: None,
            attachments: false,
        },
    })
}
#[test]
fn direct_version_received_binds_original_order_body_and_root_pair() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let peer = sender(&root, "direct-version-peer", now)?;
    let own = ramflux_protocol::encode_base64url([41; 32]);
    let value = scoped(
        &peer,
        &own,
        1,
        g::content::Value::Message(g::Message { text: "received".into(), ..Default::default() }),
    )?;
    let proof = retained(&peer, &value, now)?;
    let raw = value.encode_to_vec();
    let verify = |bytes: &[u8], own: &str, proof: &RetainedOrigin| {
        DirectVersion::verify(
            bytes,
            own,
            &peer.author.account_anchor,
            DirectEvidence::Received { origin: proof, original: None },
        )
    };
    let checked = verify(&raw, &own, &proof)?;
    assert_eq!(
        checked.original(),
        value.identity.as_ref().ok_or("identity")?,
        "original order was changed"
    );
    assert_eq!(checked.current(), checked.original(), "unmodified message gained a revision");
    assert_eq!(checked.revision(), 0, "message revision must be zero");
    assert!(
        verify(&raw, &ramflux_protocol::encode_base64url([42; 32]), &proof).is_err(),
        "foreign DM namespace accepted"
    );
    let mut clock = value.clone();
    clock.identity.as_mut().ok_or("identity")?.hlc += 1;
    assert!(verify(&clock.encode_to_vec(), &own, &proof).is_err(), "unsigned clock substituted");
    let mut route = proof.clone();
    route.routing.message_id = "other".into();
    assert!(verify(&raw, &own, &route).is_err(), "unbound routing id accepted");
    let mut body = value.clone();
    body.body =
        g::Message { text: "forged".into(), erasure_nonce: vec![0x71; 32], ..Default::default() }
            .encode_to_vec();
    assert!(verify(&body.encode_to_vec(), &own, &proof).is_err(), "unsigned body substituted");
    for (mode, class) in [("ephemeral", "message"), ("durable", "call_wake")] {
        let mut wrong = proof.clone();
        wrong.evidence = evidence_with_policy(&peer, &value, now, mode, class)?;
        assert!(verify(&raw, &own, &wrong).is_err(), "non-message delivery policy promoted");
    }
    Ok(())
}
#[test]
fn direct_version_edit_requires_independent_original_header_and_same_author() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let peer = sender(&root, "direct-version-edit", now)?;
    let own = ramflux_protocol::encode_base64url([43; 32]);
    let value = scoped(
        &peer,
        &own,
        1,
        g::content::Value::Message(g::Message { text: "retired".into(), ..Default::default() }),
    )?;
    let original = value.identity.as_ref().ok_or("original")?;
    let origin = evidence(&peer, &value, now)?;
    let header = OriginalHeader {
        exact_identity: original.encode_to_vec(),
        evidence: g::HistoryOriginalMetadataEvidence {
            canonical_sender_envelope: origin.canonical_sender_envelope,
            source_authority: origin.source_authority,
            layer: value.layer,
            ..Default::default()
        },
    };
    let edit = scoped(
        &peer,
        &own,
        2,
        g::content::Value::Edit(g::Edit {
            target: Some(g::MessageRef {
                id: original.id.clone(),
                conversation_id: original.conversation_id.clone(),
                author_anchor: peer.author.account_anchor.clone(),
            }),
            revision: 7,
            previous_content_digest: vec![3; 32],
            replacement: Some(g::Message { text: "replacement".into(), ..Default::default() }),
        }),
    )?;
    let proof = retained(&peer, &edit, now)?;
    let raw = edit.encode_to_vec();
    let checked = DirectVersion::verify(
        &raw,
        &own,
        &peer.author.account_anchor,
        DirectEvidence::Received { origin: &proof, original: Some(&header) },
    )?;
    assert_eq!(checked.original(), original, "edit replaced original identity/order");
    assert_eq!(checked.current(), edit.identity.as_ref().ok_or("edit")?, "edit revision lost");
    assert_eq!(checked.revision(), 7, "whole revision lost");
    assert!(
        DirectVersion::verify(
            &raw,
            &own,
            &peer.author.account_anchor,
            DirectEvidence::Received { origin: &proof, original: None }
        )
        .is_err(),
        "missing original proof fabricated"
    );
    let mut changed = header.clone();
    let mut id = original.clone();
    id.hlc += 1;
    changed.exact_identity = id.encode_to_vec();
    assert!(
        DirectVersion::verify(
            &raw,
            &own,
            &peer.author.account_anchor,
            DirectEvidence::Received { origin: &proof, original: Some(&changed) }
        )
        .is_err(),
        "unsigned original clock accepted"
    );
    Ok(())
}

#[test]
fn direct_version_authored_is_same_account_data_and_rejects_received_substitution() -> TestResult {
    use ramflux_crypto::native_origin::OwnAuthoredCapture;
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let author = sender(&root, "direct-version-authored", now)?;
    let own = &author.author.account_anchor;
    let peer = ramflux_protocol::encode_base64url([44; 32]);
    let value = scoped(
        &author,
        &peer,
        1,
        g::content::Value::Message(g::Message { text: "own history".into(), ..Default::default() }),
    )?;
    let original = value.identity.as_ref().ok_or("original")?;
    let capture = OwnAuthoredCapture {
        target: original.id.clone(),
        current: original.id.clone(),
        original: original.clone(),
        sent: g::OwnSentMessage {
            message_id: ramflux_protocol::encode_base64url(&original.id),
            exact_inner: value.encode_to_vec(),
            context: Some(g::OwnContext {
                conversation_id: original.conversation_id.clone(),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    let checked = DirectVersion::verify(
        &capture.sent.exact_inner,
        own,
        &peer,
        DirectEvidence::Authored(&capture),
    )?;
    assert_eq!(checked.original(), original, "own original author/order changed");
    assert!(
        DirectVersion::verify(
            &capture.sent.exact_inner,
            &peer,
            own,
            DirectEvidence::Authored(&capture)
        )
        .is_err(),
        "peer history mislabeled as own capture"
    );
    let mut mixed = value.clone();
    mixed.identity.as_mut().ok_or("identity")?.hlc += 1;
    assert!(
        DirectVersion::verify(
            &mixed.encode_to_vec(),
            own,
            &peer,
            DirectEvidence::Authored(&capture)
        )
        .is_err(),
        "capture accepted different exact bytes"
    );
    let mut wrong = capture;
    wrong.original.hlc += 1;
    assert!(
        DirectVersion::verify(
            &wrong.sent.exact_inner,
            own,
            &peer,
            DirectEvidence::Authored(&wrong)
        )
        .is_err(),
        "own original order detached from body"
    );
    Ok(())
}
