// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Genuine own-root signatures remain distinct from first-hand peer-origin proof.
use super::*;
use ramflux_crypto::native_origin::OwnSentAttestation;

pub(super) fn attest(
    author: &HistorySenderFixture,
    target: &HistorySenderFixture,
    nested: &g::Inner,
    now: u64,
) -> TestResult<OwnSentAttestation> {
    let nested_id = nested.identity.as_ref().ok_or("nested identity")?;
    let mut enclosing = identity(author, (1 << 63) | 3)?;
    enclosing.conversation_id = nested_id.conversation_id.clone();
    enclosing.id =
        g::identity::derive(&author.author, &enclosing.conversation_id, enclosing.device_sequence)?
            .to_vec();
    let sent = g::OwnSentMessage {
        message_id: ramflux_protocol::encode_base64url(&nested_id.id),
        exact_inner: nested.encode_to_vec(),
        context: Some(g::OwnContext {
            conversation_id: nested_id.conversation_id.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let value = g::Inner {
        layer: g::registry::COMPILED_LAYER,
        kind: 8,
        identity: Some(enclosing),
        body: g::Control {
            operation: 15,
            payload: Some(g::control::Payload::OwnMessageCopy(g::OwnMessageCopy {
                source: Some(author.author.clone()),
                target: Some(target.author.clone()),
                created_at: i64::try_from(now)?,
                expires_at: i64::try_from(now + 300)?,
                payload: Some(g::own_message_copy::Payload::Sent(sent)),
            })),
        }
        .encode_to_vec(),
    };
    let mut proof = retained(author, &value, now)?;
    proof.routing.kind = Kind::Control;
    Ok(OwnSentAttestation { exact_outer_inner: value.encode_to_vec(), origin: proof })
}
#[test]
fn direct_version_own_copy_preserves_nested_author_and_refuses_peer_origin_promotion() -> TestResult
{
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let (original, sibling) = same_root_senders(&root, now)?;
    let own = &original.author.account_anchor;
    let peer = ramflux_protocol::encode_base64url([45; 32]);
    let value = scoped(
        &original,
        &peer,
        1,
        g::content::Value::Message(g::Message {
            text: "own-root attested".into(),
            ..Default::default()
        }),
    )?;
    let proof = attest(&sibling, &original, &value, now)?;
    let raw = value.encode_to_vec();
    let checked = DirectVersion::verify(
        &raw,
        own,
        &peer,
        DirectEvidence::OwnCopy { attestation: &proof, original: None },
    )?;
    assert_eq!(
        checked.original(),
        value.identity.as_ref().ok_or("identity")?,
        "own copy relabeled original author/order as enclosing sibling"
    );
    assert_ne!(
        checked.original().author.as_ref(),
        Some(&sibling.author),
        "enclosing signer replaced nested author"
    );
    assert!(
        DirectVersion::verify(
            &raw,
            own,
            &peer,
            DirectEvidence::Received { origin: &proof.origin, original: None }
        )
        .is_err(),
        "own-copy control was promoted to peer Message origin"
    );
    assert!(
        DirectVersion::verify(
            &raw,
            &peer,
            own,
            DirectEvidence::OwnCopy { attestation: &proof, original: None }
        )
        .is_err(),
        "foreign own-root attestation accepted"
    );
    let mut clock = value.clone();
    clock.identity.as_mut().ok_or("identity")?.hlc += 1;
    assert!(
        DirectVersion::verify(
            &clock.encode_to_vec(),
            own,
            &peer,
            DirectEvidence::OwnCopy { attestation: &proof, original: None }
        )
        .is_err(),
        "changed nested clock escaped enclosing commitment"
    );
    Ok(())
}
#[test]
fn direct_version_own_copy_edit_needs_own_account_original_data() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let (author, sibling) = same_root_senders(&root, now)?;
    let own = &author.author.account_anchor;
    let peer = ramflux_protocol::encode_base64url([46; 32]);
    let value = scoped(
        &author,
        &peer,
        1,
        g::content::Value::Message(g::Message { text: "retired".into(), ..Default::default() }),
    )?;
    let original = value.identity.as_ref().ok_or("original")?;
    let edit = scoped(
        &author,
        &peer,
        2,
        g::content::Value::Edit(g::Edit {
            target: Some(g::MessageRef {
                id: original.id.clone(),
                conversation_id: original.conversation_id.clone(),
                author_anchor: own.clone(),
            }),
            revision: 1,
            previous_content_digest: vec![3; 32],
            replacement: Some(g::Message { text: "replacement".into(), ..Default::default() }),
        }),
    )?;
    let proof = attest(&sibling, &author, &edit, now)?;
    let raw = edit.encode_to_vec();
    let checked = DirectVersion::verify(
        &raw,
        own,
        &peer,
        DirectEvidence::OwnCopy { attestation: &proof, original: Some(original) },
    )?;
    assert_eq!(checked.original(), original, "own-account original identity/order lost");
    assert_eq!(checked.revision(), 1, "current revision lost");
    assert!(
        DirectVersion::verify(
            &raw,
            own,
            &peer,
            DirectEvidence::OwnCopy { attestation: &proof, original: None }
        )
        .is_err(),
        "missing original data reconstructed from Edit"
    );
    let mut wrong = original.clone();
    wrong.id = vec![6; 32];
    assert!(
        DirectVersion::verify(
            &raw,
            own,
            &peer,
            DirectEvidence::OwnCopy { attestation: &proof, original: Some(&wrong) }
        )
        .is_err(),
        "unbound original identity accepted"
    );
    Ok(())
}
