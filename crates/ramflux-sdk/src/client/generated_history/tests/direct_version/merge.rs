// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Whole native version resolution with genuine signatures and original immutable order.
use super::record::encode;
use super::*;
use ramflux_storage::FullDirectHistory;

fn ordinary(
    author: &HistorySenderFixture,
    own: &str,
    value: &g::Inner,
    now: u64,
) -> TestResult<FullDirectHistory> {
    Ok(FullDirectHistory::received(
        own,
        &author.author.account_anchor,
        g::HistoryItem {
            exact_inner: value.encode_to_vec(),
            source_evidence: Some(evidence(author, value, now)?),
            ..Default::default()
        },
    )?)
}
fn edited(
    author: &HistorySenderFixture,
    own: &str,
    original: &g::Inner,
    sequence: u64,
    revision: u64,
    now: u64,
) -> TestResult<FullDirectHistory> {
    let id = original.identity.as_ref().ok_or("original identity")?;
    let header = evidence(author, original, now)?;
    let value = scoped(
        author,
        own,
        sequence,
        g::content::Value::Edit(g::Edit {
            target: Some(g::MessageRef {
                id: id.id.clone(),
                conversation_id: id.conversation_id.clone(),
                author_anchor: author.author.account_anchor.clone(),
            }),
            revision,
            previous_content_digest: vec![3; 32],
            replacement: Some(g::Message {
                text: format!("revision {revision}, event {sequence}"),
                ..Default::default()
            }),
        }),
    )?;
    Ok(FullDirectHistory::received(
        own,
        &author.author.account_anchor,
        g::HistoryItem {
            exact_inner: value.encode_to_vec(),
            source_evidence: Some(evidence(author, &value, now)?),
            exact_original_identity: id.encode_to_vec(),
            original_metadata_evidence: Some(g::HistoryOriginalMetadataEvidence {
                canonical_sender_envelope: header.canonical_sender_envelope,
                source_authority: header.source_authority,
                layer: original.layer,
                ..Default::default()
            }),
            ..Default::default()
        },
    )?)
}
#[test]
fn direct_merge_selects_a_whole_newer_revision_and_preserves_original_order() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let author = sender(&root, "native-merge-peer", now)?;
    let own = ramflux_protocol::encode_base64url([61; 32]);
    let original = scoped(
        &author,
        &own,
        1,
        g::content::Value::Message(g::Message {
            text: "original merge body".into(),
            ..Default::default()
        }),
    )?;
    let base = ordinary(&author, &own, &original, now)?;
    let old = edited(&author, &own, &original, 2, 7, now)?;
    let new = edited(&author, &own, &original, 3, 9, now)?;
    let chosen = base.merge(&old, &own)?.merge(&new, &own)?;
    assert_eq!(
        *encode(chosen)?,
        *encode(&new)?,
        "merge assembled fields instead of selecting the complete version"
    );
    assert_eq!(
        chosen.verify(&own)?.original(),
        original.identity.as_ref().ok_or("original")?,
        "edit replaced original order"
    );
    assert_eq!(chosen.exact_inner(), new.exact_inner(), "new version body/proof detached");
    assert_eq!(
        *encode(new.merge(&old, &own)?)?,
        *encode(&new)?,
        "stale source revision replaced the current version"
    );
    let first = edited(&author, &own, &original, 4, 10, now)?;
    let second = edited(&author, &own, &original, 5, 10, now)?;
    let a = first.verify(&own)?;
    let b = second.verify(&own)?;
    let expected = if b.current().id > a.current().id { &second } else { &first };
    assert_eq!(
        *encode(first.merge(&second, &own)?)?,
        *encode(expected)?,
        "native Edit tie rule changed"
    );
    Ok(())
}
#[test]
fn direct_merge_equal_body_keeps_preferred_original_contributor_proof() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let author = sender(&root, "native-merge-preferred", now)?;
    let own = ramflux_protocol::encode_base64url([62; 32]);
    let original = scoped(
        &author,
        &own,
        1,
        g::content::Value::Message(g::Message {
            text: "same native body".into(),
            ..Default::default()
        }),
    )?;
    let b = ordinary(&author, &own, &original, now)?;
    let a = ordinary(&author, &own, &original, now)?;
    assert_ne!(
        *super::record::encode(&a)?,
        *super::record::encode(&b)?,
        "fixture lacks independent valid report openings/signatures"
    );
    assert_eq!(
        *encode(b.merge(&a, &own)?)?,
        *encode(&b)?,
        "matching versions replaced preferred B original proof"
    );
    assert_eq!(
        *encode(a.merge(&b, &own)?)?,
        *encode(&a)?,
        "matching versions did not preserve explicit preference"
    );
    Ok(())
}
#[test]
fn direct_merge_refuses_even_valid_signer_equivocation_and_original_clock_forks() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let author = sender(&root, "native-merge-fork", now)?;
    let own = ramflux_protocol::encode_base64url([63; 32]);
    let original = scoped(
        &author,
        &own,
        1,
        g::content::Value::Message(g::Message {
            text: "original signed version".into(),
            ..Default::default()
        }),
    )?;
    let first = ordinary(&author, &own, &original, now)?;
    let mut body = original.clone();
    let mut message = g::Message::decode(body.body.as_slice())?;
    message.text = "different but genuinely signed body".into();
    body.body = message.encode_to_vec();
    let equivocation = ordinary(&author, &own, &body, now)?;
    assert!(
        matches!(
            first.merge(&equivocation, &own),
            Err(ramflux_storage::StorageError::PairingField("TransferConflict"))
        ),
        "same-event signer equivocation selected a body"
    );
    let mut clock = original;
    clock.identity.as_mut().ok_or("identity")?.hlc += 1;
    let fork = ordinary(&author, &own, &clock, now)?;
    assert!(
        matches!(
            first.merge(&fork, &own),
            Err(ramflux_storage::StorageError::PairingField("TransferConflict"))
        ),
        "same event id with a separately signed different HLC was merged"
    );
    Ok(())
}

#[test]
fn direct_merge_refuses_original_signed_issuance_fork_with_identical_body_and_hlc() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let author = sender(&root, "native-merge-original-metadata", now)?;
    let own = ramflux_protocol::encode_base64url([64; 32]);
    let original = scoped(
        &author,
        &own,
        1,
        g::content::Value::Message(g::Message {
            text: "same event, different signed original metadata".into(),
            ..Default::default()
        }),
    )?;
    let first = ordinary(&author, &own, &original, now)?;
    let fork = ordinary(&author, &own, &original, now + 1)?;
    assert!(
        matches!(
            first.merge(&fork, &own),
            Err(ramflux_storage::StorageError::PairingField("TransferConflict"))
        ),
        "different signed original issuance/lifetime silently replaced immutable metadata"
    );
    Ok(())
}
