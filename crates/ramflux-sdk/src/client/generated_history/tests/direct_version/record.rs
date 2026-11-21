// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed private record admission uses real native signers, not fabricated origin MACs.
use super::*;
use ramflux_storage::FullDirectHistory;
use zeroize::Zeroizing;
const LENGTH_AT: usize = 4 + 1 + 2 * 43;
const ITEM_AT: usize = LENGTH_AT + 4;
const TOO_MANY: usize = ramflux_storage::FULL_DIRECT_HISTORY_LIMIT + 1;

pub(super) fn encode(value: &FullDirectHistory) -> TestResult<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    value.write(&mut *bytes)?;
    Ok(bytes)
}
#[test]
fn direct_record_received_round_trip_keeps_signed_order_and_rejects_other_account() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let peer = sender(&root, "direct-record-peer", now)?;
    let own = ramflux_protocol::encode_base64url([51; 32]);
    let inner = scoped(
        &peer,
        &own,
        1,
        g::content::Value::Message(g::Message {
            text: "received record".into(),
            ..Default::default()
        }),
    )?;
    let item = g::HistoryItem {
        exact_inner: inner.encode_to_vec(),
        source_evidence: Some(evidence(&peer, &inner, now)?),
        ..Default::default()
    };
    let value = FullDirectHistory::received(&own, &peer.author.account_anchor, item.clone())?;
    let bytes = encode(&value)?;
    let decoded = FullDirectHistory::read(&bytes, &own)?;
    assert_eq!(decoded.exact_inner(), inner.encode_to_vec(), "exact native bytes rewritten");
    assert_eq!(decoded.peer_root(), peer.author.account_anchor, "peer binding changed");
    assert_eq!(
        decoded.verify(&own)?.original(),
        inner.identity.as_ref().ok_or("identity")?,
        "signed original order changed"
    );
    assert!(
        FullDirectHistory::read(&bytes, &ramflux_protocol::encode_base64url([52; 32])).is_err(),
        "embedded own root used instead of authenticated account"
    );
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(
        FullDirectHistory::read(&trailing, &own).is_err(),
        "trailing private record bytes accepted"
    );
    let mut changed = item;
    let mut body = inner;
    body.identity.as_mut().ok_or("identity")?.hlc += 1;
    changed.exact_inner = body.encode_to_vec();
    assert!(
        FullDirectHistory::received(&own, &peer.author.account_anchor, changed).is_err(),
        "unsigned original clock accepted"
    );
    Ok(())
}
#[test]
fn direct_record_authored_projects_transport_and_refuses_unknown_protobuf() -> TestResult {
    use ramflux_crypto::native_origin::OwnAuthoredCapture;
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let author = sender(&root, "direct-record-authored", now)?;
    let own = &author.author.account_anchor;
    let peer = ramflux_protocol::encode_base64url([53; 32]);
    let inner = scoped(
        &author,
        &peer,
        1,
        g::content::Value::Message(g::Message {
            text: "authored record".into(),
            ..Default::default()
        }),
    )?;
    let id = inner.identity.as_ref().ok_or("identity")?;
    let capture = OwnAuthoredCapture {
        target: id.id.clone(),
        current: id.id.clone(),
        original: id.clone(),
        sent: g::OwnSentMessage {
            envelope_id: "never-import-outbox-marker".into(),
            sender_id: "never-import-execution-label".into(),
            original_recipients: vec!["never-import-delivery-target".into()],
            message_id: ramflux_protocol::encode_base64url(&id.id),
            exact_inner: inner.encode_to_vec(),
            context: Some(g::OwnContext {
                conversation_id: id.conversation_id.clone(),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    let value = FullDirectHistory::authored(own, &peer, &capture)?;
    let bytes = encode(&value)?;
    for canary in [
        "never-import-outbox-marker",
        "never-import-execution-label",
        "never-import-delivery-target",
    ] {
        assert!(
            !bytes.windows(canary.len()).any(|part| part == canary.as_bytes()),
            "execution/transport field copied into portable history"
        );
    }
    assert_eq!(
        FullDirectHistory::read(&bytes, own)?.verify(own)?.original(),
        id,
        "own original order changed"
    );
    // NDH1 + class + two canonical 43-byte roots + the item length.
    let length = u32::from_be_bytes(bytes.get(LENGTH_AT..ITEM_AT).ok_or("length")?.try_into()?);
    let end = ITEM_AT + usize::try_from(length)?;
    let mut unknown = bytes.get(..end).ok_or("item")?.to_vec();
    unknown.extend_from_slice(&[0x88, 0x01, 0x01]); // Unknown field17, canonical varint.
    unknown.extend_from_slice(bytes.get(end..).ok_or("proof")?);
    unknown
        .get_mut(LENGTH_AT..ITEM_AT)
        .ok_or("length")?
        .copy_from_slice(&(length + 3).to_be_bytes());
    assert!(
        FullDirectHistory::read(&unknown, own).is_err(),
        "ignored protobuf field accepted by private codec"
    );
    Ok(())
}
#[test]
fn direct_record_own_copy_keeps_attestation_and_refuses_unknown_nested_fields() -> TestResult {
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let (author, sibling) = same_root_senders(&root, now)?;
    let own = &author.author.account_anchor;
    let peer = ramflux_protocol::encode_base64url([54; 32]);
    let inner = scoped(
        &author,
        &peer,
        1,
        g::content::Value::Message(g::Message {
            text: "attested record".into(),
            ..Default::default()
        }),
    )?;
    let original = inner.identity.as_ref().ok_or("identity")?;
    let proof = super::own_copy::attest(&sibling, &author, &inner, now)?;
    let mut unknown = serde_json::to_value(&proof)?;
    unknown["origin"]["new_permission"] = json!(true);
    let value = FullDirectHistory::own_copy(own, &peer, inner.encode_to_vec(), original, proof)?;
    let bytes = encode(&value)?;
    assert_eq!(
        FullDirectHistory::read(&bytes, own)?.verify(own)?.original(),
        original,
        "enclosing sibling replaced original author"
    );
    let length = u32::from_be_bytes(bytes.get(LENGTH_AT..ITEM_AT).ok_or("length")?.try_into()?);
    let end = ITEM_AT + usize::try_from(length)?;
    let bad = serde_json::to_vec(&unknown)?;
    let mut changed = bytes.get(..end).ok_or("item")?.to_vec();
    changed.extend_from_slice(&u32::try_from(bad.len())?.to_be_bytes());
    changed.extend_from_slice(&bad);
    assert!(
        FullDirectHistory::read(&changed, own).is_err(),
        "unknown nested attestation permission silently ignored"
    );
    Ok(())
}
#[test]
fn direct_record_refuses_oversize_and_unknown_version() {
    let own = ramflux_protocol::encode_base64url([55; 32]);
    assert!(
        FullDirectHistory::read(&vec![0; TOO_MANY], &own).is_err(),
        "private record bound ignored"
    );
    assert!(
        FullDirectHistory::read(b"NDH0", &own).is_err(),
        "older private format silently converted"
    );
}

#[test]
fn direct_record_edited_received_keeps_original_header_without_retired_plaintext() -> TestResult {
    const RETIRED: &str = "retired direct message plaintext must not survive this record";
    let root = Root::new()?;
    let now = crate::custody::network_now()?;
    let peer = sender(&root, "direct-record-edited", now)?;
    let own = ramflux_protocol::encode_base64url([56; 32]);
    let original = scoped(
        &peer,
        &own,
        1,
        g::content::Value::Message(g::Message { text: RETIRED.into(), ..Default::default() }),
    )?;
    let id = original.identity.as_ref().ok_or("original identity")?;
    let header = evidence(&peer, &original, now)?;
    let edit = scoped(
        &peer,
        &own,
        2,
        g::content::Value::Edit(g::Edit {
            target: Some(g::MessageRef {
                id: id.id.clone(),
                conversation_id: id.conversation_id.clone(),
                author_anchor: peer.author.account_anchor.clone(),
            }),
            revision: 7,
            previous_content_digest: vec![3; 32],
            replacement: Some(g::Message {
                text: "current replacement".into(),
                ..Default::default()
            }),
        }),
    )?;
    let item = g::HistoryItem {
        exact_inner: edit.encode_to_vec(),
        source_evidence: Some(evidence(&peer, &edit, now)?),
        exact_original_identity: id.encode_to_vec(),
        original_metadata_evidence: Some(g::HistoryOriginalMetadataEvidence {
            canonical_sender_envelope: header.canonical_sender_envelope,
            source_authority: header.source_authority,
            layer: original.layer,
            ..Default::default()
        }),
        ..Default::default()
    };
    let value = FullDirectHistory::received(&own, &peer.author.account_anchor, item)?;
    let bytes = encode(&value)?;
    assert!(
        !bytes.windows(RETIRED.len()).any(|part| part == RETIRED.as_bytes()),
        "retired plaintext was reconstructed into portable record"
    );
    let decoded = FullDirectHistory::read(&bytes, &own)?;
    let checked = decoded.verify(&own)?;
    assert_eq!(checked.original(), id, "original signed order replaced by Edit order");
    assert_eq!(
        checked.current(),
        edit.identity.as_ref().ok_or("edit identity")?,
        "current Edit identity changed"
    );
    assert_eq!(checked.revision(), 7, "complete revision lost");
    assert_eq!(decoded.exact_inner(), edit.encode_to_vec(), "current native bytes rewritten");
    Ok(())
}
