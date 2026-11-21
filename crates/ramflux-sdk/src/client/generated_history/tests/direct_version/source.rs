// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual SDK/native storage reads, independently assembled portable evidence and erasure.
use super::*;

fn installed_edit(root: &Root) -> TestResult<(RamfluxClient, g::HistoryItem)> {
    let client = empty_import_receiver(root)?;
    let own = client.own_account_anchor()?;
    let now = crate::custody::network_now()?;
    let peer = sender(root, "direct-source-peer", now)?;
    let original = scoped(
        &peer,
        &own,
        1,
        g::content::Value::Message(g::Message {
            text: "retired source body".into(),
            ..Default::default()
        }),
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
                text: "current source body".into(),
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
    assert!(apply_claim(&client, &item)?, "native history setup failed to apply");
    Ok((client, item))
}
fn assert_product_body(client: &RamfluxClient, original: &g::EventIdentity) -> TestResult {
    let page = client.generated_message_page(&original.conversation_id, None, 10)?;
    let [update] = page.messages.as_slice() else {
        return Err("native reader must expose one original row".into());
    };
    assert_eq!(
        update.identity.as_ref(),
        Some(original),
        "product reader relabeled original identity/order"
    );
    assert!(
        matches!(update.state.as_ref(),Some(g::message_update::State::Content(g::Content {value:Some(g::content::Value::Message(message))})) if message.text=="current source body"),
        "product reader did not expose current replacement"
    );
    Ok(())
}
#[test]
fn direct_source_reads_actual_sdk_edit_and_preserves_original_native_order() -> TestResult {
    let root = Root::new()?;
    let (client, item) = installed_edit(&root)?;
    let original = g::original_header::decode_identity(&item.exact_original_identity)?;
    let id = ramflux_protocol::encode_base64url(&original.id);
    assert_product_body(&client, &original)?;
    let record =
        client.account_db()?.read_full_direct_history(&id)?.ok_or("missing source record")?;
    assert_eq!(
        record.exact_inner(),
        item.exact_inner,
        "source snapshot changed exact current bytes"
    );
    assert_eq!(
        record.verify(&client.own_account_anchor()?)?.original(),
        &original,
        "source snapshot replaced original order"
    );
    let encoded = super::record::encode(&record)?;
    assert_eq!(
        ramflux_storage::FullDirectHistory::read(&encoded, &client.own_account_anchor()?)?
            .verify(&client.own_account_anchor()?)?
            .original(),
        &original,
        "independent record decoder changed actual source version"
    );
    assert_product_body(&client, &original)?;
    Ok(())
}
#[test]
fn direct_source_erasure_does_not_reconstruct_a_retired_header_or_content() -> TestResult {
    let root = Root::new()?;
    let (client, item) = installed_edit(&root)?;
    let original = g::original_header::decode_identity(&item.exact_original_identity)?;
    let id = ramflux_protocol::encode_base64url(&original.id);
    client.delete_direct_message(
        &original.conversation_id,
        &id,
        "local",
        &ramflux_protocol::hash_base64url("ramflux.test.direct-source-delete.v1", b"erase"),
    )?;
    assert!(
        client.account_db()?.read_full_direct_history(&id)?.is_none(),
        "erased content exported as live history"
    );
    let page = client.generated_message_page(&original.conversation_id, None, 10)?;
    assert!(
        page.messages
            .iter()
            .all(|update| matches!(update.state, Some(g::message_update::State::Tombstone(_)))),
        "ordinary product reader resurrected erased content"
    );
    assert!(!apply_claim(&client, &item)?, "source inspection weakened ordinary erasure denial");
    Ok(())
}
#[test]
fn direct_source_missing_original_evidence_refuses_without_changing_product_data() -> TestResult {
    let root = Root::new()?;
    let (client, item) = installed_edit(&root)?;
    let original = g::original_header::decode_identity(&item.exact_original_identity)?;
    let id = ramflux_protocol::encode_base64url(&original.id);
    client.account_db()?.remove_actor_state(&format!("routed/original-header/{id}"))?;
    assert!(
        client.account_db()?.read_full_direct_history(&id).is_err(),
        "source fabricated missing original evidence"
    );
    assert_eq!(
        client.account_db()?.message_content(&id)?,
        Some(item.exact_inner),
        "refused source inspection changed live body"
    );
    assert_product_body(&client, &original)?;
    Ok(())
}

#[tokio::test]
async fn direct_source_reads_real_sdk_authored_capture_and_refuses_conflicting_body() -> TestResult
{
    use crate::client::native_test_support::Fixture;
    use crate::client::own_sent_message::OwnSentInput;
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let own=Fixture::new("direct-source-own").await?;
        let peer=Fixture::new("direct-source-own-peer").await?;
        own.accept_peer(&peer)?;
        let own_root=own.client.own_account_anchor()?;
        let peer_root=peer.client.own_account_anchor()?;
        let conversation=g::dm_scope::derive(&own_root,&peer_root)?;
        let db=own.client.account_db()?;
        db.persist_client_record("conversation",&conversation,&json!({"kind":"direct","group_id":null,"participants":[own.manifest.principal_id,peer.manifest.principal_id],"participant_roots":[own_root,peer_root]}))?;
        let original=own.client.allocate_generated_identity(&conversation,1000,false)?;
        let id=ramflux_protocol::encode_base64url(&original.id);
        let exact=RamfluxClient::encode_generated_inner(original.clone(),&g::Content {value:Some(g::content::Value::Message(g::Message {text:"actual authored source".into(), ..Default::default()}))})?;
        db.write_transaction(||->TestResult {
            db.import_direct_message_projection(ramflux_storage::DirectMessageWrite {conversation_id:&conversation,message_id:&id,sender_id:&own.manifest.principal_id,encrypted_body:&[],metadata:&ramflux_storage::MessageMetadata::default(),created_at:1})?;
            own.client.capture_own_authored_revision(OwnSentInput {envelope:"actual-authored-source-envelope",conversation:&conversation,message:&id,sender:&own.manifest.principal_id,original_recipients:std::slice::from_ref(&peer.manifest.principal_id),group:None,peer:Some(&peer.manifest.principal_id),body:&exact,ciphertext:&[],at:1})?;
            Ok(())
        })?;
        assert!(db.read_full_direct_history(&id).is_err(),"incomplete authored capture became a completed native message");
        assert!(db.actor_state_exists(&format!("own-history/capture/{id}"))?,"incomplete source inspection deleted authored data");
        db.write_transaction(||->TestResult {
            db.store_message_content(&conversation,&id,&exact)?;
            db.persist_message_actor_state(&id,&format!("routed/generated-identity/{id}"),&original)?;
            Ok(())
        })?;
        let record=db.read_full_direct_history(&id)?.ok_or("missing authored source")?;
        assert_eq!(record.verify(&own_root)?.original(),&original,"SDK capture original ownership/order changed");
        assert_eq!(record.exact_inner(),exact,"SDK capture body changed");
        let page=own.client.generated_message_page(&conversation,None,10)?;
        let [update]=page.messages.as_slice() else {return Err("missing product own message".into())};
        assert_eq!(update.identity.as_ref(),Some(&original),"product own author changed");
        assert!(matches!(update.state.as_ref(),Some(g::message_update::State::Content(g::Content {value:Some(g::content::Value::Message(message))})) if message.text=="actual authored source"),"product reader body changed");
        let key=format!("own-history/capture/{id}");
        let mut capture=db.load_actor_state::<ramflux_crypto::native_origin::OwnAuthoredCapture>(&key)?.ok_or("capture")?;
        let mut wrong=g::Inner::decode(capture.sent.exact_inner.as_slice())?;
        let mut message=g::Message::decode(wrong.body.as_slice())?;
        message.text="conflicting captured body".into();
        wrong.body=message.encode_to_vec();
        capture.sent.exact_inner=wrong.encode_to_vec();
        db.persist_message_actor_state(&id,&key,&capture)?;
        assert!(db.read_full_direct_history(&id).is_err(),"conflicting source capture silently replaced the visible native body");
        assert_eq!(db.message_content(&id)?,Some(exact),"refusal changed live native content");
        Ok(())
    }).await?
}
