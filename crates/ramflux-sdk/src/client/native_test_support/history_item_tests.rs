// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One authenticated page commits unrelated items and its chain despite an item refusal.
use super::*;
use prost::Message as _;
use ramflux_protocol::message as g;

fn page_inner(identity: g::EventIdentity, page: g::HistoryPage) -> Vec<u8> {
    g::Inner {
        layer: g::registry::COMPILED_LAYER,
        kind: 8,
        identity: Some(identity),
        body: g::Control { operation: 7, payload: Some(g::control::Payload::OwnHistory(page)) }
            .encode_to_vec(),
    }
    .encode_to_vec()
}
fn page(number: u64, previous: &[u8], items: Vec<g::HistoryItem>) -> TestResult<g::HistoryPage> {
    let encoded: Vec<Vec<u8>> = items.iter().map(prost::Message::encode_to_vec).collect();
    let exact: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
    Ok(g::HistoryPage {
        transfer_id: vec![41; 32],
        page: number,
        previous_page_digest: previous.to_vec(),
        page_digest: g::history_chain::digest(&[41; 32], number, previous, &exact)?.to_vec(),
        items,
    })
}

#[tokio::test(flavor = "current_thread")]
async fn history_page_item_refusal_preserves_unrelated_import_and_chain() -> TestResult {
    crate::client::native_test_support::watchdog::within(
        history_page_item_refusal_preserves_unrelated_import_and_chain_body(),
    )
    .await?
}

async fn history_page_item_refusal_preserves_unrelated_import_and_chain_body() -> TestResult {
    let mut source = Fixture::new("history-item-source").await?;
    let mut sibling = source.enroll_sibling("history-item-sibling", "sibling").await?;
    let peer = Fixture::new("history-item-peer").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let (first_id, first, conversation) =
        Box::pin(history::receive_first_hand(&mut source, &peer)).await?;
    let (second_id, second, _) = Box::pin(history::receive_first_hand(&mut source, &peer)).await?;
    let (next_id, next, _) = Box::pin(history::receive_first_hand(&mut source, &peer)).await?;
    let first_exact = first.exact_inner.clone();
    let (target_id, valid_edit) = Box::pin(receive_edited_history(&mut source, &peer)).await?;
    let expected_edit = valid_edit.exact_inner.clone();
    let mut invalid = valid_edit.clone();
    invalid.original_metadata_evidence = None;
    let first_page = page(0, &[0; 32], vec![first, invalid, valid_edit, second])?;
    let identity = source.client.allocate_generated_identity(&conversation, 1000, false)?;
    let envelope = source.seal_inner_to(&sibling, &page_inner(identity, first_page.clone()))?;
    sibling.receive(envelope.clone(), 1).await?;
    for id in [&first_id.id, &second_id.id] {
        assert!(
            sibling
                .client
                .account_db()?
                .message_content(&ramflux_protocol::encode_base64url(id))?
                .is_some(),
            "valid items on either side of a refused item must import"
        );
    }
    assert!(
        sibling.client.export_generated_history_item(&first_id.id)?.exact_inner == first_exact,
        "refused Edit must not change the original body or retained opening"
    );
    let key =
        format!("routed/history-transfer/{}", source.client.owned_device_identity()?.storage_key());
    let state = sibling
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&key)?
        .ok_or("cursor missing")?;
    assert_eq!(
        state["refusals"].as_array().ok_or("refusals missing")?.len(),
        1,
        "page must retain one bounded typed item refusal"
    );
    assert_eq!(
        state["refusals"][0]["code"], "OriginEvidenceMissing",
        "refusal must retain its type"
    );
    assert!(
        sibling.client.export_generated_history_item(&target_id.id)?.exact_inner == expected_edit,
        "an invalid target claim must not suppress the next independently evidenced Edit"
    );
    let second_page = page(1, &first_page.page_digest, vec![next])?;
    let identity = source.client.allocate_generated_identity(&conversation, 1001, false)?;
    sibling.receive(source.seal_inner_to(&sibling, &page_inner(identity, second_page))?, 2).await?;
    sibling.receive(envelope, 3).await?;
    let count = sibling.client.generated_message_view_page(&conversation, None, 10)?.messages.len();
    assert_eq!(count, 4, "refused item must neither project nor block the next page or duplicate");
    assert!(
        sibling
            .client
            .account_db()?
            .message_content(&ramflux_protocol::encode_base64url(&next_id.id))?
            .is_some(),
        "next-page import must follow the committed cursor"
    );
    drop(sibling.client.active_account_db.take());
    sibling.client.unlock_account("history-item-sibling", b"native sibling data passphrase")?;
    assert_eq!(
        sibling.client.generated_message_view_page(&conversation, None, 10)?.messages.len(),
        count,
        "unrelated imports and cursor must survive reopen"
    );
    assert!(
        sibling.client.export_generated_history_item(&target_id.id)?.exact_inner == expected_edit,
        "the valid same-target Edit must survive duplicate delivery, next page and reopen"
    );
    Ok(())
}

async fn receive_edited_history(
    source: &mut Fixture,
    peer: &Fixture,
) -> TestResult<(g::EventIdentity, g::HistoryItem)> {
    let (target, original_item, _) = Box::pin(history::receive_first_hand(source, peer)).await?;
    let original = source
        .client
        .account_db()?
        .load_actor_state::<crate::client::generated_history::OriginalHeader>(&format!(
            "routed/original-header/{}",
            ramflux_protocol::encode_base64url(&target.id)
        ))?
        .ok_or("verified original header missing")?;
    let exact = super::authored_edit::encoded_edit(peer, &target, &original_item.exact_inner)?;
    let envelope = peer.seal_inner_to(source, &exact)?;
    let entry = crate::GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 4,
        target_delivery_id: source.config.target_delivery_id.clone(),
        envelope: envelope.clone(),
    };
    let edit_origin = {
        let opened = source.client.open_routed(&entry, &source.config.device_id)?;
        source
            .client
            .capture_retained_origin(&opened, &entry)?
            .ok_or("verified Edit origin missing")?
    };
    let item = g::HistoryItem {
        exact_inner: exact,
        source_evidence: Some(edit_origin.evidence.clone()),
        exact_original_identity: original.exact_identity,
        original_metadata_evidence: Some(original.evidence),
        tombstone: None,
    };
    source
        .client
        .verify_generated_edited_history_item(&item)
        .map_err(|error| format!("verify independent Edit evidence: {error}"))?;
    source.receive(envelope, 4).await?;
    Ok((target, item))
}
