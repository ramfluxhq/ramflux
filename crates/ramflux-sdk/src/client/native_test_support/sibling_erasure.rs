// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]

//! Sibling copy/tombstone ordering through generated Control and native certified branches.
use super::{Fixture, TestResult};
use crate::GatewayDirectMessage;
use prost::Message as _;
use ramflux_protocol::message as g;

pub(crate) async fn exercise(deletion_first: bool, copies: usize) -> TestResult {
    assert!((1..=2).contains(&copies), "test: copy sources are bounded to two siblings");
    let mut source = Fixture::new("sibling-erasure-source").await?;
    let mut peer = Fixture::new("sibling-erasure-peer").await?;
    source.accept_peer(&peer)?;
    peer.accept_peer(&source)?;
    let conversation = g::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &peer.client.own_account_anchor()?,
    )?;
    let (original, mut message) =
        authored(&source, &mut peer, &conversation, "sibling-erasure-original").await?;
    let mut target = source.enroll_sibling("sibling-erasure-target", "target").await?;
    let mut forwarder = source.enroll_sibling("sibling-erasure-forwarder", "forwarder").await?;
    for fixture in [&mut target, &mut forwarder] {
        fixture.manifest = source.manifest.clone();
        fixture.client.persist_fetched_identity_directory(&source.manifest)?;
    }
    super::authored_edit::deliver_contact(&source, &peer, &mut target, &conversation).await?;
    let owner = original.message_id.clone();
    if !deletion_first {
        Box::pin(deliver_copies(&source, &forwarder, &mut target, &original, copies)).await?;
        assert_eq!(
            target.client.generated_message_view_page(&conversation, None, 10)?.messages.len(),
            1,
            "copies from two genuine siblings share one logical event",
        );
    }
    message.envelope_id = "sibling-erasure-delete".into();
    let draft = source.client.authored_delete_draft(&conversation, &owner, None)?;
    message.message_id = draft.operation;
    let prepared = source.client.prepare_authored_content(&mut message, None, &draft.content)?;
    source.client.project_authored_message(&message, &prepared.exact, &[])?;
    let erase = queued_delete(&source)?;
    Box::pin(super::authored_edit_erasure::deliver_sent(&source, &mut target, erase)).await?;
    assert_erased(&target, &conversation, &owner)?;
    Box::pin(deliver_copies(&source, &forwarder, &mut target, &original, copies)).await?;
    assert_erased(&target, &conversation, &owner)?;

    let id = target.client.account_db()?.local_account_id.clone();
    target.client.active_account_db = None;
    target.client.unlock_account(&id, b"native sibling data passphrase")?;
    target.client.initialize_born_v3_branch(&target.config.device_id, target.vault.clone()).await?;
    assert_erased(&target, &conversation, &owner)?;
    // A new genuine enclosing Control after reopen cannot bypass the retained target fence.
    Box::pin(super::authored_edit_erasure::deliver_sent(&source, &mut target, original)).await?;
    assert_erased(&target, &conversation, &owner)?;
    Ok(())
}

pub(crate) async fn authored(
    source: &Fixture,
    peer: &mut Fixture,
    conversation: &str,
    operation: &str,
) -> TestResult<(g::OwnSentMessage, GatewayDirectMessage)> {
    let mut message = GatewayDirectMessage {
        conversation_id: conversation.into(),
        message_id: operation.into(),
        envelope_id: format!("{operation}-wire"),
        source_principal_id: source.config.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(peer.config.device_id.clone()),
        recipient_principal_commitment: Some(peer.client.own_account_anchor()?),
        target_delivery_id: peer.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 300,
    };
    let prepared = source.client.prepare_authored_message(
        &mut message,
        None,
        &g::Message { text: "SIBLING_DELETION_BODY_CANARY".into(), ..Default::default() },
    )?;
    let envelope = source.seal_inner_to_with_id(peer, &prepared.wire, &message.envelope_id)?;
    source.client.project_authored_message(&message, &prepared.exact, &[])?;
    peer.receive(envelope, 1).await?;
    let capture: serde_json::Value = source
        .client
        .account_db()?
        .load_actor_state(&format!("own-history/capture/{}", message.message_id))?
        .ok_or("test: original authored capture missing")?;
    Ok((serde_json::from_value(capture["sent"].clone())?, message))
}

async fn deliver_copies(
    source: &Fixture,
    forwarder: &Fixture,
    target: &mut Fixture,
    original: &g::OwnSentMessage,
    copies: usize,
) -> TestResult {
    for sender in [source, forwarder].into_iter().take(copies) {
        Box::pin(super::authored_edit_erasure::deliver_sent(sender, target, original.clone()))
            .await?;
        if target.client.direct_message_by_id(&original.message_id)?.is_some_and(|row| !row.deleted)
        {
            target.client.account_db()?.persist_message_actor_state(
                &original.message_id,
                &format!("owncopy-test/erase-canary/{}", sender.config.device_id),
                &serde_json::json!({"body":"SIBLING_DELETION_BODY_CANARY"}),
            )?;
        }
    }
    Ok(())
}

fn queued_delete(source: &Fixture) -> TestResult<g::OwnSentMessage> {
    let db = source.client.account_db()?;
    let keys = db.actor_state_key_page("own-device/send/", 32)?;
    assert!(keys.len() < 32, "test: own-copy queue must remain bounded");
    for key in keys {
        let row: serde_json::Value = db.load_actor_state(&key)?.ok_or("test: queued copy")?;
        if row["intent"]["payload_kind"]
            != serde_json::to_value(crate::client::own_device_copy::OwnPayloadKind::Sent)?
        {
            continue;
        }
        let exact = ramflux_protocol::decode_base64url(
            row["intent"]["body"].as_str().ok_or("test: queued copy bytes")?,
        )?;
        let sent = g::OwnSentMessage::decode(exact.as_slice())?;
        if g::Inner::decode(sent.exact_inner.as_slice())?.kind == 4 {
            return Ok(sent);
        }
    }
    Err("test: production Delete did not stage a sibling copy".into())
}

fn assert_erased(target: &Fixture, conversation: &str, owner: &str) -> TestResult {
    let db = target.client.account_db()?;
    if let Some(row) = target.client.direct_message_by_id(owner)? {
        assert!(row.deleted, "a sibling tombstone must erase the shared logical row");
        assert!(row.sender_id.is_empty() && row.encrypted_body.is_empty());
    }
    assert!(db.message_content(owner)?.is_none(), "the original body must remain erased");
    assert!(target.client.message_origin(conversation, owner)?.is_none());
    for prefix in
        ["owncopy-test/erase-canary/".into(), format!("routed/own-sent-attestation/{owner}/")]
    {
        assert_eq!(db.actor_state_usage(&prefix)?.0, 0, "erased footprint retained {prefix}");
    }
    let page = target.client.generated_message_view_page(conversation, None, 10)?;
    assert!(page.messages.iter().all(|row| row.state == "tombstone" && row.text.is_none()));
    Ok(())
}

pub(crate) async fn contact(
    source: &Fixture,
    peer: &Fixture,
    target: &mut Fixture,
    conversation: &str,
) -> TestResult {
    super::authored_edit::deliver_contact(source, peer, target, conversation).await
}

pub(crate) async fn deliver(
    source: &Fixture,
    target: &mut Fixture,
    sent: g::OwnSentMessage,
) -> TestResult<ramflux_protocol::Envelope> {
    Box::pin(super::authored_edit_erasure::deliver_sent(source, target, sent)).await
}

#[tokio::test(flavor = "current_thread")]
async fn sibling_history_tombstone_erases_a_live_own_copy_and_its_footprint() -> TestResult {
    super::watchdog::within(Box::pin(exercise(false, 1))).await?
}

#[tokio::test(flavor = "current_thread")]
async fn sibling_history_tombstone_prevents_a_late_own_copy_from_reviving_content() -> TestResult {
    super::watchdog::within(Box::pin(exercise(true, 1))).await?
}

#[tokio::test(flavor = "current_thread")]
async fn sibling_history_tombstone_erases_each_live_copy_of_the_same_original() -> TestResult {
    super::watchdog::within(Box::pin(exercise(false, 2))).await?
}
