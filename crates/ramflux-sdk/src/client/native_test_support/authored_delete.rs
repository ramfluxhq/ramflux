// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]

//! Genuine generated Delete delivery, exact retries after erasure and source authority refusal.
use super::*;
use crate::client::routed::Route;
use crate::{GatewayDirectMessage, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;

fn request(
    source: &Fixture,
    target: &Fixture,
    conversation: &str,
    operation: &str,
) -> GatewayDirectMessage {
    GatewayDirectMessage {
        conversation_id: conversation.into(),
        message_id: operation.into(),
        envelope_id: operation.into(),
        source_principal_id: source.config.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(target.manifest.principal_commitment.clone()),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 300,
    }
}

fn seal(
    source: &Fixture,
    target: &Fixture,
    message: &mut GatewayDirectMessage,
    exact: &[u8],
    group: Option<&str>,
) -> TestResult<ramflux_protocol::Envelope> {
    let route = group.map_or_else(Route::direct, Route::group_message);
    let material = source.material_for(target)?;
    Ok(source.client.account_db()?.write_transaction(|| {
        let sealed = source.client.seal_generated_routed_prepared(
            &source.config,
            message,
            exact,
            route,
            material,
        )?;
        crate::dm::gateway_generated_envelope_from_sealed(&source.config, message, sealed)
    })?)
}

async fn pair(group: bool) -> TestResult<(Fixture, Fixture, String, Option<String>)> {
    let source = Box::pin(Fixture::with_device("delete-source", "source-device")).await?;
    let target = Box::pin(Fixture::with_device("delete-target", "target-device")).await?;
    source.client.persist_observed_identity_directory_now(&target.manifest)?;
    target.client.persist_observed_identity_directory_now(&source.manifest)?;
    if !group {
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        let conversation = g::dm_scope::derive(
            &source.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?;
        return Ok((source, target, conversation, None));
    }
    let primary = source
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native source")?
        .group_primary(source.vault.as_ref())?;
    source.client.shared_group_create_with_primary(
        "delete-group",
        "delete-thread",
        None,
        &source.config.target_delivery_id,
        Some(&primary),
    )?;
    let state = source.client.shared_group_change_with_primary(
        "delete-group",
        &source.config.target_delivery_id,
        ramflux_protocol::GroupStateChange::Add {
            member: target.client.owned_group_actor(&target.config.target_delivery_id)?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    target.client.accept_shared_group_state(&state, &target.config.target_delivery_id)?;
    let distribution = source
        .client
        .export_group_sender_key_distribution("delete-group", &source.config.device_id)?;
    target.client.import_group_sender_key_distribution(&distribution)?;
    Ok((source, target, "delete-thread".into(), Some("delete-group".into())))
}

#[tokio::test(flavor = "current_thread")]
async fn direct_delete_retains_one_event_and_packet_after_source_erasure() -> TestResult {
    super::watchdog::within(exercise(false)).await?
}

#[tokio::test(flavor = "current_thread")]
async fn group_delete_retains_one_event_and_packet_after_source_erasure() -> TestResult {
    super::watchdog::within(exercise(true)).await?
}

async fn exercise(group: bool) -> TestResult {
    let (source, mut target, conversation, group) =
        Box::pin(pair(group)).await.map_err(|e| format!("native Delete setup: {e}"))?;
    let mut original = request(&source, &target, &conversation, "original-operation");
    let content = g::Message { text: "content to erase".into(), ..Default::default() };
    let prepared = source
        .client
        .prepare_authored_message(&mut original, group.as_deref(), &content)
        .map_err(|e| format!("original prepare: {e}"))?;
    let first = seal(&source, &target, &mut original, &prepared.wire, group.as_deref())
        .map_err(|e| format!("original seal: {e}"))?;
    source
        .client
        .project_authored_message(&original, &prepared.exact, &original.encrypted_body)
        .map_err(|e| format!("original projection: {e}"))?;
    target.receive(first, 1).await.map_err(|e| format!("original receive: {e}"))?;
    refuse_peer_and_selected_tombstone(&source, &target, &original)?;
    let draft = source.client.authored_delete_draft(&conversation, &original.message_id, None)?;
    let mut erase = request(&source, &target, &conversation, &draft.operation);
    let retry_input = erase.clone();
    let prepared = source
        .client
        .prepare_authored_content(&mut erase, group.as_deref(), &draft.content)
        .map_err(|e| format!("Delete prepare: {e}"))?;
    let identity =
        g::Inner::decode(prepared.exact.as_slice())?.identity.ok_or("Delete identity")?;
    let envelope = seal(&source, &target, &mut erase, &prepared.wire, group.as_deref())
        .map_err(|e| format!("Delete seal: {e}"))?;
    source
        .client
        .project_authored_message(&erase, &prepared.exact, &erase.encrypted_body)
        .map_err(|e| format!("Delete source projection: {e}"))?;
    assert!(
        source.client.account_db()?.message_is_deleted(&original.message_id)?,
        "the actual source writer must erase the target"
    );
    assert!(
        source.client.direct_message_by_id(&erase.message_id)?.is_none(),
        "a Delete event must not become a second timeline message"
    );
    assert_committed_copy(&source, &erase, &prepared.exact)?;
    target.receive(envelope.clone(), 2).await.map_err(|e| format!("Delete peer receive: {e}"))?;
    let cursor = target.client.account_db()?.journal_bounds()?.head_seq;
    let repeated =
        source.client.authored_delete_draft(&conversation, &original.message_id, None)?;
    let mut retry = retry_input;
    retry.envelope_id = "changed-delete-retry-header".into();
    let retained =
        source.client.prepare_authored_content(&mut retry, group.as_deref(), &repeated.content)?;
    assert_eq!(
        retained.exact, prepared.exact,
        "erasure retry must retain the exact generated Delete identity and tombstone"
    );
    let retransmitted = seal(&source, &target, &mut retry, &retained.wire, group.as_deref())?;
    assert_eq!(
        retransmitted.encrypted_payload, envelope.encrypted_payload,
        "source erasure must preserve the content-free Delete retry packet"
    );
    target.receive(retransmitted, 2).await?;
    assert_eq!(
        target.client.account_db()?.journal_bounds()?.head_seq,
        cursor,
        "Delete redelivery must not allocate another public cursor"
    );
    let expected = ramflux_protocol::encode_base64url(g::identity::delete_tombstone(&identity.id)?);
    for client in [&source.client, &target.client] {
        let view = client.generated_message_detail(&conversation, &original.message_id)?.message;
        assert_eq!(view.state, "tombstone", "source and peer must both render the erased original");
        assert!(
            view.text.is_none() && view.content.is_none(),
            "erasure must remove public body and private revision data"
        );
        assert_eq!(
            view.erasure.ok_or("typed erasure")?.tombstone_id,
            expected,
            "both copies must use the tombstone derived from the actual Delete event"
        );
    }
    Ok(())
}

fn refuse_peer_and_selected_tombstone(
    source: &Fixture,
    target: &Fixture,
    original: &GatewayDirectMessage,
) -> TestResult {
    let before = super::generation_zero_tests::actors(&target.client)?;
    assert!(
        matches!(
            target.client.authored_delete_draft(
                &original.conversation_id,
                &original.message_id,
                None
            ),
            Err(SdkError::GeneratedRefused { code: crate::GeneratedRefusalCode::Authority, .. })
        ),
        "a recipient must not delete an original author's message for everyone"
    );
    assert_eq!(
        super::generation_zero_tests::actors(&target.client)?,
        before,
        "authority refusal must precede revision allocation and writes"
    );
    let before = super::generation_zero_tests::actors(&source.client)?;
    let draft = source.client.authored_delete_draft(
        &original.conversation_id,
        &original.message_id,
        None,
    )?;
    let mut invalid = draft.content;
    let Some(g::content::Value::Delete(delete)) = invalid.value.as_mut() else {
        return Err("Delete draft".into());
    };
    delete.tombstone_id = vec![99; 32];
    let mut request = request(source, target, &original.conversation_id, "selected-tombstone");
    assert!(
        source
            .client
            .prepare_authored_content(&mut request, draft.original.group_id.as_deref(), &invalid)
            .is_err(),
        "callers cannot select the tombstone derived from an unallocated Delete event"
    );
    assert_eq!(
        super::generation_zero_tests::actors(&source.client)?,
        before,
        "invalid public Delete must consume no identity or persistence"
    );
    Ok(())
}

fn assert_committed_copy(
    source: &Fixture,
    deletion: &GatewayDirectMessage,
    exact: &[u8],
) -> TestResult {
    let db = source.client.account_db()?;
    let mut found = 0;
    for key in db.actor_state_keys("own-device/send/")? {
        let queued: serde_json::Value = db.load_actor_state(&key)?.ok_or("own-copy intent")?;
        let intent = &queued["intent"];
        if intent["id"] != deletion.envelope_id {
            continue;
        }
        found += 1;
        assert_eq!(queued["held"], false, "committed local erasure must not await peer ACK");
        let bytes = ramflux_protocol::decode_base64url(
            intent["body"].as_str().ok_or("typed own-copy body")?,
        )?;
        let sent = g::OwnSentMessage::decode(bytes.as_slice())?;
        assert_eq!(sent.exact_inner, exact, "sibling copy must carry the same Delete event");
        assert_eq!(sent.message_id, deletion.message_id, "copy lifetime belongs to Delete");
        assert!(
            !String::from_utf8_lossy(&sent.exact_inner).contains("content to erase"),
            "a retained Delete cannot carry the erased original body"
        );
    }
    assert_eq!(found, 1, "target erasure must retain exactly one committed sibling intent");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn closed_direct_contact_does_not_select_bootstrap_for_native_group_traffic() -> TestResult {
    super::watchdog::within(async {
        for decision in ["declined", "blocked"] {
            let (source, mut target, conversation, group) = Box::pin(pair(true)).await?;
            let directory = super::directory::Directory::new(vec![
                source.manifest.clone(),
                target.manifest.clone(),
            ])
            .await?;
            directory.configure(&mut target);
            let entry = crate::client::contact_requests::native_tests::request_entry(
                &source,
                &target.manifest,
            )
            .await?;
            target
                .receive(entry.envelope, 1)
                .await
                .map_err(|e| format!("closed-contact setup request: {e}"))?;
            let root = source.client.own_account_anchor()?;
            let inbound = target
                .client
                .account_db()?
                .contact_request(&root, "inbound")?
                .ok_or("native inbound contact")?;
            target.client.decide_inbound_contact(&inbound, decision)?;
            for link in target.client.friend_links()? {
                if link.state == "accepted" && (link.requester_id == root || link.target_id == root) {
                    if decision == "blocked" {
                        target.client.block_friend_link(&link.link_id)?;
                    } else {
                        target.client.remove_friend_link(&link.link_id, "me")?;
                    }
                }
            }
            assert!(
                !target.client.friend_link_peer_is_accepted(&root)?,
                "no accepted direct alias may bypass the closed-contact gate",
            );
            source.client.remove_device_pair(
                &target.client.owned_device_identity()?,
                "test_independent_group_pair",
            )?;
            let mut message = request(&source, &target, &conversation, "group-after-direct-close");
            let content = g::Message {
                text: "group traffic follows the independent group policy".into(),
                ..Default::default()
            };
            let prepared =
                source.client.prepare_authored_message(&mut message, group.as_deref(), &content)?;
            let envelope = seal(&source, &target, &mut message, &prepared.wire, group.as_deref())?;
            let result = target.receive(envelope, 2).await;
            if decision == "blocked" {
                assert!(
                    matches!(result.as_ref().err().and_then(|error| error.downcast_ref::<SdkError>()),
                        Some(SdkError::InboundRejected(reason)) if reason.contains("group sender is blocked")),
                    "an explicit sender block must reach group policy: {result:?}",
                );
                assert!(
                    target
                        .client
                        .generated_message_view_page(&conversation, None, 10)?
                        .messages
                        .iter()
                        .all(|row| row.kind == "service"),
                    "the blocked sender must create no group row",
                );
            } else {
                result.map_err(|e| format!("independent group receive after decline: {e}"))?;
                let rendered = target
                    .client
                    .generated_message_detail(&conversation, &message.message_id)?
                    .message;
                assert_eq!(
                    rendered.text.as_deref(),
                    Some(content.text.as_str()),
                    "direct decline must not select Contact bootstrap for an authorized group",
                );
            }
            assert_eq!(
                target
                    .client
                    .account_db()?
                    .contact_request(&root, "inbound")?
                    .ok_or("retained direct fence")?
                    .state,
                decision,
                "group routing must never reopen the direct relationship",
            );
        }
        Ok(())
    })
    .await?
}
