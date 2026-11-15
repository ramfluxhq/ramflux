// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]

//! Schema-looking text crosses native crypto as Message text and cannot choose another codec.
use crate::client::native_test_support::{Fixture, TestResult, watchdog};
use crate::client::routed::Route;
use crate::{GatewayDirectMessage, SdkError};
use ramflux_protocol::message as g;

pub(in crate::client::routed) async fn roundtrip(
    text: &[u8],
    probe_wrapper: bool,
) -> Result<(), SdkError> {
    watchdog::within(roundtrip_body(text, probe_wrapper))
        .await
        .map_err(|_| {
            SdkError::InboundRejected("test: native text roundtrip exceeded watchdog".into())
        })?
        .map_err(|error| SdkError::InboundRejected(format!("native text roundtrip: {error}")))
}

async fn roundtrip_body(text: &[u8], probe_wrapper: bool) -> TestResult {
    let source = Fixture::with_principal("json-source", "alice", "alice").await?;
    let mut target = Fixture::with_principal("json-target", "bob", "bob").await?;
    source.accept_peer(&target)?;
    target.accept_peer(&source)?;
    let friends = serde_json::to_value(target.client.friend_links()?)?;
    let conversation = g::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &target.client.own_account_anchor()?,
    )?;
    let mut message = GatewayDirectMessage {
        conversation_id: conversation.clone(),
        message_id: "json-operation".into(),
        envelope_id: "json-envelope".into(),
        source_principal_id: source.config.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(target.client.own_account_anchor()?),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 300,
    };
    let content = g::Message { text: std::str::from_utf8(text)?.into(), ..Default::default() };
    let prepared = source.client.prepare_authored_message(&mut message, None, &content)?;
    let material = source.material_for(&target)?;
    let envelope = source.client.account_db()?.write_transaction(|| {
        let sealed = source.client.seal_generated_routed_prepared(
            &source.config,
            &message,
            &prepared.wire,
            Route::direct(),
            material,
        )?;
        crate::dm::gateway_generated_envelope_from_sealed(&source.config, &mut message, sealed)
    })?;
    let entry = crate::GatewayInboxEntry {
        envelope: envelope.clone(),
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: target.config.target_delivery_id.clone(),
    };
    let opened = target.client.open_routed(&entry, &target.config.device_id)?;
    assert_eq!(
        opened.routing.kind,
        crate::client::routed::Kind::Direct,
        "Message text cannot select a native control or attachment route"
    );
    assert_eq!(
        opened.body.as_slice(),
        prepared.exact,
        "real decryption must retain the exact generated Inner"
    );
    target.receive(envelope, 1).await?;
    let rendered =
        target.client.generated_message_detail(&conversation, &message.message_id)?.message;
    assert_eq!(
        rendered.text.as_deref(),
        Some(content.text.as_str()),
        "the public reader must serve the original JSON-looking text"
    );
    assert_eq!(
        serde_json::to_value(target.client.friend_links()?)?,
        friends,
        "text must not create, accept, or modify another contact"
    );
    assert!(target.client.groups()?.is_empty(), "text must not create a group");
    if probe_wrapper {
        assert_wrapper_refused(&source, &target, &message, text)?;
    }
    Ok(())
}

fn assert_wrapper_refused(
    source: &Fixture,
    target: &Fixture,
    message: &GatewayDirectMessage,
    raw: &[u8],
) -> TestResult {
    let material = source.material_for(target)?;
    let before = actors(&source.client)?;
    assert!(
        source
            .client
            .seal_generated_routed_prepared(
                &source.config,
                message,
                raw,
                Route::attachments(),
                material,
            )
            .is_err(),
        "the retired attachment wrapper cannot become an alternate send codec"
    );
    assert!(
        actors(&source.client)? == before,
        "retired raw wrapper refusal must precede pair/ratchet or queue writes"
    );
    Ok(())
}

fn actors(client: &crate::RamfluxClient) -> TestResult<Vec<(String, serde_json::Value)>> {
    let db = client.account_db()?;
    let mut keys = Vec::new();
    for prefix in ["dm-pair/", "routed/", "message-send/", "own-history/", "own-sent/"] {
        let page = db.actor_state_key_page(prefix, 256)?;
        assert!(page.len() < 256, "test fixture actor namespace must remain bounded");
        keys.extend(page);
    }
    keys.into_iter()
        .map(|key| {
            Ok((key.clone(), db.load_actor_state(&key)?.ok_or("fixture actor disappeared")?))
        })
        .collect()
}
