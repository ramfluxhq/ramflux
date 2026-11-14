// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deferred key-slot commits on genuine native pair authority.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn decrypt_object_key_slot_defers_slot_session_commit_until_committed() -> TestResult {
    crate::client::native_test_support::watchdog::within(exercise()).await?
}

async fn exercise() -> TestResult {
    let mut source = Fixture::new("native-slot-source").await?;
    let mut target = Fixture::new("native-slot-target").await?;
    source.accept_peer(&target)?;
    target.accept_peer(&source)?;
    let conversation = ramflux_protocol::message::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &target.client.own_account_anchor()?,
    )?;
    let message = GatewayDirectMessage {
        conversation_id: conversation.clone(),
        message_id: "slot-operation".into(),
        envelope_id: "slot-envelope".into(),
        source_principal_id: source.config.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(target.client.own_account_anchor()?),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: source.client.content_ttl()?,
    };
    let pair = source.client.prepared_send_pair(
        &source.config,
        &message,
        source.material_for(&target)?,
        ramflux_protocol::message::KindId::KindMessage,
    )?;
    let key = [7; 32];
    let slot = source.client.seal_pair_object_slot(
        PairObjectSlotRequest {
            config: &source.config,
            message: &message,
            object_id: "native-slot-object",
            key: &key,
            conversation: &conversation,
        },
        pair,
    )?;
    let local = target.client.owned_device_identity()?;
    let remote = source.client.owned_device_identity()?;
    let before = target.client.account_db()?.actor_state_keys("dm-pair/")?;
    let deferred = target.client.decrypt_object_key_slot(&slot)?;
    assert!(deferred.object_key == key, "native slot must open the original key");
    assert_eq!(
        target.client.account_db()?.actor_state_keys("dm-pair/")?,
        before,
        "decrypt must not persist receive ratchet or receipts before import commits"
    );
    assert!(!target.client.pair_object_slot_committed(&slot)?);
    let exact = text(&source, &target, "after key share")?;
    let packet = source.seal_inner_to(&target, &exact)?;
    let wrapped = super::super::decode(&packet)?;
    assert_eq!(
        wrapped.ciphertext.session_id, slot.ciphertext.session_id,
        "object slots forked the pair ratchet"
    );
    target.receive(packet, 1).await?;
    let reply = target.seal_inner_to(&source, &text(&target, &source, "reply")?)?;
    source.receive(reply, 1).await?;
    let before_delayed_commit = target.client.persisted_pair_snapshot(&local, &remote)?;
    target.client.commit_object_key_slot_session(&deferred)?;
    let after_delayed_commit = target.client.persisted_pair_snapshot(&local, &remote)?;
    assert_only_slot_key_consumed(&before_delayed_commit, &after_delayed_commit)?;
    let after = text(&source, &target, "after delayed download")?;
    let packet = source.seal_inner_to(&target, &after)?;
    target.receive(packet, 2).await?;

    assert!(target.client.pair_object_slot_committed(&slot)?);
    let committed = target.client.persisted_pair_snapshot(&local, &remote)?;
    target.client.commit_object_key_slot_session(&deferred)?;
    assert_eq!(
        target.client.persisted_pair_snapshot(&local, &remote)?,
        committed,
        "committing a native slot twice must not advance the receive ratchet twice"
    );
    Ok(())
}

fn text(source: &Fixture, target: &Fixture, text: &str) -> TestResult<Vec<u8>> {
    use ramflux_protocol::message as g;
    let scope = g::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &target.client.own_account_anchor()?,
    )?;
    let identity = source.client.allocate_generated_identity(
        &scope,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    Ok(RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: text.into(),
                ..Default::default()
            })),
        },
    )?)
}

fn assert_only_slot_key_consumed(before: &[u8], after: &[u8]) -> TestResult {
    let mut before: serde_json::Value = serde_json::from_slice(before)?;
    let mut after: serde_json::Value = serde_json::from_slice(after)?;
    for field in ["skipped_message_secrets", "skipped_order"] {
        let before = before
            .get_mut("snapshot")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("test: before ratchet snapshot")?
            .remove(field)
            .ok_or("test: before skipped keys")?;
        let after = after
            .get_mut("snapshot")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("test: after ratchet snapshot")?
            .remove(field)
            .ok_or("test: after skipped keys")?;
        let count = |value: &serde_json::Value| {
            value.as_array().map(Vec::len).or_else(|| value.as_object().map(serde_json::Map::len))
        };
        assert_eq!(count(&before), Some(1), "fixture must retain exactly the delayed slot key");
        assert_eq!(count(&after), Some(0), "commit must consume the delayed slot key");
    }
    assert!(
        before == after,
        "late slot commit changed live ratchet state beyond consuming its skipped key"
    );
    Ok(())
}
