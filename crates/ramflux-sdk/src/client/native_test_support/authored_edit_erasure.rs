// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Missing-target Delete retires only the authenticated author's parked Edit and its containers.
use super::*;
use ramflux_protocol::message as g;

pub(super) async fn retire_and_refuse_redelivery(
    source: &Fixture,
    target: &mut Fixture,
    original: &g::EventIdentity,
) -> TestResult {
    let owner = ramflux_protocol::encode_base64url(&original.id);
    let captured: serde_json::Value = source
        .client
        .account_db()?
        .load_actor_state(&format!("own-history/capture/{owner}"))?
        .ok_or("current capture")?;
    let sent: g::OwnSentMessage = serde_json::from_value(captured["sent"].clone())?;
    let identity = source.client.allocate_generated_identity(
        &original.conversation_id,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let delete = g::Delete {
        targets: vec![g::MessageRef {
            id: original.id.clone(),
            conversation_id: original.conversation_id.clone(),
            author_anchor: source.client.own_account_anchor()?,
        }],
        scope: g::DeleteScope::Everyone as i32,
        tombstone_id: g::identity::delete_tombstone(&identity.id)?.to_vec(),
        native_group_authorization: Vec::new(),
    };
    let mut erase = sent.clone();
    erase.message_id = ramflux_protocol::encode_base64url(&identity.id);
    erase.exact_inner = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content { value: Some(g::content::Value::Delete(delete)) },
    )?;
    let _ = Box::pin(deliver_sent(source, target, erase)).await?;
    assert_retired(target, &owner)?;
    // A new correctly signed enclosing Control cannot retain the same retired Edit again.
    let fresh = Box::pin(deliver_sent(source, target, sent)).await?;
    assert_retired(target, &owner)?;
    let entry = crate::GatewayInboxEntry {
        envelope: fresh,
        forwarded: false,
        inbox_seq: 4,
        target_delivery_id: target.config.target_delivery_id.clone(),
    };
    let key = target.client.authenticated_committed_key(
        crate::client::identity_authority::HeadUse::NewAuthorization,
        &entry,
    )?;
    let committed = target
        .client
        .account_db()?
        .load_actor_state::<crate::client::routed::Committed>(&key)?
        .ok_or("content-free replay marker")?;
    assert_eq!(committed.entry.envelope.encrypted_payload, "");
    Ok(())
}

fn assert_retired(target: &Fixture, owner: &str) -> TestResult {
    let db = target.client.account_db()?;
    assert_eq!(db.actor_state_keys(&format!("routed/pending-edit/{owner}/"))?.len(), 0);
    assert_eq!(db.actor_state_keys(&format!("routed/own-sent-attestation/{owner}/"))?.len(), 0);
    assert_eq!(db.unsupported_raw_quota(None)?.raw_bytes, 0);
    assert!(db.message_content(owner)?.is_none());
    Ok(())
}

async fn deliver_sent(
    source: &Fixture,
    target: &mut Fixture,
    sent: g::OwnSentMessage,
) -> TestResult<ramflux_protocol::Envelope> {
    let now = crate::time::now_unix_timestamp();
    let conversation = sent.context.as_ref().ok_or("context")?.conversation_id.clone();
    let control = crate::client::generated_control::control_from_payload(
        g::control::Payload::OwnMessageCopy(g::OwnMessageCopy {
            source: Some(qualified(source)?),
            target: Some(qualified(target)?),
            created_at: now,
            expires_at: now + 300,
            payload: Some(g::own_message_copy::Payload::Sent(sent)),
        }),
    )?;
    let identity = source.client.allocate_generated_identity(
        &conversation,
        crate::client::generated_identity::now_ms(),
        true,
    )?;
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content { value: Some(g::content::Value::Control(control)) },
    )?;
    let envelope = source.seal_inner_to(target, &exact)?;
    target.receive(envelope.clone(), 4).await?;
    Ok(envelope)
}

fn qualified(fixture: &Fixture) -> TestResult<g::QualifiedDevice> {
    let identity = fixture.client.owned_device_identity()?;
    let record =
        fixture.client.account_db()?.client_device_record(&identity)?.ok_or("current device")?;
    Ok(g::QualifiedDevice {
        account_anchor: identity.root_commitment().into(),
        device_id: identity.device_id().into(),
        device_epoch: record["device_epoch"].as_u64().ok_or("current epoch")?,
    })
}
