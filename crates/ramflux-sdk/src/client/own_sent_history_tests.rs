// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy projection and generated eight-field conversion, aliases and restore fences (S10a P18).
#![allow(clippy::too_many_lines, clippy::expect_used)]
use super::*;
use crate::client::native_test_support::{Fixture, TestResult, watchdog};
use ramflux_protocol::message as g;
use ramflux_storage::MessageReplayReference;
use serde_json::json;

/// A same-root native account with the local device plus two enrolled sibling devices whose
/// root-qualified references stand for the authenticated sources of own-sent copies.
struct Own {
    target: Fixture,
    source: ramflux_crypto::RootQualifiedDeviceRef,
    other: ramflux_crypto::RootQualifiedDeviceRef,
    principal: String,
    _siblings: [Fixture; 2],
}

impl Own {
    async fn new(label: &str) -> TestResult<Self> {
        let mut target = Box::pin(Fixture::with_device(label, "target_device_sync")).await?;
        let source =
            Box::pin(target.enroll_sibling(&format!("{label}-source"), "source_device_sync"))
                .await?;
        let other =
            Box::pin(target.enroll_sibling(&format!("{label}-other"), "other_device_sync")).await?;
        let principal = target
            .client
            .device_branch
            .as_ref()
            .ok_or("native device branch")?
            .principal_id
            .clone();
        Ok(Self {
            source: source.client.owned_device_identity()?,
            other: other.client.owned_device_identity()?,
            principal,
            target,
            _siblings: [source, other],
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn typed_bytes(
    principal: &str,
    envelope: &str,
    message: &str,
    sender: &str,
    recipients: &[&str],
    conversation: &str,
    hash: Option<&[u8]>,
    authored_at: i64,
    body: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let packet: SentMessage = serde_json::from_value(json!({
        "envelope_id": envelope,
        "message_id": message,
        "sender_id": sender,
        "original_recipients": recipients,
        "ciphertext_hash": hash.map(own_sent_ciphertext_hash),
        "context": {
            "conversation_id": conversation,
            "participants": [principal, "peer"],
            "group": null,
            "friend": null
        },
        "authored_at": authored_at,
        "body_base64": ramflux_protocol::encode_base64url(body)
    }))?;
    Ok(packet.to_generated()?.encode_to_vec())
}

fn generated_from_bytes(bytes: &[u8]) -> Result<g::OwnSentMessage, SdkError> {
    g::OwnSentMessage::decode(bytes).map_err(|_| invalid("typed sent message missing"))
}

fn receive_generated(
    client: &RamfluxClient,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    conversation: &str,
    at: i64,
    sent: &g::OwnSentMessage,
) -> Result<bool, SdkError> {
    // This fixture exercises the retiring legacy projection, not native generated admission.
    // Activated generated receive has independent native-authority tests.
    let packet = SentMessage::from_generated(sent)?;
    client.apply_own_sent_packet(source, &packet.envelope_id, conversation, None, at, &packet)
}

fn alias_for(
    client: &RamfluxClient,
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &str,
) -> Result<Option<MessageReplayReference>, SdkError> {
    let db = client.account_db()?;
    let id = own_row_id(source, envelope)?;
    Ok(db.load_actor_state::<MessageReplayReference>(&alias_key(db, &id)?)?)
}

fn ciphertext_alias(
    client: &RamfluxClient,
    hash: &[u8],
) -> Result<Option<MessageReplayReference>, SdkError> {
    let db = client.account_db()?;
    Ok(db.load_actor_state::<MessageReplayReference>(&ciphertext_index_key(
        db,
        &own_sent_ciphertext_hash(hash),
    )?)?)
}

fn assert_deleted(client: &RamfluxClient, id: &str) -> Result<(), SdkError> {
    let row = client.direct_message_by_id(id)?.ok_or(SdkError::IdentityRootMissing)?;
    assert!(row.deleted);
    assert_eq!(row.sender_id, "");
    assert!(client.account_db()?.message_content(id)?.is_none());
    assert!(client.message_origin("direct", id)?.is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn own_sent_fields_and_source_bound_reconciliation_round_trip() -> TestResult {
    watchdog::within(Box::pin(own_sent_fields_body())).await?
}

async fn own_sent_fields_body() -> TestResult {
    let own = Own::new("t18-fields").await?;
    let client = &own.target.client;
    let body = b"original inner body";
    let ciphertext = [1_u8, 2, 3];
    let bytes = typed_bytes(
        &own.principal,
        "copy-envelope",
        "original-message",
        "display-label",
        &[],
        "direct",
        Some(&ciphertext),
        42,
        body,
    )?;
    assert!(generated_from_bytes(b"malformed protobuf").is_err());
    let sent = generated_from_bytes(&bytes)?;
    assert_eq!(sent.envelope_id, "copy-envelope");
    assert_eq!(sent.message_id, "original-message");
    assert_eq!(sent.sender_id, "display-label");
    assert_eq!(sent.original_recipients, Vec::<String>::new());
    assert_eq!(
        sent.ciphertext_digest.as_deref().map(ramflux_protocol::encode_base64url),
        Some(own_sent_ciphertext_hash(&ciphertext))
    );
    assert_eq!(sent.ciphertext_digest.as_ref().map(Vec::len), Some(32));
    assert_eq!(sent.authored_at, Some(42));
    assert_eq!(sent.exact_inner, body);
    assert_ne!(sent.exact_inner, bytes);
    let context = sent.context.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    assert_eq!(context.conversation_id, "direct");
    assert_eq!(context.participants, [own.principal.as_str(), "peer"]);
    assert!(context.group.is_none());
    assert!(context.friend.is_none());
    assert_ne!(sent.sender_id, own.source.device_id());

    assert!(receive_generated(client, &own.source, "direct", 99, &sent)?);
    let rows = client.direct_messages("direct")?;
    assert_eq!(rows.len(), 1);
    let copy_id = own_row_id(&own.source, "copy-envelope")?;
    assert_eq!(rows[0].message_id, copy_id);
    assert_eq!(rows[0].created_at, 42);
    assert_eq!(client.account_db()?.message_content(&copy_id)?.as_deref(), Some(body.as_slice()));
    assert!(matches!(
        alias_for(client, &own.source, "copy-envelope")?,
        Some(MessageReplayReference::Target { deleted: false, .. })
    ));

    let suppressed = generated_from_bytes(&typed_bytes(
        &own.principal,
        "original-envelope",
        "original-message",
        "display-label",
        &["target_device_sync"],
        "direct",
        Some(&ciphertext),
        42,
        body,
    )?)?;
    assert_eq!(suppressed.original_recipients, ["target_device_sync"]);
    assert!(receive_generated(client, &own.source, "direct", 99, &suppressed)?);
    assert_eq!(client.direct_messages("direct")?.len(), 1);

    let other = generated_from_bytes(&typed_bytes(
        &own.principal,
        "other-envelope",
        "other-original",
        "display-label",
        &[],
        "direct",
        Some(&ciphertext),
        42,
        body,
    )?)?;
    assert!(receive_generated(client, &own.other, "direct", 99, &other)?);
    assert_eq!(client.direct_messages("direct")?.len(), 2);
    assert!(matches!(
        ciphertext_alias(client, &ciphertext)?,
        Some(MessageReplayReference::Ambiguous)
    ));

    let mut surface = b"ramflux.surface.carrier.v2\n".to_vec();
    surface.extend(serde_json::to_vec(&json!({
        "schema": ramflux_protocol::domain::SURFACE_CARRIER,
        "content_type": "surface",
        "payload_kind": "event",
        "conversation_id": "direct",
        "surface_id": "surface",
        "message_id": "surface-message",
        "sender_principal_id": own.principal,
        "sender_device_id": "source_device_sync",
        "author_principal_id": own.principal,
        "wire_base64": "",
        "signature": "sig"
    }))?);
    let structured = generated_from_bytes(&typed_bytes(
        &own.principal,
        "surface-envelope",
        "surface-original",
        "display-label",
        &[],
        "direct",
        None,
        42,
        &surface,
    )?)?;
    assert!(
        receive_generated(client, &own.source, "direct", 99, &structured)?,
        "schema-looking opaque bytes must not select a structured control parser",
    );
    let row_id = own_row_id(&own.source, "surface-envelope")?;
    assert_eq!(client.account_db()?.message_content(&row_id)?, Some(surface));
    assert_eq!(
        client.account_db()?.actor_state_usage("surface/")?.0,
        0,
        "a retired schema prefix must not create native Surface state",
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn own_sent_raw_erasure_and_replay_reference_survive_restore_without_resurrection()
-> TestResult {
    watchdog::within(Box::pin(own_sent_restore_body())).await?
}

async fn own_sent_restore_body() -> TestResult {
    let mut own = Own::new("t18-restore").await?;
    let body = b"erasure canary body";
    let ciphertext = [9_u8, 8, 7];
    let sent = generated_from_bytes(&typed_bytes(
        &own.principal,
        "live-envelope",
        "live-message",
        "display-label",
        &[],
        "direct",
        Some(&ciphertext),
        7,
        body,
    )?)?;
    assert!(receive_generated(&own.target.client, &own.source, "direct", 1, &sent)?);
    let copy_id = own_row_id(&own.source, "live-envelope")?;
    own.target.client.account_db()?.delete_direct_message(
        "direct",
        &copy_id,
        "self",
        "erase-copy",
    )?;
    assert_deleted(&own.target.client, &copy_id)?;
    assert!(matches!(
        alias_for(&own.target.client, &own.source, "live-envelope")?,
        Some(MessageReplayReference::Target { deleted: true, .. })
    ));

    own.target.reopen().await?;
    assert_deleted(&own.target.client, &copy_id)?;
    assert!(matches!(
        alias_for(&own.target.client, &own.source, "live-envelope")?,
        Some(MessageReplayReference::Target { deleted: true, .. })
    ));
    assert!(receive_generated(&own.target.client, &own.source, "direct", 1, &sent)?);
    assert_deleted(&own.target.client, &copy_id)?;
    Ok(())
}

fn retired_prefix_bytes(body: &serde_json::Value) -> Result<Vec<u8>, SdkError> {
    let mut bytes = b"ramflux.own_sent_message.v1\n".to_vec();
    bytes.extend(serde_json::to_vec(body)?);
    Ok(bytes)
}

#[tokio::test(flavor = "current_thread")]
async fn group_copy_envelopes_are_opaque_stable_on_retry_and_distinct_per_message() -> TestResult {
    let fixture = Box::pin(Fixture::with_device("opaque-envelope", "source_device_sync")).await?;
    let client = &fixture.client;
    let first = client.own_group_copy_envelope("group", "conversation", "message", None)?;
    assert_ne!(first, "message");
    assert_eq!(client.own_group_copy_envelope("group", "conversation", "message", None)?, first);
    assert_ne!(
        client.own_group_copy_envelope("group", "conversation", "other-message", None)?,
        first
    );
    assert_eq!(
        client.own_group_copy_envelope("group", "conversation", "message", Some("explicit"))?,
        "explicit"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn retired_own_sent_prefix_cannot_claim_original_dm_or_group_rows() -> TestResult {
    use crate::client::own_device_copy::{OwnMessageInput, OwnPayloadKind};
    let own = Box::pin(Own::new("original-recipient")).await?;
    let client = &own.target.client;
    for (conversation, group, context) in [
        (
            "direct-original",
            None,
            json!({"conversation_id":"direct-original","participants":[own.principal,own.principal],"group":null,"friend":null}),
        ),
        (
            "group-original",
            Some("own-group"),
            json!({"conversation_id":"group-original","participants":[],"group":{"group_id":"own-group"},"friend":null}),
        ),
    ] {
        let bytes = retired_prefix_bytes(&json!({
            "envelope_id":"original-envelope","message_id":"original-message","sender_id":"source_device_sync",
            "original_recipients":["target_device_sync"],"context":context,
            "body_base64":ramflux_protocol::encode_base64url(b"original body")
        }))?;
        let input = || OwnMessageInput {
            payload_kind: OwnPayloadKind::Sent,
            id: "original-envelope",
            conversation,
            group,
            created_at: 1,
            body: &bytes,
        };
        assert!(!client.receive_own_sent_message(&own.source, input())?);
        assert_eq!(client.direct_messages(conversation)?.len(), 0);
        client.send_direct_message(conversation, conversation, "source_device_sync", &[])?;
        client.account_db()?.store_message_content(conversation, conversation, b"original body")?;
        assert!(!client.receive_own_sent_message(&own.source, input())?);
        assert_eq!(client.direct_messages(conversation)?.len(), 1);
        client.account_db()?.delete_direct_message(
            conversation,
            conversation,
            "self",
            "original-deleted",
        )?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn retired_own_sent_prefix_cannot_alias_equal_sender_labels_ids_and_text() -> TestResult {
    use crate::client::own_device_copy::{OwnMessageInput, OwnPayloadKind};
    let own = Box::pin(Own::new("different-ciphertexts")).await?;
    let client = &own.target.client;
    client.send_direct_message("direct", "shared-id", "same-label", &[9, 8, 7])?;
    client.account_db()?.store_message_content("direct", "shared-id", b"same text")?;
    let bytes = retired_prefix_bytes(&json!({
        "envelope_id":"different-envelope","message_id":"shared-id","sender_id":"same-label",
        "ciphertext_hash":own_sent_ciphertext_hash(&[1,2,3]),
        "context":{"conversation_id":"direct","participants":[own.principal,"peer"],"group":null,"friend":null},
        "body_base64":ramflux_protocol::encode_base64url(b"same text")
    }))?;
    client.receive_own_sent_message(
        &own.source,
        OwnMessageInput {
            payload_kind: OwnPayloadKind::RawInner,
            id: "different-envelope",
            conversation: "direct",
            group: None,
            created_at: 1,
            body: &bytes,
        },
    )?;
    let rows = client.direct_messages("direct")?;
    assert_eq!(rows.len(), 1, "a retired own-sent prefix cannot mint a ciphertext alias");
    assert_eq!(
        client
            .direct_message_by_id("shared-id")?
            .ok_or(SdkError::IdentityRootMissing)?
            .encrypted_body,
        vec![9, 8, 7]
    );
    Ok(())
}
