// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated Inner size and bidirectional native pair invariants.
use super::assert_compact_frame_admitted;
use crate::client::native_test_support::{Fixture, TestResult, watchdog};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_protocol::message as g;

pub(super) fn text(source: &Fixture, target: &Fixture, body: &str) -> TestResult<Vec<u8>> {
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
                text: body.into(),
                ..Default::default()
            })),
        },
    )?)
}

pub(super) fn entry(
    source: &Fixture,
    target: &Fixture,
    exact: &[u8],
) -> TestResult<GatewayInboxEntry> {
    Ok(GatewayInboxEntry {
        envelope: source.seal_inner_to(target, exact)?,
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: target.config.target_delivery_id.clone(),
    })
}

fn persist_opened(
    target: &Fixture,
    source: &Fixture,
    packet: &GatewayInboxEntry,
) -> TestResult<String> {
    let opened = target.client.open_routed(packet, &target.config.device_id)?;
    target.client.persist_pair(
        &target.client.owned_device_identity()?,
        &source.client.owned_device_identity()?,
        &opened.bundle_hash,
        &opened.session,
    )?;
    Ok(opened.session.session_id)
}

#[tokio::test(flavor = "current_thread")]
async fn real_wire_size_preflight_accepts_maximum_generated_text() -> TestResult {
    watchdog::within(async {
        let source = Fixture::new("size-source").await?;
        let target = Fixture::new("size-target").await?;
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        let exact = text(&source, &target, &"Z".repeat(g::validation::MAX_TEXT_BYTES))?;
        let packet = entry(&source, &target, &exact)?;
        assert_compact_frame_admitted(&packet)?;
        let opened = target.client.open_routed(&packet, &target.config.device_id)?;
        assert_eq!(opened.body.as_slice(), exact);
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn over_cap_seal_leaves_pair_session_byte_identical() -> TestResult {
    watchdog::within(async {
        let source = Fixture::new("over-cap-source").await?;
        let target = Fixture::new("over-cap-target").await?;
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        entry(&source, &target, &text(&source, &target, "establish")?)?;
        let local = source.client.owned_device_identity()?;
        let remote = target.client.owned_device_identity()?;
        let before = source.client.persisted_pair_snapshot(&local, &remote)?;
        let mut exact = text(&source, &target, "oversize")?;
        prost::encoding::bytes::encode(500, &vec![0; g::outer::MAX_INNER_BYTES], &mut exact);
        assert!(exact.len() > g::outer::MAX_INNER_BYTES);
        let error = source.seal_inner_to(&target, &exact).err().ok_or("oversize accepted")?;
        assert!(
            matches!(error.downcast_ref::<SdkError>(), Some(SdkError::PayloadTooLarge)),
            "{error}"
        );
        assert_eq!(source.client.persisted_pair_snapshot(&local, &remote)?, before);
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn device_pair_session_reuses_canonical_scope_and_rejects_replay_and_tampering() -> TestResult
{
    watchdog::within(async {
        let source = Fixture::new("pair-source").await?;
        let target = Fixture::new("pair-target").await?;
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        let first = entry(&source, &target, &text(&source, &target, "one")?)?;
        let session = persist_opened(&target, &source, &first)?;
        assert!(target.client.open_routed(&first, &target.config.device_id).is_err());
        let exact = text(&source, &target, "two")?;
        let second = entry(&source, &target, &exact)?;
        let opened = target.client.open_routed(&second, &target.config.device_id)?;
        assert_eq!(opened.session.session_id, session);
        assert_eq!(opened.body.as_slice(), exact);
        let mut tampered = second.clone();
        tampered.envelope.envelope_id = "different-envelope".into();
        assert!(target.client.open_routed(&tampered, &target.config.device_id).is_err());
        let mut tampered = second.clone();
        let mut payload = ramflux_protocol::decode_base64url(&tampered.envelope.encrypted_payload)?;
        *payload.last_mut().ok_or("empty payload")? ^= 1;
        tampered.envelope.encrypted_payload = ramflux_protocol::encode_base64url(payload);
        assert!(target.client.open_routed(&tampered, &target.config.device_id).is_err());
        assert_eq!(persist_opened(&target, &source, &second)?, session);
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn device_pair_session_supports_reply_direction() -> TestResult {
    watchdog::within(async {
        let source = Fixture::new("reply-source").await?;
        let target = Fixture::new("reply-target").await?;
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        let first = entry(&source, &target, &text(&source, &target, "hello")?)?;
        let session = persist_opened(&target, &source, &first)?;
        let exact = text(&target, &source, "reply body")?;
        let reply = entry(&target, &source, &exact)?;
        let opened = source.client.open_routed(&reply, &source.config.device_id)?;
        assert_eq!(opened.session.session_id, session);
        assert_eq!(opened.body.as_slice(), exact);
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn media_projection_failure_rolls_back_generated_body_and_receive_pair() -> TestResult {
    watchdog::within(async {
        let (source, mut target, content) =
            Box::pin(crate::client::native_test_support::activation_send::tests::media_pair())
                .await?;
        let conversation = g::dm_scope::derive(
            &source.client.own_account_anchor()?,
            &target.client.own_account_anchor()?,
        )?;
        let mut request = crate::GatewayDirectMessage {
            conversation_id: conversation.clone(),
            message_id: "atomic-media-operation".into(),
            envelope_id: "atomic-media-envelope".into(),
            source_principal_id: source.config.principal_id.clone(),
            sender_id: source.config.device_id.clone(),
            recipient_device_id: Some(target.config.device_id.clone()),
            recipient_principal_commitment: Some(target.client.own_account_anchor()?),
            target_delivery_id: target.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: 300,
        };
        let prepared = source.client.prepare_authored_message(&mut request, None, &content)?;
        let packet = source.seal_inner_to_with_id(
            &target,
            &prepared.wire,
            &request.envelope_id,
        )?;
        let local = target.client.owned_device_identity()?;
        let remote = source.client.owned_device_identity()?;
        let before = target.client.persisted_pair_snapshot(&local, &remote)?;
        crate::client::routed::receive::commit_fault::fail_before(
            crate::client::routed::receive::commit_fault::Kind::Content,
        );
        let error = target.receive(packet.clone(), 1).await.err().ok_or("fault was not reached")?;
        assert!(
            matches!(error.downcast_ref::<SdkError>(), Some(SdkError::LocalBus(reason)) if reason == "routed commit fault"),
            "media fixture failed before the intended transaction cut: {error}"
        );
        assert_eq!(target.client.persisted_pair_snapshot(&local, &remote)?, before);
        assert!(target.client.account_db()?.message_content(&request.message_id)?.is_none());
        assert_eq!(target.client.direct_messages(&conversation)?.len(), 0);
        target.receive(packet.clone(), 1).await?;
        target.receive(packet, 1).await?;
        let detail = target.client.generated_message_detail(&conversation, &request.message_id)?;
        let Some(g::content::Value::Message(message)) = detail.message.content.and_then(|value| value.value) else {
            return Err("test: restored public Message missing".into());
        };
        let mut public_media = content.media.clone();
        for media in &mut public_media {
            media.key_slots.clear();
            if let Some(manifest) = media.large_manifest.as_mut() {
                manifest.key_slots.clear();
                manifest.read_capability.fill(0);
                manifest.read_capability.clear();
            }
        }
        assert_eq!(message.media, public_media, "retry lost public r4 metadata or exposed a capability");
        assert_eq!(target.client.direct_messages(&conversation)?.len(), 1);
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn native_bootstrap_refuses_retired_ordering_without_pair_effects() -> TestResult {
    watchdog::within(async {
        let source = Fixture::new("bootstrap-source").await?;
        let target = Fixture::new("bootstrap-target").await?;
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        let packet = entry(&source, &target, &text(&source, &target, "current bootstrap")?)?;
        assert!(target.client.open_routed(&packet, &target.config.device_id).is_ok());
        let header = super::super::decode(&packet.envelope)?.x3dh.ok_or("native bootstrap")?;
        assert_eq!(header.bootstrap_ordering_version, Some(2));
        let local = target.client.owned_device_identity()?;
        let remote = source.client.owned_device_identity()?;
        let before = target.client.persisted_pair_snapshot(&local, &remote)?;
        for ordering in [None, Some(1), Some(3)] {
            let mut retired = header.clone();
            retired.bootstrap_ordering_version = ordering;
            assert!(
                matches!(
                    target.client.create_recv_dm_session_with_aad(&retired, b"retired ordering"),
                    Err(SdkError::PairRecoveryRequired)
                ),
                "retired ordering {ordering:?} reached a bootstrap transcript"
            );
            assert_eq!(target.client.persisted_pair_snapshot(&local, &remote)?, before);
        }
        Ok(())
    })
    .await?
}
