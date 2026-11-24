// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(test)]

//! Ordinary sends retain one authored revision and one transport packet across lost ACKs.
#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use crate::client::routed::Route;
    use crate::{GatewayDirectMessage, SdkError};
    use prost::Message as _;
    use ramflux_protocol::message as g;

    fn message(
        source: &Fixture,
        target: &Fixture,
        operation: &str,
    ) -> TestResult<GatewayDirectMessage> {
        Ok(GatewayDirectMessage {
            conversation_id: source
                .client
                .generated_direct_conversation_id(&target.client.owned_device_identity()?)?,
            message_id: operation.into(),
            envelope_id: format!("wire-{operation}"),
            source_principal_id: source.config.principal_id.clone(),
            sender_id: source.config.device_id.clone(),
            recipient_device_id: Some(target.config.device_id.clone()),
            recipient_principal_commitment: Some(target.client.own_account_anchor()?),
            target_delivery_id: target.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: 300,
        })
    }

    pub(crate) async fn publish_layer_four(fixture: &mut Fixture) -> TestResult {
        let primary_vault = fixture.vault.clone();
        Box::pin(publish_layer_four_with_primary(fixture, primary_vault)).await
    }

    pub(crate) async fn publish_layer_four_with_primary(
        fixture: &mut Fixture,
        primary_vault: Arc<TestVault>,
    ) -> TestResult {
        let now = crate::custody::network_now()?;
        let id = fixture.client.account_db()?.local_account_id.clone();
        crate::custody::tests::mark_live(&fixture.root.0, &id, now)?;
        let account = crate::custody::load_account(&fixture.root.0, &id, now)?;
        let now = now.max(account.record().body.issued_at + 1);
        let primary = primary_vault.primary_for_public_key(
            &account.record().body.master_certificate.body.self_signing_public_key,
        )?;
        let (_, branch) =
            account.credentials(fixture.vault.as_ref(), &fixture.config.device_id, now)?;
        let certificate_expiry = account
            .record()
            .body
            .devices
            .iter()
            .find(|row| row.device_id == fixture.config.device_id)
            .and_then(|row| row.branch_certificate.as_ref())
            .ok_or("layer publication certificate")?
            .body
            .expires_at;
        let publication = account
            .candidate_message_layer_publication(
                &fixture.root.0,
                &branch,
                &primary,
                ramflux_protocol::message::registry::COMPILED_LAYER,
                crate::custody::DeclarationValidity {
                    issued_at: now,
                    expires_at: certificate_expiry.min(now + 600),
                },
            )
            .map_err(|error| format!("layer declaration candidate: {error:?}"))?;
        let mut native = (**fixture.manifest.custody.as_ref().ok_or("native manifest")?).clone();
        native.publication = publication;
        for device in &mut native.devices {
            device.message_layer = native
                .publication
                .record
                .body
                .devices
                .iter()
                .find(|row| row.device_id == device.device_ref.device_id)
                .ok_or("published device")?
                .message_layer
                .clone();
        }
        let authority = ramflux_protocol::custody::CustodyAuthority {
            publication: native.publication.clone(),
            custodian_publication: native.custodian_publication.clone(),
        };
        crate::custody::accept_publication(&fixture.root.0, &id, &authority, now)
            .map_err(|error| format!("layer declaration adoption: {error:?}"))?;
        fixture.manifest = crate::prekey::SdkDeviceManifestResponse::from_native(native)?;
        fixture
            .client
            .initialize_born_v3_branch(&fixture.config.device_id, fixture.vault.clone())
            .await
            .map_err(|error| format!("layer declaration reload: {error:?}"))?;
        fixture.client.persist_observed_identity_directory_now(&fixture.manifest)?;
        fixture.config = fixture.config.clone().with_account_identity(&fixture.client)?;
        fixture.config.device_branch = Some(std::sync::Arc::new(
            fixture.client.device_branch.as_ref().ok_or("published branch")?.clone(),
        ));
        fixture.config.source_identity = Some(fixture.client.owned_device_identity()?);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retired_attachment_send_refuses_before_state_or_network_work() -> TestResult {
        super::super::watchdog::within(async {
            let mut source = Fixture::new("retired-attachment-source").await?;
            let target = Fixture::new("retired-attachment-target").await?;
            source.client.persist_observed_identity_directory_now(&target.manifest)?;
            let mut engine = crate::GatewaySessionEngine::with_test_transport(
                source.config.clone(), Box::new(super::super::sibling::NoNetwork),
            );
            let pool = ramflux_transport::RelayQuicPool::new(
                ramflux_transport::RelayQuicPoolConfig::functional_default()?,
            );
            let obsolete = crate::LocalBusMessageAttachmentInput {
                name: Some("retired.bin".into()), mime: None, object_id: "retired-object".into(),
                plaintext_base64: "malformed input must not be decoded".into(), chunk_size: 0,
                relay_endpoint: "invalid old relay".into(), owner_home_node_id: None,
                relay_audience_node_id: None, relay_service_key_base64: None,
            };
            let before = super::super::generation_zero_tests::actors(&source.client)?;
            for attachments in [&[][..], std::slice::from_ref(&obsolete)] {
                let result = source.client.send_plaintext_direct_message_with_attachments_via_gateway(
                    &mut engine, &pool, message(&source, &target, "retired-operation")?,
                    b"retired body", attachments,
                ).await;
                assert!(matches!(result, Err(SdkError::GeneratedRefused {
                    code: crate::GeneratedRefusalCode::Content, ..
                })), "the retired API must refuse Content before inspecting legacy metadata or transport");
                assert_eq!(super::super::generation_zero_tests::actors(&source.client)?, before);
                assert_eq!(source.client.account_db()?.actor_state_key_page("message-send/", 16)?.len(), 0);
                assert_eq!(source.client.account_db()?.actor_state_key_page("dm-pair/", 16)?.len(), 0);
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        }).await?
    }

    pub(crate) async fn media_pair() -> TestResult<(Fixture, Fixture, g::Message)> {
        // Publication requires a timestamp strictly after genesis. Establish that
        // precondition without a future-dated record or a wall-clock sleep.
        let genesis = crate::custody::network_now()?.saturating_sub(2);
        let mut source = Fixture::with_device_at("activation-source", "primary", genesis).await?;
        let mut target = Fixture::with_device_at("activation-target", "primary", genesis).await?;
        source.accept_peer(&target)?;
        target.accept_peer(&source)?;
        let media = prepared_media(&target)?;
        let mut broken = media.clone();
        broken.large_manifest = None;
        assert!(
            matches!(
                RamfluxClient::attachment_message_content("caption", &[broken]),
                Err(SdkError::GeneratedRefused { code: crate::GeneratedRefusalCode::Content, .. })
            ),
            "an old reference without r4 large_manifest must be a typed Content refusal"
        );
        let generated = RamfluxClient::attachment_message_content(
            "same operation, same private revision",
            std::slice::from_ref(&media),
        )?;
        let Some(g::content::Value::Message(content)) = generated.value else {
            return Err("test: attachment producer did not build Message".into());
        };
        let mut unsupported = message(&source, &target, "unsupported-media")?;
        assert!(
            matches!(
                source.client.prepare_authored_message(&mut unsupported, None, &content),
                Err(SdkError::LocalBusRefused { code, .. }) if code == "PeerUpgradeRequired"
            ),
            "r4 media requires an endorsed layer-4 peer before allocating identity"
        );
        publish_layer_four(&mut source).await?;
        publish_layer_four(&mut target).await?;
        source.client.persist_observed_identity_directory_now(&target.manifest)?;
        target.client.persist_observed_identity_directory_now(&source.manifest)?;
        Ok((source, target, content))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn high_level_media_send_and_retry_preserve_r4_content_through_native_receive()
    -> TestResult {
        super::super::watchdog::within(async {
            let (source, mut target, content) = Box::pin(media_pair()).await?;
            let request = message(&source, &target, "high-level-media-operation")?;
            let conversation = request.conversation_id.clone();
            let mut engine = super::super::peer_control_send::engine(&source, &target, false)?;
            let first = source
                .client
                .send_media_direct_message_via_gateway(
                    &mut engine,
                    request.clone(),
                    &content.text,
                    &content.media,
                )
                .await?;
            let opened = target.client.open_routed(&first, &target.config.device_id)?;
            let (identity, exact) = RamfluxClient::decode_generated_inner(&opened.body)?;
            let Some(g::content::Value::Message(actual)) = exact.value else {
                return Err("test: high-level send lost generated Message".into());
            };
            assert_eq!(
                actual.media, content.media,
                "high-level send changed the r4 manifest or key slots"
            );
            assert_eq!(
                actual.erasure_nonce.len(),
                32,
                "high-level send must prepare one private revision"
            );
            let owner = ramflux_protocol::encode_base64url(identity.id);
            assert_ne!(
                owner, request.message_id,
                "a caller operation token must not become the event identity"
            );
            let pair_before = source.client.persisted_pair_snapshot(
                &source.client.owned_device_identity()?,
                &target.client.owned_device_identity()?,
            )?;
            let mut retry = request;
            retry.envelope_id = "different-caller-retry-label".into();
            let second = source
                .client
                .send_media_direct_message_via_gateway(
                    &mut engine,
                    retry,
                    &content.text,
                    &content.media,
                )
                .await?;
            assert_eq!(
                serde_json::to_value(&second.envelope)?,
                serde_json::to_value(&first.envelope)?,
                "high-level retry must reuse the exact sealed transport"
            );
            assert_eq!(
                source.client.persisted_pair_snapshot(
                    &source.client.owned_device_identity()?,
                    &target.client.owned_device_identity()?
                )?,
                pair_before,
                "retry must not consume another pair-ratchet step"
            );
            target.receive(first.envelope, 1).await?;
            target.receive(second.envelope, 1).await?;
            let view = target.client.generated_message_detail(&conversation, &owner)?.message;
            assert_eq!(view.text.as_deref(), Some(content.text.as_str()));
            assert_eq!(
                target.client.generated_message_view_page(&conversation, None, 10)?.messages.len(),
                1,
                "high-level retry must not duplicate the canonical received message"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_send_retry_preserves_revision_transport_and_erasure() -> TestResult {
        super::super::watchdog::within(async {
            let (mut source, mut target, content) = Box::pin(media_pair()).await?;
            let mut first = message(&source, &target, "operation-1")?;
            let exact = source.client.prepare_authored_message(&mut first, None, &content)?;
            let (original, decoded) = RamfluxClient::decode_generated_inner(&exact.exact)?;
            assert_eq!(
                decoded.value,
                Some(g::content::Value::Message({
                    let mut value = content.clone();
                    let Some(g::content::Value::Message(actual)) = decoded.value.as_ref() else {
                        return Err("test: generated attachment Message missing".into());
                    };
                    value.erasure_nonce.clone_from(&actual.erasure_nonce);
                    value
                })),
                "the exact generated revision must retain all r4 attachment fields"
            );
            let envelope = source.client.account_db()?.write_transaction(|| {
                let sealed = source.client.seal_generated_routed_prepared(
                    &crate::bus::connection_manager::SessionMetadata::sealing_config_for(
                        &source.config,
                    )?,
                    &first,
                    &exact.wire,
                    Route::direct(),
                    source
                        .material_for(&target)
                        .map_err(|e| crate::SdkError::LocalBus(e.to_string()))?,
                )?;
                crate::dm::gateway_generated_envelope_from_sealed(
                    &crate::bus::connection_manager::SessionMetadata::sealing_config_for(
                        &source.config,
                    )?,
                    &mut first,
                    sealed,
                )
            })?;
            source.client.project_authored_message(&first, &exact.exact, &first.encrypted_body)?;
            let projection = source
                .client
                .account_db()?
                .direct_message_by_id(&first.message_id)?
                .ok_or("test: authored projection missing")?;
            assert!(projection.is_own, "receipts require the outgoing ownership bit");
            assert_eq!(
                projection.created_at, first.created_at,
                "projection must retain authored time"
            );
            let retransmitted = exact_retry(&source, &target, &first, &content, &exact, &envelope)?;
            target.receive(envelope, 1).await?;
            target.receive(retransmitted, 1).await?;
            assert!(
                !target
                    .client
                    .direct_message_by_id(&first.message_id)?
                    .ok_or("test: incoming message missing")?
                    .is_own,
                "the receive writer must not mark a peer's message as locally authored"
            );
            assert_eq!(
                target.client.account_db()?.message_content(&first.message_id)?,
                Some(exact.exact.clone()),
                "actual pair decryption and projection must retain r4 media exactly once"
            );
            assert_eq!(
                target.client.direct_messages(&first.conversation_id)?.len(),
                1,
                "a replay cannot duplicate the generated attachment message"
            );
            genuine_receipt(&mut source, &target, &first, &original).await?;
            let mut conflict = message(&source, &target, "operation-1")?;
            assert!(
                source
                    .client
                    .prepare_authored_message(
                        &mut conflict,
                        None,
                        &g::Message { text: "conflicting payload".into(), ..Default::default() }
                    )
                    .is_err(),
                "operation token cannot bind two payloads"
            );
            let mut next = message(&source, &target, "operation-2")?;
            let next = source.client.prepare_authored_message(&mut next, None, &content)?;
            let next = RamfluxClient::decode_generated_inner(&next.exact)?.0;
            assert_eq!(
                next.device_sequence,
                original.device_sequence + 1,
                "retry and conflict must not consume identity sequence"
            );
            assert_authored_retirement(&source, &target, &first, &content)?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?
    }

    async fn media_group() -> TestResult<(Fixture, Fixture, g::Message)> {
        let (source, mut target, content) = Box::pin(media_pair()).await?;
        let primary = source
            .client
            .born_v3_account
            .as_ref()
            .ok_or("group account")?
            .group_primary(source.vault.as_ref())?;
        source.client.shared_group_create_with_primary(
            "activation-media-group",
            "activation-media-thread",
            None,
            &source.config.target_delivery_id,
            Some(&primary),
        )?;
        let state = source.client.shared_group_change_with_primary(
            "activation-media-group",
            &source.config.target_delivery_id,
            ramflux_protocol::GroupStateChange::Add {
                member: target
                    .client
                    .owned_group_actor(&target.config.target_delivery_id)?
                    .identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
            Some(&primary),
        )?;
        target.client.accept_shared_group_state(&state, &target.config.target_delivery_id)?;
        let snapshot = source
            .client
            .shared_group_packet_for_recipient(&state, &target.client.owned_device_identity()?)?;
        assert_eq!(
            g::Inner::decode(snapshot.as_slice())?.layer,
            g::registry::PROFILE_FLOOR,
            "ordinary native snapshots must not demand the r4 media layer"
        );
        // Snapshot admission refreshes issuer authority through the real directory adapter.
        let directory = super::super::directory::Directory::new(vec![
            source.manifest.clone(),
            target.manifest.clone(),
        ])
        .await?;
        directory.configure(&mut target);
        target
            .receive(source.seal_inner_to(&target, &snapshot)?, 1)
            .await
            .map_err(|error| format!("native group snapshot receive: {error}"))?;
        assert!(directory.requests() > 0, "snapshot admission must fetch genuine issuer authority");
        Ok((source, target, content))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn group_media_uses_one_r4_revision_through_native_group_and_pair_crypto() -> TestResult {
        super::super::watchdog::within(async {
            let (source, mut target, content) = Box::pin(media_group()).await?;
            let control_keys = source.client.account_db()?.actor_state_key_page("routed/sealed-send/", 16)?;
            let mut first = message(&source, &target, "group-media-operation")?;
            first.conversation_id = "activation-media-thread".into();
            let original_request = first.clone();
            let prepared = source.client.prepare_authored_message(
                &mut first,
                Some("activation-media-group"),
                &content,
            )?;
            assert_ne!(prepared.exact, prepared.wire, "group crypto must wrap the exact Inner");
            let wrapper = g::Inner::decode(prepared.wire.as_slice())?;
            assert_eq!(wrapper.layer, 4, "r4 media cannot be sent at a lower layer");
            let mut retry = original_request;
            retry.envelope_id = "changed-group-retry-header".into();
            let retained = source.client.prepare_authored_message(
                &mut retry,
                Some("activation-media-group"),
                &content,
            )?;
            assert_eq!(retained.exact, prepared.exact, "group retry must retain private revision");
            assert_eq!(
                retained.wire, prepared.wire,
                "group retry must retain sender-key ciphertext"
            );
            assert_eq!(
                retry.envelope_id, first.envelope_id,
                "group transport header must be stable"
            );
            let envelope = source.client.account_db()?.write_transaction(|| {
                let sealed = source.client.seal_generated_routed_prepared(
                    &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&source.config)?,
                    &first,
                    &prepared.wire,
                    Route::group_message("activation-media-group"),
                    source
                        .material_for(&target)
                        .map_err(|error| SdkError::LocalBus(error.to_string()))?,
                )?;
                crate::dm::gateway_generated_envelope_from_sealed(
                    &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&source.config)?,
                    &mut first,
                    sealed,
                )
            })?;
            source.client.project_authored_message(&first, &prepared.exact, &prepared.wire)?;
            target.receive(envelope.clone(), 2).await?;
            target.receive(envelope, 2).await?;
            assert_eq!(
                target.client.account_db()?.message_content(&first.message_id)?,
                Some(prepared.wire.clone()),
                "native group receive must retain the exact authenticated sealed Inner"
            );
            let plaintext = g::Inner::decode(prepared.exact.as_slice())?.body;
            assert_eq!(target.client.account_db()?.load_actor_state::<Vec<u8>>(
                &format!("routed/group-content/{}", first.message_id))?, Some(plaintext),
                "decrypted group content must preserve every r4 field and the exact private revision");
            assert_eq!(
                target.client.direct_chat_messages("activation-media-thread")?.len(),
                1,
                "group replay must not duplicate the media message"
            );
            source.client.delete_direct_message(
                "activation-media-thread",
                &first.message_id,
                "local",
                &ramflux_protocol::hash_base64url("ramflux.test.local-delete.v1", b"erase-group-media"),
            )?;
            assert_eq!(
                source.client.account_db()?.actor_state_key_page("routed/sealed-send/", 16)?,
                control_keys,
                "group erasure must retire media ciphertext and retain unrelated snapshot control"
            );
            let mut erased = message(&source, &target, "group-media-operation")?;
            erased.conversation_id = "activation-media-thread".into();
            assert!(
                source
                    .client
                    .prepare_authored_message(&mut erased, Some("activation-media-group"), &content)
                    .is_err(),
                "erased group operation cannot allocate a replacement revision"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?
    }

    fn assert_authored_retirement(
        source: &Fixture,
        target: &Fixture,
        first: &GatewayDirectMessage,
        content: &g::Message,
    ) -> TestResult {
        source.client.account_db()?.delete_direct_message(
            &first.conversation_id,
            &first.message_id,
            "local",
            "erase-operation",
        )?;
        let mut erased = message(source, target, "operation-1")?;
        assert!(
            source.client.prepare_authored_message(&mut erased, None, content).is_err(),
            "erasure must retire prepared content without resurrection"
        );
        assert_eq!(
            source.client.account_db()?.actor_state_keys("routed/sealed-send/")?.len(),
            0,
            "erasure must retire the retained ciphertext"
        );
        Ok(())
    }

    async fn genuine_receipt(
        source: &mut Fixture,
        target: &Fixture,
        first: &GatewayDirectMessage,
        original: &g::EventIdentity,
    ) -> TestResult {
        let own = target.client.owned_device_identity()?;
        let receipt_identity = target.client.allocate_generated_identity(
            &first.conversation_id,
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        let receipt = RamfluxClient::encode_generated_inner(
            receipt_identity.clone(),
            &g::Content {
                value: Some(g::content::Value::Receipt(g::Receipt {
                    targets: vec![g::MessageRef {
                        id: original.id.clone(),
                        conversation_id: first.conversation_id.clone(),
                        author_anchor: source.client.own_account_anchor()?,
                    }],
                    state: g::ReceiptState::ReceiptDelivered.into(),
                    at: u64::try_from(first.created_at)?,
                    receiver: receipt_identity.author.clone(),
                })),
            },
        )?;
        let sealed_receipt = target.seal_inner_to(source, &receipt)?;
        source.receive(sealed_receipt, 1).await?;
        let received = source
            .client
            .direct_message_by_id(&first.message_id)?
            .ok_or("test: receipt target missing")?;
        assert!(
            received.receipts.iter().any(|receipt| receipt.device_id == own.device_id()
                && receipt.principal_commitment.as_deref() == Some(own.root_commitment())),
            "a genuine peer receipt must update the authored canonical message"
        );
        Ok(())
    }

    fn exact_retry(
        source: &Fixture,
        target: &Fixture,
        first: &GatewayDirectMessage,
        content: &g::Message,
        exact: &crate::client::authored_send::PreparedMessage,
        envelope: &ramflux_protocol::Envelope,
    ) -> TestResult<ramflux_protocol::Envelope> {
        let mut retry = message(source, target, "operation-1")?;
        retry.envelope_id = "caller-retried-with-a-different-transport-id".into();
        retry.created_at += 10;
        let retained = source.client.prepare_authored_message(&mut retry, None, content)?;
        assert_eq!(
            retry.envelope_id, first.envelope_id,
            "an operation retry must retain its first transport identity"
        );
        assert_eq!(retained.exact, exact.exact, "retry must retain the private revision nonce");
        assert_eq!(retry.message_id, first.message_id, "retry must retain the canonical identity");
        let sealed = source.client.seal_generated_routed_prepared(
            &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&source.config)?,
            &retry,
            &retained.wire,
            Route::direct(),
            source.material_for(target)?,
        )?;
        let retransmitted = crate::dm::gateway_generated_envelope_from_sealed(
            &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&source.config)?,
            &mut retry,
            sealed,
        )?;
        assert_eq!(
            ramflux_protocol::canonical_json_bytes(envelope)?,
            ramflux_protocol::canonical_json_bytes(&retransmitted)?,
            "lost ACK must resend exactly the committed transport envelope"
        );
        Ok(retransmitted)
    }

    pub(crate) fn prepared_media(target: &Fixture) -> TestResult<g::MediaRef> {
        use ramflux_protocol::large_attachment as large;
        let own = target.client.owned_device_identity()?;
        let slots = vec![large::MediaKeySlot {
            recipient: large::QualifiedDevice {
                account_anchor: own.root_commitment().into(),
                device_id: own.device_id().into(),
                device_epoch: 1,
            },
            encrypted_key: vec![7; 48],
            format: 1,
            grant_id: vec![6; 32],
            read_capability: b"capability".to_vec(),
        }];
        let manifest = large::MediaManifest {
            manifest_id: [8; 32],
            plaintext_digest: [9; 32],
            plaintext_length: 3,
            ciphertext_length: 19,
            encrypted_segment_bytes: large::SEGMENT_BYTES,
            network_chunk_bytes: 524_288,
            segment_digests: vec![[6; 32]],
            key_slots: slots.clone(),
            relay_origin: "https://relay.example".into(),
            read_capability: Vec::new(),
            expires_at: 4_000_000_000,
            retention_class: "relay_retained.v1".into(),
        };
        let reference = large::MediaRef {
            width: None,
            height: None,
            duration_ms: None,
            animated: None,
            mime_type: "application/octet-stream".into(),
            file_name: Some("three-bytes.bin".into()),
            inline_thumbnail: None,
            object_id: ramflux_protocol::encode_base64url([5; 32]),
            manifest_digest: manifest.hash()?,
            size: 3,
            key_slots: slots,
            large_manifest: manifest,
        };
        Ok(g::MediaRef::decode(reference.canonical_bytes()?.as_slice())?)
    }

    async fn native_history_targets(
        source: &mut Fixture,
        reference: &str,
    ) -> TestResult<Vec<String>> {
        use crate::client::own_device_copy::{OwnMessageInput, OwnPayloadKind};
        let mut sibling = source.enroll_sibling("activation-history-one", "history-one").await?;
        let _other = source.enroll_sibling("activation-history-other", "history-other").await?;
        sibling.manifest = source.manifest.clone();
        sibling.client.persist_observed_identity_directory_now(&source.manifest)?;
        let target = sibling.client.owned_device_identity()?;
        let audience = g::QualifiedDevice {
            account_anchor: target.root_commitment().into(),
            device_id: target.device_id().into(),
            device_epoch: sibling
                .client
                .device_branch
                .as_ref()
                .ok_or("history branch")?
                .device_epoch,
        };
        assert!(source.client.start_generated_history_transfer(&sibling.config.device_id)?);
        let keys = source.client.account_db()?.actor_state_key_page("own-device/send/", 16)?;
        assert!(!keys.is_empty(), "native Surface history must stage a typed courier packet");
        for key in &keys {
            let row = source
                .client
                .account_db()?
                .load_actor_state::<serde_json::Value>(key)?
                .ok_or("history courier work")?;
            assert_eq!(
                row["audience"],
                serde_json::to_value(&audience)?,
                "target-bound history must retain the intended recipient across retries"
            );
            let intent = &row["intent"];
            let bytes =
                ramflux_protocol::decode_base64url(intent["body"].as_str().ok_or("history body")?)?;
            let mut draft = source
                .client
                .prepare_own_copy_draft(
                    &source.config,
                    OwnMessageInput {
                        payload_kind: OwnPayloadKind::Surface,
                        id: intent["id"].as_str().ok_or("history id")?,
                        created_at: intent["created_at"].as_i64().ok_or("history time")?,
                        conversation: intent["conversation"].as_str().ok_or("history scope")?,
                        group: None,
                        body: &bytes,
                    },
                    source.manifest.clone(),
                )?
                .ok_or("history draft")?;
            assert_eq!(draft.messages.len(), 2, "calibration must contain two active siblings");
            RamfluxClient::restrict_own_copy_target(&mut draft, &audience)?;
            assert_eq!(draft.messages.len(), 1);
            assert_eq!(
                draft.messages.first().and_then(|message| message.recipient_device_id.as_deref()),
                Some("history-one")
            );
            let envelopes = source.client.seal_own_copy_generated(
                &crate::bus::connection_manager::SessionMetadata::sealing_config_for(
                    &source.config,
                )?,
                draft,
                vec![source.material_for(&sibling)?],
            )?;
            assert_eq!(envelopes.len(), 1, "sealing must never broadcast target-bound history");
            let (_, envelope) = envelopes.into_iter().next().ok_or("history envelope")?;
            Box::pin(sibling.receive(envelope, 1)).await?;
            assert_eq!(
                sibling.client.surface_get_ref(reference, 0, None)?["version"],
                1,
                "typed history must restore actual native Surface state"
            );
        }
        Ok(keys)
    }

    pub(crate) fn task_content(
        source: &Fixture,
        target: &Fixture,
        conversation: &str,
    ) -> TestResult<g::Content> {
        let event = ramflux_protocol::TaskEvent::new(
            conversation.into(),
            ramflux_protocol::TaskEventBody::Start(ramflux_protocol::TaskStart {
                task_id: "activation-native-task".into(),
                conversation_id: conversation.into(),
                requester: source.config.principal_id.clone(),
                assignee: target.config.principal_id.clone(),
                text: "Retain the native task".into(),
                constraints: None,
            }),
            crate::prelude::sdk_device_signed_fields(&source.config.device_id, ""),
        )?;
        let carrier = source.client.sign_task_event(event, "native-task-operation".into(), None)?;
        Ok(g::Content {
            value: Some(g::content::Value::Task(g::Task {
                payload: Some(g::task::Payload::Carrier(carrier.to_generated()?)),
            })),
        })
    }

    #[tokio::test(flavor = "current_thread")]
    async fn typed_task_crosses_real_pair_and_keeps_one_canonical_authored_revision() -> TestResult
    {
        super::super::watchdog::within(async {
            let source = Fixture::new("task-activation-source").await?;
            let mut target = Fixture::new("task-activation-target").await?;
            source.accept_peer(&target)?;
            target.accept_peer(&source)?;
            let mut outgoing = message(&source, &target, "task-start-operation")?;
            let content = task_content(&source, &target, &outgoing.conversation_id)?;
            let prepared = source.client.prepare_authored_content(&mut outgoing, None, &content)?;
            let mut retry = message(&source, &target, "task-start-operation")?;
            let retained = source.client.prepare_authored_content(&mut retry, None, &content)?;
            assert_eq!(prepared.exact, retained.exact, "Task retry must retain its canonical revision");
            assert_eq!(outgoing.message_id, retry.message_id, "Task retry must retain its event identity");
            source.client.project_authored_message(&outgoing, &prepared.exact, &[])?;
            let Some(g::content::Value::Task(g::Task { payload: Some(g::task::Payload::Carrier(carrier)) })) = content.value.as_ref() else {
                return Err("test: Task carrier missing".into());
            };
            let native = crate::client::task::carrier::Carrier::from_generated(carrier)?;
            let outcome = source.client.project_task_message(&crate::client::task::Delivery {
                conversation: &outgoing.conversation_id, message: &outgoing.message_id,
                principal: &source.config.principal_id, device: &source.config.device_id, at: outgoing.created_at,
            }, &native.bytes()?)?.ok_or("test: authored Task projection missing")?;
            assert!(outcome.accepted, "native Task executor must accept the authored start");
            let envelope = source.client.account_db()?.write_transaction(|| {
                let sealed = source.client.seal_generated_routed_prepared(&crate::bus::connection_manager::SessionMetadata::sealing_config_for(&source.config)?, &outgoing,
                    &prepared.wire, Route::direct(), source.material_for(&target)
                        .map_err(|error| SdkError::LocalBus(error.to_string()))?)?;
                crate::dm::gateway_generated_envelope_from_sealed(&crate::bus::connection_manager::SessionMetadata::sealing_config_for(&source.config)?, &mut outgoing, sealed)
            })?;
            target.receive(envelope.clone(), 1).await?;
            target.receive(envelope, 1).await?;
            assert_eq!(target.client.account_db()?.message_content(&outgoing.message_id)?, Some(prepared.exact.clone()),
                "actual native Task receive must preserve the exact generated Inner");
            assert_eq!(target.client.task_get(Some(&outgoing.conversation_id), "activation-native-task")?["version"], 1,
                "the real native Task executor must apply the start exactly once");
            assert_eq!(target.client.task_history(&outgoing.conversation_id, "activation-native-task")?.events.len(), 1,
                "replayed Task transport must not duplicate native history");
            source.client.account_db()?.delete_direct_message(&outgoing.conversation_id,
                &outgoing.message_id, "local", "erase-native-task")?;
            assert!(source.client.account_db()?.message_content(&outgoing.message_id)?.is_none(),
                "canonical Task erasure must remove the authored exact Inner");
            Ok(())
        }).await?
    }

    fn surface_content(
        source: &Fixture,
        outgoing: &GatewayDirectMessage,
    ) -> TestResult<(crate::client::surface::Carrier, g::Content)> {
        use crate::client::surface::{Carrier, ControlKind, PayloadKind};
        let wire = crate::client::surface::test_support::create_frame(
            &outgoing.conversation_id,
            &crate::client::surface::test_support::text_snapshot(
                "activation_surface",
                "typed surface ready",
                "ready",
            ),
        )?
        .wire_bytes()?;
        let carrier = source.client.sign_surface_carrier(Carrier {
            typed: None,
            schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
            content_type: "surface".into(),
            posted_at: None,
            updated_at: None,
            payload_kind: PayloadKind::Event,
            conversation_id: outgoing.conversation_id.clone(),
            surface_id: "activation_surface".into(),
            message_id: "native-surface-operation".into(),
            sender_principal_id: source.config.principal_id.clone(),
            sender_device_id: source.config.device_id.clone(),
            author_principal_id: source.config.principal_id.clone(),
            wire_base64: ramflux_protocol::encode_base64url(wire),
            signature: String::new(),
            snapshot: None,
        })?;
        let delivery = source.client.surface_control_packet(&carrier, ControlKind::Peer, None)?;
        let content = g::Content {
            value: Some(g::content::Value::Surface(g::Surface {
                payload: Some(g::surface::Payload::Delivery(delivery.to_generated()?)),
            })),
        };
        Ok((carrier, content))
    }

    fn assert_peer_card_rendered(
        target: &Fixture,
        outgoing: &GatewayDirectMessage,
        reference: &str,
        exact: Vec<u8>,
    ) -> TestResult {
        let detail = target
            .client
            .generated_message_detail(&outgoing.conversation_id, &outgoing.message_id)?;
        assert_eq!(
            detail.message.kind, "surface",
            "numeric dispatch must expose a typed Surface message"
        );
        let state = target.client.surface_get_ref(reference, 0, None)?;
        assert_eq!(
            state["render_allowed"],
            serde_json::json!(true),
            "an authenticated peer card renders on the recipient"
        );
        assert!(state["snapshot"].is_object(), "peer snapshot is readable");
        assert!(
            target
                .client
                .direct_messages(&outgoing.conversation_id)?
                .iter()
                .any(|message| message.message_id == outgoing.message_id),
            "native delivery must retain its timeline entry"
        );
        assert_eq!(
            target.client.account_db()?.message_content(&outgoing.message_id)?,
            Some(exact),
            "native projection must preserve the exact generated Inner"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn typed_surface_crosses_real_pair_and_erases_its_canonical_authored_copy() -> TestResult
    {
        super::super::watchdog::within(async {
            let mut source = Fixture::new("surface-activation-source").await?;
            let mut target = Fixture::new("surface-activation-target").await?;
            for (local, remote) in [(&source, &target), (&target, &source)] {
                local.accept_peer(remote)?;
            }
            let mut outgoing = message(&source, &target, "surface-create-operation")?;
            let (carrier, content) = surface_content(&source, &outgoing)
                .map_err(|error| format!("surface source: {error}"))?;
            source.client.validate_user_authored_content(&content, &outgoing.conversation_id)?;
            let prepared = source
                .client
                .prepare_authored_content(&mut outgoing, None, &content)
                .map_err(|error| format!("surface authored preparation: {error:?}"))?;
            source
                .client
                .project_authored_message(&outgoing, &prepared.exact, &[])
                .map_err(|error| format!("surface authored projection: {error:?}"))?;
            assert!(
                source
                    .client
                    .stage_surface_outgoing_as(&carrier, None, &outgoing.message_id)?
                    .accepted,
                "native Surface authority must accept the authored command"
            );
            let envelope = source.client.account_db()?.write_transaction(|| {
                let sealed = source.client.seal_generated_routed_prepared(
                    &crate::bus::connection_manager::SessionMetadata::sealing_config_for(
                        &source.config,
                    )?,
                    &outgoing,
                    &prepared.wire,
                    Route::direct(),
                    source
                        .material_for(&target)
                        .map_err(|error| SdkError::LocalBus(error.to_string()))?,
                )?;
                crate::dm::gateway_generated_envelope_from_sealed(
                    &crate::bus::connection_manager::SessionMetadata::sealing_config_for(
                        &source.config,
                    )?,
                    &mut outgoing,
                    sealed,
                )
            })?;
            target
                .receive(envelope, 1)
                .await
                .map_err(|error| format!("surface peer receive: {error}"))?;
            let reference = carrier.surface_reference()?;
            assert_peer_card_rendered(&target, &outgoing, &reference, prepared.exact.clone())?;
            let history_keys = native_history_targets(&mut source, &reference)
                .await
                .map_err(|error| format!("surface sibling history: {error}"))?;
            source.client.account_db()?.delete_direct_message(
                &outgoing.conversation_id,
                &outgoing.message_id,
                "local",
                "erase-native-surface",
            )?;
            for key in history_keys {
                assert!(
                    !source.client.account_db()?.actor_state_exists(&key)?,
                    "canonical erasure must retire queued native history containers"
                );
            }
            assert!(
                source
                    .client
                    .account_db()?
                    .actor_state_keys(&format!("surface/authored/{reference}/"))?
                    .is_empty(),
                "canonical erasure must remove the native authored carrier, including its plaintext"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await?
    }
}
