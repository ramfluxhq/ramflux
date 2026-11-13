// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native signed group evidence: a forwarder cannot replace the original commitment.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use serde_json::json;

async fn fixture() -> TestResult<(Fixture, g::Inner, RetainedOrigin)> {
    let owner = Fixture::with_device("group-origin", "author-device").await?;
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("account")?
        .group_primary(owner.vault.as_ref())?;
    let state = owner.client.shared_group_create_with_primary(
        "origin-group",
        "origin-thread",
        None,
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    let source = owner.client.owned_device_identity()?;
    let author = g::QualifiedDevice {
        account_anchor: source.root_commitment().into(),
        device_id: source.device_id().into(),
        device_epoch: 1,
    };
    let plaintext = g::Message {
        text: "original group content".into(),
        erasure_nonce: vec![42; 32],
        ..Default::default()
    }
    .encode_to_vec();
    let mut session = ramflux_crypto::DmSession::initiator([1; 32], [2; 32], [3; 32], [4; 32])?;
    let aad = crate::group::group_key_associated_data(
        "origin-group",
        &source,
        state.view().epoch,
        Some(&state.snapshot().state_hash),
    )?;
    let encrypted = session.encrypt_with_franking_keys(&plaintext, &aad)?;
    let message = crate::client::generated_group::from_native(
        crate::group::SdkGroupEncryptedEnvelope {
            schema: "ramflux.sdk.group_sender_key.message.v2".into(),
            version: 2,
            group_id: "origin-group".into(),
            sender_id: source.device_id().into(),
            group_key_epoch: state.view().epoch,
            group_state_hash: Some(state.snapshot().state_hash.clone()),
            ciphertext: encrypted.ciphertext,
        },
        author.clone(),
    )?;
    let identity = g::EventIdentity {
        id: g::identity::derive(&author, "origin-thread", 1)?.to_vec(),
        conversation_id: "origin-thread".into(),
        author: Some(author),
        device_sequence: 1,
        hlc: 1000,
        group_id: Some("origin-group".into()),
        group_epoch: Some(state.view().epoch),
    };
    let inner = g::Inner {
        layer: g::registry::COMPILED_LAYER,
        kind: 1,
        identity: Some(identity),
        body: message.encode_to_vec(),
    };
    let (canonical_sender_envelope, kf) = signed_outer(&owner, &inner)?;
    let now = crate::custody::network_now()?;
    let custody =
        owner.client.current_custody_evidence(source.root_commitment(), now)?.ok_or("authority")?;
    let manifest = ramflux_protocol::custody::CustodyManifest {
        publication: custody.publication,
        custodian_publication: custody.custodian_publication,
        devices: Vec::new(),
    };
    let origin = RetainedOrigin {
        evidence: g::HistoryOriginEvidence {
            canonical_sender_envelope,
            source_authority: Some(g::NativeCustodyManifest {
                canonical: ramflux_protocol::canonical_json_bytes(&manifest)?,
            }),
            report_opening: kf.to_vec(),
            group_membership: Some(g::NativeGroupSnapshot {
                canonical: ramflux_protocol::canonical_json_bytes(state.snapshot())?,
            }),
            group_plaintext: plaintext,
            group_opening: [encrypted.opening_key.as_slice(), encrypted.commitment_key.as_slice()]
                .concat(),
        },
        reported_inner: Vec::new(),
        routing: Routing {
            kind: crate::client::routed::Kind::GroupMessage,
            conversation_id: "origin-thread".into(),
            message_id: ramflux_protocol::encode_base64url(
                &inner.identity.as_ref().ok_or("identity")?.id,
            ),
            group_id: Some("origin-group".into()),
            group_message_id: None,
            attachments: false,
        },
    };
    Ok((owner, inner, origin))
}

fn signed_outer(owner: &Fixture, inner: &g::Inner) -> TestResult<(Vec<u8>, [u8; 32])> {
    let source = owner.client.owned_device_identity()?;
    let exact = inner.encode_to_vec();
    let now = crate::custody::network_now()?;
    let mut vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/src/sender_transcript_vectors.json"
    ))?;
    let mut outer = vectors["envelope"].take();
    outer["created_at"] = json!(now);
    outer["ttl"] = json!(300);
    outer["delivery_mode"] = json!("durable");
    outer["delivery_class"] = json!("message");
    outer["source_principal_id"] = json!(owner.manifest.principal_id);
    outer["source_device_id"] = json!(source.device_id());
    outer["ext"] = json!({"source_root_commitment": source.root_commitment()});
    outer["ext"][g::original_header::EXT_KEY] =
        json!(g::original_header::for_inner(&exact, now, now + 300)?.ok_or("header")?);
    let envelope: ramflux_protocol::Envelope = serde_json::from_value(outer.clone())?;
    let a0 = g::outer::encode_candidate_report_a0(&g::outer::candidate_report_a0_from_envelope(
        &envelope,
    )?)?;
    let kf = [31; 32];
    outer["report_commitment"] = json!(ramflux_protocol::encode_base64url(
        ramflux_crypto::report_commitment(&kf, &exact, &a0)?
    ));
    outer["signature"] = json!(ramflux_crypto::sign_protocol_object_with_device_branch(
        owner.client.device_branch.as_ref().ok_or("branch")?,
        &outer
    )?);
    Ok((ramflux_protocol::sender_origin_evidence(&outer)?, kf))
}

#[tokio::test]
async fn group_origin_signed_wrapper_rejects_altered_plaintext_and_missing_evidence() -> TestResult
{
    let (_owner, inner, origin) = fixture().await?;
    let identity = inner.identity.as_ref().ok_or("identity")?;
    origin.verify(identity, &inner.encode_to_vec())?;
    let item = g::HistoryItem {
        exact_inner: inner.encode_to_vec(),
        source_evidence: Some(origin.evidence.clone()),
        ..Default::default()
    };
    let wire = item.encode_to_vec();
    let decoded = g::HistoryItem::decode(wire.as_slice())?;
    RamfluxClient::verify_history_message_origin(&decoded)?;
    let mut absent = decoded.clone();
    absent.source_evidence = None;
    assert!(matches!(
        RamfluxClient::verify_history_message_origin(&absent),
        Err(SdkError::HistoryEvidence(EvidenceError::OriginEvidenceMissing))
    ));
    for change in ["plaintext", "opening", "membership", "swapped", "outer", "recursive"] {
        let mut modified = origin.clone();
        match change {
            "plaintext" => {
                let mut message = g::Message::decode(modified.evidence.group_plaintext.as_slice())?;
                message.text.push('!');
                modified.evidence.group_plaintext = message.encode_to_vec();
            }
            "opening" => modified.evidence.group_opening.clear(),
            "membership" => modified.evidence.group_membership = None,
            "swapped" => modified.evidence.group_opening.rotate_left(32),
            "outer" => modified.evidence.canonical_sender_envelope.clear(),
            "recursive" => {
                modified.evidence.group_plaintext = g::Message {
                    sealed_group: Some(g::GroupSealedContent::default()),
                    ..Default::default()
                }
                .encode_to_vec();
            }
            _ => unreachable!(),
        }
        assert!(
            modified.verify(identity, &inner.encode_to_vec()).is_err(),
            "signed group origin accepted {change}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn group_opening_is_captured_during_native_first_decrypt() -> TestResult {
    let owner = Fixture::with_device("opening-owner", "owner-device").await?;
    let peer = Fixture::with_device("opening-peer", "peer-device").await?;
    owner.client.persist_fetched_identity_directory(&peer.manifest)?;
    peer.client.persist_fetched_identity_directory(&owner.manifest)?;
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("account")?
        .group_primary(owner.vault.as_ref())?;
    owner.client.shared_group_create_with_primary(
        "opening-group",
        "opening-thread",
        None,
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    let state = owner.client.shared_group_change_with_primary(
        "opening-group",
        &owner.config.target_delivery_id,
        ramflux_protocol::GroupStateChange::Add {
            member: peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    peer.client.accept_shared_group_state(&state, &peer.config.target_delivery_id)?;
    peer.client.import_group_sender_key_distribution(
        &owner
            .client
            .export_group_sender_key_distribution("opening-group", &owner.config.device_id)?,
    )?;
    let source = owner.client.owned_device_identity()?;
    for counter in 0..2 {
        let message = g::Message {
            text: format!("message {counter}"),
            erasure_nonce: vec![50 + counter; 32],
            ..Default::default()
        };
        let _effect_profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let wrapper = owner.client.encrypt_generated_group_message(
            "opening-group",
            &owner.config.device_id,
            &message,
        )?;
        let sealed = wrapper.sealed_group.as_ref().ok_or("sealed")?;
        let native = crate::client::generated_group::to_native(sealed)?;
        let decrypted = peer.client.account_db()?.write_transaction(|| {
            peer.client.decrypt_group_envelope_with_opening(
                &native,
                &format!("message-{counter}"),
                &source,
            )
        })?;
        assert_eq!(decrypted.plaintext, message.encode_to_vec());
        let mut opening = zeroize::Zeroizing::new(
            [decrypted.opening_key.as_slice(), decrypted.commitment_key.as_slice()].concat(),
        );
        ramflux_crypto::verify_group_message_opening(&mut opening, &decrypted.plaintext, sealed)?;
        assert!(opening.iter().all(|byte| *byte == 0));
        // Evidence must be captured from this success; decrypting again is a replay.
        assert!(
            peer.client
                .account_db()?
                .write_transaction(|| peer.client.decrypt_group_envelope_with_opening(
                    &native,
                    &format!("replay-{counter}"),
                    &source
                ))
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn group_reparse_uses_signed_opening_without_retaining_sender_chain() -> TestResult {
    use crate::client::routed::generated_receive::Provenance;
    use ramflux_storage::{RawInnerCopyKind, RawInnerCopyWrite};
    let (mut owner, inner, origin) = fixture().await?;
    let identity = inner.identity.as_ref().ok_or("identity")?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let source = owner.client.owned_device_identity()?;
    let outer: serde_json::Value =
        ramflux_protocol::parse_i_json(&origin.evidence.canonical_sender_envelope)?;
    let proof_id = origin.copy_id()?;
    let copy_id = "group-reparse/outer";
    let db = owner.client.account_db()?;
    let provenance = Provenance {
        source: source.storage_key().into(),
        conversation: identity.conversation_id.clone(),
        message: id.clone(),
        envelope_id: outer["envelope_id"].as_str().ok_or("envelope")?.into(),
        payload_hash: outer["payload_hash"].as_str().ok_or("payload")?.into(),
        expires_at: outer["created_at"].as_i64().ok_or("issued")?
            + outer["ttl"].as_i64().ok_or("ttl")?,
        original_mode: "durable".into(),
        source_epoch: 1,
        original_route: serde_json::to_string(&origin.routing)?,
        outer_receipt_key: copy_id.into(),
        source_evidence_copy: Some(proof_id.clone()),
        received_erasure_generation: db.privacy_erasure_generation()?,
    };
    db.write_transaction(|| -> Result<(), SdkError> {
        owner.client.merge_routed_group_link("origin-group", "origin-thread")?;
        db.import_direct_message_projection(ramflux_storage::DirectMessageWrite {
            conversation_id: "origin-thread",
            message_id: &id,
            sender_id: &owner.manifest.principal_id,
            encrypted_body: &[],
            metadata: &ramflux_storage::MessageMetadata::default(),
            created_at: crate::time::now_unix_timestamp(),
        })?;
        db.persist_message_actor_state(
            &id,
            &format!("routed/unsupported/{id}"),
            &g::UnsupportedView::default(),
        )?;
        owner.client.retain_raw_origin_copy(
            &id,
            source.root_commitment(),
            &proof_id,
            &origin,
            None,
        )?;
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: &id,
            verified_source_anchor: source.root_commitment(),
            copy_id,
            kind: RawInnerCopyKind::OuterInner,
            bytes: &inner.encode_to_vec(),
            bounded_metadata: &serde_json::to_vec(&provenance)?,
        })?;
        Ok(())
    })?;
    // No native sender-key distribution was ever installed: reparse has only the original proof.
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let progress = owner.client.reparse_raw_inner_page()?;
    assert_eq!(progress.projected, 1, "signed group origin did not reparse without chain keys");
    let db = owner.client.account_db()?;
    let projection = db
        .load_actor_state::<g::Message>(&format!("routed/group-projection/{id}"))?
        .ok_or("group projection")?;
    assert_eq!(projection.text, "original group content");
    assert!(db.raw_inner_copy(copy_id)?.is_none());
    assert!(db.raw_inner_copy(&proof_id)?.is_none());
    assert!(
        db.load_actor_state::<RetainedOrigin>(&format!("routed/origin-evidence/{id}"))?.is_some()
    );
    let exported = owner.client.export_generated_history_item(&identity.id)?;
    assert_eq!(exported.exact_inner, inner.encode_to_vec());
    let (reported, evidence) = owner.client.selected_generated_report_evidence(&identity.id)?;
    assert_eq!(reported, exported.exact_inner);
    assert!(evidence == origin.evidence, "report selected different original evidence");
    retire_and_fence_group_opening(&owner, &id, &origin)?;
    Ok(())
}

fn retire_and_fence_group_opening(
    owner: &Fixture,
    id: &str,
    origin: &RetainedOrigin,
) -> TestResult {
    let db = owner.client.account_db()?;
    db.write_transaction(|| -> Result<(), SdkError> {
        db.persist_message_actor_state(id, "history/page/cache/group", origin)?;
        db.persist_message_actor_state(id, "own-copy/prepared/group", origin)?;
        owner.client.retire_generated_edit_payloads("origin-thread", id)?;
        Ok(())
    })?;
    for key in [
        format!("routed/origin-evidence/{id}"),
        "history/page/cache/group".into(),
        "own-copy/prepared/group".into(),
    ] {
        assert!(!db.actor_state_exists(&key)?, "group opening survived Edit retirement at {key}");
    }
    assert!(matches!(
        db.write_transaction(|| owner.client.persist_known_origin(id, origin)),
        Err(SdkError::HistoryEvidence(EvidenceError::ReportOpeningRetired))
    ));
    db.delete_direct_message("origin-thread", id, "local", "group-delete")?;
    assert!(
        db.write_transaction(|| owner.client.persist_known_origin(id, origin)).is_err(),
        "Delete accepted a stale group opening"
    );
    Ok(())
}

#[tokio::test]
async fn native_history_message_import_preserves_original_proof_and_delete_fence() -> TestResult {
    let (owner, inner, origin) = fixture().await?;
    let source = owner.client.owned_device_identity()?;
    let item = g::HistoryItem {
        exact_inner: inner.encode_to_vec(),
        source_evidence: Some(origin.evidence.clone()),
        ..Default::default()
    };
    let id = inner.identity.as_ref().ok_or("identity")?.id.clone();
    let key = ramflux_protocol::encode_base64url(&id);
    assert!(owner.client.import_generated_history_message(&source, &item)?);
    assert!(
        !owner.client.import_generated_history_message(&source, &item)?,
        "same original is idempotent"
    );
    assert_eq!(owner.client.export_generated_history_item(&id)?.exact_inner, item.exact_inner);
    let row = owner.client.direct_message_by_id(&key)?.ok_or("row")?;
    let update = owner.client.generated_message_update(&row, "origin-thread", 0)?;
    let Some(g::message_update::State::Content(g::Content {
        value: Some(g::content::Value::Message(public)),
    })) = update.state
    else {
        return Err("public message missing".into());
    };
    assert!(public.erasure_nonce.is_empty(), "private entropy must never enter history updates");
    assert_eq!(public.text, "original group content");
    let mut forged = item.clone();
    forged.source_evidence.as_mut().ok_or("evidence")?.group_plaintext[2] ^= 1;
    assert!(
        owner.client.import_generated_history_message(&source, &forged).is_err(),
        "duplicate optimization must not skip original proof verification"
    );
    owner.client.account_db()?.delete_direct_message(
        "origin-thread",
        &key,
        "self",
        "native-history-delete",
    )?;
    assert!(!owner.client.import_generated_history_message(&source, &item)?);
    assert!(owner.client.account_db()?.message_content(&key)?.is_none());
    assert!(
        owner
            .client
            .account_db()?
            .load_actor_state::<RetainedOrigin>(&format!("routed/origin-evidence/{key}"))?
            .is_none()
    );
    assert!(owner.client.export_generated_history_item(&id).is_err());
    Ok(())
}

#[tokio::test]
async fn own_group_copy_of_received_original_matches_exact_authenticated_plaintext() -> TestResult {
    let (owner, inner, origin) = fixture().await?;
    let source = owner.client.owned_device_identity()?;
    let identity = inner.identity.as_ref().ok_or("identity")?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let item = g::HistoryItem {
        exact_inner: inner.encode_to_vec(),
        source_evidence: Some(origin.evidence.clone()),
        ..Default::default()
    };
    assert!(owner.client.import_generated_history_message(&source, &item)?);
    let group = owner
        .client
        .own_device_group_snapshot("origin-group", source.device_id())?
        .ok_or("own group context")?;
    let context = crate::client::surface::OwnContext {
        conversation_id: "origin-thread".into(),
        participants: Vec::new(),
        group: Some(group),
        friend: None,
    };
    let mut plaintext = inner.clone();
    plaintext.body = origin.evidence.group_plaintext.clone();
    let mut sent = g::OwnSentMessage {
        envelope_id: "copy-envelope".into(),
        message_id: id.clone(),
        sender_id: source.device_id().into(),
        original_recipients: vec![source.device_id().into()],
        exact_inner: plaintext.encode_to_vec(),
        context: Some(g::OwnContext::try_from(&context)?),
        ..Default::default()
    };
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/src/sender_transcript_vectors.json"
    ))?;
    let entry = crate::GatewayInboxEntry {
        envelope: serde_json::from_value(vectors["envelope"].clone())?,
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "copy-test".into(),
    };
    let mut forged = sent.clone();
    let mut changed_inner = plaintext.clone();
    let mut changed_body = g::Message::decode(changed_inner.body.as_slice())?;
    changed_body.text.push('!');
    changed_inner.body = changed_body.encode_to_vec();
    forged.exact_inner = changed_inner.encode_to_vec();
    assert!(
        matches!(
            owner.client.receive_generated_own_sent(&entry, &source, 42, &forged),
            Err(SdkError::ReplayMismatch)
        ),
        "a copy cannot replace received group plaintext"
    );
    assert!(owner.client.receive_generated_own_sent(&entry, &source, 42, &sent)?);
    assert_eq!(
        owner.client.account_db()?.message_content(&id)?,
        Some(inner.encode_to_vec()),
        "duplicate copy preserves first-hand signed group wrapper"
    );
    owner.client.export_generated_history_item(&identity.id)?;
    let mut message = g::Message::decode(plaintext.body.as_slice())?;
    message.text.push('!');
    plaintext.body = message.encode_to_vec();
    sent.exact_inner = plaintext.encode_to_vec();
    assert!(matches!(
        owner.client.receive_generated_own_sent(&entry, &source, 42, &sent),
        Err(SdkError::ReplayMismatch)
    ));
    Ok(())
}
