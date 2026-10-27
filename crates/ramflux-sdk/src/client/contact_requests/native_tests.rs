// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native consent validation, delayed exact-hash authority and primary-free retries.
use super::{Decision, delivery::Intent};
use crate::{
    GatewayDirectMessage, GatewayInboxEntry, SdkError,
    client::{
        native_test_support::{Fixture, TestResult},
        routed::{Kind, Routing},
    },
    custody::tests::TestVault,
};
use ramflux_protocol::custody::{CustodyAuthority, object_hash};
use std::{collections::BTreeSet, sync::Arc};

fn intent(sender: &Fixture, target: &Fixture) -> TestResult<Intent> {
    let root = sender.manifest.principal_commitment.clone();
    let nonce = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let now = crate::time::now_unix_timestamp();
    Ok(Intent {
        kind: Decision::Request,
        request_id: super::wire::request_id(&root, &nonce)?,
        requester_root: root,
        target_root: target.manifest.principal_commitment.clone(),
        peer_root: target.manifest.principal_commitment.clone(),
        note: Some("Hello from native authority".into()),
        expires_at: now + super::TTL,
        issued_at: now,
        nonce,
        attempts: 0,
        next_at: now,
        delivered: BTreeSet::new(),
        native_approval: None,
    })
}

pub(crate) async fn approve_request(sender: &Fixture, target: &Fixture) -> TestResult<Vec<u8>> {
    Ok(super::native_delivery::approve(
        &sender.client,
        &sender.config,
        &mut intent(sender, target)?,
        &sender.manifest,
    )
    .await?
    .to_vec())
}

fn transport(sender: &Fixture, target: &Fixture) -> TestResult<(GatewayInboxEntry, Routing)> {
    let conversation = super::conversation(
        &sender.manifest.principal_commitment,
        &target.manifest.principal_commitment,
    )?;
    let message = GatewayDirectMessage {
        conversation_id: conversation.clone(),
        message_id: "native-consent".into(),
        envelope_id: "native-consent".into(),
        source_principal_id: sender.manifest.principal_id.clone(),
        sender_id: "primary".into(),
        recipient_device_id: Some("primary".into()),
        recipient_principal_commitment: Some(target.manifest.principal_commitment.clone()),
        target_delivery_id: target.client.owned_device_identity()?.storage_key().into(),
        encrypted_body: b"authenticated carrier validation fixture".to_vec(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 3600,
    };
    Ok((
        GatewayInboxEntry {
            inbox_seq: 1,
            target_delivery_id: message.target_delivery_id.clone(),
            envelope: crate::dm::gateway_direct_message_envelope(&sender.config, &message, None)?,
        },
        Routing {
            kind: Kind::Control,
            conversation_id: conversation,
            group_id: None,
            message_id: message.message_id,
            attachments: false,
        },
    ))
}

#[tokio::test]
async fn native_contact_delayed_consent_requires_exact_old_record_and_current_branch() -> TestResult
{
    let sender = Fixture::new("native-consent-sender").await?;
    let target = Fixture::new("native-consent-target").await?;
    target.client.persist_fetched_identity_directory(&sender.manifest)?;
    let bytes = approve_request(&sender, &target).await?;
    let (entry, route) = transport(&sender, &target)?;
    let original = sender.manifest.custody.as_ref().ok_or("native")?.publication.clone();
    target.client.verify_contact_control(&entry, &route, &bytes)?;
    let primary = sender.vault.primary_for_public_key(
        &original.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = original.record.body.clone();
    body.device_set_epoch += 1;
    body.previous_record_hash = Some(object_hash(&original.record)?);
    body.profile.display_name = "Renamed Sender".into();
    let renamed = primary.sign_record(body)?;
    let mut manifest = sender.manifest.clone();
    manifest.custody.as_mut().ok_or("native")?.publication.record = renamed;
    target.client.persist_fetched_identity_directory(&manifest)?;
    assert!(matches!(
        target.client.verify_contact_control(&entry, &route, &bytes),
        Err(SdkError::ContactUnavailable(_))
    ));
    target.client.cache_contact_consent_authority(
        &original,
        crate::custody::network_now()? + 604_800,
        crate::custody::network_now()?,
    )?;
    let control = target.client.verify_contact_control(&entry, &route, &bytes)?;
    target.client.apply_contact_control(&control)?;
    assert_eq!(
        target
            .client
            .account_db()?
            .contact_request(&sender.manifest.principal_commitment, "inbound")?
            .ok_or("request")?
            .state,
        "pending"
    );
    let current = ramflux_crypto::custody::verify_publication(
        &CustodyAuthority {
            publication: manifest.custody.as_ref().ok_or("native")?.publication.clone(),
            custodian_publication: None,
        },
        crate::custody::network_now()?,
    )?;
    let revoked = primary.revoke_device(&current, "primary", crate::custody::network_now()?)?;
    let mut native = manifest.custody.ok_or("native")?;
    native.publication.record = revoked;
    native.devices.clear();
    target.client.persist_fetched_identity_directory(
        &crate::prekey::SdkDeviceManifestResponse::from_native(*native)?,
    )?;
    assert!(target.client.verify_contact_control(&entry, &route, &bytes).is_err());
    assert!(sender.client.identity_root.is_none());
    assert!(target.client.identity_root.is_none());
    assert!(!sender.root.0.join("local_bus_accounts").exists());
    Ok(())
}

#[tokio::test]
async fn native_contact_retry_needs_no_primary_but_new_intent_cannot_fall_back() -> TestResult {
    let sender = Fixture::new("native-retry-sender").await?;
    let target = Fixture::new("native-retry-target").await?;
    let mut pending = intent(&sender, &target)?;
    let approved = super::native_delivery::approve(
        &sender.client,
        &sender.config,
        &mut pending,
        &sender.manifest,
    )
    .await?;
    let mut unavailable = sender.config.clone();
    unavailable.custody.as_mut().ok_or("custody config")?.vault = Arc::new(TestVault::default());
    let retried = super::native_delivery::approve(
        &sender.client,
        &unavailable,
        &mut pending,
        &sender.manifest,
    )
    .await?;
    assert_eq!(approved, retried);
    let mut fresh = intent(&sender, &target)?;
    assert!(matches!(
        super::native_delivery::approve(&sender.client, &unavailable, &mut fresh, &sender.manifest)
            .await,
        Err(SdkError::CustodyVaultUnavailable)
    ));
    assert!(fresh.native_approval.is_none());
    Ok(())
}

#[tokio::test]
async fn native_expired_primary_signature_cannot_trigger_a_history_lookup() -> TestResult {
    let sender = Fixture::new("native-expired-sender").await?;
    let target = Fixture::new("native-expired-target").await?;
    let bytes = approve_request(&sender, &target).await?;
    let mut expired: ramflux_protocol::custody::Envelope<
        ramflux_protocol::custody::ContactConsentV2,
    > = serde_json::from_slice(&bytes)?;
    let now = crate::custody::network_now()?;
    expired.body.issued_at = now - 604_801;
    expired.body.expires_at = now - 1;
    expired.body.actor_record_hash = ramflux_protocol::encode_base64url([92; 32]);
    let primary = sender.vault.primary_for_public_key(
        &sender
            .manifest
            .custody
            .as_ref()
            .ok_or("native")?
            .publication
            .record
            .body
            .master_certificate
            .body
            .self_signing_public_key,
    )?;
    // Deliberately sign an invalid-lifetime intent to prove primary possession cannot
    // make an expired request spend lookup capacity or initiate network I/O.
    expired.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::custody::signing_bytes(
            ramflux_protocol::domain::CONTACT_REQUEST_V2,
            &expired.body,
        )?,
        *primary.vault_seed(),
    );
    let (entry, route) = transport(&sender, &target)?;
    assert!(matches!(
        target
            .client
            .prepare_native_contact_control(
                &target.config,
                &entry,
                &route,
                &serde_json::to_vec(&expired)?,
                Some(&sender.manifest)
            )
            .await,
        Err(SdkError::InboundRejected(_))
    ));
    assert!(target.client.account_db()?.contact_request_budget_available(
        "consent-history-global",
        1,
        crate::time::now_unix_timestamp()
    )?);
    Ok(())
}
