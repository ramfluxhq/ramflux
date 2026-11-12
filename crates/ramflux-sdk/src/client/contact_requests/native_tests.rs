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
    intent_for(sender, &target.manifest.principal_commitment)
}
fn intent_for(sender: &Fixture, target: &str) -> TestResult<Intent> {
    let root = sender.manifest.principal_commitment.clone();
    let nonce = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let now = crate::time::now_unix_timestamp();
    Ok(Intent {
        kind: Decision::Request,
        request_id: super::wire::request_id(&root, &nonce)?,
        requester_root: root,
        target_root: target.to_owned(),
        peer_root: target.to_owned(),
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

pub(crate) async fn request_entry(
    sender: &Fixture,
    target: &crate::prekey::SdkDeviceManifestResponse,
) -> TestResult<GatewayInboxEntry> {
    sender.client.persist_fetched_identity_directory(target)?;
    let mut intent = intent_for(sender, &target.principal_commitment)?;
    let body = super::native_delivery::approve(
        &sender.client,
        &sender.config,
        &mut intent,
        &sender.manifest,
    )
    .await?;
    let device = target.devices.first().ok_or("target device")?;
    let mut message = GatewayDirectMessage {
        conversation_id: super::conversation(
            &sender.manifest.principal_commitment,
            &target.principal_commitment,
        )?,
        message_id: super::generated::message_id(&body, "autonomous-contact")?,
        envelope_id: "autonomous-contact".into(),
        source_principal_id: sender.config.principal_id.clone(),
        sender_id: sender.config.device_id.clone(),
        recipient_device_id: Some(device.device_id.clone()),
        recipient_principal_commitment: Some(target.principal_commitment.clone()),
        target_delivery_id: device.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 3600,
    };
    let mut packet = sender.client.seal_routed_prepared(
        &sender.config,
        &message,
        &body,
        crate::client::routed::Route::control(),
        crate::client::routed::SendMaterial {
            manifest: None,
            bundle: Some(device.prekey_bundle.clone()),
        },
    )?;
    packet.packet.schema = super::ENVELOPE_SCHEMA.into();
    message.encrypted_body = serde_json::to_vec(&packet)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: message.target_delivery_id.clone(),
        envelope: crate::dm::gateway_direct_message_envelope(&sender.config, &message, None)?,
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
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: message.target_delivery_id.clone(),
            envelope: crate::dm::gateway_direct_message_envelope(&sender.config, &message, None)?,
        },
        Routing {
            group_message_id: None,
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

#[tokio::test]
async fn native_inbound_accept_persists_safety_before_the_first_directory_read() -> TestResult {
    let sender = Fixture::new("native-safety-sender").await?;
    let target = Fixture::new("native-safety-target").await?;
    target.client.persist_fetched_identity_directory(&sender.manifest)?;
    let bytes = approve_request(&sender, &target).await?;
    let (entry, route) = transport(&sender, &target)?;
    let control = target.client.verify_contact_control(&entry, &route, &bytes)?;
    target.client.apply_contact_control(&control)?;
    let db = target.client.account_db()?;
    let root = &sender.manifest.principal_commitment;
    let request = db.contact_request(root, "inbound")?.ok_or("request")?;
    assert_eq!(request.state, "pending");
    assert!(db.client_record("identity", &sender.manifest.principal_id)?
        .ok_or("identity")?["safety_number"].is_null());
    target.vault.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    target.client.decide_inbound_contact(&request, "accepted")?;
    let directory = crate::bus::read_model::read(
        &target.client,
        &crate::LocalBusFrame::request(
            "native-accepted-directory",
            Some(db.local_account_id.clone()),
            "identity",
            "identity.directory",
            serde_json::json!({}),
        ),
    )?;
    let row = directory["identities"]
        .as_array()
        .ok_or("identities")?
        .iter()
        .find(|row| row["principal_id"] == sender.manifest.principal_id)
        .ok_or("sender identity")?;
    let expected =
        ramflux_crypto::custody::safety_number(&target.manifest.principal_commitment, root)?;
    assert_eq!(row["safety_number_available"], true);
    assert_eq!(row["safety_number"], serde_json::json!(expected));
    assert_eq!(row["safety_number"].as_array().map(Vec::len), Some(12));
    assert_eq!(row["safety_number_algorithm_version"], 2);
    assert_eq!(row["verified"], false);
    assert!(target.client.identity_root.is_none());
    Ok(())
}

#[tokio::test]
async fn native_received_request_keeps_lookup_provenance_and_preserves_card_pins() -> TestResult {
    let sender = Fixture::new("native-provenance-sender").await?;
    let target = Fixture::new("native-provenance-target").await?;
    let bytes = approve_request(&sender, &target).await?;
    let (entry, route) = transport(&sender, &target)?;
    let db = target.client.account_db()?;
    let principal = &sender.manifest.principal_id;
    assert!(db.client_record("identity", principal)?.is_none());
    target
        .client
        .prepare_native_contact_control(
            &target.config,
            &entry,
            &route,
            &bytes,
            Some(&sender.manifest),
        )
        .await?;
    assert_eq!(
        db.client_record("identity", principal)?.ok_or("identity")?["root_source"],
        "lookup"
    );
    let control = target.client.verify_contact_control(&entry, &route, &bytes)?;
    target.client.apply_contact_control(&control)?;
    let pending =
        db.contact_request(&sender.manifest.principal_commitment, "inbound")?.ok_or("request")?;
    target.client.decide_inbound_contact(&pending, "accepted")?;
    assert_eq!(target.client.contact_entry(principal)?["root_source"], "lookup");
    // A previously explicit card pin is independent of later network observations.
    let mut identity = db.client_record("identity", principal)?.ok_or("identity")?;
    identity["root_source"] = serde_json::json!("card");
    db.persist_client_record("identity", principal, &identity)?;
    target
        .client
        .prepare_native_contact_control(
            &target.config,
            &entry,
            &route,
            &bytes,
            Some(&sender.manifest),
        )
        .await?;
    assert_eq!(target.client.contact_entry(principal)?["root_source"], "card");
    Ok(())
}

#[tokio::test]
async fn native_contact_request_preview_uses_anchor_safety_number() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let sender = Fixture::new("native-preview-sender").await?;
        let target = Fixture::new("native-preview-target").await?;
        target.client.persist_fetched_identity_directory(&sender.manifest)?;
        let bytes = approve_request(&sender, &target).await?;
        let (entry, route) = transport(&sender, &target)?;
        let control = target.client.verify_contact_control(&entry, &route, &bytes)?;
        target.client.apply_contact_control(&control)?;
        let root = &sender.manifest.principal_commitment;
        let request =
            target.client.account_db()?.contact_request(root, "inbound")?.ok_or("request")?;
        let preview = target.client.contact_request_preview(&request)?;
        let expected =
            ramflux_crypto::custody::safety_number(&target.manifest.principal_commitment, root)?;
        assert!(target.client.identity_root.is_none());
        assert_eq!(preview["safety_number"], serde_json::json!(expected));
        assert_eq!(preview["safety_number"].as_array().map(Vec::len), Some(12));
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn generated_native_contact_keeps_primary_consent_and_one_retry_identity() -> TestResult {
    use prost::Message as _;
    use ramflux_protocol::message as g;
    let _gate = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let sender = Box::pin(Fixture::new("generated-native-contact-sender")).await?;
    let target = Box::pin(Fixture::new("generated-native-contact-target")).await?;
    target.client.persist_fetched_identity_directory(&sender.manifest)?;
    let mut pending = intent(&sender, &target)?;
    let bytes = super::native_delivery::approve(
        &sender.client,
        &sender.config,
        &mut pending,
        &sender.manifest,
    )
    .await?;
    let identity = g::Inner::decode(bytes.as_slice())?.identity.ok_or("identity")?;
    g::identity::verify(&identity)?;
    assert_eq!(identity.device_sequence & (1 << 63), 0);
    sender.vault.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let retry = super::native_delivery::approve(
        &sender.client,
        &sender.config,
        &mut pending,
        &sender.manifest,
    )
    .await?;
    assert_eq!(
        bytes.as_slice(),
        retry.as_slice(),
        "one generated identity across primary-free retries"
    );
    sender.vault.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    // This fixture uses real native pair encryption and source signature; no router is involved.
    let entry = request_entry(&sender, &target.manifest).await?;
    let opened =
        target.client.open_routed(&entry, target.client.owned_device_identity()?.device_id())?;
    target
        .client
        .prepare_native_contact_control(
            &target.config,
            &entry,
            &opened.routing,
            &opened.body,
            Some(&sender.manifest),
        )
        .await?;
    let consent = super::generated::decode(&opened.body)?.ok_or("native consent")?;
    assert_eq!(consent.body.actor_root, sender.client.own_account_anchor()?);
    assert!(
        target
            .client
            .account_db()?
            .contact_request(&sender.client.own_account_anchor()?, "inbound")?
            .is_none()
    );
    let mut inner = g::Inner::decode(opened.body.as_slice())?;
    let mut control = g::Control::decode(inner.body.as_slice())?;
    let Some(g::control::Payload::ContactControl(payload)) = control.payload.as_mut() else {
        return Err("contact".into());
    };
    let leaf = payload.consent.as_mut().ok_or("consent")?;
    leaf.canonical.push(b' ');
    inner.body = control.encode_to_vec();
    assert!(
        super::generated::decode(&inner.encode_to_vec()).is_err(),
        "fixed native leaf cannot normalize signed bytes"
    );
    let mut tampered = consent.clone();
    tampered.body.note = Some("changed without primary consent".into());
    let Some(g::control::Payload::ContactControl(payload)) = control.payload.as_mut() else {
        return Err("contact".into());
    };
    payload.consent.as_mut().ok_or("consent")?.canonical =
        ramflux_protocol::canonical_json_bytes(&tampered)?;
    inner.body = control.encode_to_vec();
    assert!(
        target
            .client
            .verify_contact_control(&entry, &opened.routing, &inner.encode_to_vec())
            .is_err()
    );
    target.client.receive_generated_contact_control(&entry, &opened.routing, &opened.body)?;
    let request = target
        .client
        .account_db()?
        .contact_request(&sender.client.own_account_anchor()?, "inbound")?
        .ok_or("native pending request")?;
    assert_eq!(request.state, "pending");
    assert!(target.client.friend_links()?.is_empty(), "receiving a request never accepts it");
    Ok(())
}
