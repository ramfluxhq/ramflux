// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sibling safety evidence is accepted only from the authenticated origin bytes.
use crate::client::native_test_support::{Fixture, TestResult};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;

fn confirmation_key(commitment: &str) -> String {
    format!("identity/contact_safety_confirmation/{commitment}")
}

fn origin_key(commitment: &str) -> String {
    format!("identity/contact_safety_origin_inner/{commitment}")
}

fn load_pair(
    client: &RamfluxClient,
    commitment: &str,
) -> TestResult<(g::ContactSafetyConfirmation, Vec<u8>)> {
    let db = client.account_db()?;
    let encoded =
        db.load_actor_state::<String>(&confirmation_key(commitment))?.ok_or("confirmation")?;
    let bytes = ramflux_protocol::decode_base64url(&encoded).map_err(|_| "confirmation bytes")?;
    let confirmation = g::ContactSafetyConfirmation::decode(bytes.as_slice())
        .map_err(|_| "confirmation decode")?;
    let inner_encoded = db.load_actor_state::<String>(&origin_key(commitment))?.ok_or("origin")?;
    let inner = ramflux_protocol::decode_base64url(&inner_encoded).map_err(|_| "origin bytes")?;
    Ok((confirmation, inner))
}

fn origin_id(confirmation: &g::ContactSafetyConfirmation) -> TestResult<Vec<u8>> {
    Ok(confirmation.origin.as_ref().ok_or("origin")?.id.clone())
}

fn sync_of(inner: &[u8]) -> TestResult<g::OwnContactSync> {
    let scanned = g::validation::scan_inner(inner).map_err(|_| "scan")?;
    let control = g::Control::decode(scanned.body).map_err(|_| "control")?;
    match control.payload {
        Some(g::control::Payload::OwnContactSync(sync)) => Ok(sync),
        _ => Err("own contact".into()),
    }
}

fn encode_sync(identity: g::EventIdentity, sync: g::OwnContactSync) -> TestResult<Vec<u8>> {
    let control = crate::client::generated_control::control_from_payload(
        g::control::Payload::OwnContactSync(sync),
    )?;
    Ok(RamfluxClient::encode_generated_inner(
        identity,
        &g::Content { value: Some(g::content::Value::Control(control)) },
    )?)
}

fn state(client: &RamfluxClient, commitment: &str) -> TestResult<String> {
    Ok(client.contact_safety_number(commitment)?.verification_state)
}

fn install(client: &RamfluxClient, sync: &g::OwnContactSync, inner: &[u8]) -> Result<(), SdkError> {
    let identity = sync
        .safety_confirmation
        .as_ref()
        .and_then(|confirmation| confirmation.origin.clone())
        .ok_or(SdkError::ReplayMismatch)?;
    crate::client::contact_verification_cas::install_sibling_confirmation(
        client, sync, &identity, inner,
    )
}

fn reject_wrong_context(client: &RamfluxClient, commitment: &str, inner: &[u8]) -> TestResult {
    let before = origin_id(&load_pair(client, commitment)?.0)?;
    let mut sync = sync_of(inner)?;
    let mut stale = sync.clone();
    if let Some(confirmation) = stale.safety_confirmation.as_mut() {
        confirmation.verified_at = None;
    }
    install(client, &stale, inner)?;
    assert_eq!(origin_id(&load_pair(client, commitment)?.0)?, before, "missing time is discarded");
    let mut mismatched = sync.clone();
    if let Some(confirmation) = mismatched.safety_confirmation.as_mut()
        && let Some(expected) = confirmation.expected.as_mut()
    {
        expected.safety_number_hash.push('x');
    }
    install(client, &mismatched, inner)?;
    assert_eq!(
        state(client, commitment)?,
        "verified",
        "stale material cannot replace current evidence"
    );
    if let Some(confirmation) = sync.safety_confirmation.as_mut() {
        confirmation.verified_at = confirmation.verified_at.map(|at| at.saturating_add(1));
    }
    let identity =
        sync.safety_confirmation.as_ref().and_then(|c| c.origin.clone()).ok_or("origin")?;
    let changed = encode_sync(identity, sync)?;
    let replay = install(client, &sync_of(&changed)?, &changed);
    assert!(
        matches!(replay, Err(SdkError::ReplayMismatch)),
        "same origin and different bytes conflict"
    );
    assert_eq!(origin_id(&load_pair(client, commitment)?.0)?, before);
    Ok(())
}

fn install_later_origin(
    client: &RamfluxClient,
    commitment: &str,
    inner: &[u8],
) -> TestResult<Vec<u8>> {
    let mut sync = sync_of(inner)?;
    let origin = client.allocate_generated_identity(
        "own-contact",
        crate::client::generated_identity::now_ms(),
        true,
    )?;
    let confirmation = sync.safety_confirmation.as_mut().ok_or("confirmation")?;
    confirmation.origin = Some(origin.clone());
    let exact = encode_sync(origin, sync.clone())?;
    install(client, &sync, &exact)?;
    assert_eq!(state(client, commitment)?, "verified");
    Ok(exact)
}

fn reinstall_keeps_higher(
    client: &RamfluxClient,
    commitment: &str,
    older: &[u8],
    current: &[u8],
) -> TestResult {
    let kept = origin_id(&load_pair(client, commitment)?.0)?;
    install(client, &sync_of(older)?, older)?;
    install(client, &sync_of(current)?, current)?;
    assert_eq!(
        origin_id(&load_pair(client, commitment)?.0)?,
        kept,
        "a lower order cannot overwrite"
    );
    Ok(())
}

async fn forbidden_relay(confirmation: &g::ContactSafetyConfirmation, inner: &[u8]) -> TestResult {
    let other = Fixture::new("cas-relay").await?;
    let db = other.client.account_db()?;
    db.persist_actor_state(
        &confirmation_key("relay-contact"),
        &ramflux_protocol::encode_base64url(confirmation.encode_to_vec()),
    )?;
    db.persist_actor_state(
        &origin_key("relay-contact"),
        &ramflux_protocol::encode_base64url(inner),
    )?;
    crate::client::contact_verification_cas::stage_stored_origin(&other.client, "relay-contact")?;
    assert_eq!(db.actor_state_usage("own-device/send/")?.0, 0, "a non-origin device cannot relay");
    Ok(())
}

fn enroll_sibling(
    own: &Fixture,
) -> TestResult<(ramflux_crypto::RootQualifiedDeviceRef, ramflux_protocol::custody::CustodyManifest)>
{
    let mut native = own.manifest.custody.as_ref().ok_or("custody")?.as_ref().clone();
    let primary = own.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let now = crate::custody::network_now()?;
    let current =
        ramflux_crypto::custody::verify_record(&native.publication.record, now, None, None)?;
    let signing_seed = zeroize::Zeroizing::new(ramflux_crypto::random_32()?);
    let branch = ramflux_crypto::create_device_branch(
        &own.manifest.principal_id,
        "sibling",
        1,
        *signing_seed,
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed(ramflux_crypto::random_32()?);
    let mut certificate = native.publication.record.body.devices[0]
        .branch_certificate
        .as_ref()
        .ok_or("branch")?
        .body
        .clone();
    certificate.device_id = "sibling".into();
    certificate.branch_signing_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes());
    certificate.agreement_identity_public_key =
        ramflux_protocol::encode_base64url(&agreement.public);
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    native.publication.record =
        primary.enroll_device(&current, primary.certify_branch(certificate)?, now)?;
    own.client.observe_custody_manifest(&native, &own.manifest.principal_commitment, now)?;
    let sibling = ramflux_protocol::custody::DeviceRef {
        account_anchor: own.manifest.principal_commitment.clone(),
        device_id: "sibling".into(),
        device_epoch: 1,
    };
    let mut seeds = zeroize::Zeroizing::new([0; 64]);
    seeds[..32].copy_from_slice(signing_seed.as_ref());
    seeds[32..].copy_from_slice(&agreement.secret.to_bytes());
    let credentials = crate::custody::BranchCredentials::from_vault_seeds(
        &own.manifest.principal_id,
        &sibling,
        &seeds,
    )?;
    let verified =
        ramflux_crypto::custody::verify_record(&native.publication.record, now, None, None)?;
    let qualified =
        ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(&verified, "sibling")?;
    native.devices.push(ramflux_protocol::custody::CustodyManifestDevice {
        device_ref: sibling,
        target_delivery_id: qualified.storage_key().into(),
        prekey_bundle: serde_json::to_value(credentials.prekey_bundle()?)?,
        message_layer: None,
    });
    let fetched = crate::prekey::SdkDeviceManifestResponse::from_native(native.clone())?;
    own.client.persist_fetched_identity_directory(&fetched)?;
    Ok((qualified, native))
}

fn revoke_sibling_sync(
    own: &Fixture,
    native: &mut ramflux_protocol::custody::CustodyManifest,
) -> TestResult {
    let primary = own.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    body.device_set_epoch += 1;
    let entry =
        body.devices.iter_mut().find(|entry| entry.device_id == "sibling").ok_or("sibling")?;
    let mut certificate = entry.branch_certificate.as_ref().ok_or("certificate")?.body.clone();
    certificate.capabilities.retain(|scope| scope != "sync");
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    entry.branch_certificate = Some(primary.certify_branch(certificate)?);
    native.publication.record = primary.sign_record(body)?;
    let fetched = crate::prekey::SdkDeviceManifestResponse::from_native(native.clone())?;
    own.client.persist_fetched_identity_directory(&fetched)?;
    Ok(())
}

fn addition_and_convergence(
    own: &Fixture,
    peer: &Fixture,
    peer_root: &str,
    older: &[u8],
) -> TestResult {
    let (sibling, mut native) = enroll_sibling(own)?;
    assert_eq!(
        state(&own.client, peer_root)?,
        "verification_stale",
        "adding a device changes the own head"
    );
    install(&own.client, &sync_of(older)?, older)?;
    assert_eq!(
        state(&own.client, peer_root)?,
        "verification_stale",
        "offline evidence stays stale"
    );
    let renewed =
        crate::client::contact_verification_cas::verify_linked_contact(&own.client, peer_root)?;
    assert_eq!(renewed.verification_state, "verified");
    let before = own.client.account_db()?.actor_state_usage("own-device/send/")?.0;
    assert_eq!(
        own.client.stage_contact_backfill_batch()?,
        0,
        "restrictions are queued before accepted contacts"
    );
    assert_ne!(
        own.client.stage_contact_backfill_batch()?,
        0,
        "the enrolled sibling receives a backfill"
    );
    assert_ne!(own.client.account_db()?.actor_state_usage("own-device/send/")?.0, before);
    revoke_sibling_sync(own, &mut native)?;
    assert_eq!(
        state(&own.client, peer_root)?,
        "verification_stale",
        "revoking sync changes the own authority head"
    );
    let (before, current) = load_pair(&own.client, peer_root)?;
    let kept = origin_id(&before)?;
    assert!(crate::client::contact_verification_cas::accept_staged_safety_inner(
        &own.client,
        &sibling,
        &current
    )?);
    assert_eq!(
        origin_id(&load_pair(&own.client, peer_root)?.0)?,
        kept,
        "a revoked sibling cannot become the origin"
    );
    advance_peer_head(own, peer)?;
    install(&own.client, &sync_of(&current)?, &current)?;
    assert_eq!(
        origin_id(&load_pair(&own.client, peer_root)?.0)?,
        kept,
        "a newer authenticated peer head discards the old confirmation"
    );
    assert_eq!(
        state(&own.client, peer_root)?,
        "verification_stale",
        "refresh does not import a stale head"
    );
    let renewed_after_head =
        crate::client::contact_verification_cas::verify_linked_contact(&own.client, peer_root)?;
    assert_eq!(
        renewed_after_head.verification_state, "verified",
        "fresh comparison converges after the head change"
    );
    let (_, current) = load_pair(&own.client, peer_root)?;
    own.client.block_friend_link("cas-sibling-link")?;
    assert_eq!(state(&own.client, peer_root)?, "blocked_by_policy");
    install(&own.client, &sync_of(&current)?, &current)?;
    assert_eq!(
        state(&own.client, peer_root)?,
        "blocked_by_policy",
        "a restriction refuses sibling evidence"
    );
    own.client.unblock_friend_link("cas-sibling-link")?;
    assert_eq!(
        state(&own.client, peer_root)?,
        "verified",
        "unblock recomputes the stored evidence"
    );
    Ok(())
}

fn advance_peer_head(own: &Fixture, peer: &Fixture) -> TestResult {
    let mut native = peer.manifest.custody.as_ref().ok_or("custody")?.as_ref().clone();
    let primary = peer.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    body.device_set_epoch = body.device_set_epoch.saturating_add(1);
    native.publication.record = primary.sign_record(body)?;
    own.client.observe_custody_manifest(
        &native,
        &peer.manifest.principal_commitment,
        crate::custody::network_now()?,
    )?;
    Ok(())
}

#[tokio::test]
async fn verify_cas_sibling_evidence_is_context_bound() -> TestResult {
    let local = Fixture::new("cas-origin").await?;
    let peer = Fixture::new("cas-foreign").await?;
    local.client.persist_fetched_identity_directory(&peer.manifest)?;
    let peer_root = peer.manifest.principal_commitment.clone();
    local.client.establish_friend_link(
        "cas-sibling-link",
        &local.client.own_account_anchor()?,
        &peer_root,
    )?;
    let recorded =
        crate::client::contact_verification_cas::verify_linked_contact(&local.client, &peer_root)?;
    assert_eq!(recorded.verification_state, "verified");
    let (confirmation, inner) = load_pair(&local.client, &peer_root)?;
    reject_wrong_context(&local.client, &peer_root, &inner)?;
    let higher = install_later_origin(&local.client, &peer_root, &inner)?;
    reinstall_keeps_higher(&local.client, &peer_root, &inner, &higher)?;
    let foreign = peer.client.owned_device_identity()?;
    assert!(crate::client::contact_verification_cas::accept_staged_safety_inner(
        &local.client,
        &foreign,
        &higher
    )?);
    assert_eq!(
        state(&local.client, &peer_root)?,
        "verified",
        "a foreign source is consumed without install"
    );
    forbidden_relay(&confirmation, &higher).await?;
    let item = g::HistoryItem {
        exact_inner: higher.clone(),
        source_evidence: None,
        tombstone: None,
        exact_original_identity: Vec::new(),
        original_metadata_evidence: None,
    };
    assert!(
        !local
            .client
            .import_generated_history_message(&local.client.owned_device_identity()?, &item)?,
        "history promotion drops a safety grant"
    );
    addition_and_convergence(&local, &peer, &peer_root, &inner)?;
    Box::pin(
        crate::bus::dispatch::surface_transport::own_tests::deliver_compared_safety_to_sibling_device(),
    )
    .await?;
    Ok(())
}
