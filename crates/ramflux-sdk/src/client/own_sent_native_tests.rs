// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native sent-copy admission follows certified sync membership without root private keys.
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn native_own_sent_admission_tracks_enrollment_scope_and_revocation() -> TestResult {
    let own = Fixture::new("native-own-sent").await?;
    assert!(own.client.identity_root.is_none());
    assert!(!own.client.own_sent_has_siblings()?);
    let staged = std::cell::Cell::new(false);
    assert!(
        own.client
            .queue_own_sent_copy("no-sibling", || {
                staged.set(true);
                Ok("unexpected staging".into())
            })
            .is_none()
    );
    assert!(!staged.get());
    assert_eq!(own.client.account_db()?.actor_state_usage("own-device/")?.0, 0);
    let mut native = own.manifest.custody.as_ref().ok_or("native")?.clone();
    let primary = own.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let now = crate::custody::network_now()?;
    let current =
        ramflux_crypto::custody::verify_record(&native.publication.record, now, None, None)?;
    let branch = ramflux_crypto::create_device_branch(
        &own.manifest.principal_id,
        "sibling",
        1,
        ramflux_crypto::random_32()?,
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed(ramflux_crypto::random_32()?);
    let mut certificate = native.publication.record.body.devices[0]
        .branch_certificate
        .as_ref()
        .ok_or("certificate")?
        .body
        .clone();
    certificate.device_id = "sibling".into();
    certificate.branch_signing_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes());
    certificate.agreement_identity_public_key =
        ramflux_protocol::encode_base64url(agreement.public);
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let message_layer = ramflux_crypto::custody::sign_enrollment_layer(&branch, &certificate)?;
    native.publication.record = primary.enroll_device(
        &current,
        primary.certify_branch(certificate)?,
        message_layer,
        now,
    )?;
    own.client.observe_custody_manifest(&native, &own.manifest.principal_commitment, now)?;
    assert!(own.client.own_sent_has_siblings()?);
    assert!(own.client.local_own_copy_manifest().is_err(), "old cached roster must refresh");
    assert_eq!(
        own.client.queue_own_sent_copy("sibling", || Ok("ticket".into())),
        Some("ticket".into())
    );
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
    own.client.observe_custody_manifest(&native, &own.manifest.principal_commitment, now)?;
    assert!(!own.client.own_sent_has_siblings()?, "message scope must not replace sync");
    let current =
        ramflux_crypto::custody::verify_record(&native.publication.record, now, None, None)?;
    native.publication.record = primary.revoke_device(&current, "sibling", now)?;
    own.client.observe_custody_manifest(&native, &own.manifest.principal_commitment, now)?;
    assert!(!own.client.own_sent_has_siblings()?);
    Ok(())
}

#[tokio::test]
async fn native_live_sent_copy_keeps_a_private_replay_claim_after_deletion() -> TestResult {
    crate::client::native_test_support::watchdog::within(
        crate::client::native_test_support::live_own_copy::exercise(true),
    )
    .await?
}

#[tokio::test]
async fn own_manifest_signature_cache_rechecks_changed_native_material() -> TestResult {
    let own = Fixture::new("own-manifest-cache").await?;
    let anchor = own.client.own_account_anchor()?;
    let key = format!("identity/manifest-root/{anchor}");
    own.client.local_own_copy_manifest()?;
    own.client.local_own_copy_manifest()?;
    let db = own.client.account_db()?;
    let original: crate::prekey::SdkDeviceManifestResponse =
        db.load_actor_state(&key)?.ok_or("own manifest")?;
    let mut changed = original.clone();
    changed
        .devices
        .first_mut()
        .ok_or("native device")?
        .prekey_bundle
        .signature_by_device_identity = ramflux_protocol::encode_base64url([0; 64]);
    db.persist_actor_state(&key, &changed)?;
    assert!(
        own.client.local_own_copy_manifest().is_err(),
        "same-second material mutation must invalidate signature reuse"
    );
    db.persist_actor_state(&key, &original)?;
    own.client.local_own_copy_manifest()?;
    Ok(())
}
