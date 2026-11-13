// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native own-contact queues follow the signed roster without loading a branch credential.
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn native_contacts_backfill_once_after_enrollment_without_private_branch_loaded() -> TestResult
{
    let mut own = Fixture::new("native-own-contact").await?;
    let peer = Fixture::new("native-own-contact-peer").await?;
    own.client.persist_fetched_identity_directory(&peer.manifest)?;
    own.client.establish_friend_link(
        "native-before-enrollment",
        &own.manifest.principal_commitment,
        &peer.manifest.principal_commitment,
    )?;
    own.client.stage_own_contact(&peer.manifest, "native-before-enrollment")?;
    assert_eq!(own.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    let value = {
        let _effect_profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        own.client.change_self_sync(
            "native-bootstrap-thread",
            ramflux_protocol::message::SelfSync { operation: 6, mute: true, ..Default::default() },
        )?
    };
    assert_eq!(value.revision, 1);
    let mut native = own.manifest.custody.as_ref().ok_or("native")?.clone();
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
    assert_eq!(own.client.stage_contact_backfill_batch()?, 0);
    assert_eq!(own.client.account_db()?.actor_state_usage("self-sync/repair/")?.0, 0);
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
    let fetched = crate::prekey::SdkDeviceManifestResponse::from_native((*native).clone())?;
    own.client.persist_fetched_identity_directory(&fetched)?;
    assert_history_bootstrap_once(&own.client)?;
    let before = crate::bus::own_device_copy::copy_id(&own.client, "public-id")?;
    own.client.device_branch = None;
    assert_eq!(crate::bus::own_device_copy::copy_id(&own.client, "public-id")?, before);
    assert_eq!(own.client.stage_contact_backfill_batch()?, 1);
    assert_eq!(own.client.stage_contact_backfill_batch()?, 0);
    assert_eq!(own.client.account_db()?.actor_state_usage("own-device/send/")?.0, 1);
    assert_eq!(own.client.account_db()?.actor_state_usage("self-sync/repair/")?.0, 0);
    assert_bootstrap_revision(&own.client, &value)?;
    own.client.stage_own_contact(&peer.manifest, "native-before-enrollment")?;
    assert_eq!(own.client.account_db()?.actor_state_usage("own-device/send/")?.0, 1);
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    assert_restore_refresh_round(&own.client, &qualified)?;
    remove_sibling_sync(&own, &mut native, &primary)?;
    assert!(own.client.prepare_self_sync_repair(&own.config)?.is_none());
    assert_eq!(
        own.client.account_db()?.actor_state_usage("self-sync/repair/")?.0,
        0,
        "a certified Sync restriction retires an obsolete target without blocking the courier"
    );
    Ok(())
}

fn remove_sibling_sync(
    own: &Fixture,
    native: &mut ramflux_protocol::custody::CustodyManifest,
    primary: &ramflux_crypto::custody::SelfSigningKey,
) -> TestResult {
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

fn assert_history_bootstrap_once(client: &crate::RamfluxClient) -> TestResult {
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    client.stage_native_history_bootstrap()?;
    let db = client.account_db()?;
    let transfers = db.actor_state_keys("history-out/transfer/")?;
    assert_eq!(transfers.len(), 1, "the newly certified sibling gets a history transfer");
    let before = db.load_actor_state::<serde_json::Value>(&transfers[0])?;
    client.stage_native_history_bootstrap()?;
    assert_eq!(
        db.load_actor_state::<serde_json::Value>(&transfers[0])?,
        before,
        "repeated backfill preserves the transfer identity and cursor"
    );
    assert_eq!(db.actor_state_keys("history-out/bootstrap/")?.len(), 1);
    Ok(())
}

fn assert_restore_refresh_round(
    client: &crate::RamfluxClient,
    sibling: &ramflux_crypto::RootQualifiedDeviceRef,
) -> TestResult {
    use ramflux_protocol::message::SelfSync;
    let scope = "native-bootstrap-thread";
    let mute = || SelfSync { operation: 6, revision: 1, mute: true, ..Default::default() };
    let db = client.account_db()?;
    db.write_transaction(|| client.mark_self_sync_restore_refresh())?;
    assert!(matches!(
        client.change_self_sync(scope, mute()),
        Err(crate::SdkError::InboundPending(_))
    ));
    let current = SelfSync { operation: 7, revision: 9, ..Default::default() };
    assert!(matches!(
        db.write_transaction(|| client.apply_self_sync_in(sibling, scope, &current)),
        Err(crate::SdkError::InboundPending(_))
    ));
    assert!(
        matches!(client.change_self_sync(scope, mute()), Err(crate::SdkError::InboundPending(_))),
        "a packet cannot complete a floor-bearing authenticated snapshot round"
    );
    Ok(())
}

fn assert_bootstrap_revision(
    client: &crate::RamfluxClient,
    value: &ramflux_protocol::message::SelfSync,
) -> TestResult {
    assert_eq!(
        client.self_sync_state("native-bootstrap-thread", value)?.ok_or("state")?.value.revision,
        1,
        "bootstrap never increments the accepted revision"
    );

    Ok(())
}
