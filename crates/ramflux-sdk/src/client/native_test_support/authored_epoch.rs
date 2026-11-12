// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A newly certified target incarnation never exposes an older epoch's cached attestation.
use super::*;
use crate::client::routed::SendMaterial;
use ramflux_protocol::message as g;

#[tokio::test(flavor = "current_thread")]
async fn own_authored_history_target_epoch_rechecks_before_cached_exposure_and_restages()
-> TestResult {
    let mut source = Fixture::new("authored-epochs-source").await?;
    let peer = Fixture::new("authored-epochs-peer").await?;
    let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let conversation = g::dm_scope::derive(
        &source.client.own_account_anchor()?,
        &peer.client.own_account_anchor()?,
    )?;
    source.client.persist_fetched_identity_directory(&peer.manifest)?;
    source.client.establish_friend_link(
        "authored-link",
        &source.client.own_account_anchor()?,
        &peer.client.own_account_anchor()?,
    )?;
    source
        .client
        .receive_generated_own_contact(&super::authored::authored_contact(&source, &peer)?)?;
    let identity = source.client.allocate_generated_identity(
        &conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let owner = ramflux_protocol::encode_base64url(&identity.id);
    let exact = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "epoch scoped capture".into(),
                ..Default::default()
            })),
        },
    )?;
    super::authored::capture_before_enrollment(&source, &peer, &conversation, &owner, &exact)?;
    let mut target = source.enroll_sibling("authored-epochs-target", "target").await?;
    let first =
        source.client.prepare_authored_history(&source.config)?.ok_or("first epoch plan")?;
    let (first, old) = source
        .client
        .seal_authored_history(&source.config, first, source.material_for(&target)?)?
        .ok_or("first epoch sealed")?;
    certify_target_epoch(&mut source, &mut target, 2)?;
    assert!(
        source
            .client
            .seal_authored_history(
                &source.config,
                first,
                SendMaterial { manifest: None, bundle: None }
            )?
            .is_none()
    );
    let next =
        source.client.prepare_authored_history(&source.config)?.ok_or("second epoch plan")?;
    let (_, fresh) = source
        .client
        .seal_authored_history(&source.config, next, source.material_for(&target)?)?
        .ok_or("second epoch sealed")?;
    assert_ne!(old.envelope_id, fresh.envelope_id);
    assert_ne!(old.encrypted_payload, fresh.encrypted_payload);
    assert_eq!(source.client.account_db()?.actor_state_keys("own-history/staged/")?.len(), 2);
    Ok(())
}

fn certify_target_epoch(source: &mut Fixture, target: &mut Fixture, epoch: u64) -> TestResult {
    let reference = target.client.owned_device_identity()?;
    let mut private = target.client.load_x3dh_private_state(&reference)?;
    let mut branch = target.client.device_branch.as_ref().ok_or("target branch")?.clone();
    branch.device_epoch = epoch;
    private.bundle = ramflux_crypto::create_prekey_bundle(
        &branch,
        &ramflux_crypto::X25519KeyPair::from_seed(private.identity_seed),
        &private.signed_prekey_id,
        &ramflux_crypto::X25519KeyPair::from_seed(private.signed_prekey_seed),
        private.bundle.one_time_prekey_id.clone(),
        private.bundle.one_time_prekey,
    )?;
    target.client.persist_owned_private_prekey(&reference, &private)?;
    let mut native = source.manifest.custody.as_ref().ok_or("native")?.clone();
    let primary = source.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    body.device_set_epoch += 1;
    let entry = body
        .devices
        .iter_mut()
        .find(|entry| entry.device_id == target.config.device_id)
        .ok_or("target device")?;
    let mut certificate = entry.branch_certificate.as_ref().ok_or("certificate")?.body.clone();
    certificate.device_epoch = epoch;
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    entry.device_epoch = epoch;
    entry.branch_certificate = Some(primary.certify_branch(certificate)?);
    native.publication.record = primary.sign_record(body)?;
    for entry in &mut native.devices {
        if entry.device_ref.device_id == target.config.device_id {
            entry.device_ref.device_epoch = epoch;
            entry.prekey_bundle = serde_json::to_value(&private.bundle)?;
        }
    }
    let full = SdkDeviceManifestResponse::from_native((*native).clone())?;
    source.client.persist_fetched_identity_directory(&full)?;
    target.client.persist_fetched_identity_directory(&full)?;
    source.manifest = full.clone();
    target.manifest = full;
    Ok(())
}
