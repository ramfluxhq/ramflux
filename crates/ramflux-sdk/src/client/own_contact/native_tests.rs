// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native own-contact queues follow the signed roster without loading a branch credential.
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn native_contacts_backfill_once_after_enrollment_without_private_branch_loaded() -> TestResult
{
    let mut own = Fixture::new("native-own-contact").await?;
    let peer = Fixture::new("native-own-contact-peer").await?;
    own.client.persist_identity_directory(&peer.manifest)?;
    own.client.establish_friend_link(
        "native-before-enrollment",
        &own.manifest.principal_commitment,
        &peer.manifest.principal_commitment,
    )?;
    own.client.stage_own_contact(&peer.manifest, "native-before-enrollment")?;
    assert_eq!(own.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
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
    let before = crate::bus::own_device_copy::copy_id(&own.client, "public-id")?;
    own.client.device_branch = None;
    assert_eq!(crate::bus::own_device_copy::copy_id(&own.client, "public-id")?, before);
    assert_eq!(own.client.stage_contact_backfill_batch()?, 0);
    assert_eq!(own.client.stage_contact_backfill_batch()?, 1);
    assert_eq!(own.client.stage_contact_backfill_batch()?, 0);
    assert_eq!(own.client.account_db()?.actor_state_usage("own-device/send/")?.0, 1);
    own.client.stage_own_contact(&peer.manifest, "native-before-enrollment")?;
    assert_eq!(own.client.account_db()?.actor_state_usage("own-device/send/")?.0, 1);
    Ok(())
}
