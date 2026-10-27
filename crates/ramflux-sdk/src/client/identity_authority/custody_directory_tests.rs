// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native directory provenance and key substitution regressions through ordinary client APIs.
use super::*;
use crate::custody::tests::{Root, TestVault, create};
use ramflux_protocol::custody::{CustodyManifest, CustodyManifestDevice, Publication};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn native_manifest(
    root: &Root,
    id: &str,
    vault: &TestVault,
    now: u64,
) -> TestResult<CustodyManifest> {
    let account = create(&root.0, id, vault, now)?;
    let (reference, credentials) = account.credentials(vault, "primary", now)?;
    let signed = ramflux_crypto::X25519KeyPair::random()?;
    let bundle = ramflux_crypto::create_prekey_bundle(
        &credentials.signing,
        &credentials.agreement,
        "native-signed",
        &signed,
        None,
        None,
    )?;
    let identity =
        ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(account.verified(), "primary")?;
    Ok(CustodyManifest {
        publication: Publication { record: account.record().clone(), compacted_ids: None },
        custodian_publication: None,
        devices: vec![CustodyManifestDevice {
            device_ref: reference,
            target_delivery_id: identity.storage_key().into(),
            prekey_bundle: serde_json::to_value(bundle)?,
        }],
    })
}
fn receiver(root: &Root, vault: &TestVault, now: u64) -> TestResult<RamfluxClient> {
    let account = create(&root.0, "receiver", vault, now)?;
    let mut client = RamfluxClient::new();
    client.open_account_index(&root.0)?;
    client.seal_new_account_data(
        "receiver",
        &account.record().body.account_anchor,
        b"test-passphrase",
    )?;
    client.unlock_account("receiver", b"test-passphrase")?;
    Ok(client)
}
#[test]
fn ordinary_directory_accepts_native_provenance_and_rejects_metadata_or_key_substitution()
-> TestResult {
    let root = Root::new()?;
    let vault = TestVault::default();
    let now = crate::custody::network_now()?;
    let native = native_manifest(&root, "peer", &vault, now)?;
    let anchor = native.publication.record.body.account_anchor.clone();
    let principal = native.publication.record.body.principal_id.clone();
    let material = crate::prekey::SdkDeviceManifestResponse::from_native(native.clone())?;
    assert!(material.signed_device_set.is_none());
    assert!(material.devices[0].branch_proof.is_none());
    RamfluxClient::verify_device_manifest_json(serde_json::to_value(&native)?, &anchor)?;
    let client = receiver(&root, &vault, now)?;
    client.persist_identity_directory(&material)?;
    let identity = client.peer_device_identity(&principal, "primary")?;
    assert_eq!(identity.root_commitment(), anchor);
    assert!(client.require_current_device_authorization(&identity).is_err());
    client.persist_fetched_identity_directory(&material)?;
    client.require_current_device_authorization(&identity)?;
    // Neither restored evidence nor the public JSON import API can manufacture a fresh fetch.
    *client.native_head_freshness.borrow_mut() = NativeHeadFreshness::default();
    client.observe_device_manifest_json(serde_json::to_value(&material)?, &anchor)?;
    assert!(client.require_current_device_authorization(&identity).is_err());
    client.persist_fetched_identity_directory(&material)?;
    client.require_current_device_authorization(&identity)?;
    assert_eq!(client.root_asserted_principal_kind(&principal)?, Some(PrincipalKind::Human));
    let profile = client.verified_identity_profile(&principal)?.ok_or("native profile absent")?;
    assert_eq!(profile.display_name, native.publication.record.body.profile.display_name);
    assert_eq!(profile.principal_commitment, anchor);
    assert_eq!(profile.kind, PrincipalKind::Human);
    let mut mixed = material.clone();
    mixed.root_public_key = ramflux_crypto::fixture_public_key_base64url();
    assert!(client.persist_fetched_identity_directory(&mixed).is_err());
    let mut substituted = native;
    substituted.devices[0].prekey_bundle["device_identity_ed25519_public"] =
        serde_json::json!(ramflux_crypto::fixture_public_key_base64url());
    let substituted = crate::prekey::SdkDeviceManifestResponse::from_native(substituted)?;
    assert!(client.persist_fetched_identity_directory(&substituted).is_err());
    client.require_current_device_authorization(&identity)?;
    Ok(())
}
#[test]
fn authenticated_native_head_is_retained_when_prekey_signature_is_bad() -> TestResult {
    let root = Root::new()?;
    let vault = TestVault::default();
    let now = crate::custody::network_now()?;
    let mut native = native_manifest(&root, "peer", &vault, now)?;
    let anchor = native.publication.record.body.account_anchor.clone();
    native.devices[0].prekey_bundle["signature_by_device_identity"] =
        serde_json::json!(ramflux_protocol::encode_base64url([0; 64]));
    let client = receiver(&root, &vault, now)?;
    assert!(client.observe_custody_manifest(&native, &anchor, now).is_err());
    assert!(client.current_custody_authority(&anchor, now)?.is_some());
    assert!(
        client
            .account_db()?
            .client_record("identity", &native.publication.record.body.principal_id)?
            .is_none()
    );
    Ok(())
}

#[test]
fn native_safety_uses_stable_anchor_comparison_and_separate_roster_stamp() -> TestResult {
    let root = Root::new()?;
    let vault = TestVault::default();
    let now = crate::custody::network_now()?;
    let mut peer = native_manifest(&root, "peer", &vault, now)?;
    let anchor = peer.publication.record.body.account_anchor.clone();
    let client = receiver(&root, &vault, now)?;
    client.observe_custody_manifest(&peer, &anchor, now)?;
    let own = client.own_account_anchor()?;
    client.establish_friend_link("native-link", &own, &anchor)?;
    let before = client.contact_safety_number(&anchor)?;
    assert_eq!(before.algorithm_version, 2);
    assert_eq!(before.safety_number, ramflux_crypto::custody::safety_number(&own, &anchor)?);
    client.mark_contact_safety_verified(&anchor, "primary")?;
    assert_eq!(client.contact_safety_number(&anchor)?.verification_state, "verified");
    let primary = vault.primary_for_public_key(
        &peer.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = peer.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&peer.publication.record)?);
    body.device_set_epoch += 1;
    body.profile.display_name = "Renamed Human".into();
    peer.publication.record = primary.sign_record(body)?;
    client.observe_custody_manifest(&peer, &anchor, now)?;
    let renamed = client.contact_safety_number(&anchor)?;
    assert_eq!(renamed.safety_number, before.safety_number);
    assert_eq!(renamed.contact_device_set_hash, before.contact_device_set_hash);
    assert_eq!(renamed.verification_state, "verified");
    let current = client.current_custody_authority(&anchor, now)?.ok_or("authority")?;
    peer.publication.record = primary.revoke_device(&current, "primary", now)?;
    peer.devices.clear();
    client.observe_custody_manifest(&peer, &anchor, now)?;
    let revoked = client.contact_safety_number(&anchor)?;
    assert_eq!(revoked.safety_number, before.safety_number);
    assert_ne!(revoked.contact_device_set_hash, before.contact_device_set_hash);
    assert_eq!(revoked.verification_state, "verification_stale");
    Ok(())
}
