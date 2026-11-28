// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SDK authority regressions against genuine root signatures and the node registry.
use super::*;
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;
use ramflux_protocol::{DeviceSetStatus, PrincipalKind};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Actor {
    client: RamfluxClient,
    id: String,
    path: ramflux_test_support::TestPath,
}
impl Actor {
    fn new(
        principal: &str,
        id: &str,
        root_seed: u8,
        device_seed: u8,
        epoch: u64,
    ) -> Result<Self, SdkError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!(
                "rf-authority-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
        let mut client = RamfluxClient::new();
        client.create_identity_root(principal, [root_seed; 32]);
        client.create_device_branch(principal, id, epoch, [device_seed; 32]);
        client.open_account_index(&path)?;
        client.create_account(id, id)?;
        client.unlock_account(id, b"test-secret")?;
        client.initialize_and_publish_prekey_bundle(principal, id, id, [device_seed; 32], None)?;
        Ok(Self { client, path, id: id.into() })
    }
    fn manifest(&self) -> Result<SdkDeviceManifestResponse, SdkError> {
        test_support::manifest(&self.client)
    }
    fn reopen(&mut self) -> Result<(), SdkError> {
        self.client = RamfluxClient::new();
        self.client.open_account_index(&self.path)?;
        self.client.unlock_account(&self.id, b"test-secret")?;
        Ok(())
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        self.client = RamfluxClient::new();
    }
}
fn observe(client: &RamfluxClient, manifest: &SdkDeviceManifestResponse) -> Result<(), SdkError> {
    client.observe_device_manifest_json(
        serde_json::to_value(manifest)?,
        &manifest.principal_commitment,
    )
}
fn sign_set(
    owner: &Actor,
    manifest: &mut SdkDeviceManifestResponse,
    epoch: u64,
) -> Result<(), SdkError> {
    test_support::sign_manifest(
        owner.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        manifest,
        epoch,
    )
}
fn enroll(
    node: &mut ramflux_node_core::IdentityRegistry,
    actor: &Actor,
    remote: Option<&SdkDeviceManifestResponse>,
) -> Result<SdkDeviceManifestResponse, Box<dyn std::error::Error>> {
    let set = actor.client.prepare_owned_authority(remote)?;
    actor.client.account_db()?.persist_actor_state("identity/registration_set", &set)?;
    let request = actor.client.mvp1_identity_registration_request(
        &actor.id,
        &actor.id,
        "session",
        &set.principal_commitment,
    )?;
    let request = serde_json::from_value(serde_json::to_value(request)?)?;
    node.register_identity(&request)?;
    node.publish_prekey(ramflux_node_core::PrekeyPublishRequest {
        device_id: actor.id.clone(),
        bundle: actor
            .client
            .load_x3dh_private_state(&actor.client.local_device_identity(&actor.id)?)?
            .bundle,
    })?;
    actor.client.accept_owned_record(&set)?;
    Ok(serde_json::from_value(serde_json::to_value(
        node.device_manifest(&set.principal_commitment).ok_or("manifest")?,
    )?)?)
}
#[test]
fn real_node_enrollment_device_add_signed_revoke_and_restart_reject_rollback() -> TestResult {
    let first = Actor::new("alice", "alice-one", 11, 12, 1)?;
    let second = Actor::new("alice", "alice-two", 11, 13, 1)?;
    let mut peer = Actor::new("bob", "bob", 21, 22, 1)?;
    let mut node = ramflux_node_core::IdentityRegistry::new();
    let initial = enroll(&mut node, &first, None)?;
    observe(&peer.client, &initial)?;
    let added = enroll(&mut node, &second, Some(&initial))?;
    observe(&peer.client, &added)?;
    assert_eq!(added.signed_device_set.as_ref().ok_or("set")?.devices.len(), 2);
    let pair = ramflux_crypto::DmSession::initiator(
        [1; 32],
        dm_device_id_hash("bob"),
        dm_device_id_hash("alice-two"),
        [2; 32],
    )?;
    let reference =
        ramflux_protocol::qualified_device_id(&added.principal_commitment, "alice-two")?;
    peer.client.persist_pair(
        &peer.client.local_device_identity("bob")?,
        &peer.client.device_identity(&reference)?,
        &[3; 32],
        &pair,
    )?;
    let mut entries = added.signed_device_set.as_ref().ok_or("set")?.devices.clone();
    let entry = entries.iter_mut().find(|e| e.device_id == "alice-two").ok_or("device")?;
    entry.status = DeviceSetStatus::Revoked;
    entry.revoked_at = Some(now_unix_timestamp());
    let record = ramflux_crypto::sign_device_set_with_profile(
        first.client.identity_root.as_ref().ok_or("root")?,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 3,
            devices: entries,
        },
        added.signed_device_set.as_ref().ok_or("set")?.profile.as_deref().cloned(),
    )?;
    node.publish_signed_device_set(&ramflux_node_core::DeviceSetPublishRequest {
        root_public_key: initial.root_public_key.clone(),
        record: record.clone(),
    })?;
    let revoked: SdkDeviceManifestResponse = serde_json::from_value(serde_json::to_value(
        node.device_manifest(&initial.principal_commitment).ok_or("manifest")?,
    )?)?;
    observe(&peer.client, &revoked)?;
    assert!(
        !peer
            .client
            .account_db()?
            .pair_peer_devices(&peer.client.local_device_identity("bob")?)?
            .iter()
            .any(|d| d == &reference)
    );
    assert!(
        peer.client
            .device_identity(&reference)
            .and_then(|identity| peer
                .client
                .require_cached_root_authority(HeadUse::NewAuthorization, &identity))
            .is_err()
    );
    peer.reopen()?;
    assert_eq!(peer.client.observed_device_set(&initial.principal_commitment)?, Some(record));
    assert!(observe(&peer.client, &added).is_err());
    assert!(
        peer.client
            .device_identity(&reference)
            .and_then(|identity| peer
                .client
                .require_cached_root_authority(HeadUse::NewAuthorization, &identity))
            .is_err()
    );
    assert!(
        peer.client
            .account_db()?
            .journal_after(0, 128)?
            .iter()
            .any(|e| e.topic == "safety.changed")
    );
    Ok(())
}
#[test]
fn substituted_branch_or_agreement_key_and_real_v1_proof_never_enter_the_cache() -> TestResult {
    let owner = Actor::new("alice", "alice", 31, 32, 1)?;
    let peer = Actor::new("bob", "bob", 41, 42, 1)?;
    let original = owner.manifest()?;
    let mut forged = original.clone();
    let attacker = ramflux_crypto::create_device_branch("alice", "alice", 1, [90; 32]);
    let identity = X25519KeyPair::from_seed([91; 32]);
    let signed = X25519KeyPair::from_seed([92; 32]);
    forged.devices[0].branch_public_key =
        ramflux_protocol::encode_base64url(attacker.signing_key.verifying_key().to_bytes());
    forged.devices[0].prekey_bundle =
        ramflux_crypto::create_prekey_bundle(&attacker, &identity, "signed", &signed, None, None)?;
    ramflux_crypto::verify_prekey_bundle(
        &attacker.signing_key.verifying_key(),
        &forged.devices[0].prekey_bundle,
    )?;
    assert!(observe(&peer.client, &forged).is_err());
    let branch = owner.client.device_branch.as_ref().ok_or("branch")?;
    forged = original.clone();
    forged.devices[0].prekey_bundle =
        ramflux_crypto::create_prekey_bundle(branch, &identity, "signed", &signed, None, None)?;
    assert!(observe(&peer.client, &forged).is_err());
    forged = original.clone();
    forged.devices[0].branch_proof.as_mut().ok_or("proof")?.key_binding = None;
    assert!(observe(&peer.client, &forged).is_err());
    forged.signed_device_set = None;
    assert!(observe(&peer.client, &forged).is_err());
    assert!(peer.client.account_db()?.client_record("device", "alice")?.is_none());
    observe(&peer.client, &original)?;
    assert_eq!(
        peer.client.observed_device_set(&original.principal_commitment)?,
        original.signed_device_set
    );
    Ok(())
}
#[test]
fn newer_root_authorized_rotation_retires_pairs_and_preserves_friend() -> TestResult {
    let owner = Actor::new("alice", "alice", 51, 52, 1)?;
    let replacement = Actor::new("alice", "alice", 51, 53, 2)?;
    let peer = Actor::new("bob", "bob", 61, 62, 1)?;
    let original = owner.manifest()?;
    observe(&peer.client, &original)?;
    peer.client.establish_friend_link("friend", "bob", "alice")?;
    let reference = ramflux_protocol::qualified_device_id(&original.principal_commitment, "alice")?;
    let pair = ramflux_crypto::DmSession::initiator(
        [1; 32],
        dm_device_id_hash("bob"),
        dm_device_id_hash("alice"),
        [2; 32],
    )?;
    peer.client.persist_pair(
        &peer.client.local_device_identity("bob")?,
        &peer.client.device_identity(&reference)?,
        &[3; 32],
        &pair,
    )?;
    let mut rotated = replacement.manifest()?;
    sign_set(&replacement, &mut rotated, 2)?;
    observe(&peer.client, &rotated)?;
    assert!(
        !peer
            .client
            .account_db()?
            .pair_peer_devices(&peer.client.local_device_identity("bob")?)?
            .iter()
            .any(|d| d == &reference)
    );
    assert!(peer.client.friend_link_peer_is_accepted("alice")?);
    assert!(observe(&peer.client, &original).is_err());
    let mut conflict = original.clone();
    sign_set(&owner, &mut conflict, 2)?;
    assert!(observe(&peer.client, &conflict).is_err());
    assert_eq!(
        peer.client.observed_device_set(&original.principal_commitment)?,
        rotated.signed_device_set
    );
    Ok(())
}
#[test]
fn migration_requires_independent_root_binding_for_every_legacy_device_and_reuses_pending_proposal()
-> TestResult {
    let first = Actor::new("alice", "first", 71, 72, 1)?;
    let second = Actor::new("alice", "second", 71, 73, 1)?;
    let mut legacy = first.manifest()?;
    legacy.devices.extend(second.manifest()?.devices);
    legacy.signed_device_set = None;
    for d in &mut legacy.devices {
        d.branch_proof.as_mut().ok_or("proof")?.key_binding = None;
    }
    assert!(first.client.prepare_owned_authority(Some(&legacy)).is_err());
    let now = now_unix_timestamp();
    let approval = second.client.authorize_current_device(
        "ramflux-node",
        vec!["device.delivery.bind".into()],
        now,
        now + 3600,
    )?;
    first.client.import_legacy_device_authorizations(&[approval])?;
    let proposal = first.client.prepare_owned_authority(Some(&legacy))?;
    assert_eq!(proposal.devices.len(), 2);
    assert_eq!(first.client.prepare_owned_authority(Some(&legacy))?, proposal);
    first.client.accept_owned_record(&proposal)?;
    assert!(
        first
            .client
            .account_db()?
            .load_actor_state::<SignedDeviceSetRecord>("identity/owned_pending_set")?
            .is_none()
    );
    let mut revoked = legacy.clone();
    revoked.signed_device_set = Some(proposal.clone());
    let mut entries = proposal.devices.clone();
    let e = entries.iter_mut().find(|e| e.device_id == "first").ok_or("device")?;
    e.status = DeviceSetStatus::Revoked;
    e.revoked_at = Some(now);
    let record = ramflux_crypto::sign_device_set_with_profile(
        first.client.identity_root.as_ref().ok_or("root")?,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 2,
            devices: entries,
        },
        proposal.profile.as_deref().cloned(),
    )?;
    revoked.signed_device_set = Some(record.clone());
    assert!(first.client.prepare_owned_authority(Some(&revoked)).is_err());
    assert_eq!(first.client.observed_device_set(&record.principal_commitment)?, Some(record));
    legacy.signed_device_set = Some(proposal);
    assert!(first.client.prepare_owned_authority(Some(&legacy)).is_err());
    Ok(())
}
#[test]
fn principal_label_root_substitution_is_a_hard_safety_failure() -> TestResult {
    let first = Actor::new("alice", "alice", 81, 82, 1)?;
    let attacker = Actor::new("alice", "alice", 91, 92, 1)?;
    let peer = Actor::new("bob", "bob", 101, 102, 1)?;
    let original = first.manifest()?;
    observe(&peer.client, &original)?;
    assert!(observe(&peer.client, &attacker.manifest()?).is_err());
    assert_eq!(
        peer.client.account_db()?.client_record("identity", "alice")?.ok_or("identity")?["contact_identity_commitment"],
        original.principal_commitment
    );
    assert_eq!(
        peer.client.observed_device_set(&original.principal_commitment)?,
        original.signed_device_set
    );
    Ok(())
}

#[path = "gateway_tests.rs"]
mod gateway;

#[path = "review_r2_tests.rs"]
mod review_r2;

#[path = "review_r3_tests.rs"]
mod review_r3;

#[test]
fn verify_manifest_json_rejects_swapped_branch_and_agreement_keys() -> TestResult {
    let bob = Actor::new("bob", "bob-device", 31, 32, 1)?;
    let attacker = Actor::new("mallory", "mallory-device", 51, 52, 1)?;
    let honest = test_support::public_manifest(&bob.client)?;
    let attack = test_support::public_manifest(&attacker.client)?;
    RamfluxClient::verify_device_manifest_json(
        serde_json::to_value(&honest)?,
        &honest.principal_commitment,
    )?;
    for agreement in [false, true] {
        let mut forged = honest.clone();
        forged.devices[0].branch_public_key.clone_from(&attack.devices[0].branch_public_key);
        if agreement {
            forged.devices[0].prekey_bundle = attack.devices[0].prekey_bundle.clone();
        }
        assert!(
            RamfluxClient::verify_device_manifest_json(
                serde_json::to_value(forged)?,
                &honest.principal_commitment
            )
            .is_err()
        );
    }
    Ok(())
}

#[path = "proof_lifetime_tests.rs"]
mod proof_lifetime;

#[path = "profile_tests.rs"]
mod profile;
