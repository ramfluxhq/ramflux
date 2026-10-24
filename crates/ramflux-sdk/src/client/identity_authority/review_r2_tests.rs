// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publication forks and expired session proofs cannot wedge long-lived root authority.
use super::*;
#[test]
fn concurrent_own_registration_proposals_rebase_on_the_nodes_accepted_fork() -> TestResult {
    let first = Actor::new("alice", "one", 181, 182, 1)?;
    let second = Actor::new("alice", "two", 181, 183, 1)?;
    let rotated = Actor::new("alice", "one", 181, 184, 2)?;
    let mut node = ramflux_node_core::IdentityRegistry::new();
    let initial = enroll(&mut node, &first, None)?;
    let pending = second.client.prepare_owned_authority(Some(&initial))?;
    assert_eq!(pending.device_set_epoch, 2);
    let accepted_fork = enroll(&mut node, &rotated, Some(&initial))?;
    assert_eq!(accepted_fork.signed_device_set.as_ref().ok_or("set")?.device_set_epoch, 2);
    let converged = enroll(&mut node, &second, Some(&accepted_fork))?;
    let record = converged.signed_device_set.ok_or("set")?;
    assert_eq!(record.device_set_epoch, 3);
    assert_eq!(record.devices.len(), 2);
    assert_eq!(second.client.observed_device_set(&record.principal_commitment)?, Some(record));
    assert!(!second.client.account_db()?.actor_state_exists("identity/owned_pending_set")?);
    assert!(
        second
            .client
            .account_db()?
            .journal_after(0, 100)?
            .iter()
            .any(|entry| entry.topic == "safety.changed")
    );
    Ok(())
}
#[test]
fn expired_sibling_proof_does_not_block_newer_signed_revocation_or_authorize_a_new_session()
-> TestResult {
    let owner = Actor::new("alice", "one", 191, 192, 1)?;
    let sibling = Actor::new("alice", "two", 191, 193, 1)?;
    let stolen = Actor::new("alice", "stolen", 191, 194, 1)?;
    let peer = Actor::new("bob", "bob", 201, 202, 1)?;
    let mut manifest = owner.manifest()?;
    manifest.devices.extend(sibling.manifest()?.devices);
    manifest.devices.extend(stolen.manifest()?.devices);
    sign_set(&owner, &mut manifest, 1)?;
    observe(&peer.client, &manifest)?;
    let now = now_unix_timestamp();
    let old = manifest.devices.iter_mut().find(|d| d.device_id == "two").ok_or("sibling")?;
    old.branch_proof.issued_at = now - 7200;
    old.branch_proof.expires_at = now - 3601;
    old.branch_proof.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_crypto::branch_proof_signing_bytes(&old.branch_proof)?,
        owner.client.identity_root.as_ref().ok_or("root")?.signing_key.to_bytes(),
    );
    let mut entries = manifest.signed_device_set.as_ref().ok_or("set")?.devices.clone();
    let target = entries.iter_mut().find(|d| d.device_id == "stolen").ok_or("target")?;
    target.status = DeviceSetStatus::Revoked;
    target.revoked_at = Some(now);
    let record = ramflux_crypto::sign_device_set(
        owner.client.identity_root.as_ref().ok_or("root")?,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 2,
            devices: entries,
        },
    )?;
    manifest.signed_device_set = Some(record.clone());
    manifest.devices.retain(|d| d.device_id != "stolen");
    observe(&peer.client, &manifest)?;
    assert_eq!(peer.client.observed_device_set(&manifest.principal_commitment)?, Some(record));
    assert!(peer.client.require_cached_root_authority("stolen").is_err());
    peer.client.require_cached_root_authority("two")?;
    assert!(peer.client.require_fresh_device_authorization("two").is_err());
    assert!(
        peer.client
            .verify_root_bound_prekey("two", &sibling.client.load_x3dh_private_state("two")?.bundle)
            .is_err()
    );
    let owner_key = &owner.client.identity_root.as_ref().ok_or("root")?.signing_key.verifying_key();
    let proof =
        &manifest.devices.iter().find(|d| d.device_id == "two").ok_or("proof")?.branch_proof;
    assert!(
        ramflux_crypto::verify_root_bound_branch_proof(
            owner_key,
            proof,
            proof.key_binding.as_ref().ok_or("binding")?,
            "ramflux-node",
            "device.delivery.bind",
            now
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn own_proof_refresh_is_due_five_minutes_before_the_hour_expires() -> TestResult {
    let owner = Actor::new("alice", "one", 211, 212, 1)?;
    assert!(!owner.client.own_proof_refresh_due(1000)?);
    owner.client.record_owned_proof_published(1000)?;
    assert!(!owner.client.own_proof_refresh_due(4299)?);
    assert!(owner.client.own_proof_refresh_due(4300)?);
    assert!(owner.client.own_proof_refresh_due(4601)?);
    Ok(())
}

#[test]
fn another_roots_equal_device_name_and_tombstone_leave_bobs_keys_pair_and_group_pin_intact()
-> TestResult {
    let alice = Actor::new("alice", "alice", 21, 22, 1)?;
    let bob = Actor::new("bob", "shared", 31, 32, 1)?;
    let mallory = Actor::new("mallory", "shared", 41, 42, 1)?;
    let b = bob.manifest()?;
    let mut m = mallory.manifest()?;
    observe(&alice.client, &b)?;
    let bob_ref = ramflux_protocol::qualified_device_id(&b.principal_commitment, "shared")?;
    let mallory_ref = ramflux_protocol::qualified_device_id(&m.principal_commitment, "shared")?;
    alice.client.create_group("group", "alice")?;
    alice.client.add_group_member_with_root(
        "group",
        "shared",
        "member",
        &b.principal_commitment,
    )?;
    let pin = alice.client.account_db()?.group_member_device_key("group", &bob_ref)?;
    let pair = ramflux_crypto::DmSession::initiator(
        [1; 32],
        dm_device_id_hash("alice"),
        dm_device_id_hash("shared"),
        [2; 32],
    )?;
    alice.client.persist_pair("alice", &bob_ref, &[3; 32], &pair)?;
    observe(&alice.client, &m)?;
    assert!(alice.client.account_db()?.client_record("device", "shared").is_err());
    assert_eq!(
        alice.client.account_db()?.client_record("device", &bob_ref)?.ok_or("bob row")?["principal_id"],
        "bob"
    );
    let mut entries = m.signed_device_set.as_ref().ok_or("set")?.devices.clone();
    entries[0].status = DeviceSetStatus::Revoked;
    entries[0].revoked_at = Some(now_unix_timestamp());
    m.signed_device_set = Some(ramflux_crypto::sign_device_set(
        mallory.client.identity_root.as_ref().ok_or("root")?,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 2,
            devices: entries,
        },
    )?);
    m.devices.clear();
    observe(&alice.client, &m)?;
    alice.client.require_cached_root_authority(&bob_ref)?;
    assert!(alice.client.require_cached_root_authority(&mallory_ref).is_err());
    assert_eq!(alice.client.account_db()?.group_member_device_key("group", &bob_ref)?, pin);
    assert_eq!(
        alice.client.active_pair("alice", &bob_ref)?.ok_or("bob pair")?.0.session_id,
        pair.session_id
    );
    assert_ne!(
        alice.client.pair_key("alice", &bob_ref)?,
        alice.client.pair_key("alice", &mallory_ref)?
    );
    assert_eq!(
        alice
            .client
            .account_db()?
            .load_actor_state::<bool>(&alice.client.device_revocation_key(&mallory_ref)?)?,
        Some(true)
    );
    assert_eq!(
        alice
            .client
            .account_db()?
            .load_actor_state::<bool>(&alice.client.device_revocation_key(&bob_ref)?)?,
        None
    );
    let addressed = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "test".into(),
        envelope_id: "test".into(),
        source_principal_id: "alice".into(),
        sender_id: "alice".into(),
        recipient_device_id: Some("shared".into()),
        recipient_principal_commitment: Some(b.principal_commitment),
        target_delivery_id: "shared".into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 300,
    };
    assert_eq!(
        alice.client.send_pair_session_from_url("alice", &addressed, None)?.0.session_id,
        pair.session_id
    );
    Ok(())
}

#[test]
fn pending_revocation_intent_survives_a_concurrent_own_registration_fork() -> TestResult {
    let first = Actor::new("alice", "one", 51, 52, 1)?;
    let second = Actor::new("alice", "two", 51, 53, 1)?;
    let stolen = Actor::new("alice", "stolen", 51, 54, 1)?;
    let mut registry = ramflux_node_core::IdentityRegistry::new();
    let initial = enroll(&mut registry, &first, None)?;
    let initial = enroll(&mut registry, &stolen, Some(&initial))?;
    let old = initial.signed_device_set.as_ref().ok_or("set")?;
    first.client.accept_owned_record(old)?;
    let mut entries = old.devices.clone();
    let entry = entries.iter_mut().find(|entry| entry.device_id == "stolen").ok_or("stolen")?;
    entry.status = DeviceSetStatus::Revoked;
    entry.revoked_at = Some(now_unix_timestamp());
    let pending = ramflux_crypto::sign_device_set(
        first.client.identity_root.as_ref().ok_or("root")?,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: PrincipalKind::Human,
            device_set_epoch: 3,
            devices: entries,
        },
    )?;
    first.client.account_db()?.persist_actor_state("identity/owned_pending_set", &pending)?;
    let fork = enroll(&mut registry, &second, Some(&initial))?;
    first.client.accept_owned_record(fork.signed_device_set.as_ref().ok_or("fork")?)?;
    let proposal = first.client.prepare_owned_authority(Some(&fork))?;
    assert_eq!(proposal.device_set_epoch, 4);
    assert!(
        proposal
            .devices
            .iter()
            .any(|entry| entry.device_id == "stolen" && entry.status == DeviceSetStatus::Revoked)
    );
    assert!(
        proposal
            .devices
            .iter()
            .any(|entry| entry.device_id == "two" && entry.status == DeviceSetStatus::Active)
    );
    Ok(())
}

#[test]
fn a_foreign_roots_copy_of_the_local_name_cannot_prevent_creating_an_own_group() -> TestResult {
    let owner = Actor::new("alice", "alice", 61, 62, 1)?;
    let stranger = Actor::new("mallory", "alice", 71, 72, 1)?;
    observe(&owner.client, &stranger.manifest()?)?;
    owner.client.create_group("own-group", "alice")?;
    let own = owner.client.local_device_reference("alice")?;
    let binding =
        owner.client.account_db()?.group_member_key_binding("own-group", &own)?.ok_or("own pin")?;
    assert_eq!(binding.principal_id.as_deref(), Some("alice"));
    assert_eq!(
        binding.signing_public_key,
        ramflux_protocol::encode_base64url(
            owner
                .client
                .device_branch
                .as_ref()
                .ok_or("branch")?
                .signing_key
                .verifying_key()
                .to_bytes()
        )
    );
    Ok(())
}
