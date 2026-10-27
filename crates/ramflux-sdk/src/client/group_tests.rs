// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated group control and membership regression fixtures.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root(test_name: &str) -> PathBuf {
    let nanos =
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("ramflux-sdk-group-{test_name}-{nanos}"))
}

fn group_client(
    test_name: &str,
    principal: &str,
    device: &str,
    device_seed: [u8; 32],
) -> Result<RamfluxClient, SdkError> {
    let root = temp_root(test_name);
    let mut client = RamfluxClient::new();
    client.create_identity_root(principal, root_seed(principal));
    client.create_device_branch(principal, device, 1, device_seed);
    client.open_account_index(root)?;
    client.create_account("acct", principal)?;
    client.unlock_account("acct", b"group-control-test")?;
    Ok(client)
}

fn root_seed(principal: &str) -> [u8; 32] {
    ramflux_protocol::blake3_hash_bytes("ramflux.test.group.root.v1", principal.as_bytes())
}
type ManifestMap = std::collections::BTreeMap<(String, String), SdkDeviceManifestResponse>;
fn manifests() -> &'static std::sync::Mutex<ManifestMap> {
    static MAP: std::sync::OnceLock<std::sync::Mutex<ManifestMap>> = std::sync::OnceLock::new();
    MAP.get_or_init(Default::default)
}
fn root_for(principal: &str) -> String {
    let root = ramflux_crypto::create_identity_root(principal, root_seed(principal));
    ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key())
}
fn own_root(client: &RamfluxClient) -> Result<String, SdkError> {
    let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    client.device_root(&client.local_device_reference(&branch.device_id)?)
}
fn fixture_manifest(public: &str, device: &str) -> Result<SdkDeviceManifestResponse, SdkError> {
    manifests()
        .lock()
        .map_err(|_| SdkError::LocalBus("fixture manifest lock".into()))?
        .get(&(public.into(), device.into()))
        .cloned()
        .ok_or_else(|| SdkError::LocalBus("fixture manifest absent".into()))
}
fn device_public_key(principal: &str, device: &str, seed: [u8; 32]) -> Result<String, SdkError> {
    let root = ramflux_crypto::create_identity_root(principal, root_seed(principal));
    let branch = ramflux_crypto::create_device_branch(principal, device, 1, seed);
    let identity = X25519KeyPair::from_seed(ramflux_protocol::blake3_hash_bytes(
        "ramflux.test.group.identity.v1",
        &seed,
    ));
    let signed = X25519KeyPair::from_seed(ramflux_protocol::blake3_hash_bytes(
        "ramflux.test.group.prekey.v1",
        &seed,
    ));
    let public = ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let commitment = root_for(principal);
    let now = now_unix_timestamp();
    let mut manifest = SdkDeviceManifestResponse {
        custody: None,
        principal_id: principal.into(),
        principal_commitment: commitment.clone(),
        root_public_key: ramflux_protocol::encode_base64url(
            root.signing_key.verifying_key().to_bytes(),
        ),
        signed_device_set: None,
        devices: vec![crate::prekey::SdkDeviceManifestEntry {
            principal_id: principal.into(),
            principal_commitment: commitment,
            device_id: device.into(),
            device_epoch: 1,
            branch_public_key: public.clone(),
            target_delivery_id: device.into(),
            branch_authorized_event_id: format!("authorized:{device}"),
            branch_proof: Some(ramflux_crypto::authorize_device_branch_v2(
                &root,
                &branch,
                ramflux_crypto::BranchAuthorization {
                    audience: "ramflux-node",
                    capability_scope: vec!["device.delivery.bind".into()],
                    issued_at: now,
                    expires_at: now + 3600,
                    principal_kind: ramflux_protocol::PrincipalKind::Human,
                    agreement_identity_public_key: identity.public,
                },
            )?),
            prekey_bundle: ramflux_crypto::create_prekey_bundle(
                &branch, &identity, "signed", &signed, None, None,
            )?,
        }],
    };
    crate::client::identity_authority::test_support::sign_manifest(&root, &mut manifest, 1)?;
    manifests()
        .lock()
        .map_err(|_| SdkError::LocalBus("fixture manifest lock".into()))?
        // Repeated seeds denote one fixture authority, including across parallel tests.
        // Preserve its first signed epoch instead of creating time-dependent same-epoch forks.
        .entry((public.clone(), device.into()))
        .or_insert(manifest);
    Ok(public)
}
fn seed_group_named(
    client: &RamfluxClient,
    group_id: &str,
    alice_key: &str,
    bob_key: &str,
) -> Result<(), SdkError> {
    let bob = fixture_manifest(bob_key, "bob_device")?;
    client.observe_device_manifest_json(serde_json::to_value(&bob)?, &bob.principal_commitment)?;
    let manifest = fixture_manifest(alice_key, "alice_device")?;
    client.observe_device_manifest_json(
        serde_json::to_value(&manifest)?,
        &manifest.principal_commitment,
    )?;
    client.create_group(
        group_id,
        &ramflux_protocol::qualified_device_id(&manifest.principal_commitment, "alice_device")?,
    )?;
    // Fixture membership alone conveys no key authority; roots and key pins are explicit below.
    client.account_db()?.add_group_member(group_id, "bob_device", "member")?;
    client.persist_group_member_route(
        group_id,
        &LocalBusGroupMemberRoute {
            member_id: "bob_device".into(),
            member_principal_commitment: Some(root_for("bob")),
            device_signing_public_key: None,
            target_delivery_id: Some("bob-target".into()),
            federation: None,
        },
    )?;
    if client.device_branch.as_ref().is_some_and(|local| local.device_id == "bob_device") {
        client.pin_local_group_member(group_id)?;
    }
    Ok(())
}
fn seed_group(client: &RamfluxClient, alice_key: &str, bob_key: &str) -> Result<(), SdkError> {
    seed_group_named(client, "group_test", alice_key, bob_key)
}
fn seed_member_key(client: &RamfluxClient, member: &str, public: &str) -> Result<(), SdkError> {
    let manifest = fixture_manifest(public, member)?;
    client.observe_device_manifest_json(
        serde_json::to_value(&manifest)?,
        &manifest.principal_commitment,
    )?;
    client.pin_joined_group_member(
        "group_test",
        &ramflux_protocol::qualified_device_id(&manifest.principal_commitment, member)?,
    )
}

fn invite_id_from_event(event: &ramflux_protocol::GroupEvent) -> Result<String, SdkError> {
    match &event.body {
        ramflux_protocol::GroupEventBody::MemberInvitedV2 { invite_id, .. } => {
            Ok(invite_id.clone())
        }
        _ => Err(SdkError::LocalBus("expected member invite event".to_owned())),
    }
}

#[test]
fn bootstrap_member_join_requires_verified_actor_key_and_source_device() -> Result<(), SdkError> {
    let alice_seed = [0x72; 32];
    let bob_seed = [0x73; 32];
    let carol_seed = [0x74; 32];
    let alice_key = device_public_key("alice", "alice_device", alice_seed)?;
    let bob_key = device_public_key("bob", "bob_device", bob_seed)?;
    let carol_key = device_public_key("carol", "carol_device", carol_seed)?;
    let alice = group_client("alice_join", "alice", "alice_device", alice_seed)?;
    let bob = group_client("bob_join", "bob", "bob_device", bob_seed)?;
    let carol = group_client("carol_join", "carol", "carol_device", carol_seed)?;

    alice.create_group("group_join", "alice_device")?;
    let bob_manifest = fixture_manifest(&bob_key, "bob_device")?;
    alice.observe_device_manifest_json(serde_json::to_value(&bob_manifest)?, &root_for("bob"))?;
    alice.add_group_member_with_root("group_join", "bob_device", "member", &root_for("bob"))?;
    let alice_manifest = fixture_manifest(&alice_key, "alice_device")?;
    bob.observe_device_manifest_json(serde_json::to_value(&alice_manifest)?, &root_for("alice"))?;
    let event = alice.create_signed_group_member_join_event(
        "group_join",
        "alice_device",
        "bob_device",
        "member",
        &own_root(&alice)?,
    )?;

    assert!(
        bob.apply_bootstrap_group_member_join_event(&event, "mallory_device", &alice_key).is_err()
    );
    assert!(
        carol.apply_bootstrap_group_member_join_event(&event, "alice_device", &carol_key).is_err()
    );

    let state = bob.apply_bootstrap_group_member_join_event(&event, "alice_device", &alice_key)?;
    assert!(state.members.contains("bob_device"));
    assert_eq!(state.roles.get("alice_device").map(String::as_str), Some("owner"));
    assert_eq!(state.roles.get("bob_device").map(String::as_str), Some("member"));
    assert_eq!(
        bob.account_db()?.group_member_device_key(
            "group_join",
            &crate::client::identity_authority::test_support::group_device(
                &bob,
                "group_join",
                "alice_device"
            )?
        )?,
        Some(alice_key)
    );
    assert_ne!(bob_key, carol_key);
    Ok(())
}

#[test]
fn owner_can_generate_onboard_events_for_multiple_direct_adds() -> Result<(), SdkError> {
    let alice_seed = [0x75; 32];
    let alice_key = device_public_key("alice", "alice_device", alice_seed)?;
    let alice = group_client("alice_multi_join", "alice", "alice_device", alice_seed)?;
    let bob_key = device_public_key("bob", "bob_device", [0x74; 32])?;
    seed_group_named(&alice, "group_multi_join", &alice_key, &bob_key)?;

    let bob_event = alice.create_signed_group_member_join_event(
        "group_multi_join",
        "alice_device",
        "bob_device",
        "member",
        &own_root(&alice)?,
    )?;
    assert_eq!(bob_event.event_type, "group.member_joined");

    let carol_key = device_public_key("carol", "carol_device", [0x76; 32])?;
    let carol = fixture_manifest(&carol_key, "carol_device")?;
    alice
        .observe_device_manifest_json(serde_json::to_value(&carol)?, &carol.principal_commitment)?;
    alice.add_group_member_with_root(
        "group_multi_join",
        "carol_device",
        "member",
        &carol.principal_commitment,
    )?;
    let carol_event = alice.create_signed_group_member_join_event(
        "group_multi_join",
        "alice_device",
        "carol_device",
        "member",
        &own_root(&alice)?,
    )?;
    assert_eq!(carol_event.event_type, "group.member_joined");

    assert!(matches!(
        alice.create_signed_group_member_join_event(
            "group_multi_join",
            "bob_device",
            "dave_device",
            "member",
            "bob_commitment"
        ),
        Err(SdkError::Storage(StorageError::GroupPermissionDenied))
    ));
    Ok(())
}

#[test]
fn signed_group_role_change_rejects_forgery_epoch_mismatch_and_replay() -> Result<(), SdkError> {
    let alice_seed = [0x42; 32];
    let alice_key = device_public_key("alice", "alice_device", alice_seed)?;
    let alice = group_client("alice", "alice", "alice_device", alice_seed)?;
    let bob = group_client("bob", "bob", "bob_device", [0x44; 32])?;
    let bob_key = device_public_key("bob", "bob_device", [0x44; 32])?;
    seed_group(&alice, &alice_key, &bob_key)?;
    seed_group(&bob, &alice_key, &bob_key)?;

    let (event, _state) = alice.create_signed_group_role_change(
        "group_test",
        "alice_device",
        "bob_device",
        "admin",
    )?;

    let mut forged = event.clone();
    if let ramflux_protocol::GroupEventBody::RoleChanged { new_role, .. } = &mut forged.body {
        *new_role = "bot".to_owned();
    }
    assert!(bob.apply_group_role_change(&forged).is_err());

    let mut wrong_epoch = event.clone();
    if let ramflux_protocol::GroupEventBody::RoleChanged { previous_epoch, .. } =
        &mut wrong_epoch.body
    {
        *previous_epoch = 99;
    }
    let branch = alice.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    wrong_epoch.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(branch, &wrong_epoch)?;
    assert!(matches!(
        bob.apply_group_role_change(&wrong_epoch),
        Err(SdkError::Storage(StorageError::GroupControlEpochMismatch { .. }))
    ));

    bob.apply_group_role_change(&event)?;
    assert!(matches!(
        bob.apply_group_role_change(&event),
        Err(SdkError::Storage(StorageError::GroupControlReplay(_)))
    ));
    Ok(())
}

#[test]
fn signed_group_invite_accept_enforces_state_expiry_and_bound_invitee_key() -> Result<(), SdkError>
{
    let alice_seed = [0x62; 32];
    let bob_seed = [0x63; 32];
    let carol_seed = [0x64; 32];
    let alice_key = device_public_key("alice", "alice_device", alice_seed)?;
    let bob_key = device_public_key("bob", "bob_device", bob_seed)?;
    let carol_key = device_public_key("carol", "carol_device", carol_seed)?;
    let alice = group_client("alice_s46", "alice", "alice_device", alice_seed)?;
    let bob = group_client("bob_s46", "bob", "bob_device", bob_seed)?;
    let carol = group_client("carol_s46", "carol", "carol_device", carol_seed)?;
    seed_group(&alice, &alice_key, &bob_key)?;
    seed_group(&bob, &alice_key, &bob_key)?;
    seed_group(&carol, &alice_key, &bob_key)?;
    seed_member_key(&alice, "bob_device", &bob_key)?;
    seed_member_key(&bob, "bob_device", &bob_key)?;
    seed_member_key(&carol, "bob_device", &bob_key)?;

    let carol_manifest = fixture_manifest(&carol_key, "carol_device")?;
    alice
        .observe_device_manifest_json(serde_json::to_value(&carol_manifest)?, &root_for("carol"))?;
    let (invite, _state) = alice.create_signed_group_member_invite(
        "group_test",
        "alice_device",
        &ramflux_protocol::qualified_device_id(&root_for("carol"), "carol_device")?,
        &carol_key,
        "member",
        4_000_000_000,
        "unit test",
    )?;
    let invite_id = invite_id_from_event(&invite)?;
    bob.apply_group_control_event(&invite)?;
    carol.apply_group_control_event(&invite)?;

    assert!(matches!(
        bob.create_signed_group_member_accept("group_test", "bob_device", &invite_id),
        Err(SdkError::Protocol(_))
    ));

    let (accept, carol_state) =
        carol.create_signed_group_member_accept("group_test", "carol_device", &invite_id)?;
    assert!(carol_state.members.contains("carol_device"));
    let alice_state = alice.apply_group_control_event(&accept)?;
    assert!(alice_state.members.contains("carol_device"));
    assert!(matches!(
        carol.create_signed_group_member_accept("group_test", "carol_device", &invite_id),
        Err(SdkError::Storage(StorageError::GroupInviteInvalidState { .. }))
    ));

    let expired_group = "group_expired";
    seed_group_named(&alice, expired_group, &alice_key, &bob_key)?;
    seed_group_named(&carol, expired_group, &alice_key, &bob_key)?;
    let (expired_invite, _state) = alice.create_signed_group_member_invite(
        expired_group,
        "alice_device",
        &ramflux_protocol::qualified_device_id(&root_for("carol"), "carol_device")?,
        &carol_key,
        "member",
        1,
        "unit test",
    )?;
    let expired_invite_id = invite_id_from_event(&expired_invite)?;
    carol.apply_group_control_event(&expired_invite)?;
    assert!(matches!(
        carol.create_signed_group_member_accept(expired_group, "carol_device", &expired_invite_id),
        Err(SdkError::Storage(StorageError::GroupInviteExpired(_)))
    ));
    Ok(())
}

#[test]
fn signed_group_kick_ban_and_delete_apply_authoritatively() -> Result<(), SdkError> {
    let alice_seed = [0x52; 32];
    let bob_seed = [0x53; 32];
    let alice_key = device_public_key("alice", "alice_device", alice_seed)?;
    let bob_key = device_public_key("bob", "bob_device", bob_seed)?;
    let alice = group_client("alice_s45", "alice", "alice_device", alice_seed)?;
    let bob = group_client("bob_s45", "bob", "bob_device", bob_seed)?;
    seed_group(&alice, &alice_key, &bob_key)?;
    seed_group(&bob, &alice_key, &bob_key)?;
    seed_member_key(&alice, "bob_device", &bob_key)?;
    seed_member_key(&bob, "bob_device", &bob_key)?;

    alice.account_db()?.send_direct_message(
        "group_test",
        "msg_from_bob",
        "bob_device",
        b"ciphertext",
    )?;
    let epoch_before_delete = alice.group_state("group_test")?.group_epoch;
    let (_delete, delete_state) = alice.create_signed_group_message_delete(
        "group_test",
        "alice_device",
        "msg_from_bob",
        "group_tombstone",
        "unit test",
    )?;
    assert_eq!(delete_state.group_epoch, epoch_before_delete);

    let (kick, _state) = alice.create_signed_group_member_kick(
        "group_test",
        "alice_device",
        "bob_device",
        "unit test",
    )?;
    bob.apply_group_control_event(&kick)?;
    assert!(!bob.group_state("group_test")?.members.contains("bob_device"));
    assert!(matches!(
        bob.apply_group_control_event(&kick),
        Err(SdkError::Storage(StorageError::GroupControlReplay(_)))
    ));

    let alice_ban = group_client("alice_s45_ban", "alice", "alice_device", alice_seed)?;
    seed_group(&alice_ban, &alice_key, &bob_key)?;
    seed_member_key(&alice_ban, "bob_device", &bob_key)?;
    let (_ban, state) = alice_ban.create_signed_group_member_ban(
        "group_test",
        "alice_device",
        "bob_device",
        "unit test",
    )?;
    assert!(!state.members.contains("bob_device"));
    assert!(matches!(
        alice_ban.add_group_member_with_root(
            "group_test",
            "bob_device",
            "member",
            &root_for("bob")
        ),
        Err(SdkError::Storage(StorageError::GroupPermissionDenied))
    ));
    Ok(())
}
#[test]
fn kicked_member_can_rejoin_and_all_members_converge() -> Result<(), SdkError> {
    let alice_seed = [0x62; 32];
    let bob_seed = [0x63; 32];
    let carol_seed = [0x64; 32];
    let alice_key = device_public_key("alice", "alice_device", alice_seed)?;
    let bob_key = device_public_key("bob", "bob_device", bob_seed)?;
    let alice = group_client("rejoin_alice", "alice", "alice_device", alice_seed)?;
    let bob = group_client("rejoin_bob", "bob", "bob_device", bob_seed)?;
    let carol = group_client("rejoin_carol", "carol", "carol_device", carol_seed)?;
    let carol_key = device_public_key("carol", "carol_device", carol_seed)?;
    for client in [&alice, &bob, &carol] {
        seed_group(client, &alice_key, &bob_key)?;
        let manifest = fixture_manifest(&carol_key, "carol_device")?;
        client
            .observe_device_manifest_json(serde_json::to_value(&manifest)?, &root_for("carol"))?;
        client.add_group_member_with_root(
            "group_test",
            "carol_device",
            "member",
            &root_for("carol"),
        )?;
        seed_member_key(client, "bob_device", &bob_key)?;
    }
    let (kick, _) = alice.create_signed_group_member_kick(
        "group_test",
        "alice_device",
        "bob_device",
        "test rejoin",
    )?;
    bob.apply_group_control_event(&kick)?;
    carol.apply_group_control_event(&kick)?;
    let (invite, _) = alice.create_signed_group_member_invite(
        "group_test",
        "alice_device",
        &ramflux_protocol::qualified_device_id(&root_for("bob"), "bob_device")?,
        &bob_key,
        "member",
        now_unix_timestamp() + 3600,
        "test rejoin",
    )?;
    let invite_id = invite_id_from_event(&invite)?;
    bob.apply_group_control_event(&invite)?;
    carol.apply_group_control_event(&invite)?;
    let (accept, _) =
        bob.create_signed_group_member_accept("group_test", "bob_device", &invite_id)?;
    alice.apply_group_control_event(&accept)?;
    carol.apply_group_control_event(&accept)?;
    let state = alice.group_state("group_test")?;
    assert!(state.members.contains("bob_device"));
    assert_eq!(state, bob.group_state("group_test")?);
    assert_eq!(state, carol.group_state("group_test")?);
    for client in [&alice, &bob, &carol] {
        assert_eq!(
            client.account_db()?.group_member_device_key(
                "group_test",
                &crate::client::identity_authority::test_support::group_device(
                    client,
                    "group_test",
                    "bob_device"
                )?
            )?,
            Some(bob_key.clone())
        );
    }
    Ok(())
}
#[test]
fn an_admin_cannot_invite_the_active_owner_under_an_attackers_key() -> Result<(), SdkError> {
    let alice_seed = [0x72; 32];
    let bob_seed = [0x73; 32];
    let alice_key = device_public_key("alice", "alice_device", alice_seed)?;
    let bob_key = device_public_key("bob", "bob_device", bob_seed)?;
    let attacker = device_public_key("mallory", "alice_device", [0x74; 32])?;
    let alice = group_client("owner_invite_guard_alice", "alice", "alice_device", alice_seed)?;
    let bob = group_client("owner_invite_guard_bob", "bob", "bob_device", bob_seed)?;
    for client in [&alice, &bob] {
        seed_group(client, &alice_key, &bob_key)?;
        seed_member_key(client, "bob_device", &bob_key)?;
    }
    let (promotion, _) = alice.create_signed_group_role_change(
        "group_test",
        "alice_device",
        "bob_device",
        "admin",
    )?;
    bob.apply_group_control_event(&promotion)?;
    let before = alice.group_state("group_test")?;
    let event = bob.signed_group_control_base(
        "group_test",
        "bob_device",
        "malicious-owner-invite".into(),
        "group.member_invited",
        before.group_epoch,
        ramflux_protocol::GroupEventBody::MemberInvitedV2 {
            group_id: "group_test".into(),
            group_epoch: before.group_epoch,
            invite_id: "malicious-owner-invite".into(),
            invitee_identity: "alice_device".into(),
            invitee_signing_public_key: attacker,
            invited_role: "member".into(),
            inviter_device_id: "bob_device".into(),
            expires_at: now_unix_timestamp() + 3600,
            reason: "active owner takeover probe".into(),
        },
    )?;
    let event = bob.sign_group_control_event(event)?;
    assert!(matches!(
        alice.apply_group_control_event(&event),
        Err(SdkError::Storage(StorageError::GroupPermissionDenied))
    ));
    assert_eq!(alice.group_state("group_test")?, before);
    assert_eq!(
        alice.account_db()?.group_member_device_key(
            "group_test",
            &crate::client::identity_authority::test_support::group_device(
                &alice,
                "group_test",
                "alice_device"
            )?
        )?,
        Some(alice_key)
    );
    Ok(())
}
#[test]
fn an_old_invite_accept_cannot_replace_a_member_who_is_now_active() -> Result<(), SdkError> {
    let alice_seed = [0x72; 32];
    let attacker_seed = [0x74; 32];
    let alice_key = device_public_key("alice", "alice_device", alice_seed)?;
    let attacker_key = device_public_key("mallory", "victim_device", attacker_seed)?;
    let alice = group_client("accept_active_guard_alice", "alice", "alice_device", alice_seed)?;
    let mallory =
        group_client("accept_active_guard_mallory", "mallory", "victim_device", attacker_seed)?;
    let bob_key = device_public_key("bob", "bob_device", [0x73; 32])?;
    seed_group(&alice, &alice_key, &bob_key)?;
    let (invite, _) = alice.create_signed_group_member_invite(
        "group_test",
        "alice_device",
        &ramflux_protocol::qualified_device_id(&root_for("mallory"), "victim_device")?,
        &attacker_key,
        "member",
        now_unix_timestamp() + 3600,
        "pending before legitimate join",
    )?;
    let invite_id = invite_id_from_event(&invite)?;
    let genuine = device_public_key("victim", "victim_device", [0x75; 32])?;
    seed_member_key(&alice, "victim_device", &genuine)?;
    alice.add_group_member_with_root(
        "group_test",
        "victim_device",
        "admin",
        &root_for("victim"),
    )?;
    let before = alice.group_state("group_test")?;
    let accept = mallory.signed_group_control_base(
        "group_test",
        "victim_device",
        "malicious-old-accept".into(),
        "group.member_accepted",
        before.group_epoch + 1,
        ramflux_protocol::GroupEventBody::MemberAccepted {
            group_id: "group_test".into(),
            previous_epoch: before.group_epoch,
            new_group_epoch: before.group_epoch + 1,
            invite_id,
            invitee_identity: "victim_device".into(),
            accepted_role: "member".into(),
        },
    )?;
    let manifest = fixture_manifest(&attacker_key, "victim_device")?;
    alice.observe_device_manifest_json(serde_json::to_value(&manifest)?, &root_for("mallory"))?;
    let accept = mallory.sign_group_control_event(accept)?;
    assert!(matches!(
        alice.apply_group_control_event(&accept),
        Err(SdkError::InboundRejected(reason)) if reason == "group control root binding mismatch"
    ));
    assert_eq!(alice.group_state("group_test")?, before);
    assert_eq!(
        alice.account_db()?.group_member_device_key(
            "group_test",
            &crate::client::identity_authority::test_support::group_device(
                &alice,
                "group_test",
                "victim_device"
            )?
        )?,
        Some(genuine)
    );
    Ok(())
}
#[test]
fn member_and_admin_join_events_cannot_promote_the_actor_or_demote_the_owner()
-> Result<(), SdkError> {
    for role in ["member", "admin"] {
        let owner = group_client("join-owner-guard", "alice", "alice_device", [71; 32])?;
        let attacker = ramflux_crypto::create_device_branch("bob", "bob_device", 1, [72; 32]);
        let owner_key = device_public_key("alice", "alice_device", [71; 32])?;
        let bob_key = device_public_key("bob", "bob_device", [72; 32])?;
        seed_group(&owner, &owner_key, &bob_key)?;
        if role == "admin" {
            owner.account_db()?.upsert_group_member_snapshot(
                "group_test",
                "bob_device",
                "admin",
                2,
            )?;
        }
        seed_member_key(&owner, "bob_device", &device_public_key("bob", "bob_device", [72; 32])?)?;
        let mut event = owner.create_signed_group_member_join_event(
            "group_test",
            "alice_device",
            "bob_device",
            "member",
            &own_root(&owner)?,
        )?;
        event.actor_device_id = "bob_device".into();
        event.signed.signing_key_id = "device:bob_device".into();
        if let ramflux_protocol::GroupEventBody::MemberJoined {
            actor_role,
            joined_identity,
            joined_role,
            actor_device_signing_public_key,
            ..
        } = &mut event.body
        {
            *actor_role = "owner".into();
            *joined_identity = "alice_device".into();
            *joined_role = "member".into();
            *actor_device_signing_public_key =
                ramflux_protocol::encode_base64url(attacker.signing_key.verifying_key().to_bytes());
        }
        event.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(&attacker, &event)?;
        let before = owner.group_state("group_test")?;
        assert!(owner.apply_group_control_event(&event).is_err());
        assert_eq!(owner.group_state("group_test")?, before);
    }
    Ok(())
}
#[test]
fn bootstrap_join_cannot_replace_membership_of_an_already_known_group() -> Result<(), SdkError> {
    let owner = group_client("bootstrap-existing", "alice", "alice_device", [73; 32])?;
    owner.create_group("known", "alice_device")?;
    let bob_key = device_public_key("bob", "bob_device", [74; 32])?;
    let manifest = fixture_manifest(&bob_key, "bob_device")?;
    owner.observe_device_manifest_json(
        serde_json::to_value(&manifest)?,
        &manifest.principal_commitment,
    )?;
    owner.add_group_member_with_root(
        "known",
        "bob_device",
        "member",
        &manifest.principal_commitment,
    )?;
    let event = owner.create_signed_group_member_join_event(
        "known",
        "alice_device",
        "bob_device",
        "member",
        &own_root(&owner)?,
    )?;
    let bob = group_client("bootstrap-target", "bob", "bob_device", [74; 32])?;
    bob.create_group("known", "bob_device")?;
    let before = bob.group_state("known")?;
    assert!(
        bob.apply_bootstrap_group_member_join_event(
            &event,
            "alice_device",
            &device_public_key("alice", "alice_device", [73; 32])?
        )
        .is_err()
    );
    assert_eq!(bob.group_state("known")?, before);
    Ok(())
}
