// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native authority runs the ordinary group invitation, sender-key and removal paths.
use crate::client::native_test_support::{Fixture, TestResult};
#[tokio::test]
async fn native_group_invite_accept_message_replay_and_kick_use_real_authority() -> TestResult {
    let alice = Fixture::with_device("native-group-owner", "owner-device").await?;
    let bob = Fixture::with_device("native-group-member", "member-device").await?;
    alice.client.persist_fetched_identity_directory(&bob.manifest)?;
    bob.client.persist_fetched_identity_directory(&alice.manifest)?;
    let owner = alice.client.owned_device_identity()?;
    let member = bob.client.owned_device_identity()?;
    for fixture in [&alice, &bob] {
        fixture.client.create_group("native-group", owner.storage_key())?;
    }
    let (invite, _) = alice.client.create_signed_group_member_invite(
        "native-group",
        owner.device_id(),
        member.storage_key(),
        &bob.manifest.devices[0].branch_public_key,
        "member",
        crate::time::now_unix_timestamp() + 3600,
        "native integration",
    )?;
    let ramflux_protocol::GroupEventBody::MemberInvitedV2 { invite_id, .. } = &invite.body else {
        return Err("invite body".into());
    };
    bob.client.apply_group_control_event(&invite)?;
    let (accept, _) = bob.client.create_signed_group_member_accept(
        "native-group",
        member.device_id(),
        invite_id,
    )?;
    let state = alice.client.apply_group_control_event(&accept)?;
    assert_eq!(state, bob.client.group_state("native-group")?);
    assert!(state.members.contains(member.device_id()));
    let distribution = zeroize::Zeroizing::new(
        alice.client.export_group_sender_key_distribution("native-group", owner.device_id())?,
    );
    bob.client.import_group_sender_key_distribution(&distribution)?;
    let encrypted = alice.client.encrypt_group_message(
        "native-group",
        owner.device_id(),
        b"native group message",
    )?;
    let envelope = serde_json::from_slice(&encrypted)?;
    assert_eq!(
        bob.client.decrypt_group_envelope(&envelope, "native-group-message")?,
        b"native group message"
    );
    assert!(bob.client.decrypt_group_envelope(&envelope, "native-group-message").is_err());
    let (kick, state) = alice.client.create_signed_group_member_kick(
        "native-group",
        owner.device_id(),
        member.storage_key(),
        "native member removed",
    )?;
    bob.client.apply_group_control_event(&kick)?;
    assert!(!state.members.contains(member.device_id()));
    assert!(alice.client.identity_root.is_none());
    assert!(bob.client.identity_root.is_none());
    Ok(())
}
