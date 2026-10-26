// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Outstanding rename intents survive stale restores without replaying acknowledged names.
use super::*;
const DESIRED: &str = "identity/owned_public_profile";

fn publish_remote(
    node: &mut ramflux_node_core::IdentityRegistry,
    manifest: &SdkDeviceManifestResponse,
) -> TestResult {
    node.publish_signed_device_set(&ramflux_node_core::DeviceSetPublishRequest {
        root_public_key: manifest.root_public_key.clone(),
        record: manifest.signed_device_set.clone().ok_or("set")?,
    })?;
    Ok(())
}

#[test]
fn stale_restore_rebases_lower_and_equal_epoch_rename_intents_and_retries_exactly() -> TestResult {
    for remote_epoch in [2, 3] {
        let mut owner = Actor::new("owner", "phone", 71, 72, 1)?;
        let mut node = ramflux_node_core::IdentityRegistry::new();
        let first = enroll(&mut node, &owner, None)?;
        let desired = owner.client.set_identity_display_name("Desired Name")?;
        assert_eq!(desired.epoch, 2);
        let pending = owner.client.prepare_owned_authority(None)?;
        let remote = with_profile(&owner, first, "Sibling Name", remote_epoch, remote_epoch)?;
        publish_remote(&mut node, &remote)?;
        owner.reopen()?;
        owner.client.create_identity_root("owner", [71; 32]);
        owner.client.create_device_branch("owner", "phone", 1, [72; 32]);
        let next = owner.client.prepare_owned_authority(Some(&remote))?;
        let profile = next.profile.as_ref().ok_or("profile")?;
        assert_eq!(profile.display_name, "Desired Name");
        assert_eq!(profile.epoch, remote_epoch + 1);
        assert_eq!(next.device_set_epoch, remote_epoch + 1);
        assert_ne!(next, pending);
        assert_eq!(owner.client.prepare_owned_authority(Some(&remote))?, next);
        assert_eq!(
            owner
                .client
                .account_db()?
                .load_actor_state::<ramflux_protocol::SignedIdentityProfile>(DESIRED)?
                .as_ref(),
            Some(profile.as_ref())
        );
        let published = enroll(&mut node, &owner, Some(&remote))?;
        assert_eq!(published.signed_device_set.as_ref(), Some(&next));
        assert!(
            owner
                .client
                .account_db()?
                .load_actor_state::<ramflux_protocol::SignedIdentityProfile>(DESIRED)?
                .is_none()
        );
        assert_eq!(owner.client.prepare_owned_authority(Some(&published))?, next);
    }
    Ok(())
}

#[test]
fn restored_acknowledged_intent_does_not_undo_a_later_sibling_rename() -> TestResult {
    let owner = Actor::new("owner", "phone", 73, 74, 1)?;
    let mut node = ramflux_node_core::IdentityRegistry::new();
    owner.client.set_identity_display_name("Previous Name")?;
    let first = enroll(&mut node, &owner, None)?;
    let acknowledged =
        first.signed_device_set.as_ref().ok_or("set")?.profile.as_ref().ok_or("profile")?;
    // Older backups retained desired data even after this exact profile was acknowledged.
    owner.client.account_db()?.persist_actor_state(DESIRED, acknowledged)?;
    let remote = with_profile(&owner, first.clone(), "Sibling Name", 2, 2)?;
    publish_remote(&mut node, &remote)?;
    let published = enroll(&mut node, &owner, Some(&remote))?;
    assert_eq!(published.signed_device_set.as_ref(), remote.signed_device_set.as_ref());
    assert!(
        owner
            .client
            .account_db()?
            .load_actor_state::<ramflux_protocol::SignedIdentityProfile>(DESIRED)?
            .is_none()
    );
    Ok(())
}

#[test]
fn exhausted_acknowledged_epoch_refuses_without_dropping_the_pending_rename() -> TestResult {
    let owner = Actor::new("owner", "phone", 75, 76, 1)?;
    let mut node = ramflux_node_core::IdentityRegistry::new();
    let first = enroll(&mut node, &owner, None)?;
    let desired = owner.client.set_identity_display_name("Desired Name")?;
    let remote = with_profile(
        &owner,
        first,
        "Acknowledged Name",
        ramflux_protocol::MAX_SAFE_JSON_INTEGER,
        2,
    )?;
    publish_remote(&mut node, &remote)?;
    for _ in 0..2 {
        assert!(
            matches!(owner.client.prepare_owned_authority(Some(&remote)), Err(SdkError::InboundRejected(reason)) if reason == "identity authority: profile epoch exhausted")
        );
        assert_eq!(
            owner
                .client
                .account_db()?
                .load_actor_state::<ramflux_protocol::SignedIdentityProfile>(DESIRED)?,
            Some(desired.clone())
        );
    }
    assert!(
        matches!(owner.client.set_identity_display_name("Another Name"), Err(SdkError::InboundRejected(reason)) if reason == "identity authority: profile epoch exhausted")
    );
    assert_eq!(
        owner
            .client
            .account_db()?
            .load_actor_state::<ramflux_protocol::SignedIdentityProfile>(DESIRED)?,
        Some(desired)
    );
    Ok(())
}
