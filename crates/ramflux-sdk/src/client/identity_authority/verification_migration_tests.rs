// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A current confirmation commit persists its authority stamp before later reads.
use super::*;

#[test]
fn confirmed_safety_commit_writes_authority_before_any_later_read() -> TestResult {
    let owner = Actor::new("owner", "phone", 101, 102, 1)?;
    let peer = Actor::new("peer", "peer", 103, 104, 1)?;
    let manifest = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
    let own = peer.manifest()?;
    observe(&peer.client, &manifest)?;
    observe(&peer.client, &own)?;
    peer.client.establish_friend_link(
        "contact",
        &own.principal_commitment,
        &manifest.principal_commitment,
    )?;
    let safety = peer.client.contact_safety_number(&manifest.principal_commitment)?;
    let key = format!("identity/safety_verified_set/{}", manifest.principal_commitment);
    let db = peer.client.account_db()?;
    assert!(db.load_actor_state::<String>(&key)?.is_none());
    crate::client::contact_verification_cas::verify_linked_contact(
        &peer.client,
        &manifest.principal_commitment,
    )?;
    let stamp = set_fingerprint(manifest.signed_device_set.as_ref().ok_or("set")?)?;
    assert_eq!(
        db.load_actor_state::<String>(&key)?,
        Some(stamp.clone()),
        "confirmation writer must persist authority without reading a contact view"
    );
    let retired = Actor::new("owner", "retired", 101, 105, 1)?;
    let changed = with_revoked_device(&owner, &manifest, &retired)?;
    observe(&peer.client, &changed)?;
    assert_eq!(
        peer.client.contact_safety_number(&manifest.principal_commitment)?.contact_device_set_hash,
        safety.contact_device_set_hash
    );
    assert_eq!(
        peer.client.contact_safety_number(&manifest.principal_commitment)?.verification_state,
        "verification_stale"
    );
    assert_eq!(db.load_actor_state::<String>(&key)?, Some(stamp));
    Ok(())
}
