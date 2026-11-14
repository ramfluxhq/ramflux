// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A missing custody account refuses confirmation and writes no stamp.
use super::*;

#[test]
fn missing_custody_account_refuses_confirmation_and_writes_no_stamp() -> TestResult {
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
    assert_eq!(safety.verification_state, "unverified");
    let key = format!("identity/safety_verified_set/{}", manifest.principal_commitment);
    let db = peer.client.account_db()?;
    assert!(db.load_actor_state::<String>(&key)?.is_none());
    let refused = crate::client::contact_verification_cas::verify_linked_contact(
        &peer.client,
        &manifest.principal_commitment,
    );
    assert!(matches!(refused, Err(SdkError::CustodyModeDowngrade)), "{refused:?}");
    assert!(db.load_actor_state::<String>(&key)?.is_none());
    Ok(())
}
