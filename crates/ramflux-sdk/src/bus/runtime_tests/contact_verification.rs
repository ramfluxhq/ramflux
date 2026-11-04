// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native safety reads retain unverified, verified and stale states without a live session.

use super::*;
use crate::bus::readers::AccountReaders;
use crate::client::native_test_support::Fixture;
use serde_json::json;

#[tokio::test]
async fn contact_verification_status_is_a_local_read_with_stored_authority_distinctions()
-> Result<(), Box<dyn std::error::Error>> {
    let own = Box::pin(Fixture::new("local-safety")).await?;
    let peer = Box::pin(Fixture::new("peer-safety")).await?;
    own.client.persist_fetched_identity_directory(&peer.manifest)?;
    let own_root = own.manifest.principal_commitment.clone();
    let peer_root = peer.manifest.principal_commitment.clone();
    own.client.establish_friend_link("safety-link", &own_root, &peer_root)?;
    let reference = own.client.owned_device_identity()?;
    let account = LocalBusAccountState::disconnected(own.client, own.config, own_root);
    let state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(own.root.0.join("bus.sock"), &own.root.0),
        accounts: BTreeMap::from([("local-safety".into(), account)]),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let account = state.accounts.get("local-safety").ok_or("account")?;
    let db = account.client.account_db()?;
    let pool = AccountReaders::start(db, Some(reference))?;
    pool.set_account_view(&state, "local-safety")?;
    let read = || {
        LocalBusFrame::request(
            "safety",
            Some("local-safety".into()),
            "contact",
            "contact.verification.status",
            json!({"contact_identity_commitment":peer_root}),
        )
    };
    let wall = std::time::Instant::now();
    let unverified = pool.request(read()).await?;
    assert!(wall.elapsed() < Duration::from_secs(1));
    assert_eq!(unverified["verification_state"], "unverified");
    assert_eq!(unverified["stored_verification_state"], "unverified");
    let safety = account.client.contact_safety_number(&peer_root)?;
    db.mark_contact_verified(ContactVerificationUpdate {
        contact_identity_commitment: &peer_root,
        safety_number_hash: &safety.safety_number_hash,
        device_set_hash: &safety.contact_device_set_hash,
        lineage_head: &safety.contact_lineage_head,
        verified_at: now_unix_timestamp(),
        verified_by_device_id: "primary",
    })?;
    db.persist_actor_state(
        &format!("identity/safety_verified_set/{peer_root}"),
        &safety.contact_device_set_hash,
    )?;
    let verified = pool.request(read()).await?;
    assert_eq!(verified["verification_state"], "verified");
    assert_eq!(verified["stored_verification_state"], "verified");
    db.persist_actor_state(
        &format!("identity/safety_verified_set/{peer_root}"),
        &"older-authority",
    )?;
    let expired_status = pool.request(read()).await?;
    assert_eq!(expired_status["verification_state"], "verification_stale");
    assert_eq!(expired_status["safety_number"], verified["safety_number"]);
    assert!(
        account.connection.is_none() && account.engine.is_none(),
        "local verification must not create a session"
    );
    pool.stop().await;
    drop(pool);
    drop(state);
    Ok(())
}
