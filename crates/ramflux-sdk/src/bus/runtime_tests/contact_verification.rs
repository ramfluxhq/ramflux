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
    own.client.persist_observed_identity_directory_now(&peer.manifest)?;
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
    assert!(
        pool.request(read()).await.is_err(),
        "a verified row without a confirmation is refused"
    );
    crate::client::contact_verification_cas::verify_linked_contact(&account.client, &peer_root)?;
    let verified = pool.request(read()).await?;
    assert_eq!(verified["verification_state"], "verified");
    assert_eq!(verified["stored_verification_state"], "verified");
    assert!(
        account.connection.is_none() && account.engine.is_none(),
        "local verification must not create a session"
    );
    pool.stop().await;
    drop(pool);
    drop(state);
    Ok(())
}

fn read_request(peer: &str) -> LocalBusFrame {
    LocalBusFrame::request(
        "safety",
        Some("cas-views".into()),
        "contact",
        "contact.verification.status",
        json!({"contact_identity_commitment": peer}),
    )
}

async fn read_view(pool: &AccountReaders, peer: &str) -> Result<serde_json::Value, SdkError> {
    crate::client::native_test_support::watchdog::within(pool.request(read_request(peer)))
        .await
        .map_err(|_| SdkError::LocalBus("contact verification read deadline exceeded".into()))?
}

fn rename_peer(
    local: &crate::RamfluxClient,
    peer: &mut Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut native = peer.manifest.custody.as_ref().ok_or("custody")?.as_ref().clone();
    let anchor = native.publication.record.body.account_anchor.clone();
    let primary = peer.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let now = crate::custody::network_now()?;
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    body.device_set_epoch += 1;
    body.profile.display_name = "Renamed Human".into();
    native.publication.record = primary.sign_record(body)?;
    local.observe_custody_manifest(&native, &anchor, now)?;
    peer.manifest = crate::prekey::SdkDeviceManifestResponse::from_native(native)?;
    Ok(())
}

fn archived_grant_count(client: &crate::RamfluxClient) -> Result<i64, Box<dyn std::error::Error>> {
    use std::fmt::Write;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("account.db");
    let saved = client.account_db()?.write_backup_snapshot(&path)?;
    let backup = ramflux_storage::BackupDatabase::open(&path, &saved.key)?;
    backup.sanitize_native_backup()?;
    drop(backup);
    let mut hex = zeroize::Zeroizing::new(String::new());
    for byte in saved.key.bytes() {
        write!(&mut *hex, "{byte:02x}")?;
    }
    let db = rusqlite::Connection::open(&path)?;
    db.execute_batch(&zeroize::Zeroizing::new(format!("PRAGMA key=\"x'{}'\"", hex.as_str())))?;
    let count: i64 = db.query_row(
        "SELECT COUNT(*) FROM runtime_actor_state WHERE state_kind LIKE 'identity/contact_safety_%'",
        [],
        |row| row.get(0),
    )?;
    Ok(count)
}

fn daemon(root: &std::path::Path, account: LocalBusAccountState) -> LocalBusDaemonState {
    LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), root),
        accounts: BTreeMap::from([("cas-views".into(), account)]),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    }
}

async fn matching_then_stale(
    state: &LocalBusDaemonState,
    pool: &AccountReaders,
    peer: &mut Fixture,
    peer_root: &str,
    safety_number: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let unverified = read_view(pool, peer_root).await?;
    assert_eq!(unverified["verification_state"], "unverified");
    let client = &state.accounts.get("cas-views").ok_or("account")?.client;
    let mut bad: ramflux_protocol::message::ExpectedContactSafety =
        serde_json::from_value(unverified["expected"].clone())?;
    bad.link_id.clear();
    assert!(matches!(
        client.compare_and_record_contact_safety_verified(&bad),
        Err(crate::SdkError::ContactInput(crate::ContactReason::ExpectedSafetyRequired))
    ));
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "unverified");
    let submitted: ramflux_protocol::message::ExpectedContactSafety =
        serde_json::from_value(read_view(pool, peer_root).await?["expected"].clone())?;
    let verified = client.compare_and_record_contact_safety_verified(&submitted)?;
    assert_eq!(verified.verification_state, "verified");
    let again: ramflux_protocol::message::ExpectedContactSafety =
        serde_json::from_value(read_view(pool, peer_root).await?["expected"].clone())?;
    let again = client.compare_and_record_contact_safety_verified(&again)?;
    assert_eq!(again.verification_state, "verified");
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "verified");
    rename_peer(client, peer)?;
    let after_rename = read_view(pool, peer_root).await?;
    assert_eq!(after_rename["verification_state"], "verification_stale");
    assert_eq!(after_rename["safety_number"], serde_json::json!(safety_number));
    let recovered: ramflux_protocol::message::ExpectedContactSafety =
        serde_json::from_value(after_rename["expected"].clone())?;
    let recovered = client.compare_and_record_contact_safety_verified(&recovered)?;
    assert_eq!(recovered.verification_state, "verified");
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "verified");
    Ok(())
}

async fn changed_blocked_and_restore(
    state: &LocalBusDaemonState,
    pool: &AccountReaders,
    peer: &Fixture,
    peer_root: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = &state.accounts.get("cas-views").ok_or("account")?.client;
    {
        let db = client.account_db()?;
        db.remove_actor_state(&format!("identity/contact_safety_confirmation/{peer_root}"))?;
        db.remove_actor_state(&format!("identity/contact_safety_origin_inner/{peer_root}"))?;
        db.observe_contact_fork(peer_root, "fork-1", 1)?;
    }
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "changed");
    let mut bad: ramflux_protocol::message::ExpectedContactSafety =
        serde_json::from_value(read_view(pool, peer_root).await?["expected"].clone())?;
    bad.safety_number_hash.push('x');
    assert!(matches!(
        client.compare_and_record_contact_safety_verified(&bad),
        Err(crate::SdkError::ContactInput(crate::ContactReason::SafetyMaterialMismatch))
    ));
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "changed");
    client.account_db()?.remove_actor_state(&format!("identity/custody/{peer_root}"))?;
    assert!(matches!(read_view(pool, peer_root).await, Err(crate::SdkError::NetworkingPending)));
    client.persist_observed_identity_directory_now(&peer.manifest)?;
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "changed");
    client.block_friend_link("cas-views-link")?;
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "blocked_by_policy");
    let expected = crate::client::contact_verification_cas::current_contact_safety_expectation(
        client, peer_root,
    )?;
    assert!(matches!(
        client.compare_and_record_contact_safety_verified(&expected),
        Err(crate::SdkError::LocalBus(_))
    ));
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "blocked_by_policy");
    client.unblock_friend_link("cas-views-link")?;
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "changed");
    let verified =
        crate::client::contact_verification_cas::verify_linked_contact(client, peer_root)?;
    assert_eq!(verified.verification_state, "verified");
    assert_eq!(archived_grant_count(client)?, 0, "an archive copy carries no safety grant");
    assert_eq!(read_view(pool, peer_root).await?["verification_state"], "verified");
    let db = client.account_db()?;
    db.remove_actor_state(&format!("identity/contact_safety_confirmation/{peer_root}"))?;
    db.remove_actor_state(&format!("identity/contact_safety_origin_inner/{peer_root}"))?;
    db.observe_contact_fork(peer_root, "fork-2", 2)?;
    assert_eq!(read_view(pool, peer_root).await?["stored_verification_state"], "changed");
    Ok(())
}

#[tokio::test]
async fn verify_cas_reverification_updates_all_views() -> Result<(), Box<dyn std::error::Error>> {
    let mut own = Box::pin(Fixture::new("cas-views")).await?;
    let mut peer = Box::pin(Fixture::new("cas-views-peer")).await?;
    own.client.persist_observed_identity_directory_now(&peer.manifest)?;
    let own_root = own.client.own_account_anchor()?;
    let peer_root = peer.manifest.principal_commitment.clone();
    own.client.establish_friend_link("cas-views-link", &own_root, &peer_root)?;
    let safety_number = own.client.contact_safety_number(&peer_root)?.safety_number;
    let reference = own.client.owned_device_identity()?;
    let root = own.root.0.clone();
    let config = own.config.clone();
    let device = own.config.device_id.clone();
    let vault = own.vault.clone();
    let manifest = own.manifest.clone();
    let client = std::mem::replace(&mut own.client, crate::RamfluxClient::new());
    let state = daemon(&root, LocalBusAccountState::disconnected(client, config, own_root));
    let pool = {
        let db = state.accounts.get("cas-views").ok_or("account")?.client.account_db()?;
        AccountReaders::start(db, Some(reference))?
    };
    pool.set_account_view(&state, "cas-views")?;
    matching_then_stale(&state, &pool, &mut peer, &peer_root, &safety_number).await?;
    changed_blocked_and_restore(&state, &pool, &peer, &peer_root).await?;
    pool.stop().await;
    drop(pool);
    drop(state);
    let mut reopened = crate::RamfluxClient::new();
    reopened.open_account_index(&root)?;
    reopened.unlock_account("cas-views", b"native fixture data passphrase")?;
    reopened.initialize_born_v3_branch(&device, vault).await?;
    reopened.persist_observed_identity_directory_now(&manifest)?;
    reopened.persist_observed_identity_directory_now(&peer.manifest)?;
    assert_eq!(reopened.contact_safety_number(&peer_root)?.verification_state, "changed");
    let reverified =
        crate::client::contact_verification_cas::verify_linked_contact(&reopened, &peer_root)?;
    assert_eq!(reverified.verification_state, "verified");
    drop(own);
    Ok(())
}
