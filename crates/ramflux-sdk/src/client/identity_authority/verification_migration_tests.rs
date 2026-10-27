// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Manual safety verification upgrades without inventing authenticated kind or forgetting stamps.
use super::*;
use crate::client::contact_verification::{MIGRATION_MARKER, migrate_legacy_contact_verifications};
use serde_json::json;

fn directory_request(account: &str) -> LocalBusFrame {
    LocalBusFrame::request(
        "directory",
        Some(account.into()),
        "client",
        "identity.directory",
        json!({}),
    )
}

#[tokio::test]
async fn legacy_card_synthetic_verification_agrees_across_views_without_authenticating_kind()
-> TestResult {
    let owner = Actor::new("owner", "phone", 81, 82, 1)?;
    let mut peer = Actor::new("peer", "peer", 83, 84, 1)?;
    let root = owner.manifest()?.principal_commitment;
    let own_root = peer.manifest()?.principal_commitment;
    peer.client.establish_friend_link("contact", &own_root, &root)?;
    peer.client.account_db()?.persist_client_record(
        "identity",
        "owner",
        &json!({
            "principal_id":"owner", "contact_identity_commitment":root, "display_name":"Owner",
            "root_source":"card", "device_set_hash":"legacy-card-device-hash",
        }),
    )?;
    assert!(peer.client.observed_device_set(&root)?.is_none());
    assert_eq!(
        peer.client.mark_contact_safety_verified(&root, "peer")?.verification_state,
        "verified"
    );
    let stamp_key = format!("identity/safety_verified_set/{root}");
    assert!(peer.client.account_db()?.load_actor_state::<String>(&stamp_key)?.is_none());
    assert_eq!(peer.client.contact_safety_number(&root)?.verification_state, "verified");
    assert!(peer.client.verified_principal_kind("owner")?.is_none());
    assert_eq!(peer.client.contact_entry("owner")?["verified"], true);
    assert_eq!(peer.client.contact_entry("owner")?["kind_verified"], false);
    peer.reopen()?;
    assert_eq!(peer.client.contact_safety_number(&root)?.verification_state, "verified");
    let db = peer.client.account_db()?;
    let result = crate::bus::test_account_reader_request(db, directory_request(&peer.id)).await?;
    let row = result["identities"]
        .as_array()
        .ok_or("identities")?
        .iter()
        .find(|r| r["principal_id"] == "owner")
        .ok_or("owner")?;
    assert_eq!(row["safety_state"], "verified");
    assert_eq!(row["verified"], true);
    assert_eq!(row["kind_verified"], false);
    assert!(db.load_actor_state::<String>(&stamp_key)?.is_none());
    Ok(())
}

#[tokio::test]
async fn legacy_verification_is_baselined_before_the_first_query_only_directory_read() -> TestResult
{
    for matches in [true, false] {
        let owner = Actor::new("owner", "phone", 85, 86, 1)?;
        let mut peer = Actor::new("peer", "peer", 87, 88, 1)?;
        let manifest = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
        observe(&peer.client, &manifest)?;
        let db = peer.client.account_db()?;
        let identity = db.client_record("identity", "owner")?.ok_or("identity")?;
        let current_hash = identity["device_set_hash"].as_str().ok_or("hash")?;
        db.mark_contact_verified(ramflux_storage::ContactVerificationUpdate {
            contact_identity_commitment: &manifest.principal_commitment,
            safety_number_hash: "legacy-safety",
            device_set_hash: if matches { current_hash } else { "old-device-hash" },
            lineage_head: "legacy-lineage",
            verified_at: 1,
            verified_by_device_id: "peer",
        })?;
        // Simulate an account written before the migration marker existed.
        db.remove_actor_state(MIGRATION_MARKER)?;
        let stamp_key = format!("identity/safety_verified_set/{}", manifest.principal_commitment);
        assert!(db.load_actor_state::<String>(&stamp_key)?.is_none());
        assert!(!db.is_query_only()?);
        let query = db.open_reader()?;
        assert!(query.is_query_only()?);
        assert!(query.persist_actor_state("must-stay-read-only", &true).is_err());
        let mut reader = RamfluxClient::new();
        reader.active_account_db = Some(query);
        assert_eq!(
            reader.contact_safety_verification_state(
                &manifest.principal_commitment,
                Some(current_hash)
            )?,
            "verification_stale"
        );
        assert!(db.load_actor_state::<String>(&stamp_key)?.is_none());
        drop(reader);
        peer.reopen()?;
        let db = peer.client.account_db()?;
        assert_eq!(db.load_actor_state::<bool>(MIGRATION_MARKER)?, Some(true));
        let result =
            crate::bus::test_account_reader_request(db, directory_request(&peer.id)).await?;
        let row = result["identities"]
            .as_array()
            .ok_or("identities")?
            .iter()
            .find(|r| r["principal_id"] == "owner")
            .ok_or("owner")?;
        let expected = if matches { "verified" } else { "verification_stale" };
        assert_eq!(row["safety_state"], expected);
        assert_eq!(row["verified"], matches);
        assert_eq!(row["kind_verified"], true);
        assert_eq!(
            peer.client.contact_safety_verification_state(
                &manifest.principal_commitment,
                Some(current_hash)
            )?,
            expected
        );
        let stamp = db.load_actor_state::<String>(&stamp_key)?;
        if matches {
            assert_eq!(
                stamp,
                Some(set_fingerprint(manifest.signed_device_set.as_ref().ok_or("set")?)?)
            );
            assert_eq!(peer.client.verified_principal_kind("owner")?, Some(PrincipalKind::Human));
        } else {
            assert!(stamp.is_none(), "a device-hash mismatch must not acquire a migration stamp");
            assert!(peer.client.verified_principal_kind("owner")?.is_none());
        }
    }
    Ok(())
}

fn legacy_record(client: &RamfluxClient, manifest: &SdkDeviceManifestResponse) -> TestResult {
    let db = client.account_db()?;
    let row = db.client_record("identity", &manifest.principal_id)?.ok_or("identity")?;
    db.mark_contact_verified(ramflux_storage::ContactVerificationUpdate {
        contact_identity_commitment: &manifest.principal_commitment,
        safety_number_hash: "legacy-safety",
        device_set_hash: row["device_set_hash"].as_str().ok_or("hash")?,
        lineage_head: "legacy-lineage",
        verified_at: 1,
        verified_by_device_id: "peer",
    })?;
    Ok(())
}

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
    let own_material = crate::client::contact::contact_safety_material_from_manifest(&own)?;
    let material = crate::client::contact::contact_safety_material_from_manifest(&manifest)?;
    let key = format!("identity/safety_verified_set/{}", manifest.principal_commitment);
    let db = peer.client.account_db()?;
    assert!(db.load_actor_state::<String>(&key)?.is_none());
    peer.client.commit_contact_safety(&safety, &own_material, &material, "peer")?;
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

#[tokio::test]
async fn sealed_migration_never_absorbs_new_unstamped_records_or_rescans_on_reader_start()
-> TestResult {
    let owner = Actor::new("owner", "phone", 111, 112, 1)?;
    let peer = Actor::new("peer", "peer", 113, 114, 1)?;
    let manifest = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
    let db = peer.client.account_db()?;
    assert_eq!(db.load_actor_state::<bool>(MIGRATION_MARKER)?, Some(true));
    observe(&peer.client, &manifest)?;
    legacy_record(&peer.client, &manifest)?;
    let row = db.client_record("identity", "owner")?.ok_or("identity")?;
    let key = format!("identity/safety_verified_set/{}", manifest.principal_commitment);
    assert_eq!(
        peer.client.contact_safety_verification_state(
            &manifest.principal_commitment,
            row["device_set_hash"].as_str()
        )?,
        "verification_stale"
    );
    migrate_legacy_contact_verifications(db)?;
    assert!(db.load_actor_state::<String>(&key)?.is_none());
    assert_eq!(peer.client.contact_entry("owner")?["verified"], false);
    let directory =
        crate::bus::test_account_reader_request(db, directory_request(&peer.id)).await?;
    let owner_row = directory["identities"]
        .as_array()
        .ok_or("identities")?
        .iter()
        .find(|r| r["principal_id"] == "owner")
        .ok_or("owner")?;
    assert_eq!(owner_row["safety_state"], "verification_stale");
    assert!(db.load_actor_state::<String>(&key)?.is_none());
    // A later malformed authority would fail the old full scan. Sealed startup must not scan it.
    db.persist_actor_state(
        &record_key(&manifest.principal_commitment),
        &json!({"invalid":"authority"}),
    )?;
    let messages = crate::bus::test_account_reader_request(
        db,
        LocalBusFrame::request(
            "messages",
            Some(peer.id.clone()),
            "client",
            "message.list",
            json!({"conversation_id":"empty"}),
        ),
    )
    .await?;
    assert_eq!(messages["messages"].as_array().map(Vec::len), Some(0));
    assert_eq!(db.load_actor_state::<bool>(MIGRATION_MARKER)?, Some(true));
    Ok(())
}

#[test]
fn migration_failure_rolls_back_prior_stamps_and_completion_marker() -> TestResult {
    let alpha = Actor::new("alpha", "phone", 121, 122, 1)?;
    let beta = Actor::new("beta", "phone", 123, 124, 1)?;
    let peer = Actor::new("peer", "peer", 125, 126, 1)?;
    let a = with_profile(&alpha, alpha.manifest()?, "Alpha", 1, 1)?;
    let b = with_profile(&beta, beta.manifest()?, "Beta", 1, 1)?;
    for manifest in [&a, &b] {
        observe(&peer.client, manifest)?;
        legacy_record(&peer.client, manifest)?;
    }
    let db = peer.client.account_db()?;
    db.remove_actor_state(MIGRATION_MARKER)?;
    db.persist_actor_state(&record_key(&b.principal_commitment), &json!({"invalid":"authority"}))?;
    assert!(
        migrate_legacy_contact_verifications(db).is_err(),
        "invalid legacy authority must leave migration incomplete"
    );
    assert!(db.load_actor_state::<bool>(MIGRATION_MARKER)?.is_none());
    for manifest in [&a, &b] {
        assert!(
            db.load_actor_state::<String>(&format!(
                "identity/safety_verified_set/{}",
                manifest.principal_commitment
            ))?
            .is_none()
        );
    }
    db.persist_actor_state(
        &record_key(&b.principal_commitment),
        b.signed_device_set.as_ref().ok_or("set")?,
    )?;
    migrate_legacy_contact_verifications(db)?;
    assert_eq!(db.load_actor_state::<bool>(MIGRATION_MARKER)?, Some(true));
    for manifest in [&a, &b] {
        assert_eq!(
            db.load_actor_state::<String>(&format!(
                "identity/safety_verified_set/{}",
                manifest.principal_commitment
            ))?,
            Some(set_fingerprint(manifest.signed_device_set.as_ref().ok_or("set")?)?)
        );
    }
    Ok(())
}
