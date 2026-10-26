// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Manual safety verification upgrades without inventing authenticated kind or forgetting stamps.
use super::*;
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
async fn fresh_synthetic_safety_verification_can_remain_verified_without_a_signed_set() -> TestResult
{
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
        let peer = Actor::new("peer", "peer", 87, 88, 1)?;
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
        let stamp_key = format!("identity/safety_verified_set/{}", manifest.principal_commitment);
        assert!(db.load_actor_state::<String>(&stamp_key)?.is_none());
        assert!(!db.is_query_only()?);
        let query = db.open_reader()?;
        assert!(query.is_query_only()?);
        assert!(query.persist_actor_state("must-stay-read-only", &true).is_err());
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
