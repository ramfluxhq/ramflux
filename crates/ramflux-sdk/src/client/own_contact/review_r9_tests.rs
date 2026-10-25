// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! New-device restriction ordering, retry cursor and bounded history export regressions.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn path() -> Result<std::path::PathBuf, SdkError> {
    Ok(std::env::temp_dir().join(format!(
        "rf-contact-r9-{}",
        ramflux_protocol::encode_base64url(&ramflux_crypto::random_32()?[..8])
    )))
}
fn client(path: &std::path::Path, principal: &str, seed: u8) -> Result<RamfluxClient, SdkError> {
    super::tests::client(path, principal, seed)
}
fn activate(own: &RamfluxClient, sibling: &RamfluxClient) -> Result<(), SdkError> {
    let mut manifest = crate::client::identity_authority::test_support::public_manifest(own)?;
    manifest.devices.push(
        crate::client::identity_authority::test_support::public_manifest(sibling)?
            .devices
            .remove(0),
    );
    crate::client::identity_authority::test_support::sign_manifest(
        own.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut manifest,
        2,
    )?;
    own.persist_identity_directory(&manifest)
}
#[test]
fn removed_and_blocked_contacts_arrive_before_acceptances_and_cannot_be_resurrected() -> TestResult
{
    let root = path()?;
    let own = client(&root.join("own"), "bob", 1)?;
    let mut sibling = client(&root.join("sibling"), "bob", 1)?;
    sibling.create_device_branch("bob", "second", 1, [8; 32]);
    let peer = client(&root.join("peer"), "alice", 3)?;
    let manifest = crate::client::identity_authority::test_support::public_manifest(&peer)?;
    let own_root = own.owned_device_identity()?.root_commitment().to_owned();
    own.persist_identity_directory(&manifest)?;
    for (id, mode) in
        [("a-accepted", "accepted"), ("z-removed", "removed"), ("zz-blocked", "blocked")]
    {
        own.establish_friend_link(id, &own_root, &manifest.principal_commitment)?;
        if mode == "removed" {
            own.remove_friend_link(id, "own_devices")?;
        } else if mode == "blocked" {
            own.block_friend_link(id)?;
        }
    }
    for n in 0..16 {
        own.establish_friend_link(
            &format!("early-accepted-{n:02}"),
            &own_root,
            &manifest.principal_commitment,
        )?;
    }
    activate(&own, &sibling)?;
    // A completed r8 acceptance-only cursor must restart to propagate restrictions after upgrade.
    own.account_db()?.persist_actor_state(
        "own-contact/backfill",
        &serde_json::json!({"epoch":2,"cursor":"zzz","complete":true}),
    )?;
    assert_eq!(own.stage_contact_backfill_batch()?, 2);
    assert_eq!(own.stage_contact_backfill_batch()?, 4);
    let work = own.account_db()?.list_actor_states::<serde_json::Value>("own-device/send/")?;
    let mut staged = work
        .iter()
        .map(|job| {
            Ok((
                job["intent"]["sequence"].as_u64().ok_or("seq")?,
                ramflux_protocol::decode_base64url(job["intent"]["body"].as_str().ok_or("body")?)?,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    staged.sort_by_key(|(seq, _)| *seq);
    assert_eq!(staged.len(), 6);
    assert!(is_tombstone_packet(&staged[0].1));
    assert!(is_tombstone_packet(&staged[1].1));
    assert!(!is_tombstone_packet(&staged[2].1));
    let history = own.own_history_contacts()?;
    assert!(is_tombstone_packet(&ramflux_protocol::decode_base64url(&history[0])?));
    for packet in &history {
        sibling.receive_own_contact(&ramflux_protocol::decode_base64url(packet)?)?;
    }
    assert_eq!(sibling.account_db()?.friend_link("z-removed")?.state, "removed");
    assert!(sibling.account_db()?.friend_link("zz-blocked")?.blocked);
    // A delayed old acceptance for the removed relationship cannot undo a learned restriction.
    let mut delayed = PREFIX.to_vec();
    let mut link = own.account_db()?.friend_link("z-removed")?;
    link.state = "accepted".into();
    link.capability_revoked_at = None;
    link.remove_scope = None;
    delayed.extend(serde_json::to_vec(&Contact { manifest, link })?);
    sibling.receive_own_contact(&delayed)?;
    assert_eq!(sibling.account_db()?.friend_link("z-removed")?.state, "removed");
    drop((own, sibling, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn missing_peer_manifest_leaves_cursor_retryable_until_authority_arrives() -> TestResult {
    let root = path()?;
    let own = client(&root.join("own"), "bob", 1)?;
    let mut sibling = client(&root.join("sibling"), "bob", 1)?;
    sibling.create_device_branch("bob", "second", 1, [8; 32]);
    let peer = client(&root.join("peer"), "alice", 3)?;
    let manifest = crate::client::identity_authority::test_support::public_manifest(&peer)?;
    own.establish_friend_link(
        "missing",
        own.owned_device_identity()?.root_commitment(),
        &manifest.principal_commitment,
    )?;
    activate(&own, &sibling)?;
    assert_eq!(own.stage_contact_backfill_batch()?, 0);
    assert_eq!(own.stage_contact_backfill_batch()?, 0);
    let before = own
        .account_db()?
        .load_actor_state::<Backfill>("own-contact/backfill")?
        .ok_or("progress")?;
    assert_eq!(before.cursor, "");
    assert!(!before.complete);
    assert_eq!(own.pending_contact_backfill_root()?, Some(manifest.principal_commitment.clone()));
    own.persist_identity_directory(&manifest)?;
    assert_eq!(own.stage_contact_backfill_batch()?, 1);
    assert_eq!(own.stage_contact_backfill_batch()?, 0);
    assert_eq!(own.account_db()?.actor_state_usage("own-device/send/")?.0, 1);
    drop((own, sibling, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn heavy_account_history_pages_preserve_every_contact_and_manifest_within_admission_budgets()
-> TestResult {
    let root = path()?;
    let own = client(&root.join("own"), "bob", 1)?;
    let peer = client(&root.join("peer"), "alice", 3)?;
    let manifest = crate::client::identity_authority::test_support::public_manifest(&peer)?;
    own.persist_identity_directory(&manifest)?;
    for n in 0..513 {
        own.establish_friend_link(
            &format!("link-{n:04}"),
            own.owned_device_identity()?.root_commitment(),
            &manifest.principal_commitment,
        )?;
    }
    let contacts = own.own_history_contacts()?;
    assert_ne!(contacts.len(), 0);
    assert_eq!(contacts.len(), 513);
    let mut pins = Vec::new();
    for n in 0..513 {
        // Public manifest payload remains valid; distinct cache keys exercise root-list admission.
        let name = format!("manifest-{n:04}");
        own.account_db()?
            .persist_actor_state(&format!("identity/manifest-root/{name}"), &manifest)?;
        pins.push(crate::own_device_sync::SdkOwnDeviceGroupMemberPin {
            group_id: "group".into(),
            device_id: format!("member-{n}"),
            signing_public_key: String::new(),
            principal_id: None,
            principal_commitment: Some(name),
        });
    }
    let manifests = own.own_history_device_manifests(&pins)?;
    assert_ne!(manifests.len(), 0);
    assert_eq!(manifests.len(), 513);
    assert!(RamfluxClient::check_own_history_authority_budget(&manifests, &contacts).is_err());
    let history = serde_json::from_value::<crate::own_device_sync::SdkOwnDeviceHistoryBundle>(
        serde_json::json!({
            "schema":"ramflux.sdk.own_device_history_bundle.v1","version":1,
            "principal_commitment":own.owned_device_identity()?.root_commitment(),"source_device_id":"source","target_device_id":"target","snapshot_id":"budget-pages",
            "messages":[],"dm_sessions":[],"groups":[],"sender_key_distributions_base64":[],
            "group_member_pins":pins,"device_manifests":manifests,"accepted_contacts":contacts
        }),
    )?;
    let pages = crate::client::own_device_history_pages::pages(history)?;
    assert_eq!(pages.iter().map(|p| p.accepted_contacts.len()).sum::<usize>(), 513);
    assert_eq!(pages.iter().map(|p| p.device_manifests.len()).sum::<usize>(), 513);
    for page in pages {
        assert!(page.accepted_contacts.len() <= 512);
        assert!(page.device_manifests.len() <= 512);
        RamfluxClient::check_own_history_authority_budget(
            &page.device_manifests,
            &page.accepted_contacts,
        )?;
    }
    drop((own, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn unreachable_contact_manifest_is_throttled_then_parked_without_blocking_later_links() -> TestResult
{
    let root = path()?;
    let own = client(&root.join("own"), "bob", 1)?;
    let mut sibling = client(&root.join("sibling"), "bob", 1)?;
    sibling.create_device_branch("bob", "second", 1, [8; 32]);
    let peer = client(&root.join("peer"), "alice", 3)?;
    let manifest = crate::client::identity_authority::test_support::public_manifest(&peer)?;
    own.persist_identity_directory(&manifest)?;
    own.establish_friend_link(
        "a-unavailable",
        own.owned_device_identity()?.root_commitment(),
        "unavailable-root",
    )?;
    own.establish_friend_link(
        "z-deliverable",
        own.owned_device_identity()?.root_commitment(),
        &manifest.principal_commitment,
    )?;
    activate(&own, &sibling)?;
    own.stage_contact_backfill_batch_at(100)?;
    own.stage_contact_backfill_batch_at(100)?;
    for (at, next) in [(100, 105), (105, 115), (115, 135), (135, 175), (175, 255)] {
        assert_eq!(own.claim_contact_backfill_refresh(at)?, Some("unavailable-root".into()));
        assert_eq!(own.claim_contact_backfill_refresh(at)?, None);
        assert_eq!(own.claim_contact_backfill_refresh(next - 1)?, None);
    }
    assert_eq!(own.stage_contact_backfill_batch_at(175)?, 1);
    assert_eq!(own.claim_contact_backfill_refresh(999)?, None);
    let parked = own.account_db()?.list_actor_states::<serde_json::Value>("own-contact/parked/")?;
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0]["reason"], "manifest_retry_exhausted");
    assert_eq!(parked[0]["attempts"], 5);
    assert_eq!(own.account_db()?.actor_state_usage("own-device/send/")?.0, 1);
    drop((own, sibling, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
