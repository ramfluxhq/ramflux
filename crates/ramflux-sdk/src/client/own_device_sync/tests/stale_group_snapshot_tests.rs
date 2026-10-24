// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Old same-root snapshots cannot undo membership removals or revive their pins.
use super::*;
fn setup(
    name: &str,
) -> Result<(RamfluxClient, PathBuf, RamfluxClient, PathBuf, SdkOwnDeviceHistoryBundle), SdkError> {
    let (source, sr) =
        client_with_account(&format!("{name}-source"), "principal_sync", "source_device_sync")?;
    let (mut target, tr) =
        client_with_account(&format!("{name}-target"), "principal_sync", "target_device_sync")?;
    target.create_device_branch("principal_sync", "target_device_sync", 1, [0x53; 32]);
    source.create_group("g", "source_device_sync")?;
    source.account_db()?.persist_client_record("device","bob",&serde_json::json!({"principal_id":"bob","principal_commitment":"bob-root","signing_public_key":ramflux_protocol::encode_base64url(ramflux_crypto::create_device_branch("bob","bob",1,[0x63;32]).signing_key.verifying_key().to_bytes())}))?;
    let record = source
        .account_db()?
        .client_record("device", "bob")?
        .ok_or(SdkError::IdentityRootMissing)?;
    target.account_db()?.persist_client_record("device", "bob", &record)?;
    source.add_group_member("g", "bob", "member")?;
    let history = source.own_device_history_bundle(
        "principal_sync",
        "source_device_sync",
        "target_device_sync",
        "snapshot_sync",
    )?;
    Ok((source, sr, target, tr, history))
}
fn finish(
    source: RamfluxClient,
    sr: PathBuf,
    target: RamfluxClient,
    tr: PathBuf,
) -> Result<(), SdkError> {
    drop(source);
    drop(target);
    std::fs::remove_dir_all(sr)?;
    std::fs::remove_dir_all(tr)?;
    Ok(())
}
#[test]
fn stale_snapshot_preserves_removed_members_and_inactive_pins_after_reopen() -> Result<(), SdkError>
{
    let (source, sr, mut target, tr, history) = setup("stale-member")?;
    target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    let (mut bob, bob_root) = client_with_account("stale-member-bob", "bob", "bob")?;
    bob.create_device_branch("bob", "bob", 1, [0x63; 32]);
    bob.create_group("g", "bob")?;
    bob.add_group_member("g", "source_device_sync", "member")?;
    target.import_group_sender_key_distribution(
        &bob.export_group_sender_key_distribution("g", "bob")?,
    )?;
    let before = member_packet(&bob, "before-removal", &bob_root)?;
    assert!(matches!(
        target.append_group_gateway_delivery_for_recipient(
            "g",
            "g",
            "before-removal",
            &before,
            "target_device_sync"
        )?,
        GroupGatewayDeliveryResult::Message(_)
    ));
    let db = target.account_db()?;
    db.remove_group_member("g", "target_device_sync", "bob")?;
    let epoch = target.group_state("g")?.group_epoch;
    let key = db.group_member_device_key("g", "bob")?.ok_or(SdkError::IdentityRootMissing)?;
    drop(target.active_account_db.take());
    target.unlock_account("acct", b"own-device-sync-test")?;
    target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert_eq!(target.group_state("g")?.group_epoch, epoch);
    assert!(target.account_db()?.group_member_role("g", "bob")?.is_none());
    assert!(target.account_db()?.group_member_key_binding("g", "bob")?.is_none());
    assert_eq!(target.account_db()?.group_member_device_key("g", "bob")?, Some(key));
    assert!(target.require_group_sender_pin("g", "bob", "bob").is_err());
    let after = member_packet(&bob, "after-removal", &bob_root)?;
    assert!(target.authenticated_envelope_sender(&after).is_ok());
    assert!(
        target
            .append_group_gateway_delivery_for_recipient(
                "g",
                "g",
                "after-removal",
                &after,
                "target_device_sync"
            )
            .is_err()
    );
    assert!(target.direct_message_by_id("after-removal")?.is_none());
    drop(bob);
    std::fs::remove_dir_all(bob_root)?;

    assert_ne!(
        target.account_db()?.list_actor_states::<serde_json::Value>("own-device/restore-skip/")?,
        Vec::<serde_json::Value>::new()
    );
    finish(source, sr, target, tr)
}
#[test]
fn highest_snapshot_epoch_wins_for_an_unseen_group_regardless_of_bundle_order()
-> Result<(), SdkError> {
    for reverse in [false, true] {
        let (source, sr, target, tr, mut history) = setup(&format!("unseen-{reverse}"))?;
        let mut newest = history.groups[0].clone();
        newest.group_epoch += 2;
        newest.members.retain(|m| m.member_id != "bob");
        history.groups.push(newest);
        if reverse {
            history.groups.reverse();
        }
        target.import_own_device_history_bundle(
            &envelope("source_device_sync", "target_device_sync"),
            &history,
        )?;
        assert_eq!(target.group_state("g")?.group_epoch, 4);
        assert!(target.account_db()?.group_member_role("g", "bob")?.is_none());
        assert!(target.account_db()?.group_member_key_binding("g", "bob")?.is_none());
        finish(source, sr, target, tr)?;
    }
    Ok(())
}
#[test]
fn a_newer_snapshot_omission_retires_members_before_an_older_snapshot_can_reintroduce_them()
-> Result<(), SdkError> {
    let (source, sr, target, tr, history) = setup("newer-omission")?;
    target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    let mut newer = history.clone();
    newer.groups[0].group_epoch = 3;
    newer.groups[0].members.retain(|m| m.member_id != "bob");
    target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &newer,
    )?;
    target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert!(target.account_db()?.group_member_role("g", "bob")?.is_none());
    assert!(target.account_db()?.group_member_key_binding("g", "bob")?.is_none());
    finish(source, sr, target, tr)
}
#[test]
fn snapshot_import_cannot_reactivate_a_removed_local_device() -> Result<(), SdkError> {
    let (source, sr, target, tr, history) = setup("removed-local")?;
    let db = target.account_db()?;
    db.upsert_group_local_membership_snapshot(
        "g",
        2,
        128,
        "none",
        "target_device_sync",
        "member",
        1,
    )?;
    db.upsert_group_member_snapshot("g", "source_device_sync", "owner", 1)?;
    db.remove_group_member("g", "source_device_sync", "target_device_sync")?;
    target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert!(db.group_member_role("g", "target_device_sync")?.is_none());
    assert!(db.group_member_key_binding("g", "target_device_sync")?.is_none());
    assert_eq!(target.group_state("g")?.group_epoch, 3);
    finish(source, sr, target, tr)
}
#[test]
fn a_distribution_for_a_member_omitted_from_the_snapshot_is_skipped_without_losing_direct_history()
-> Result<(), SdkError> {
    let (source, sr, target, tr, mut history) = setup("orphan-distribution")?;
    let valid = history.sender_key_distributions_base64[0].clone();
    let mut distribution: SdkGroupSenderKeyDistribution = serde_json::from_slice(
        &ramflux_protocol::decode_base64url(&valid).map_err(|_| SdkError::IdentityRootMissing)?,
    )?;
    distribution.sender_id = "missing-member".into();
    history
        .sender_key_distributions_base64
        .insert(0, ramflux_protocol::encode_base64url(serde_json::to_vec(&distribution)?));
    source.send_direct_message("dm", "ordinary", "source_device_sync", b"ordinary")?;
    history.messages = source.direct_messages("dm")?;
    let result = target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert_eq!(result.imported_sender_keys, 1);
    assert_eq!(result.imported_messages, 1);
    assert!(target.direct_message_by_id("ordinary")?.is_some());
    let skipped =
        target.account_db()?.list_actor_states::<serde_json::Value>("own-device/restore-skip/")?;
    assert!(skipped.iter().any(|row| row["reason"] == "distribution_member_unavailable"));
    finish(source, sr, target, tr)
}

#[test]
fn equal_epoch_conflicting_snapshots_fail_closed_for_an_unseen_group() -> Result<(), SdkError> {
    let (source, sr, target, tr, mut history) = setup("same-epoch-conflict")?;
    let mut conflicting = history.groups[0].clone();
    conflicting.members.retain(|m| m.member_id != "bob");
    history.groups.push(conflicting);
    target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert!(target.group_state("g").is_err());
    assert!(
        target
            .account_db()?
            .list_actor_states::<serde_json::Value>("own-device/restore-skip/")?
            .iter()
            .any(|row| row["reason"] == "conflicting_group_snapshot")
    );
    finish(source, sr, target, tr)
}
#[test]
fn a_member_joined_after_the_snapshot_epoch_is_not_activated_or_pinned() -> Result<(), SdkError> {
    let (source, sr, target, tr, mut history) = setup("future-member")?;
    history.groups[0]
        .members
        .iter_mut()
        .find(|m| m.member_id == "bob")
        .ok_or(SdkError::IdentityRootMissing)?
        .joined_epoch = 3;
    target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert!(target.account_db()?.group_member_role("g", "bob")?.is_none());
    assert!(target.account_db()?.group_member_key_binding("g", "bob")?.is_none());
    finish(source, sr, target, tr)
}
#[test]
fn equal_epoch_snapshot_does_not_lower_the_existing_local_join_floor_or_raise_its_role()
-> Result<(), SdkError> {
    let (source, sr, target, tr, mut history) = setup("join-floor")?;
    history.groups[0].group_epoch = 5;
    target.account_db()?.upsert_group_local_membership_snapshot(
        "g",
        5,
        128,
        "none",
        "target_device_sync",
        "member",
        5,
    )?;
    target.import_own_device_history_bundle(
        &envelope("source_device_sync", "target_device_sync"),
        &history,
    )?;
    assert_eq!(target.account_db()?.group_member_joined_epoch("g", "target_device_sync")?, Some(5));
    assert_eq!(
        target.account_db()?.group_member_role("g", "target_device_sync")?.as_deref(),
        Some("member")
    );
    finish(source, sr, target, tr)
}

fn member_packet(
    bob: &RamfluxClient,
    id: &str,
    root: &Path,
) -> Result<GatewayInboxEntry, SdkError> {
    let branch = bob.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let config = GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|e| SdkError::LocalBus(format!("{e}")))?,
        gateway_addr: "127.0.0.1:1".parse().map_err(|e| SdkError::LocalBus(format!("{e}")))?,
        server_name: "test".into(),
        ca_cert: root.join("ca.pem"),
        principal_id: "bob".into(),
        device_id: "bob".into(),
        target_delivery_id: "target_device_sync".into(),
        prekey_http_url: None,
    })
    .with_device_branch(branch.clone());
    let message = GatewayDirectMessage {
        conversation_id: "g".into(),
        message_id: id.into(),
        envelope_id: id.into(),
        source_principal_id: "bob".into(),
        sender_id: "bob".into(),
        recipient_device_id: Some("target_device_sync".into()),
        target_delivery_id: "target_device_sync".into(),
        encrypted_body: bob.encrypt_group_message("g", "bob", b"removed member message")?,
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    Ok(GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: "target_device_sync".into(),
        envelope: crate::dm::gateway_direct_message_envelope(&config, &message, None)?,
    })
}
