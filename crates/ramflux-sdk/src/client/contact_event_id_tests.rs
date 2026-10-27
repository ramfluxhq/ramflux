// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Repeated consent decisions have distinct journal identities; immutable replays remain no-ops.
use super::tests::unlocked_client;
use super::*;

fn checkpoint(client: &RamfluxClient, name: &str) -> Result<String, SdkError> {
    client
        .projection_checkpoint(name)?
        .ok_or_else(|| SdkError::LocalBus("checkpoint missing".into()))
}
fn event_count(client: &RamfluxClient) -> Result<usize, SdkError> {
    Ok(client
        .account_db()?
        .export_history_bundle("device_contact", "receiver")?
        .encrypted_event_batch
        .len())
}

#[test]
fn same_second_blocks_and_unblocks_have_distinct_decision_event_ids() -> Result<(), SdkError> {
    let (client, root) = unlocked_client("decision-same-second")?;
    client.establish_friend_link("link", "principal_contact", "peer")?;
    let first = client.block_friend_link_at("link", 1000)?;
    let first_id = checkpoint(&client, "friend.control")?;
    client.unblock_friend_link_at("link", 1000)?;
    let lift_id = checkpoint(&client, "friend.control")?;
    let second = client.block_friend_link_at("link", 1000)?;
    let second_id = checkpoint(&client, "friend.control")?;
    assert_eq!(first.capability_revoked_at, second.capability_revoked_at);
    assert_eq!(client.event_body(&first_id)?, client.event_body(&second_id)?);
    assert_ne!(first_id, second_id, "identical state in a later decision is not a replay");
    client.unblock_friend_link_at("link", 1000)?;
    let second_lift = checkpoint(&client, "friend.control")?;
    assert_ne!(lift_id, second_lift);
    assert_eq!(client.event_body(&lift_id)?, client.event_body(&second_lift)?);
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn later_second_reblock_does_not_conflict() -> Result<(), SdkError> {
    let (client, root) = unlocked_client("decision-later-second")?;
    client.establish_friend_link("link", "principal_contact", "peer")?;
    client.block_friend_link_at("link", 1000)?;
    let old_id = checkpoint(&client, "friend.control")?;
    client.unblock_friend_link_at("link", 1001)?;
    let blocked = client.block_friend_link_at("link", 1002)?;
    assert!(blocked.blocked);
    assert_eq!(blocked.capability_revoked_at, Some(1002));
    assert_ne!(old_id, checkpoint(&client, "friend.control")?);
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn removal_scope_cycles_in_one_consent_epoch_have_distinct_ids() -> Result<(), SdkError> {
    let (client, root) = unlocked_client("decision-remove-cycle")?;
    client.establish_friend_link("link", "principal_contact", "peer")?;
    client.remove_friend_link_at("link", "me", 1000)?;
    let first = checkpoint(&client, "friend.control")?;
    client.remove_friend_link_at("link", "both", 1000)?;
    let middle = checkpoint(&client, "friend.control")?;
    let removed = client.remove_friend_link_at("link", "me", 1000)?;
    let last = checkpoint(&client, "friend.control")?;
    assert_eq!(client.event_body(&first)?, client.event_body(&last)?);
    assert_ne!(first, middle);
    assert_ne!(first, last);
    let count = event_count(&client)?;
    client.append_contact_control_event("friend.removed", &removed)?;
    assert_eq!(checkpoint(&client, "friend.control")?, last);
    assert_eq!(event_count(&client)?, count);
    client.unblock_friend_link_at("link", 1001)?;
    client.remove_friend_link_at("link", "me", 1002)?;
    assert_ne!(checkpoint(&client, "friend.control")?, last);
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn sibling_reblock_after_local_lift_and_duplicate_tombstone_are_safe() -> Result<(), SdkError> {
    let (client, root) = unlocked_client("decision-sibling")?;
    let own = client.owned_device_identity()?.root_commitment().to_owned();
    let peer = ramflux_protocol::encode_base64url([0x33; 32]);
    client.establish_friend_link("link", &own, &peer)?;
    let mut sibling_block = client.block_friend_link_at("link", 1000)?;
    let old = checkpoint(&client, "friend.control")?;
    client.unblock_friend_link_at("link", 1001)?;
    sibling_block.capability_revoked_at = Some(2000);
    let mut packet = b"ramflux.own_contact_tombstone.v1\n".to_vec();
    packet.extend(serde_json::to_vec(&serde_json::json!({"link":sibling_block}))?);
    assert!(client.receive_own_contact(&packet)?);
    assert!(client.account_db()?.friend_link("link")?.blocked);
    let fresh = checkpoint(&client, "friend.control")?;
    assert_ne!(fresh, old);
    let count = event_count(&client)?;
    assert!(client.receive_own_contact(&packet)?);
    assert_eq!(checkpoint(&client, "friend.control")?, fresh);
    assert_eq!(event_count(&client)?, count, "same sibling decision must remain a no-op");
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn legacy_rows_and_new_decision_replays_survive_reopen() -> Result<(), SdkError> {
    let (mut client, root) = unlocked_client("decision-legacy-reopen")?;
    let legacy = b"{\"type\":\"friend.blocked\",\"link_id\":\"link\",\"legacy\":true}";
    client.append_event("friend.blocked:link", "friend.blocked", legacy)?;
    client.establish_friend_link("link", "principal_contact", "peer")?;
    let blocked = client.block_friend_link_at("link", 1000)?;
    let first_id = checkpoint(&client, "friend.control")?;
    let first_body =
        client.event_body(&first_id)?.ok_or_else(|| SdkError::LocalBus("event missing".into()))?;
    client.unblock_friend_link_at("link", 1001)?;
    let final_link = client.block_friend_link_at("link", 1002)?;
    let final_id = checkpoint(&client, "friend.control")?;
    let count = event_count(&client)?;
    // Replaying an older immutable decision must not append or roll back the current projection.
    client.append_event(&first_id, "friend.blocked", &first_body)?;
    assert_eq!(event_count(&client)?, count);
    assert_eq!(checkpoint(&client, "friend.control")?, final_id);
    assert_eq!(client.account_db()?.friend_link("link")?.capability_revoked_at, Some(1002));
    assert!(blocked.blocked);
    client.unlock_account("acct", b"contact-reject-test")?;
    client.append_contact_control_event("friend.blocked", &final_link)?;
    assert_eq!(checkpoint(&client, "friend.control")?, final_id);
    assert_eq!(event_count(&client)?, count);
    assert_eq!(client.event_body("friend.blocked:link")?, Some(legacy.to_vec()));
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn a_new_decline_preserves_legacy_rows_and_its_replay_is_idempotent() -> Result<(), SdkError> {
    let (client, root) = unlocked_client("decision-decline")?;
    let legacy = b"{\"type\":\"friend.rejected\",\"legacy\":true}";
    client.append_event("friend.rejected:pending", "friend.rejected", legacy)?;
    client.record_pending_friend_link("pending", "peer", "principal_contact")?;
    let declined = client.reject_friend_link("pending")?;
    assert_eq!(declined.state, "rejected");
    let id = checkpoint(&client, "friend.control")?;
    assert_ne!(id, "friend.rejected:pending");
    let count = event_count(&client)?;
    client.append_contact_control_event("friend.rejected", &declined)?;
    assert_eq!(checkpoint(&client, "friend.control")?, id);
    assert_eq!(event_count(&client)?, count);
    assert_eq!(client.event_body("friend.rejected:pending")?, Some(legacy.to_vec()));
    assert!(client.reject_friend_link("pending").is_err(), "closed decline remains closed");
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn regranted_object_revocations_use_their_own_decision_identity() -> Result<(), SdkError> {
    let (client, root) = unlocked_client("decision-regrant")?;
    client.establish_friend_link("link", "principal_contact", "peer")?;
    let mut ids = Vec::new();
    for at in [1000, 1000, 1002] {
        client.account_db()?.record_object_share_grant(&ObjectShareGrantWrite {
            object_id: "shared",
            recipient_principal_id: "peer",
            recipient_principal_commitment: None,
            recipient_device_id: None,
            conversation_id: None,
            shared_at: 999,
        })?;
        client.block_friend_link_at("link", at)?;
        let id = checkpoint(&client, "object.revoke_access")?;
        assert!(!ids.contains(&id), "each revocation decision must have its own journal event");
        ids.push(id);
        client.unblock_friend_link_at("link", at)?;
    }
    assert_eq!(client.event_body(&ids[0])?, client.event_body(&ids[1])?);
    assert_ne!(client.event_body(&ids[1])?, client.event_body(&ids[2])?);
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn equal_stamps_and_payloads_from_distinct_device_signers_have_distinct_ids() -> Result<(), SdkError>
{
    let (mut client, root) = unlocked_client("decision-device-namespace")?;
    client.establish_friend_link("link", "principal_contact", "peer")?;
    let blocked = client.block_friend_link_at("link", 1000)?;
    let first_id = checkpoint(&client, "friend.control")?;
    let first_body =
        client.event_body(&first_id)?.ok_or_else(|| SdkError::LocalBus("event missing".into()))?;
    let stamp = client.account_db()?.friend_link_consent_stamp("link")?;
    // Reopen the same decision snapshot under another signer, as on a restored sibling.
    client.create_device_branch("principal_contact", "second-device", 1, [0x71; 32]);
    client.unlock_account("acct", b"contact-reject-test")?;
    client.append_contact_control_event("friend.blocked", &blocked)?;
    let second_id = checkpoint(&client, "friend.control")?;
    assert_eq!(client.account_db()?.friend_link_consent_stamp("link")?, stamp);
    assert_eq!(client.event_body(&second_id)?, Some(first_body));
    assert_ne!(first_id, second_id, "distinct device decisions must not collide at equal stamps");
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
