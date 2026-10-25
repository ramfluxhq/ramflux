// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared history projects authenticated sibling records without treating literal names as keys.
use super::*;
use ramflux_protocol::group_state::GroupStateChange;
fn person(
    root: &std::path::Path,
    principal: &str,
    device: &str,
    seed: u8,
    branch: u8,
) -> Result<RamfluxClient, SdkError> {
    let mut client = RamfluxClient::new();
    client.create_identity_root(principal, [seed; 32]);
    client.create_device_branch(principal, device, 1, [branch; 32]);
    client.open_account_index(root)?;
    let actor = client.owned_group_actor(&format!("target-{device}"))?;
    client.create_account("acct", &actor.identity.root_commitment)?;
    client.unlock_account("acct", b"group-history")?;
    Ok(client)
}
#[test]
fn shared_group_history_with_colliding_sender_names_does_not_abort_own_restore()
-> Result<(), SdkError> {
    let root = temp_root("shared-history");
    let owner = person(&root.join("owner"), "owner", "phone", 61, 62)?;
    let peer = person(&root.join("peer"), "peer", "phone", 71, 72)?;
    let sibling = person(&root.join("sibling"), "owner", "laptop", 61, 82)?;
    let mut own = crate::client::identity_authority::test_support::public_manifest(&owner)?;
    own.devices.extend(
        crate::client::identity_authority::test_support::public_manifest(&sibling)?.devices,
    );
    crate::client::identity_authority::test_support::sign_manifest(
        owner.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut own,
        2,
    )?;
    let remote = crate::client::identity_authority::test_support::public_manifest(&peer)?;
    for client in [&owner, &peer, &sibling] {
        client.persist_identity_directory(&own)?;
        client.persist_identity_directory(&remote)?;
    }
    owner.shared_group_create("group", "thread", Some("Signed name".into()), "target-phone")?;
    owner.shared_group_change(
        "group",
        "target-phone",
        GroupStateChange::Add {
            member: peer.owned_group_actor("target-phone")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let encrypted = owner.encrypt_group_message("group", "phone", b"historical group message")?;
    owner.send_direct_message("thread", "history-message", "phone", &encrypted)?;
    let bundle = owner.own_device_history_bundle(
        &own.principal_commitment,
        "phone",
        "laptop",
        "snapshot",
    )?;
    let mut transport = envelope("phone", "laptop");
    transport.principal_commitment = own.principal_commitment.clone();
    transport.snapshot_id = "snapshot".into();
    let imported = sibling.import_own_device_history_bundle(&transport, &bundle)?;
    assert_eq!(imported.imported_messages, 1);
    assert_eq!(sibling.direct_messages("thread")?.len(), 1);
    assert_eq!(sibling.group_state("group")?.group_epoch, 2);
    assert_eq!(
        sibling
            .account_db()?
            .client_record("conversation", "thread")?
            .ok_or(StorageError::GroupPermissionDenied)?["title"],
        "Signed name"
    );
    drop((owner, peer, sibling));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
