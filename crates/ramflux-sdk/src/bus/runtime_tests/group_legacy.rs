// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy compatibility receive quarantines one bad entry and still delivers the next.
use super::*;
#[tokio::test(flavor = "current_thread")]
async fn a_rejected_legacy_group_entry_does_not_block_read_or_receive_of_valid_messages()
-> Result<(), SdkError> {
    let (root, sender, mut receiver, good) = legacy_group_fixture()?;
    let mut bad = good.clone();
    bad.inbox_seq = 1;
    bad.envelope.envelope_id = "bad".into();
    bad.envelope.signed.signature = "invalid".into();
    for entry in [&bad, &good] {
        receiver.client.account_db()?.hold_unrouted(
            &crate::client::routed::committed_key(entry)?,
            entry.inbox_seq,
            &serde_json::to_vec(entry)?,
            now_unix_timestamp(),
        )?;
    }
    for method in ["group.receive", "group.read"] {
        let request = LocalBusFrame::request(
            method,
            Some("bob".into()),
            "group",
            method,
            serde_json::json!({"group_id":"g","conversation_id":"thread","limit":32}),
        );
        crate::bus::dispatch::group::dispatch_group_receive_request(&request, &mut receiver)
            .await?;
    }
    assert!(receiver.client.direct_message_by_id("bad")?.is_none());
    assert!(
        receiver.client.direct_message_by_id("valid")?.is_some(),
        "messages {:?}, journal {}",
        receiver
            .client
            .direct_messages("thread")?
            .iter()
            .map(|m| &m.message_id)
            .collect::<Vec<_>>(),
        serde_json::to_string(&receiver.client.account_db()?.journal_after(0, 128)?)?
    );
    assert_eq!(receiver.client.account_db()?.unrouted_entries()?, Vec::<Vec<u8>>::new());
    let journal = serde_json::to_string(&receiver.client.account_db()?.journal_after(0, 128)?)?;
    assert!(journal.contains("legacy_group_rejected"));
    assert!(!journal.contains("valid after rejected"));
    drop(sender);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn legacy_group_fixture()
-> Result<(PathBuf, LocalBusAccountState, LocalBusAccountState, GatewayInboxEntry), SdkError> {
    let root = root("legacy-group-page");
    let mut sender =
        account(&root.join("sender"), "alice", None, Arc::new(AtomicBool::new(false)))?;
    let receiver = account(&root.join("receiver"), "bob", None, Arc::new(AtomicBool::new(false)))?;
    sender.client.create_identity_root("alice", [0x71; 32]);
    sender.client.create_device_branch("alice", "device-alice", 1, [0x72; 32]);
    sender.client.initialize_and_publish_prekey_bundle(
        "alice",
        "device-alice",
        "target",
        [0x72; 32],
        None,
    )?;
    let d = sender.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let master = sender.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let commitment = crate::identity_root_public_key_commitment(
        &ramflux_protocol::encode_base64url(master.signing_key.verifying_key().to_bytes()),
    )?;
    receiver.client.account_db()?.persist_client_record("device","device-alice",&serde_json::json!({"principal_id":"alice","principal_commitment":commitment,"x25519_identity_public":sender.client.load_x3dh_private_state("device-alice")?.bundle.identity_key,"signing_public_key":ramflux_protocol::encode_base64url(d.signing_key.verifying_key().to_bytes())}))?;
    sender.client.create_group("g", "device-alice")?;
    sender.client.add_group_member("g", "device-bob", "member")?;
    receiver.client.create_group("g", "device-bob")?;
    receiver.client.add_group_member("g", "device-alice", "member")?;
    receiver.client.import_group_sender_key_distribution(
        &sender.client.export_group_sender_key_distribution("g", "device-alice")?,
    )?;
    receiver.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &serde_json::json!({"kind":"group","group_id":"g"}),
    )?;
    let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(
        &root.join("sender"),
        "alice",
    ))?;
    let config = GatewaySessionConfig::quic(manifest.gateway).with_device_branch(d.clone());
    let encrypted =
        sender.client.encrypt_group_message("g", "device-alice", b"valid after rejected")?;
    let message = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "valid".into(),
        envelope_id: "valid".into(),
        source_principal_id: "alice".into(),
        sender_id: "device-alice".into(),
        recipient_device_id: Some("device-bob".into()),
        target_delivery_id: "target".into(),
        encrypted_body: encrypted,
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let good = GatewayInboxEntry {
        inbox_seq: 2,
        target_delivery_id: "target".into(),
        envelope: crate::dm::gateway_direct_message_envelope(&config, &message, None)?,
    };
    receiver.client.authenticated_envelope_sender(&good)?;
    receiver.client.require_group_sender_pin("g", "alice", "device-alice")?;
    assert!(receiver.client.legacy_group_binding("thread", "g", &good)?);
    Ok((root, sender, receiver, good))
}
