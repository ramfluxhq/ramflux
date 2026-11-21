// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! F1: two born-v3 accounts, contact cards, DM A→B, exact text, ACK visible to A.
#![cfg(all(any(unix, windows), feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    assert_texts_once_in_order, boot_stack, configure_node, create_account, dm_ack,
    dm_receipt_delivered, dm_send, dump_logs, envelope_id_from_read, exchange_contacts,
    inbox_seq_from_read, start_daemon, unique, wait_dm_receipt, wait_dm_texts,
    wait_node_observed_ack,
};

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn f1_two_accounts_contact_dm_receive_ack() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = e2e::dm_conversation(&alice, &bob)?;
    let message = unique("msg");
    let body = "hello from Alice over the real wire";
    let sent = dm_send(&alice_d, &alice, &bob, &conversation, &message, body)?;
    let received = wait_dm_texts(&bob_d, &bob, &conversation, &[body])?;
    assert_texts_once_in_order(&received, &[body])?;
    let envelope = envelope_id_from_read(&sent).ok_or_else(|| {
        format!("receive JSON missing wire envelope_id; sent={sent} received={received}")
    })?;
    wait_node_observed_ack(&stack, &bob, &envelope).map_err(|error| {
        format!(
            "node ACK for envelope {envelope} missing after receive: {error}; logs={}",
            dump_logs(&stack, &[&alice_d, &bob_d])
        )
    })?;
    let inbox_seq = inbox_seq_from_read(&sent, &envelope).ok_or_else(|| {
        format!("receive JSON missing inbox_seq for {envelope}; received={received}")
    })?;
    // Default-on Push installs the receive ledger, so public `message.ack` /
    // `rf dm ack` is refused with receive_ledger_managed_ack (P25). The node
    // ACK is the engine ack_batch from live intake (wait_node_observed_ack).
    match dm_ack(&bob_d, &bob, &conversation, &envelope, Some(inbox_seq)) {
        Ok(_) => {}
        Err(error) if error.to_string().contains("receive_ledger_managed_ack") => {}
        Err(error) => {
            return Err(format!(
                "dm_ack envelope={envelope} message={message} received={received} error={error} logs={}",
                dump_logs(&stack, &[&alice_d, &bob_d])
            )
            .into());
        }
    }
    let logical = sent["message_id"].as_str().ok_or("sender canonical message identity missing")?;
    let receipt = dm_receipt_delivered(&bob_d, &bob, &conversation, logical).map_err(|error| {
        format!(
            "receipt delivered failed: {error}; logs={}",
            dump_logs(&stack, &[&alice_d, &bob_d])
        )
    })?;
    if receipt.get("ok").and_then(serde_json::Value::as_bool) == Some(false) {
        return Err(format!("B receipt delivered was refused: {receipt}").into());
    }
    wait_dm_receipt(&alice_d, &alice, &conversation, logical, &bob)
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;
    // Reopen the receiving store and read the same body back. Linux already covers this
    // through the restart jobs; the Windows acceptance requires it in this test.
    #[cfg(windows)]
    {
        let (socket, data_root) = e2e::shutdown_daemon(bob_d)?;
        let bob_again = e2e::start_daemon_at(socket, data_root)?;
        e2e::unlock_account_without_wait(&bob_again, &bob)?;
        let persisted = wait_dm_texts(&bob_again, &bob, &conversation, &[body])?;
        assert_texts_once_in_order(&persisted, &[body])?;
    }
    Ok(())
}

#[ignore = "real-process Demo B B1 single-node: CLI e2e CI job"]
#[test]
fn b1_same_node_bidirectional_dm_uses_deliver_without_resume() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = e2e::dm_conversation(&alice, &bob)?;
    for (sender_d, sender, recipient_d, recipient, body) in [
        (&alice_d, &alice, &bob_d, &bob, "B1 Alice to Bob"),
        (&bob_d, &bob, &alice_d, &alice, "B1 Bob to Alice"),
    ] {
        let before = e2e::wait_receive_settled(recipient_d, recipient)?;
        let ids = [unique("b1-first"), unique("b1-second")];
        let sent = ids
            .iter()
            .map(|id| dm_send(sender_d, sender, recipient, &conversation, id, body))
            .collect::<e2e::Result<Vec<_>>>()?;
        let logical = sent
            .iter()
            .map(|entry| entry["message_id"].as_str().ok_or("canonical sender identity missing"))
            .collect::<Result<Vec<_>, _>>()?;
        for id in &ids {
            wait_node_observed_ack(&stack, recipient, id)?;
        }
        let after = e2e::wait_receive_settled(recipient_d, recipient)?;
        assert!(
            e2e::receive_counter(&after, "deliver_frames")?
                > e2e::receive_counter(&before, "deliver_frames")?,
            "B1 must receive Deliver frames: before={before} after={after}"
        );
        for counter in ["resume_requests", "page_fetches", "catch_up_passes"] {
            assert_eq!(after[counter], before[counter], "B1 {counter}: {before} -> {after}");
        }
        wait_dm_texts(recipient_d, recipient, &conversation, &[body, body])?;
        for owner in [(sender_d, sender), (recipient_d, recipient)] {
            let view = e2e::rf_json(
                &owner.0.socket,
                &["dm", "read", "--account", &owner.1.id, "--conversation", &conversation],
            )?;
            for id in &logical {
                let rows =
                    view["messages"].as_array().ok_or("canonical message projection missing")?;
                let count = rows
                    .iter()
                    .filter(|row| {
                        row["message_id"].as_str().or_else(|| row["id"].as_str()) == Some(*id)
                    })
                    .count();
                assert_eq!(
                    count, 1,
                    "logical message id {id} must occur once in account {} canonical projection",
                    owner.1.id
                );
            }
        }
        let [first_sent, second_sent] = sent.as_slice() else {
            return Err("two sender transport entries required".into());
        };
        let [first_id, second_id] = ids.as_slice() else {
            return Err("two envelope IDs required".into());
        };
        let first = inbox_seq_from_read(first_sent, first_id)
            .ok_or("first node-assigned inbox sequence missing from submit result")?;
        let second = inbox_seq_from_read(second_sent, second_id)
            .ok_or("second node-assigned inbox sequence missing from submit result")?;
        // Background contact-control envelopes may legitimately interleave between two sends
        // (each new send authorization now waits for a fresh authority fetch); the two message
        // deliveries must still arrive in order, with no resume or page fetch (asserted above).
        assert!(second > first, "B1 Deliver sequences must increase: {first} -> {second}");
        assert!(
            e2e::receive_counter(&after, "last_acked_seq")?
                <= e2e::receive_counter(&after, "committed_cursor")?,
            "{after}"
        );
        eprintln!("B1 recipient={} before={before} after={after}", recipient.id);
    }
    Ok(())
}

#[ignore = "two-node harness calibration for the controller's post-demo federation module; CLI e2e CI job"]
#[test]
fn two_nodes_have_separate_identities_cas_and_stores() -> e2e::Result<()> {
    let a = e2e::boot_node("node-a", true)?;
    let b = e2e::boot_node("node-b", false)?;
    assert_ne!(a.node_id, b.node_id);
    assert_ne!(a.root, b.root);
    assert_ne!(a.admin_url, b.admin_url);
    for path in ["secrets/node-signing.key", "certs/ca.pem"] {
        assert_ne!(std::fs::read(a.root.join(path))?, std::fs::read(b.root.join(path))?);
    }
    for node in [&a, &b] {
        for service in ["ramflux-router", "ramflux-gateway"] {
            assert!(node.root.join("state").join(format!("{service}.redb")).is_file());
        }
    }
    Ok(())
}

fn pause() {
    std::thread::sleep(std::time::Duration::from_millis(10));
}

fn write_broken_package(path: &std::path::Path, object_id: &str) -> e2e::Result<()> {
    let package = ramflux_sdk::SdkObjectSharePackage {
        schema: "ramflux.sdk.object_share_package.v1".to_owned(),
        version: 1,
        object: ramflux_sync::EncryptedObject {
            object_id: object_id.to_owned(),
            manifest_hash: "not-the-retained-manifest".to_owned(),
            nonce: "nonce".to_owned(),
            ciphertext: Vec::new(),
            plaintext_hash: "plain".to_owned(),
            tombstoned: false,
            backup_excluded: false,
        },
        ciphertext_base64: "!!!!".to_owned(),
        key_slot: ramflux_sdk::SdkObjectKeySlot {
            schema: "slot".to_owned(),
            version: 1,
            object_id: object_id.to_owned(),
            conversation_id: "thread".to_owned(),
            recipient_device_id: "device".to_owned(),
            source_principal_commitment: None,
            x3dh: None,
            ciphertext: ramflux_crypto::DmCiphertext {
                session_id: String::new(),
                counter: 0,
                nonce: [0; 12],
                ciphertext: Vec::new(),
                ratchet_public_key: None,
                previous_chain_length: 0,
                sender_device_id_hash: [0; 32],
                recipient_device_id_hash: [0; 32],
                device_epoch: 0,
                message_event_id: String::new(),
                canonical_header_bytes: Vec::new(),
                header_hash: String::new(),
                key_commitment: String::new(),
                franking_commitment: String::new(),
                commitment: String::new(),
                ciphertext_hash: String::new(),
            },
        },
    };
    std::fs::write(path, serde_json::to_vec(&package)?)?;
    Ok(())
}

fn import_output(
    daemon: &e2e::Daemon,
    account: &str,
    package: &str,
) -> e2e::Result<std::process::Output> {
    e2e::rf_output(&daemon.socket, &["object", "import", "--account", account, package])
        .map_err(|error| format!("object import failed to spawn: {error}").into())
}

fn logged(
    error: impl std::fmt::Display,
    stack: &e2e::Stack,
    daemons: &[&e2e::Daemon],
) -> Box<dyn std::error::Error> {
    format!("{error}; logs={}", dump_logs(stack, daemons)).into()
}

/// A fresh CLI account has no endorsed layer-4 declaration, so `rf dm send --media-ref`
/// refuses r4 media. These are the rows `record_received_media_objects` would have written.
fn install_received_reference(
    alice_root: &std::path::Path,
    bob_root: &std::path::Path,
    alice: &e2e::Account,
    bob: &e2e::Account,
    conversation: &str,
) -> e2e::Result<()> {
    use ramflux_storage::VaultSecretSource as _;
    const OBJECT_ID: &str = "demo-b-b4-object";
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    // A layer install may still be in flight on a slow host; PublicationPending is the typed
    // retryable refusal, so retry only that within a bounded deadline.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let authority = loop {
        match ramflux_sdk::custody::load_account(alice_root, &alice.id, now) {
            Ok(authority) => break authority,
            Err(error)
                if format!("{error:?}").contains("PublicationPending")
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(error) => return Err(error.into()),
        }
    };
    let body = &authority.record().body;
    let device = body
        .devices
        .iter()
        .find(|row| row.device_id == alice.device_id)
        .ok_or("alice device is missing from the custody record")?;
    let author = ramflux_protocol::message::QualifiedDevice {
        account_anchor: body.account_anchor.clone(),
        device_id: device.device_id.clone(),
        device_epoch: device.device_epoch,
    };
    let id = ramflux_protocol::message::identity::derive(&author, conversation, 1)?;
    let identity = ramflux_protocol::message::EventIdentity {
        id: id.to_vec(),
        conversation_id: conversation.to_owned(),
        author: Some(author),
        device_sequence: 1,
        hlc: 1,
        group_id: None,
        group_epoch: None,
    };
    let message_id = ramflux_protocol::encode_base64url(id);
    let index = ramflux_storage::AccountIndex::open(bob_root)?;
    let wrapped =
        index.load_wrapped_db_key(&bob.id)?.ok_or("bob wrapped account key is missing")?;
    let vault = ramflux_storage::FileVaultSecretSource::new(bob_root).vault_secret(&bob.id)?;
    let kek = ramflux_sdk::account_db_key_encryption_key(&vault, e2e::PASSPHRASE.as_bytes());
    let key = ramflux_storage::unwrap_with_vault_secret(&kek, &wrapped)?;
    let db = ramflux_storage::AccountDb::open(&index, &bob.id, &key)?;
    db.persist_client_record(
        "object",
        OBJECT_ID,
        &serde_json::json!({
            "object_id": OBJECT_ID,
            "message_id": message_id,
            "conversation_id": conversation,
        }),
    )?;
    db.persist_message_actor_state(
        &message_id,
        &format!("routed/generated-identity/{message_id}"),
        &identity,
    )?;
    let manifest_hash = ramflux_protocol::encode_base64url([9_u8; 32]);
    let reference_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object.received_media.v1",
        &ramflux_protocol::canonical_json_bytes(&(&message_id, OBJECT_ID))?,
    );
    let reference = serde_json::json!({});
    let metadata = serde_json::json!({});
    db.register_object_reference(
        ramflux_storage::ObjectReferenceAdmission::FreshMessage,
        &ramflux_storage::ObjectReferenceOwner {
            reference_hash: &reference_hash,
            wire_id: OBJECT_ID,
            manifest_hash: &manifest_hash,
            selector: OBJECT_ID,
            message_id: &message_id,
            reference: &reference,
            metadata: &metadata,
        },
    )?;
    Ok(())
}

fn revoke_b4(
    stack: &e2e::Stack,
    alice_d: &e2e::Daemon,
    alice: &e2e::Account,
    bob_d: &e2e::Daemon,
    bob: &e2e::Account,
    conversation: &str,
) -> e2e::Result<()> {
    e2e::rf_json(
        &alice_d.socket,
        &[
            "object",
            "revoke",
            "--account",
            &alice.id,
            "--object",
            "demo-b-b4-object",
            "--conversation",
            conversation,
            "--recipient",
            &bob.principal_id,
            "--link",
            "demo-b-link",
            "--effective-at",
            "1700000000",
            "--reason",
            "owner revoke",
            "--recipient-device",
            &bob.device_id,
            "--recipient-principal-commitment",
            &bob.principal_commitment,
            "--target",
            &bob.target_delivery_id,
        ],
    )
    .map_err(|error| logged(format!("object revoke failed: {error}"), stack, &[alice_d, bob_d]))?;
    Ok(())
}

fn poll_attachment_deleted(
    stack: &e2e::Stack,
    alice_d: &e2e::Daemon,
    bob_d: &e2e::Daemon,
    account_id: &str,
    package: &str,
) -> e2e::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let output = import_output(bob_d, account_id, package)?;
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if !output.status.success() && stderr.contains("AttachmentDeleted") {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(logged(
                format!(
                    "import was not AttachmentDeleted after object revoke: status={} stderr={stderr}",
                    output.status
                ),
                stack,
                &[alice_d, bob_d],
            ));
        }
        pause();
    }
}

/// Owner `rf object revoke` on the booted node, then the recipient's `rf object import`
/// of a package that never matched the retained manifest is `AttachmentDeleted`.
#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn revoke_then_import_refuses_attachment_deleted() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = e2e::dm_conversation(&alice, &bob)?;
    let (socket, root) = e2e::shutdown_daemon(bob_d)?;
    install_received_reference(&alice_d.data_root, &root, &alice, &bob, &conversation)?;
    // Push safety sweep defaults to 900s. A missed live Deliver is only retried
    // on that sweep, which is outside this poll. 60s is the daemon's floor.
    let bob_d =
        e2e::spawn_daemon_with_env(socket, root, &[("RAMFLUX_SESSION_SAFETY_SWEEP_SECS", "60")])?;
    e2e::unlock_account(&bob_d, &bob)?;
    let package_path = stack.root.join("broken-package.json");
    write_broken_package(&package_path, "demo-b-b4-object")?;
    let package_arg = package_path.to_str().ok_or("package path is not utf-8")?;
    let before = import_output(&bob_d, &bob.id, package_arg)?;
    let before_err = String::from_utf8_lossy(&before.stderr);
    assert!(
        !before.status.success(),
        "broken package imported before revoke: stdout={}",
        String::from_utf8_lossy(&before.stdout)
    );
    assert!(
        !before_err.contains("AttachmentDeleted"),
        "untombstoned import must not be AttachmentDeleted: {before_err}"
    );
    revoke_b4(&stack, &alice_d, &alice, &bob_d, &bob, &conversation)?;
    match poll_attachment_deleted(&stack, &alice_d, &bob_d, &bob.id, package_arg) {
        Ok(()) => Ok(()),
        Err(error) => {
            let (_socket, root) = e2e::shutdown_daemon(bob_d)?;
            let facts = bob_object_facts(&root, &alice, &bob)?;
            Err(format!("{error}; facts={facts}").into())
        }
    }
}

fn bob_object_facts(
    bob_root: &std::path::Path,
    alice: &e2e::Account,
    bob: &e2e::Account,
) -> e2e::Result<String> {
    use ramflux_storage::ProjectionStore as _;
    use ramflux_storage::VaultSecretSource as _;
    let index = ramflux_storage::AccountIndex::open(bob_root)?;
    let wrapped =
        index.load_wrapped_db_key(&bob.id)?.ok_or("bob wrapped account key is missing")?;
    let vault = ramflux_storage::FileVaultSecretSource::new(bob_root).vault_secret(&bob.id)?;
    let kek = ramflux_sdk::account_db_key_encryption_key(&vault, e2e::PASSPHRASE.as_bytes());
    let key = ramflux_storage::unwrap_with_vault_secret(&kek, &wrapped)?;
    let db = ramflux_storage::AccountDb::open(&index, &bob.id, &key)?;
    let record = db.client_record("object", "demo-b-b4-object")?;
    let message_id = record
        .as_ref()
        .and_then(|value| value.get("message_id"))
        .and_then(|value| value.as_str())
        .ok_or("seeded object record has no message_id")?;
    let identity = db
        .load_actor_state::<ramflux_protocol::message::EventIdentity>(&format!(
            "routed/generated-identity/{message_id}"
        ))
        .map(|found| {
            found.map(|identity| {
                let anchor = identity
                    .author
                    .as_ref()
                    .map(|author| author.account_anchor.clone())
                    .unwrap_or_default();
                let verified = ramflux_protocol::message::identity::verify(&identity).is_ok();
                format!("anchor={anchor} verified={verified}")
            })
        });
    let tombstoned = db.object_is_tombstoned("demo-b-b4-object")?;
    let cursor =
        db.projection_checkpoint(&format!("gateway_receive_cursor:{}", bob.target_delivery_id))?;
    let bounds = db.journal_bounds()?;
    let start = bounds.head_seq.saturating_sub(24);
    let tail: Vec<String> =
        db.journal_after(start, 32)?.into_iter().map(|event| event.topic).collect();
    Ok(format!(
        "tombstoned={tombstoned} cursor={cursor:?} head={} identity={identity:?} record={record:?} tail={tail:?} alice_anchor={}",
        bounds.head_seq, alice.principal_commitment
    ))
}
