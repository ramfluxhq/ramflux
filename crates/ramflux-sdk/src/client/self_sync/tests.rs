// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::client::own_device_sync::tests::client_with_account;
use ramflux_storage::{DirectMessageWrite, MessageMetadata};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn value(operation: u32, revision: u64) -> g::SelfSync {
    g::SelfSync { operation, revision, ..Default::default() }
}

fn reference(id: &str) -> g::MessageRef {
    g::MessageRef {
        id: blake3::hash(id.as_bytes()).as_bytes().to_vec(),
        conversation_id: "c".into(),
        author_anchor: "peer".into(),
    }
}

fn read(id: &str, revision: u64) -> g::SelfSync {
    g::SelfSync { read_through: Some(reference(id)), ..value(1, revision) }
}

fn apply(client: &RamfluxClient, update: &g::SelfSync) -> Result<bool, SdkError> {
    let source = client.owned_device_identity()?;
    client.account_db()?.write_transaction(|| client.apply_self_sync_in(&source, "c", update))
}

fn install_read_messages(client: &RamfluxClient) -> TestResult {
    let db = client.account_db()?;
    for (id, at) in [("m1", 1), ("m2", 2)] {
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: "c",
            message_id: &ramflux_protocol::encode_base64url(reference(id).id),
            sender_id: "peer",
            encrypted_body: b"body",
            metadata: &MessageMetadata::default(),
            created_at: at,
        })?;
        db.persist_message_actor_state(&ramflux_protocol::encode_base64url(reference(id).id),
            &format!("routed/generated-identity/{}", ramflux_protocol::encode_base64url(reference(id).id)),
            &g::EventIdentity { id: reference(id).id, conversation_id: "c".into(), author: Some(g::QualifiedDevice { account_anchor: "peer".into(), device_id: "peer-device".into(), device_epoch: 1 }), hlc: u64::try_from(at)?, device_sequence: u64::try_from(at)?, ..Default::default() })?;
    }
    Ok(())
}

#[test]
fn self_sync_read_draft_pin_mute_revision_authority_and_erasure() -> TestResult {
    let (mut client, root) = client_with_account("self-sync", "principal_sync", "local")?;
    let db = client.account_db()?;
    db.persist_client_record("conversation", "c", &json!({"kind":"direct"}))?;
    install_read_messages(&client)?;
    let draft = g::SelfSync {
        draft: Some(g::Message {
            text: "draft".into(),
            reply_to: Some(reference("m1")),
            ..Default::default()
        }),
        ..value(2, 1)
    };
    assert!(apply(&client, &draft)?);
    let competing = g::SelfSync { draft: Some(g::Message { text: "equal revision".into(), ..Default::default() }), ..draft.clone() };
    let expected = if body_hash(&draft.encode_to_vec())? > body_hash(&competing.encode_to_vec())? { &draft } else { &competing };
    apply(&client, &competing)?;
    assert_eq!(client.self_sync_state("c", &draft)?.ok_or("draft")?.exact_body, expected.encode_to_vec());
    let cleared = client.change_self_sync("c", value(3, 0))?;
    assert_eq!(cleared.revision, 2);
    assert!(client.self_sync_state("c", &draft)?.ok_or("clear")?.value.draft.is_none());
    assert!(!apply(&client, &draft)?);
    assert!(apply(&client, &read("m2", 1))?);
    assert!(apply(&client, &read("m1", 2))?);
    let stored = client.self_sync_state("c", &read("m2", 1))?.ok_or("read")?;
    assert_eq!(stored.value.revision, 2);
    assert_eq!(stored.read_marker.ok_or("marker")?.id, reference("m2").id);
    for (set, clear) in [(4, 5), (6, 7)] {
        let mut update = value(set, 1);
        update.pin = (set == 4).then(|| reference("m1"));
        update.mute = set == 6;
        assert!(apply(&client, &update)?);
        let mut cleared = update.clone();
        cleared.operation = clear;
        cleared.mute = false;
        assert_eq!(client.change_self_sync("c", cleared)?.revision, 2);
        assert!(!apply(&client, &update)?);
    }
    assert!(client.change_self_sync("unseen", value(7, 0)).is_ok());
    let mut wrong_ref = read("m1", 10);
    wrong_ref.read_through.as_mut().ok_or("ref")?.conversation_id = "other".into();
    assert!(apply(&client, &wrong_ref).is_err());
    // The old fixture seed is shared; use an independently created root for this attack.
    let mut attacker = RamfluxClient::new();
    attacker.create_identity_root("attacker", [0xe9; 32]);
    attacker.create_device_branch("attacker", "bad-device", 1, [0xea; 32]);
    let source = RootQualifiedDeviceRef::for_owned_account_device(
        attacker.identity_root.as_ref().ok_or("root")?,
        "bad-device",
    )?;
    assert!(
        client
            .account_db()?
            .write_transaction(|| client.apply_self_sync_in(&source, "c", &value(7, 3)))
            .is_err()
    );
    client.active_account_db = None;
    client.unlock_account("acct", b"own-device-sync-test")?;
    assert_eq!(client.self_sync_state("c", &draft)?.ok_or("reopened")?.value.revision, 2);
    client.delete_direct_message("c", &ramflux_protocol::encode_base64url(reference("m1").id), "local", "self-sync-delete")?;
    assert!(!apply(&client, &g::SelfSync { revision: 10, ..draft.clone() })?);
    assert!(apply(&client, &value(3, 11))?);
    for operation in [0, 8, u32::MAX] {
        assert!(self_sync::validate(&value(operation, 1)).is_err());
    }
    assert!(self_sync::validate(&g::SelfSync { pin: Some(reference("m1")), ..draft }).is_err());
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}


#[test]
fn self_sync_converges_under_reorder_duplicate_and_equal_revision() -> TestResult {
    let a = g::SelfSync { mute: true, ..value(6, 6) };
    let b = value(7, 6);
    let c = value(7, 7);
    let updates = [a, b, c];
    let orders = [[0,1,2], [0,2,1], [1,0,2], [1,2,0], [2,0,1], [2,1,0]];
    let mut winner = None;
    for order in orders {
        let (client, root) = client_with_account("self-sync-converges", "principal_sync", "local")?;
        client.account_db()?.persist_client_record("conversation", "c", &json!({"kind":"direct"}))?;
        for index in order { apply(&client, &updates[index])?; apply(&client, &updates[index])?; }
        let state = client.self_sync_state("c", &updates[0])?.ok_or("state")?;
        let bytes = serde_json::to_vec(&state)?;
        if let Some(winner) = &winner { assert_eq!(&bytes, winner); } else { winner = Some(bytes); }
        drop(client); std::fs::remove_dir_all(root)?;
    }
    // The equal-revision prefix itself converges too, before revision seven arrives.
    let mut pairs = Vec::new();
    for order in [[0,1], [1,0]] {
        let (client, root) = client_with_account("self-sync-equal", "principal_sync", "local")?;
        client.account_db()?.persist_client_record("conversation", "c", &json!({"kind":"direct"}))?;
        for index in order { apply(&client, &updates[index])?; }
        pairs.push(client.self_sync_state("c", &updates[0])?.ok_or("state")?.exact_body);
        drop(client); std::fs::remove_dir_all(root)?;
    }
    assert_eq!(pairs[0], pairs[1]);
    Ok(())
}
