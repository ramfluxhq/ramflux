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
        db.persist_message_actor_state(
            &ramflux_protocol::encode_base64url(reference(id).id),
            &format!(
                "routed/generated-identity/{}",
                ramflux_protocol::encode_base64url(reference(id).id)
            ),
            &g::EventIdentity {
                id: reference(id).id,
                conversation_id: "c".into(),
                author: Some(g::QualifiedDevice {
                    account_anchor: "peer".into(),
                    device_id: "peer-device".into(),
                    device_epoch: 1,
                }),
                hlc: u64::try_from(at)?,
                device_sequence: u64::try_from(at)?,
                ..Default::default()
            },
        )?;
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
    let competing = g::SelfSync {
        draft: Some(g::Message { text: "equal revision".into(), ..Default::default() }),
        ..draft.clone()
    };
    let expected = if body_hash(&draft.encode_to_vec())? > body_hash(&competing.encode_to_vec())? {
        &draft
    } else {
        &competing
    };
    apply(&client, &competing)?;
    assert_eq!(
        client.self_sync_state("c", &draft)?.ok_or("draft")?.exact_body,
        expected.encode_to_vec()
    );
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
    client.delete_direct_message(
        "c",
        &ramflux_protocol::encode_base64url(reference("m1").id),
        "local",
        "self-sync-delete",
    )?;
    assert!(!apply(&client, &g::SelfSync { revision: 10, ..draft.clone() })?);
    assert!(apply(&client, &value(3, 11))?);
    let live_draft = g::SelfSync {
        draft: Some(g::Message { text: "erased draft".into(), ..Default::default() }),
        ..value(2, 12)
    };
    assert!(apply(&client, &live_draft)?);
    client.erase_self_sync_conversation("c")?;
    assert!(client.self_sync_state("c", &live_draft)?.is_none());
    assert!(!apply(&client, &g::SelfSync { revision: 99, ..live_draft.clone() })?);
    client.active_account_db = None;
    client.unlock_account("acct", b"own-device-sync-test")?;
    assert!(!apply(&client, &g::SelfSync { revision: 100, ..live_draft.clone() })?);
    client.recreate_self_sync_conversation("c")?;
    assert!(!apply(&client, &live_draft)?);
    assert_eq!(client.change_self_sync("c", value(3, 0))?.revision, 13);
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
    let orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    let mut winner = None;
    for order in orders {
        let (client, root) = client_with_account("self-sync-converges", "principal_sync", "local")?;
        client.account_db()?.persist_client_record(
            "conversation",
            "c",
            &json!({"kind":"direct"}),
        )?;
        for index in order {
            apply(&client, &updates[index])?;
            apply(&client, &updates[index])?;
        }
        let state = client.self_sync_state("c", &updates[0])?.ok_or("state")?;
        let bytes = serde_json::to_vec(&state)?;
        if let Some(winner) = &winner {
            assert_eq!(&bytes, winner);
        } else {
            winner = Some(bytes);
        }
        drop(client);
        std::fs::remove_dir_all(root)?;
    }
    // The equal-revision prefix itself converges too, before revision seven arrives.
    let mut pairs = Vec::new();
    for order in [[0, 1], [1, 0]] {
        let (client, root) = client_with_account("self-sync-equal", "principal_sync", "local")?;
        client.account_db()?.persist_client_record(
            "conversation",
            "c",
            &json!({"kind":"direct"}),
        )?;
        for index in order {
            apply(&client, &updates[index])?;
        }
        pairs.push(client.self_sync_state("c", &updates[0])?.ok_or("state")?.exact_body);
        drop(client);
        std::fs::remove_dir_all(root)?;
    }
    assert_eq!(pairs[0], pairs[1]);
    Ok(())
}

#[test]
fn self_sync_local_repair_preserves_read_max_beyond_winning_revision() -> TestResult {
    let mut states = Vec::new();
    for order in [[read("m2", 1), read("m1", 2)], [read("m1", 2), read("m2", 1)]] {
        let (client, root) =
            client_with_account("self-sync-read-bootstrap", "principal_sync", "local")?;
        install_read_messages(&client)?;
        for update in order {
            apply(&client, &update)?;
        }
        let state = client.self_sync_state("c", &read("m1", 1))?.ok_or("state")?;
        assert_eq!(state.value.revision, 2);
        assert_eq!(state.read_marker.as_ref(), Some(&reference("m2")));
        assert_eq!(
            state.read_marker_body.as_ref().ok_or("max read body")?.exact_body,
            read("m2", 1).encode_to_vec()
        );
        let own = client.owned_device_identity()?;
        assert!(matches!(client.bootstrap_self_sync(&own), Err(SdkError::InboundPending(_))));
        queue_local_repair(&client, &state.value)?;
        let repair_keys = client.account_db()?.actor_state_keys("self-sync/repair/")?;
        assert_eq!(repair_keys.len(), 1);
        let repair: serde_json::Value =
            client.account_db()?.load_actor_state(&repair_keys[0])?.ok_or("repair")?;
        assert_eq!(
            serde_json::from_value::<Vec<u8>>(repair["read_marker_body"].clone())?,
            read("m2", 1).encode_to_vec()
        );
        states.push(serde_json::to_vec(&state)?);
        drop(client);
        std::fs::remove_dir_all(root)?;
    }
    assert_eq!(states[0], states[1]);
    Ok(())
}

#[test]
fn self_sync_unknown_conversation_limit_is_bounded_and_known_scopes_still_apply() -> TestResult {
    let (client, root) = client_with_account("self-sync-unseen-limit", "principal_sync", "local")?;
    let own = client.owned_device_identity()?;
    client
        .account_db()?
        .write_transaction(|| client.apply_self_sync_in(&own, "unseen-0", &value(7, 1)))?;
    let prototype = client.self_sync_state("unseen-0", &value(7, 1))?.ok_or("prototype")?;
    client.account_db()?.write_transaction(|| -> TestResult {
        for index in 1..SELF_SYNC_MAX_UNSEEN_CONVERSATIONS {
            let conversation = format!("unseen-{index}");
            let mut state = prototype.clone();
            state.conversation_id.clone_from(&conversation);
            client.account_db()?.persist_actor_state(
                &key(own.root_commitment(), &conversation, &value(7, 1))?,
                &state,
            )?;
        }
        Ok(())
    })?;
    assert!(
        client
            .account_db()?
            .write_transaction(|| client.apply_self_sync_in(&own, "over-limit", &value(7, 1)))
            .is_err()
    );
    assert!(client.self_sync_state("over-limit", &value(7, 1))?.is_none());
    assert!(client.account_db()?.write_transaction(|| client.apply_self_sync_in(
        &own,
        "unseen-0",
        &value(7, 2)
    ))?);
    client.account_db()?.persist_client_record(
        "conversation",
        "known",
        &json!({"kind":"direct"}),
    )?;
    assert!(client.account_db()?.write_transaction(|| client.apply_self_sync_in(
        &own,
        "known",
        &value(7, 1)
    ))?);
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn self_sync_read_order_uses_signed_identity_when_display_timestamps_disagree() -> TestResult {
    let (client, root) = client_with_account("self-sync-read-order", "principal_sync", "local")?;
    install_read_messages(&client)?;
    let db = client.account_db()?;
    let first_id = ramflux_protocol::encode_base64url(reference("m1").id);
    let key = format!("routed/generated-identity/{first_id}");
    let mut identity: g::EventIdentity = db.load_actor_state(&key)?.ok_or("identity")?;
    identity.hlc = 9;
    db.persist_message_actor_state(&first_id, &key, &identity)?;
    apply(&client, &read("m2", 1))?;
    apply(&client, &read("m1", 2))?;
    let projection = db.conversation_projection("c", Some(&client.owned_device_identity()?))?;
    assert_eq!(projection.read_through_message_id, Some(first_id));
    assert!(!projection.is_unread);
    assert!(!apply(&client, &read("m2", 1))?);
    assert_eq!(
        client.self_sync_state("c", &read("m1", 1))?.ok_or("state")?.read_marker,
        Some(reference("m1"))
    );
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn self_sync_publication_defers_without_identity_across_fanout_and_restart() -> TestResult {
    let (mut client, root) =
        client_with_account("self-sync-publication", "principal_sync", "local")?;
    let update = client.change_self_sync("c", value(7, 0))?;
    for restart in [false, true] {
        if restart {
            client.active_account_db = None;
            client.unlock_account("acct", b"own-device-sync-test")?;
        }
        for _ in 0..2 {
            assert!(matches!(
                client
                    .account_db()?
                    .write_transaction(|| client.self_sync_publication_inner("c", &update)),
                Err(SdkError::InboundPending(_))
            ));
        }
        assert_eq!(client.account_db()?.actor_state_keys("message-identity/counter/")?.len(), 0);
        assert!(
            client.self_sync_state("c", &update)?.ok_or("state")?.publication_identity.is_none()
        );
    }
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn self_sync_local_state_preserves_exact_body_and_independent_read_while_publication_defers()
-> TestResult {
    let (client, root) =
        client_with_account("self-sync-exact-publication", "principal_sync", "local")?;
    let source = client.owned_device_identity()?;
    let update = value(7, 9);
    let exact = update.encode_to_vec();
    client
        .account_db()?
        .write_transaction(|| client.apply_self_sync_exact(&source, "c", &update, &exact))?;
    assert_eq!(client.self_sync_state("c", &update)?.ok_or("exact state")?.exact_body, exact);
    assert!(matches!(
        client.account_db()?.write_transaction(|| client.self_sync_publication_inner("c", &update)),
        Err(SdkError::InboundPending(_))
    ));
    install_read_messages(&client)?;
    apply(&client, &read("m1", 20))?;
    let greater_read = read("m2", 5);
    apply(&client, &greater_read)?;
    let state = client.self_sync_state("c", &greater_read)?.ok_or("read state")?;
    assert_eq!(state.read_marker_body.ok_or("read body")?.exact_body, greater_read.encode_to_vec());
    assert_eq!(state.value.revision, 20);
    assert!(matches!(
        client
            .account_db()?
            .write_transaction(|| client.self_sync_publication_inner("c", &greater_read)),
        Err(SdkError::InboundPending(_))
    ));
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn self_sync_repair_tracks_equal_revision_winner_and_retires_cleared_draft_copies() -> TestResult {
    let (client, root) =
        client_with_account("self-sync-repair-lifetime", "principal_sync", "local")?;
    let a = g::SelfSync {
        operation: 2,
        revision: 1,
        draft: Some(g::Message { text: "draft alpha".into(), ..Default::default() }),
        ..Default::default()
    };
    let b = g::SelfSync {
        draft: Some(g::Message { text: "draft beta".into(), ..Default::default() }),
        ..a.clone()
    };
    let (loser, winner) = if body_hash(&a.encode_to_vec())? < body_hash(&b.encode_to_vec())? {
        (a, b)
    } else {
        (b, a)
    };
    let db = client.account_db()?;
    apply(&client, &loser)?;
    queue_local_repair(&client, &loser)?;
    let old_marker =
        db.actor_state_keys("self-sync/repair-sent/")?.pop().ok_or("old repair marker")?;
    let old_repair = db.actor_state_keys("self-sync/repair/")?.pop().ok_or("old repair")?;
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/src/sender_transcript_vectors.json"
    ))?;
    let envelope: ramflux_protocol::Envelope = serde_json::from_value(vectors["envelope"].clone())?;
    client.persist_self_sync_delivery("c", &loser, &envelope)?;
    assert!(apply(&client, &winner)?, "equal-revision greater hash must win");
    assert!(!db.actor_state_exists(&old_marker)?);
    assert!(
        !serde_json::to_string(&db.pending_outbox(256)?)?.contains(&old_marker),
        "erased draft hash must also leave the private outbox keys"
    );
    assert!(!db.actor_state_exists(&old_repair)?);
    assert_eq!(db.actor_state_usage("self-sync/pending/")?.0, 0);
    assert!(!apply(&client, &loser)?, "equal-revision losing writer is stale");
    assert_eq!(
        db.actor_state_usage("self-sync/repair/")?.0,
        1,
        "equal-revision stale writer receives the current exact register once"
    );
    let key = db.actor_state_keys("self-sync/repair/")?.pop().ok_or("winning repair")?;
    let repair: serde_json::Value = db.load_actor_state(&key)?.ok_or("repair")?;
    assert_eq!(
        serde_json::from_value::<Vec<u8>>(repair["exact_body"].clone())?,
        winner.encode_to_vec()
    );
    apply(&client, &value(3, 2))?;
    assert_eq!(db.actor_state_usage("self-sync/repair/")?.0, 0);
    assert_eq!(
        db.actor_state_usage("self-sync/repair-sent/")?.0,
        0,
        "cleared draft cannot leave a plaintext guessing fingerprint"
    );
    assert!(!db.actor_state_exists(&key)?);
    queue_local_repair(&client, &value(3, 2))?;
    client.erase_self_sync_conversation("c")?;
    assert_eq!(db.actor_state_usage("self-sync/repair-sent/")?.0, 0);
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn self_sync_repair_max_read_change_invalidates_old_revision_deduplication() -> TestResult {
    let (client, root) =
        client_with_account("self-sync-repair-read-max", "principal_sync", "local")?;
    install_read_messages(&client)?;
    apply(&client, &read("m1", 2))?;
    queue_local_repair(&client, &read("m1", 2))?;
    let db = client.account_db()?;
    let old = db.actor_state_keys("self-sync/repair/")?.pop().ok_or("old read repair")?;
    assert!(apply(&client, &read("m2", 1))?);
    assert!(!db.actor_state_exists(&old)?, "new max read retires an obsolete exact repair body");
    let next = db.actor_state_keys("self-sync/repair/")?.pop().ok_or("updated read repair")?;
    let repair: serde_json::Value = db.load_actor_state(&next)?.ok_or("repair")?;
    assert_eq!(
        serde_json::from_value::<Vec<u8>>(repair["read_marker_body"].clone())?,
        read("m2", 1).encode_to_vec()
    );
    queue_local_repair(&client, &read("m1", 2))?;
    assert_eq!(db.actor_state_usage("self-sync/repair/")?.0, 1);
    assert_eq!(client.self_sync_state("c", &read("m1", 1))?.ok_or("state")?.value.revision, 2);
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn self_sync_read_reference_requires_authenticated_author_and_conversation() -> TestResult {
    let (client, root) =
        client_with_account("self-sync-read-reference", "principal_sync", "local")?;
    let mut wrong_author = read("m2", 1);
    wrong_author.read_through.as_mut().ok_or("reference")?.author_anchor = "another-root".into();
    // Receipt before the target is a parked register, never an active read marker.
    assert!(apply(&client, &wrong_author)?);
    assert!(client.self_sync_state("c", &wrong_author)?.ok_or("state")?.read_marker.is_none());
    install_read_messages(&client)?;
    client.account_db()?.write_transaction(|| client.resolve_self_sync_read_references("c"))?;
    let resolved = client.self_sync_state("c", &wrong_author)?.ok_or("resolved")?;
    assert!(resolved.read_marker.is_none(), "wrong root must not activate when the target arrives");
    assert!(resolved.pending_read.is_none(), "known-invalid reference is settled");
    wrong_author.revision = 2;
    assert!(apply(&client, &wrong_author).is_err());
    let mut wrong_conversation = read("m1", 2);
    wrong_conversation.read_through.as_mut().ok_or("reference")?.conversation_id = "other".into();
    assert!(apply(&client, &wrong_conversation).is_err());
    assert!(apply(&client, &read("m2", 3))?);
    assert_eq!(
        client.self_sync_state("c", &read("m2", 3))?.ok_or("valid")?.read_marker,
        Some(reference("m2"))
    );
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn queue_local_repair(client: &RamfluxClient, value: &g::SelfSync) -> Result<(), SdkError> {
    let source = client.owned_device_identity()?;
    let scope = key(source.root_commitment(), "c", value)?;
    let state = client
        .self_sync_state("c", value)?
        .ok_or_else(|| refused("local test register missing"))?;
    client
        .account_db()?
        .write_transaction(|| client.queue_self_sync_repair(&source, &scope, &state))
}
