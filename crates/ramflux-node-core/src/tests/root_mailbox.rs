// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent root-qualified senders retain distinct mailbox deliveries across restart.
use super::federation::root_bound_forward;
use super::*;

struct Mailbox {
    path: PathBuf,
    store: RouterRedbStore,
    router: RouterCore,
}
fn populated_mailbox() -> Result<Mailbox, Box<dyn std::error::Error>> {
    let path = temp_store_path("root-qualified-mailbox")?;
    let store = RouterRedbStore::open(&path)?;
    let router = RouterCore::new();
    store.save_router(&router)?;
    let bob_root = ramflux_crypto::create_identity_root("bob", [0xb1; 32]);
    let mallory_root = ramflux_crypto::create_identity_root("mallory", [0xb2; 32]);
    for root in [&mallory_root, &bob_root] {
        let mut forward = root_bound_forward(root, "bob", None, "next-bob-envelope")?;
        forward.envelope.created_at = i64::try_from(now_unix_seconds())?;
        forward.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes(
            &ramflux_protocol::envelope_sender_signed_bytes(&forward.envelope)?,
        );
        let source = router.authenticated_envelope_source(&forward.envelope)?;
        let key = envelope_replay_tuple_key(&source, &forward.envelope);
        let expiry = forward.envelope.created_at + i64::from(forward.envelope.ttl);
        let outcome = router.submit_envelope_at(
            &source,
            forward.envelope.clone(),
            forward.envelope.created_at + 1,
        );
        let RouterSubmitOutcome::OfflineQueued(queued) = outcome else {
            return Err(format!("unexpected {outcome:?}").into());
        };
        store.record_submission_increment(&key, expiry, Some(&queued.entry))?;
    }
    assert_eq!(router.resume("root-replay-target", 0, 10).len(), 2);
    Ok(Mailbox { path, store, router })
}

#[test]
fn copied_envelope_ids_from_distinct_roots_survive_mailbox_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let Mailbox { path, store, router: _ } = populated_mailbox()?;
    drop(store);
    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened.load_router()?.ok_or("restored router")?;
    let entries = restored.resume("root-replay-target", 0, 10);
    assert_eq!(entries.len(), 2, "one root must never overwrite another root's delivery");
    assert_ne!(entries[0].envelope.source_principal_id, entries[1].envelope.source_principal_id);
    Ok(())
}

#[test]
fn acknowledging_one_delivery_never_deletes_a_different_roots_same_id_message()
-> Result<(), Box<dyn std::error::Error>> {
    let Mailbox { path, store, router } = populated_mailbox()?;
    let entries = router.resume("root-replay-target", 0, 10);
    assert_eq!(entries[0].envelope.source_principal_id, "mallory");
    assert_eq!(entries[1].envelope.source_principal_id, "bob");
    let mut first = ack("next-bob-envelope");
    assert!(matches!(
        router.apply_ack_for_target("root-replay-target", &first),
        Err(NodeCoreError::AmbiguousEnvelopeId(_))
    ));
    first.ext.ext.insert("inbox_seq".into(), serde_json::json!(entries[0].inbox_seq));
    let cursor = router.apply_ack_for_target("root-replay-target", &first)?;
    store.record_ack_increment(&cursor, &first.envelope_id)?;
    assert_eq!(router.resume("root-replay-target", 0, 10).len(), 1);
    let legacy_retry = ack("next-bob-envelope");
    assert!(matches!(
        router.apply_ack_for_target("root-replay-target", &legacy_retry),
        Err(NodeCoreError::AmbiguousEnvelopeId(_))
    ));
    drop(store);
    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened.load_router()?.ok_or("router")?;
    let remaining = restored.resume("root-replay-target", 0, 10);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].envelope.source_principal_id, "bob");
    let mut second = ack("next-bob-envelope");
    second.ext.ext.insert("inbox_seq".into(), serde_json::json!(entries[1].inbox_seq));
    let cursor = restored.apply_ack_for_target("root-replay-target", &second)?;
    reopened.record_ack_increment(&cursor, &second.envelope_id)?;
    assert_eq!(restored.resume("root-replay-target", 0, 10), Vec::<InboxEntry>::new());
    // A lost ACK reply can retry the earlier sequence without affecting another delivery.
    assert!(restored.apply_ack_for_target("root-replay-target", &first).is_ok());
    Ok(())
}

#[test]
fn migration_never_interprets_an_old_sender_chosen_id_as_a_current_delivery_key()
-> Result<(), Box<dyn std::error::Error>> {
    use redb::{ReadableTable, TableDefinition};
    let Mailbox { path, store, router } = populated_mailbox()?;
    let mut entries = router.resume("root-replay-target", 0, 10);
    let target = ramflux_protocol::encode_base64url("root-replay-target");
    entries[0].envelope.envelope_id = format!("delivery/v1/{target}/{:020}", entries[1].inbox_seq);
    entries[1].envelope.envelope_id = "honest-message".into();
    for entry in &mut entries {
        entry.envelope.signed.signature = ramflux_crypto::sign_canonical_bytes(
            &ramflux_protocol::envelope_sender_signed_bytes(&entry.envelope)?,
        );
        DeviceAuthKeyResponse::forwarded_envelope_source(&entry.envelope)?;
    }
    drop(store);
    let db = redb::Database::create(&path)?;
    let transaction = db.begin_write()?;
    {
        let mut table = transaction.open_table(ROUTER_INBOX_ENTRY_TABLE)?;
        let old = table
            .iter()?
            .map(|row| row.map(|(key, _)| key.value().to_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        for key in old {
            table.remove(key.as_str())?;
        }
        for entry in &entries {
            let bytes = serde_json::to_vec(entry)?;
            table.insert(entry.envelope.envelope_id.as_str(), bytes.as_slice())?;
        }
        let format: TableDefinition<&str, u8> =
            TableDefinition::new("router_mailbox_key_format_v1");
        transaction.open_table(format)?.remove("version")?;
    }
    transaction.commit()?;
    drop(db);
    let reopened = RouterRedbStore::open(&path)?;
    let restored = reopened.load_router()?.ok_or("router")?;
    let pending = restored.resume("root-replay-target", 0, 10);
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].envelope.source_principal_id, "mallory");
    assert_eq!(pending[1].envelope.source_principal_id, "bob");
    assert_eq!(pending[1].envelope.envelope_id, "honest-message");
    Ok(())
}
