// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::{AccountDbKey, AccountIndex};
fn database() -> Result<(ramflux_test_support::TestPath, AccountDb), StorageError> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!("ramflux-journal-{}-{sequence}-{unique}", std::process::id()));
    let index = AccountIndex::open(&root)?;
    index.create_account("a", "principal")?;
    let db = AccountDb::open(&index, "a", &AccountDbKey::derive("a", b"secret"))?;
    Ok((root, db))
}
fn retry_source(name: &str) -> Result<ramflux_crypto::RootQualifiedDeviceRef, StorageError> {
    Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
        &ramflux_crypto::create_identity_root("retry-test", [0xa1; 32]),
        name,
    )?)
}
#[test]
fn sequences_survive_reopen_and_retention_never_reuses_them() -> Result<(), StorageError> {
    let (root, db) = database()?;
    for n in 0..6 {
        db.append_journal(
            &format!("event:{n}"),
            "conversation.changed",
            &serde_json::json!({"id":n}),
            n,
            None,
        )?;
    }
    let head = db.journal_bounds()?.head_seq;
    assert_eq!(head, 6);
    db.retain_journal(6, 2, 100)?;
    assert_eq!(db.journal_bounds()?.floor_seq, 5);
    assert_eq!(db.journal_bounds()?.pruned_through, 4);
    assert_eq!(db.journal_after(4, 128)?.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![5, 6]);
    drop(db);
    let db =
        AccountDb::open(&AccountIndex::open(&root)?, "a", &AccountDbKey::derive("a", b"secret"))?;
    assert_eq!(db.journal_bounds()?.head_seq, head);
    db.retain_journal(1000, 0, 0)?;
    assert_eq!(db.journal_after(0, 128)?, Vec::<JournalEvent>::new());
    assert!(
        db.append_journal("new", "sync.status", &serde_json::json!({}), 1000, None)?.seq > head
    );
    drop(db);
    Ok(())
}
#[test]
fn sticky_events_survive_age_count_until_ack_and_holes_are_detectable() -> Result<(), StorageError>
{
    let (_root, db) = database()?;
    let safety = db.append_journal(
        "safety",
        "safety.changed",
        &serde_json::json!({"id":"peer"}),
        1,
        Some("peer"),
    )?;
    let approval = db.append_journal(
        "approval",
        "mcp.approval.request",
        &serde_json::json!({"id":"approval"}),
        1,
        Some("approval"),
    )?;
    db.append_journal(
        "ordinary",
        "message.updated",
        &serde_json::json!({"id":"message"}),
        2,
        None,
    )?;
    db.retain_journal(100, 0, 0)?;
    assert_eq!(db.journal_after(0, 128)?, vec![safety.clone(), approval.clone()]);
    assert_eq!(db.journal_bounds()?.floor_seq, safety.seq);
    assert_eq!(db.journal_bounds()?.pruned_through, 3);
    db.acknowledge_journal_subject("peer")?;
    db.acknowledge_journal(approval.seq)?;
    db.retain_journal(100, 0, 0)?;
    assert_eq!(db.journal_after(0, 128)?, Vec::<JournalEvent>::new());
    drop(db);
    Ok(())
}
#[test]
fn outbox_and_journal_commit_atomically_and_quarantine_never_evicts() -> Result<(), StorageError> {
    let (_root, db) = database()?;
    db.persist_actor_state("directory/conversation/example", &serde_json::json!({"id":"example"}))?;
    let entry = db.pending_outbox(128)?.pop().ok_or(StorageError::AuthorizationRejected)?;
    assert_eq!(entry.keys["state_kind"], "directory/conversation/example");
    let failed = db.journal_outbox(
        entry.sequence,
        &[(
            "conversation.changed".to_owned(),
            serde_json::json!({"huge":"x".repeat(600_000)}),
            None,
        )],
        1,
    );
    assert!(failed.is_err());
    assert_ne!(db.pending_outbox(128)?.len(), 0);
    assert_eq!(db.journal_bounds()?.head_seq, 0);
    db.journal_outbox(
        entry.sequence,
        &[("conversation.changed".to_owned(), serde_json::json!({"id":"example"}), None)],
        1,
    )?;
    assert_eq!(db.pending_outbox(128)?.len(), 0);
    assert_eq!(db.journal_bounds()?.head_seq, 1);
    for n in 0..64 {
        db.hold_unrouted(&format!("e{n}"), n, b"ciphertext", 1)?;
    }
    db.hold_unrouted("overflow", 65, b"ciphertext", 1)?;
    assert_eq!(db.unrouted_count()?, 64);
    assert_eq!(db.unrouted_entries()?.len(), 64);
    drop(db);
    Ok(())
}

#[test]
fn deleting_message_erases_approved_content_copy() -> Result<(), StorageError> {
    let (_root, db) = database()?;
    db.send_direct_message("conversation", "message", "sender", b"encrypted bytes")?;
    db.store_message_content("conversation", "message", b"approved plaintext")?;
    assert!(db.message_content("message")?.is_some());
    db.delete_direct_message("conversation", "message", "local", "tombstone")?;
    assert_eq!(db.message_content("message")?, None);
    drop(db);
    Ok(())
}

#[test]
fn dead_letters_refuse_over_capacity_expire_and_keep_ciphertext_out_of_journal()
-> Result<(), StorageError> {
    let (_root, db) = database()?;
    for n in 0..65 {
        db.set_inbox_failure_policy(
            &format!("bad-{n:02}"),
            b"PRIVATE_CIPHERTEXT",
            InboxFailureSource::Authenticated {
                device: &retry_source(&format!("bad-{n:02}"))?,
                related: true,
            },
            ("none", ""),
            100 + n,
        )?;
        db.dead_letter_inbox(&format!("bad-{n:02}"),b"PRIVATE_CIPHERTEXT",&serde_json::json!({"envelope_id":format!("e{n}"),"error_code":"authentication_failed"}),100+n)?;
    }
    let count: u32 =
        db.connection
            .query_row("SELECT count(*) FROM runtime_inbox_dead_letter", [], |row| row.get(0))?;
    assert_eq!(count, 64);
    let oldest: String = db.connection.query_row(
        "SELECT envelope_key FROM runtime_inbox_dead_letter ORDER BY received_at LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(oldest, "bad-00");
    for event in db.journal_after(0, 100)? {
        assert!(!serde_json::to_string(&event)?.contains("PRIVATE_CIPHERTEXT"));
    }
    db.expire_inbox_holds(165 + 7 * 24 * 60 * 60)?;
    let count: u32 =
        db.connection
            .query_row("SELECT count(*) FROM runtime_inbox_dead_letter", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    drop(db);
    Ok(())
}

#[test]
fn transient_retry_capacity_and_expiry_emit_terminal_metadata_with_bounded_backoff()
-> Result<(), StorageError> {
    let (_root, db) = database()?;
    for n in 0..65 {
        db.set_inbox_failure_policy(
            &format!("retry-{n:02}"),
            b"PRIVATE_RETRY",
            InboxFailureSource::Authenticated {
                device: &retry_source(&format!("retry-{n:02}"))?,
                related: true,
            },
            ("none", ""),
            100,
        )?;
        let expected = u32::from(n < 64);
        assert_eq!(
            db.defer_inbox_entry(&format!("retry-{n:02}"), b"PRIVATE_RETRY", 100)?,
            expected
        );
    }
    assert_eq!(db.due_inbox_retries(101)?.len(), 0);
    assert_eq!(db.due_inbox_retries(102)?.len(), 64);
    assert_eq!(db.journal_after(0, 100)?, Vec::<JournalEvent>::new());
    assert_eq!(db.defer_inbox_entry("retry-63", b"PRIVATE_RETRY", 102)?, 2);
    assert_eq!(db.due_inbox_retries(105)?.len(), 63);
    db.expire_inbox_holds(101 + 7 * 24 * 60 * 60)?;
    assert_eq!(db.due_inbox_retries(i64::MAX)?.len(), 0);
    let events = db.journal_after(0, 100)?;
    assert!(events.iter().any(|event| event.body["error_code"] == "retry_expired"));
    assert!(!serde_json::to_string(&events)?.contains("PRIVATE_RETRY"));
    drop(db);
    Ok(())
}

#[test]
fn a_junk_source_cannot_evict_another_sources_pending_ciphertext() -> Result<(), StorageError> {
    let (_root, db) = database()?;
    let genuine =
        serde_json::to_vec(&serde_json::json!({"envelope":{"source_device_id":"friend"}}))?;
    db.defer_inbox_entry("genuine", &genuine, 100)?;
    db.dead_letter_inbox(
        "genuine-dead",
        &genuine,
        &serde_json::json!({"error_code":"membership_pending"}),
        100,
    )?;
    let junk = serde_json::to_vec(&serde_json::json!({"envelope":{"source_device_id":"junk"}}))?;
    for n in 0..128 {
        db.defer_inbox_entry(&format!("junk-{n}"), &junk, 100)?;
        db.dead_letter_inbox(
            &format!("junk-dead-{n}"),
            &junk,
            &serde_json::json!({"error_code":"authentication_failed"}),
            100,
        )?;
    }
    assert!(db.has_inbox_retry("genuine")?);
    let retained: bool = db.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_inbox_dead_letter WHERE envelope_key='genuine-dead')",
        [],
        |r| r.get(0),
    )?;
    assert!(retained);
    drop(db);
    Ok(())
}
#[test]
fn retry_attempts_are_bounded_even_when_the_peer_chooses_a_long_ttl() -> Result<(), StorageError> {
    let (_root, db) = database()?;
    let packet = serde_json::to_vec(
        &serde_json::json!({"envelope":{"source_device_id":"stranger","created_at":100,"ttl":604_800}}),
    )?;
    for n in 1..=3 {
        assert_eq!(db.defer_inbox_entry("pending", &packet, 100)?, n);
    }
    assert_eq!(db.defer_inbox_entry("pending", &packet, 100)?, 0);
    db.expire_inbox_holds(130)?;
    assert!(!db.has_inbox_retry("pending")?);
    drop(db);
    Ok(())
}

#[test]
fn legacy_imported_ratchets_are_erased_with_secure_delete_and_a_wal_checkpoint()
-> Result<(), StorageError> {
    use crate::{EventStore, ProjectionStore};
    let (_root, db) = database()?;
    let id = "dm.session:thread:recv:own-device-sync:old-export";
    db.append_event(id, "dm.ratchet_session", b"old secret snapshot")?;
    db.set_projection_checkpoint("dm_session:thread:recv", id)?;
    db.enable_runtime()?;
    assert!(db.event_body(id)?.is_none());
    assert!(db.projection_checkpoint("dm_session:thread:recv")?.is_none());
    let enabled: i64 = db.connection.query_row("PRAGMA secure_delete", [], |r| r.get(0))?;
    assert_eq!(enabled, 1);
    let busy: i64 = db.connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
    assert_eq!(busy, 0);
    drop(db);
    Ok(())
}

fn pin_source(
    owner: &str,
    name: &str,
) -> Result<ramflux_crypto::RootQualifiedDeviceRef, StorageError> {
    let seed = ramflux_crypto::blake3_256("ramflux.storage.test.pin.v1", owner.as_bytes());
    Ok(ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
        &ramflux_crypto::create_identity_root(owner, seed),
        name,
    )?)
}
#[test]
fn unverified_device_claims_cannot_spend_a_verified_senders_failure_quota()
-> Result<(), StorageError> {
    let (_root, db) = database()?;
    let packet = serde_json::to_vec(
        &serde_json::json!({"envelope":{"source_device_id":"friend","created_at":100,"ttl":3600}}),
    )?;
    for index in 0..16 {
        let id = format!("forged-{index}");
        assert_ne!(db.defer_inbox_entry(&id, &packet, 100)?, 0);
    }
    assert!(db.set_verified_inbox_failure_policy(
        "genuine",
        &packet,
        InboxFailurePolicy {
            verified_source: Some(&pin_source("principal", "device")?),
            trusted: true,
            dependency: ("group", "g"),
            at: 100,
        }
    )?);
    assert_eq!(db.defer_inbox_entry("genuine", &packet, 100)?, 1);
    assert!(db.has_inbox_retry("genuine")?);
    drop(db);
    Ok(())
}
#[test]
fn authenticated_policy_promotion_wakes_backoff_without_resetting_attempts_or_first_seen()
-> Result<(), StorageError> {
    let (_root, db) = database()?;
    let packet = serde_json::to_vec(
        &serde_json::json!({"envelope":{"source_device_id":"friend","created_at":100,"ttl":3600}}),
    )?;
    assert_eq!(db.defer_inbox_entry("pending", &packet, 100)?, 1);
    assert!(!db.inbox_retry_ready("pending", 101)?);
    assert!(db.set_verified_inbox_failure_policy(
        "pending",
        &packet,
        InboxFailurePolicy {
            verified_source: Some(&pin_source("principal", "device")?),
            trusted: true,
            dependency: ("group", "g"),
            at: 101,
        }
    )?);
    assert!(db.inbox_retry_ready("pending", 101)?);
    assert_eq!(db.defer_inbox_entry("pending", &packet, 101)?, 2);
    let position: (i64,i64,u32) = db.connection.query_row("SELECT first_seen,expires_at,attempts FROM runtime_inbox_policy WHERE envelope_key='pending'", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    assert_eq!(position, (100, 700, 2));
    for time in 102..108 {
        assert_ne!(db.defer_inbox_entry("pending", &packet, time)?, 0);
    }
    assert_eq!(db.defer_inbox_entry("pending", &packet, 108)?, 0);
    drop(db);
    Ok(())
}
#[test]
fn legacy_budget_expiry_parks_ciphertext_until_the_original_quarantine_retention_expires()
-> Result<(), StorageError> {
    let (_root, db) = database()?;
    let packet = serde_json::to_vec(
        &serde_json::json!({"envelope":{"source_device_id":"friend","created_at":100,"ttl":3600}}),
    )?;
    db.hold_unrouted("legacy-key", 1, &packet, 100)?;
    db.retain_legacy_inbox("legacy-key")?;
    assert_eq!(db.load_actor_state::<bool>("inbox/legacy-held/legacy-key")?, Some(true));
    db.set_inbox_failure_policy(
        "legacy-key",
        &packet,
        InboxFailureSource::Authenticated {
            device: &pin_source("principal", "friend")?,
            related: true,
        },
        ("group", "g"),
        100,
    )?;
    db.defer_inbox_entry("legacy-key", &packet, 100)?;
    db.expire_inbox_holds(701)?;
    assert_eq!(db.unrouted_count()?, 1);
    assert!(!db.has_inbox_retry("legacy-key")?);
    assert!(db.legacy_inbox_parked("legacy-key")?);
    assert_eq!(db.due_inbox_retries(702)?, Vec::<Vec<u8>>::new());
    assert_eq!(db.journal_after(0, 64)?, Vec::<JournalEvent>::new());
    db.hold_unrouted("legacy-key", 1, &packet, 1000)?;
    let received: i64 = db.connection.query_row(
        "SELECT received_at FROM runtime_unrouted WHERE envelope_id='legacy-key'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(received, 100);
    db.expire_inbox_holds(101 + 7 * 24 * 60 * 60)?;
    assert_eq!(db.unrouted_count()?, 0);
    assert_eq!(db.load_actor_state::<serde_json::Value>("inbox/legacy-held/legacy-key")?, None);
    drop(db);
    Ok(())
}

#[test]
fn parked_and_expired_legacy_holds_release_shared_stranger_source_and_retry_slots()
-> Result<(), StorageError> {
    for expired in [false, true] {
        for (count, trusted, same_source) in
            [(16, false, false), (64, true, false), (8, true, true)]
        {
            let (root, db) = database()?;
            for index in 0..count {
                let key = format!("legacy-{index}");
                let source = if same_source { "peer".into() } else { format!("claim-{index}") };
                let source_identity = pin_source("principal", &source)?;
                let packet = serde_json::to_vec(
                    &serde_json::json!({"envelope":{"source_device_id":source,"created_at":100,"ttl":1_000_000}}),
                )?;
                db.hold_unrouted(&key, index, &packet, 100)?;
                db.retain_legacy_inbox(&key)?;
                assert!(db.set_inbox_failure_policy(
                    &key,
                    &packet,
                    if trusted {
                        InboxFailureSource::Authenticated {
                            device: &source_identity,
                            related: true,
                        }
                    } else {
                        InboxFailureSource::Unverified
                    },
                    ("manifest", "peer"),
                    100
                )?);
                assert_eq!(db.defer_inbox_entry(&key, &packet, 100)?, 1);
                if !expired {
                    db.park_legacy_inbox_retry(&key)?;
                }
            }
            let at = if expired { 701 } else { 101 };
            if expired {
                db.expire_inbox_holds(at)?;
            }
            let genuine = serde_json::to_vec(
                &serde_json::json!({"envelope":{"source_device_id":if same_source {"peer"}else{"genuine"},"created_at":at,"ttl":3600}}),
            )?;
            let genuine_source = pin_source("principal", "peer")?;
            assert!(
                db.set_inbox_failure_policy(
                    "routed-genuine",
                    &genuine,
                    if same_source {
                        InboxFailureSource::Authenticated { device: &genuine_source, related: true }
                    } else {
                        InboxFailureSource::Unverified
                    },
                    ("manifest", "genuine"),
                    at
                )?,
                "legacy holds cannot pin shared admission"
            );
            assert_eq!(db.defer_inbox_entry("routed-genuine", &genuine, at)?, 1);
            assert_eq!(db.unrouted_count()?, count);
            assert_eq!(
                db.connection
                    .query_row("SELECT count(*) FROM runtime_inbox_retry", [], |r| r
                        .get::<_, u64>(0))?,
                1
            );
            assert_eq!(
                db.connection
                    .query_row("SELECT count(*) FROM runtime_inbox_policy", [], |r| r
                        .get::<_, u64>(0))?,
                1
            );
            for index in 0..count {
                let key = format!("legacy-{index}");
                assert!(!db.has_inbox_retry(&key)?);
                assert!(db.legacy_inbox_parked(&key)?);
                let source_identity =
                    pin_source("principal", if same_source { "peer" } else { "unused" })?;
                assert!(
                    !db.set_inbox_failure_policy(
                        &key,
                        &genuine,
                        if trusted {
                            InboxFailureSource::Authenticated {
                                device: &source_identity,
                                related: true,
                            }
                        } else {
                            InboxFailureSource::Unverified
                        },
                        ("manifest", "peer"),
                        at + 6 * 86400
                    )?,
                    "redelivery never renews a parked slot"
                );
            }
            assert_eq!(db.journal_after(0, 100)?, Vec::<JournalEvent>::new());
            drop(db);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

#[test]
fn parking_a_legacy_hold_keeps_only_ciphertext_and_marker_even_after_an_old_rejection()
-> Result<(), StorageError> {
    let (_root, db) = database()?;
    let packet = br#"{"envelope":{"source_device_id":"uncached"}}"#;
    db.hold_unrouted("legacy-upgrade", 1, packet, 100)?;
    db.retain_legacy_inbox("legacy-upgrade")?;
    db.dead_letter_inbox(
        "legacy-upgrade",
        packet,
        &serde_json::json!({"error_code":"old_schema_rejection"}),
        100,
    )?;
    let journal = db.journal_after(0, 100)?;
    db.park_legacy_inbox_retry("legacy-upgrade")?;
    assert_eq!(db.unrouted_entries()?, vec![packet.to_vec()]);
    for table in ["runtime_inbox_retry", "runtime_inbox_policy", "runtime_inbox_dead_letter"] {
        let sql = format!("SELECT count(*) FROM {table}");
        assert_eq!(db.connection.query_row(&sql, [], |r| r.get::<_, u32>(0))?, 0);
    }
    assert_eq!(db.journal_after(0, 100)?, journal);
    assert!(!db.set_inbox_failure_policy(
        "legacy-upgrade",
        packet,
        InboxFailureSource::Unverified,
        ("manifest", "uncached"),
        101
    )?);
    drop(db);
    Ok(())
}

#[test]
fn status_transitions_never_spend_the_message_retention_budget() -> Result<(), StorageError> {
    let (_root, db) = database()?;
    for n in 1..=3 {
        db.append_journal(
            &format!("m:{n}"),
            "message.received",
            &serde_json::json!({"message_id":n}),
            1,
            None,
        )?;
    }
    for n in 0..300 {
        db.append_journal(
            &format!("sync:{n}"),
            "sync.status",
            &serde_json::json!({"state":if n%2==0 {"idle"}else{"error"}}),
            2,
            None,
        )?;
    }
    db.retain_journal(2, 2, 100)?;
    let mut events = Vec::new();
    let mut cursor = 0;
    loop {
        let page = db.journal_after(cursor, 128)?;
        if page.is_empty() {
            break;
        }
        cursor = page.last().map_or(cursor, |e| e.seq);
        events.extend(page);
    }
    let messages = events.iter().filter(|e| e.topic == "message.received").collect::<Vec<_>>();
    assert_eq!(messages.len(), 2, "status transitions must not evict retained messages");
    assert_eq!(messages[0].body["message_id"], 2);
    assert_eq!(messages[1].body["message_id"], 3);
    assert!(events.iter().filter(|e| e.topic == "sync.status").count() <= 128);
    drop(db);
    Ok(())
}

#[test]
fn transient_topic_never_enters_replay_or_advances_cursor() -> Result<(), StorageError> {
    let (_root, db) = database()?;
    let before = db.journal_bounds()?;
    let error = db.append_journal(
        "typing:1",
        ramflux_protocol::message::TRANSIENT_TOPIC,
        &serde_json::json!({"journal_sequence":"0"}),
        1,
        None,
    );
    assert!(matches!(error, Err(StorageError::AuthorizationRejected)));
    assert_eq!(db.journal_bounds()?, before);
    assert_eq!(db.journal_after(0, 128)?, Vec::<JournalEvent>::new());
    drop(db);
    Ok(())
}
