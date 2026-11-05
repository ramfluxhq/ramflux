// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Worker bounds and failure isolation against real durable obligations.
use super::*;
use ramflux_node_core::{
    MigrationDrainEntry, MigrationDrainOutcome, MigrationDrainState, RouterRedbStore,
};
use ramflux_protocol::home_migration::{BacklogProgress, HomeRecord};
use redb::ReadableTable;
use std::sync::Arc;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) fn seed(path: &std::path::Path, count: u64) -> Result<u64> {
    let head = window_tests::fixture(path)?;
    let HomeRecord::Committed { authorization, commit_proof, .. } = head.record else {
        return Err("commit".into());
    };
    let now = commit_proof.body.forward_until - 100;
    let db = redb::Database::create(path)?;
    let tx = db.begin_write()?;
    let operation_key = serde_json::to_string(&(
        &authorization.body.account_anchor,
        &authorization.body.migration_id,
        "source",
    ))?;
    {
        let mut operations =
            tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_ops_v1"))?;
        let mut operation: ramflux_node_core::MigrationOperation = serde_json::from_slice(
            operations.get(operation_key.as_str())?.ok_or("source operation")?.value(),
        )?;
        operation.delivery_map = vec![ramflux_protocol::home_migration::DeliveryMapEntry {
            device_ref: authorization.body.actor.clone(),
            target_delivery_id: "moving".into(),
        }];
        operations.insert(operation_key.as_str(), serde_json::to_vec(&operation)?.as_slice())?;
    }
    for i in 1..=count {
        let row = MigrationDrainEntry {
            account_anchor: authorization.body.account_anchor.clone(),
            migration_id: authorization.body.migration_id.clone(),
            entry: ramflux_node_core::InboxEntry {
                inbox_seq: i,
                target_delivery_id: "moving".into(),
                envelope: migration_tests::envelope("moving", &format!("drain-{i}"))?,
            },
            retain_until: i64::try_from(now.max(ramflux_node_core::now_unix_seconds()) + 500)?,
            state: MigrationDrainState::Pending,
            attempts: 0,
            next_attempt: now,
        };
        let key = format!("delivery/v1/{}/{i:020}", ramflux_protocol::encode_base64url("moving"));
        tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_drain_entries_v1"))?
            .insert(key.as_str(), serde_json::to_vec(&row)?.as_slice())?;
    }
    let cursor = ramflux_node_core::MigrationBacklogCursor {
        account_anchor: authorization.body.account_anchor.clone(),
        migration_id: authorization.body.migration_id.clone(),
        target_delivery_id: "moving".into(),
        high_water: count,
        next_seq: 1,
        progress: BacklogProgress { scheduled: count, remaining: count, ..Default::default() },
    };
    let key = serde_json::to_string(&(
        &authorization.body.account_anchor,
        &authorization.body.migration_id,
        "moving",
    ))?;
    tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_backlog_cursor_v1"))?
        .insert(key.as_str(), serde_json::to_vec(&cursor)?.as_slice())?;
    tx.commit()?;
    Ok(now)
}

#[test]
fn drain_pages_at_most_64_entries_and_128_transitions_per_tick() -> Result {
    let dir = migration_tests::directory()?;
    let path = dir.0.join("bounded.redb");
    let now = seed(&path, 140)?;
    let store = RouterRedbStore::open(path)?;
    assert_eq!(store.migration_drain_work_page("")?.len(), 64);
    let mut position = String::new();
    let count = crate::migration_drain::tick(
        &ramflux_node_core::RouterCore::new(),
        &store,
        &mut position,
        now,
        |_, _| Ok(MigrationDrainOutcome::Held),
    )?;
    assert_eq!(count, 128);
    let count = crate::migration_drain::tick(
        &ramflux_node_core::RouterCore::new(),
        &store,
        &mut position,
        now,
        |_, _| Ok(MigrationDrainOutcome::Held),
    )?;
    assert_eq!(count, 12);
    assert_eq!(position, "");
    let page = store.migration_drain_page("moving", 0)?;
    assert!(page.iter().all(|r| r.attempts == 1));
    Ok(())
}

#[test]
fn drain_store_error_stops_tick_without_advancing_or_releasing() -> Result {
    let dir = migration_tests::directory()?;
    let path = dir.0.join("failure.redb");
    let now = seed(&path, 1)?;
    // A schema error at the mandatory window transaction occurs before transport or settlement.
    let db = redb::Database::create(&path)?;
    let tx = db.begin_write()?;
    tx.open_table(redb::TableDefinition::<&str, &str>::new("migration_window_closed_v1"))?
        .insert("wrong", "schema")?;
    tx.commit()?;
    drop(db);
    let store = RouterRedbStore::open(&path)?;
    let before = store.migration_drain_page("moving", 0)?;
    let mut position = String::new();
    let mut forwarded = false;
    assert!(
        crate::migration_drain::tick(
            &ramflux_node_core::RouterCore::new(),
            &store,
            &mut position,
            now,
            |_, _| {
                forwarded = true;
                Ok(MigrationDrainOutcome::Held)
            }
        )
        .is_err()
    );
    assert!(!forwarded);
    assert_eq!(position, "");
    assert_eq!(before, store.migration_drain_page("moving", 0)?);
    drop(store);
    let db = redb::Database::create(&path)?;
    let tx = db.begin_write()?;
    tx.delete_table(redb::TableDefinition::<&str, &str>::new("migration_window_closed_v1"))?;
    tx.commit()?;
    drop(db);
    let store = RouterRedbStore::open(path)?;
    assert_eq!(
        crate::migration_drain::tick(
            &ramflux_node_core::RouterCore::new(),
            &store,
            &mut position,
            now,
            |_, _| Ok(MigrationDrainOutcome::Held)
        )?,
        1
    );
    Ok(())
}

#[test]
fn poison_entry_does_not_stop_later_entries_drain() -> Result {
    let _guard = window_tests::FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = migration_tests::directory()?;
    let path = dir.0.join("poison.redb");
    let now = seed(&path, 2)?;
    let store = RouterRedbStore::open(path)?;
    let state = ramflux_node_core::RouterCore::new();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: format!("http://{}/forward", listener.local_addr()?),
        admin_token: None,
        source_node_id: "A".into(),
    };
    let server = std::thread::spawn(move || listener.accept());
    let mut attempted = 0;
    crate::migration_drain::tick(&state, &store, &mut String::new(), now, |row, now| {
        let mut row = row.clone();
        if row.entry.inbox_seq == 1 {
            row.entry.envelope.signed.signature = "poison".into();
        }
        attempted += 1;
        crate::migration_drain::forward(
            &state,
            &store,
            AsyncForwardContext {
                client: Some(&client),
                semaphore: &semaphore,
                timeout: std::time::Duration::from_millis(100),
            },
            &row,
            now,
        )
    })?;
    assert_eq!(attempted, 2);
    drop(server.join().map_err(|_| "server panic")??);
    assert_eq!(store.migration_drain_page("moving", 0)?.len(), 2);
    Ok(())
}

/// Inject only the federation bridge: B still verifies sender authority and commits its inbox.
pub(super) fn destination_reply(
    listener: &std::net::TcpListener,
    b: &ramflux_node_core::RouterCore,
    store: &RouterRedbStore,
    lose_reply: bool,
) -> std::io::Result<()> {
    use std::io::{Read, Write};
    let (mut socket, _) = listener.accept()?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let header = String::from_utf8(header).map_err(std::io::Error::other)?;
    let length: usize = header
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().ok()).flatten()
        })
        .ok_or_else(|| std::io::Error::other("content length"))?;
    let mut body = vec![0; length];
    socket.read_exact(&mut body)?;
    let body: serde_json::Value = serde_json::from_slice(&body)?;
    let request: ramflux_node_core::FederatedEnvelopeForwardRequest =
        serde_json::from_value(body["forward"].clone())?;
    // This fixture starts B active. Sealed-proof activation is covered by P2 core tests.
    let retain_until =
        request.migration_evidence.ok_or_else(|| std::io::Error::other("evidence"))?.retain_until;
    let outcome = b
        .submit_forwarded_envelope(
            store,
            None,
            ramflux_node_core::ForwardedEnvelopeRequest {
                peer_node_id: "A".into(),
                envelope: request.envelope,
                migration_evidence: Some(ramflux_node_core::ForwardedMigrationEvidence {
                    commit_proof: None,
                    retain_until,
                    floors: vec![],
                }),
            },
            ramflux_node_core::now_unix_seconds(),
        )
        .map_err(std::io::Error::other)?;
    let delivery = submit_response_from_outcome(b, outcome);
    assert!(matches!(delivery.outcome.as_str(), "offline_queued" | "duplicate_federated_forward"));
    if lose_reply {
        return Ok(());
    }
    let response = serde_json::to_vec(&ramflux_node_core::FederatedEnvelopeForwardResponse {
        accepted: true,
        source_node_id: "A".into(),
        target_node_id: "B".into(),
        delivery,
    })?;
    write!(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    )?;
    socket.write_all(&response)
}

fn durable_destination_retry(lose_reply: bool) -> Result {
    let _guard = window_tests::FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = migration_tests::directory()?;
    let path = dir.0.join("source.redb");
    let now = seed(&path, 1)?;
    let store = RouterRedbStore::open(path)?;
    let row = store.migration_drain_page("moving", 0)?.remove(0);
    let state = ramflux_node_core::RouterCore::new();
    let destination = Arc::new(RouterRedbStore::open(dir.0.join("destination.redb"))?);
    let b = Arc::new(ramflux_node_core::RouterCore::new());
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: format!("http://{}/forward", listener.local_addr()?),
        admin_token: None,
        source_node_id: "A".into(),
    };
    let (b_worker, destination_worker) = (Arc::clone(&b), Arc::clone(&destination));
    let server = std::thread::spawn(move || {
        destination_reply(&listener, &b_worker, &destination_worker, lose_reply)?;
        if lose_reply {
            destination_reply(&listener, &b_worker, &destination_worker, false)?;
        }
        Ok::<_, std::io::Error>(())
    });
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
    let forward = AsyncForwardContext {
        client: Some(&client),
        semaphore: &semaphore,
        timeout: std::time::Duration::from_secs(2),
    };
    let run = |at| {
        crate::migration_drain::tick(&state, &store, &mut String::new(), at, |row, now| {
            crate::migration_drain::forward(&state, &store, forward, row, now)
        })
    };
    run(now)?;
    if lose_reply {
        let held = store.migration_drain_page("moving", 0)?;
        assert_eq!(held.len(), 1, "lost reply is not an ACK");
        assert_eq!(held[0].state, MigrationDrainState::Held);
        assert_eq!(held[0].entry, row.entry);
        // A's reservation lease has expired by this retry, but B's durable tuple still dedups.
        run(held[0].next_attempt.max(now + forward.timeout.as_secs() + 1))?;
    }
    server.join().map_err(|_| "destination worker")??;
    assert_eq!(store.migration_drain_page("moving", 0)?, []);
    assert_eq!(b.resume("moving", 0, 10).len(), 1);
    let mut expected = row.entry.envelope;
    expected
        .ext
        .ext
        .insert(ramflux_node_core::HOME_NODE_FORWARD_COUNT_EXT_KEY.into(), serde_json::json!(1));
    assert_eq!(b.resume("moving", 0, 10)[0].envelope, expected);
    let progress = store.migration_backlog_progress(
        &row.account_anchor,
        &row.migration_id,
        ramflux_node_core::MigrationRole::Source,
    )?;
    assert_eq!((progress.remaining, progress.forwarded), (0, 1));
    assert_eq!(semaphore.available_permits(), 4);
    drop(b);
    drop(destination);
    let reopened = RouterRedbStore::open(dir.0.join("destination.redb"))?;
    assert_eq!(
        reopened.load_router()?.ok_or("destination snapshot")?.resume("moving", 0, 10).len(),
        1
    );
    Ok(())
}

#[test]
fn offline_sibling_backlog_drains_without_device_online() -> Result {
    durable_destination_retry(false)
}

#[test]
fn drain_lease_expiry_is_not_an_ack_and_does_not_duplicate_b_delivery() -> Result {
    durable_destination_retry(true)
}

#[test]
fn expired_lease_sender_entry_is_held_evidence_required_without_blocking_others() -> Result {
    let _guard = window_tests::FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = migration_tests::directory()?;
    let path = dir.0.join("expired-authority.redb");
    let now = seed(&path, 2)?;
    install_expired_authority(&path)?;
    let store = RouterRedbStore::open(path)?;
    let original = store.migration_drain_page("moving", 0)?[0].entry.clone();
    let state = ramflux_node_core::RouterCore::new();
    let b = Arc::new(ramflux_node_core::RouterCore::new());
    let destination = Arc::new(RouterRedbStore::open(dir.0.join("destination.redb"))?);
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: format!("http://{}/forward", listener.local_addr()?),
        admin_token: None,
        source_node_id: "A".into(),
    };
    let (b_worker, destination_worker) = (Arc::clone(&b), Arc::clone(&destination));
    let server = std::thread::spawn(move || {
        destination_reply(&listener, &b_worker, &destination_worker, false)
    });
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
    crate::migration_drain::tick(&state, &store, &mut String::new(), now, |row, now| {
        crate::migration_drain::forward(
            &state,
            &store,
            AsyncForwardContext {
                client: Some(&client),
                semaphore: &semaphore,
                timeout: std::time::Duration::from_secs(2),
            },
            row,
            now,
        )
    })?;
    server.join().map_err(|_| "destination worker")??;
    let rows = store.migration_drain_page("moving", 0)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, MigrationDrainState::Held);
    assert_eq!(rows[0].entry, original);
    assert!(rows[0].next_attempt > now);
    assert_eq!(b.resume("moving", 0, 10).len(), 1);
    assert_eq!(b.resume("moving", 0, 10)[0].envelope.envelope_id, "drain-2");
    Ok(())
}

pub(super) fn install_expired_authority(path: &std::path::Path) -> Result {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../crates/ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    let record: ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet> =
        serde_json::from_value(fixture["record"].clone())?;
    let reference = &record.body.master_certificate.body.primary_device_ref;
    let verified =
        ramflux_crypto::custody::verify_record(&record, record.body.issued_at, None, None)?;
    let cert = verified.authorize(reference, "message", record.body.issued_at)?;
    assert!(
        verified.authorize(reference, "message", ramflux_node_core::now_unix_seconds()).is_err()
    );
    let authority = ramflux_node_core::DeviceAuthKeyResponse {
        principal_id: record.body.principal_id.clone(),
        device_id: reference.device_id.clone(),
        device_epoch: reference.device_epoch,
        root_public_key: None,
        signed_device_set: None,
        branch_public_key: cert.branch_signing_public_key.clone(),
        target_delivery_id: ramflux_protocol::qualified_device_id(
            &record.body.account_anchor,
            &reference.device_id,
        )?,
        revoked: false,
        custody_authority: Some(Box::new(ramflux_protocol::custody::CustodyAuthority {
            publication: ramflux_protocol::custody::Publication {
                record: record.clone(),
                compacted_ids: None,
            },
            custodian_publication: None,
        })),
    };
    {
        let db = redb::Database::create(path)?;
        let tx = db.begin_write()?;
        let mut entries =
            tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_drain_entries_v1"))?;
        let key = format!("delivery/v1/{}/{:020}", ramflux_protocol::encode_base64url("moving"), 1);
        let mut row: MigrationDrainEntry =
            serde_json::from_slice(entries.get(key.as_str())?.ok_or("row")?.value())?;
        let envelope = &mut row.entry.envelope;
        envelope.source_principal_id.clone_from(&authority.principal_id);
        envelope.source_device_id.clone_from(&authority.device_id);
        envelope
            .ext
            .ext
            .insert("source_root_commitment".into(), serde_json::json!(record.body.account_anchor));
        envelope.ext.ext.insert("source_device_authority".into(), serde_json::to_value(authority)?);
        let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
        envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &ramflux_protocol::envelope_sender_signed_bytes(envelope)?,
            &branch,
        );
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::envelope_sender_signed_bytes(envelope)?,
            &envelope.signed.signature,
            &cert.branch_signing_public_key,
        )?;
        entries.insert(key.as_str(), serde_json::to_vec(&row)?.as_slice())?;
        drop(entries);
        tx.commit()?;
    }
    Ok(())
}

#[test]
fn drain_tick_publishes_terminal_settlement_to_live_inbox() -> Result {
    for expired in [false, true] {
        let dir = migration_tests::directory()?;
        let path = dir.0.join("live-projection.redb");
        // Populate the mailbox before installing the committed source-home fixture.
        let pending = ramflux_node_core::InboxEntry {
            inbox_seq: 1,
            target_delivery_id: "moving".into(),
            envelope: migration_tests::envelope("moving", "drain-1")?,
        };
        RouterRedbStore::open(&path)?.record_inbox_entry(&pending)?;
        let now = seed(&path, 1)?;
        let store = RouterRedbStore::open(&path)?;
        let row = store.migration_drain_page("moving", 0)?.remove(0);
        let state = store.load_router()?.ok_or("router snapshot")?;
        assert_eq!(state.resume("moving", 0, 10), vec![pending.clone()]);
        let at = if expired { u64::try_from(row.retain_until)? } else { now };
        let mut sent = false;
        assert_eq!(
            crate::migration_drain::tick(&state, &store, &mut String::new(), at, |_, _| {
                assert!(!expired, "expired entries must not be sent");
                assert_eq!(state.resume("moving", 0, 10), vec![pending.clone()]);
                sent = true;
                Ok(MigrationDrainOutcome::BAck)
            },)?,
            1
        );
        assert_eq!(sent, !expired);
        assert_eq!(state.resume("moving", 0, 10), []);
        assert_eq!(store.load_router()?.ok_or("rebuilt router")?.resume("moving", 0, 10), []);
    }
    Ok(())
}
