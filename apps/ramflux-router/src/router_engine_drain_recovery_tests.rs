// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Held obligations recover without changing sender bytes or starving other accounts.
use super::*;
use ramflux_node_core::{MigrationDrainEntry, MigrationDrainState, RouterCore, RouterRedbStore};
use redb::ReadableTable;
use std::{sync::Arc, time::Duration};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn run(
    store: &RouterRedbStore,
    state: &RouterCore,
    client: &crate::router_runtime::LocalFederationForwardClient,
    now: u64,
) -> Result<usize> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
    let count = crate::migration_drain::tick(store, &mut String::new(), now, |row, now| {
        crate::migration_drain::forward(
            state,
            store,
            AsyncForwardContext {
                client: Some(client),
                semaphore: &semaphore,
                timeout: Duration::from_secs(2),
            },
            row,
            now,
        )
    })?;
    assert_eq!(semaphore.available_permits(), 4);
    Ok(count)
}

fn listener() -> Result<(std::net::TcpListener, crate::router_runtime::LocalFederationForwardClient)>
{
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let client = crate::router_runtime::LocalFederationForwardClient {
        url: format!("http://{}/forward", listener.local_addr()?),
        admin_token: None,
        source_node_id: "A".into(),
    };
    Ok((listener, client))
}

#[test]
fn held_entry_forwards_after_sender_authority_refresh_within_window() -> Result {
    let _guard = window_tests::FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = migration_tests::directory()?;
    let path = dir.0.join("refresh.redb");
    let now = drain_tests::seed(&path, 1)?;
    drain_tests::install_expired_authority(&path)?;
    let store = RouterRedbStore::open(&path)?;
    let state = RouterCore::new();
    let original = store.migration_drain_page("moving", 0)?.remove(0);
    let (listener, client) = listener()?;
    assert_eq!(run(&store, &state, &client, now)?, 1);
    let held = store.migration_drain_page("moving", 0)?.remove(0);
    assert_eq!(held.state, MigrationDrainState::Held);
    assert_eq!(held.entry, original.entry);
    assert!(held.next_attempt > now);
    assert_eq!(listener.accept().err().map(|e| e.kind()), Some(std::io::ErrorKind::WouldBlock));
    let progress = store.migration_backlog_progress(
        &held.account_anchor,
        &held.migration_id,
        ramflux_node_core::MigrationRole::Source,
    )?;
    assert_eq!((progress.remaining, progress.evidence_required, progress.forwarded), (1, 1, 0));

    // Publish a genuine successor renewing the same branch, without editing the stored envelope.
    let authority: ramflux_node_core::DeviceAuthKeyResponse =
        serde_json::from_value(original.entry.envelope.ext.ext["source_device_authority"].clone())?;
    let old = authority.custody_authority.ok_or("native authority")?.publication.record;
    let primary = ramflux_crypto::custody::SelfSigningKey::from_vault_seed(&[2; 32].into());
    let current = ramflux_node_core::now_unix_seconds();
    let mut body = old.body.clone();
    body.device_set_epoch += 1;
    body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(&old)?);
    body.issued_at = current;
    let mut cert = body.devices[0].branch_certificate.take().ok_or("branch certificate")?.body;
    cert.not_before = current;
    cert.expires_at = current + 3600;
    cert.cert_id = ramflux_protocol::encode_base64url([99; 32]);
    body.devices[0].branch_certificate = Some(primary.certify_branch(cert)?);
    let publication = ramflux_node_core::CustodyPublication {
        record: primary.sign_record(body)?,
        compacted_ids: None,
    };
    state.publish_custody_record(&publication, current, &store)?;
    assert_eq!(store.migration_drain_page("moving", 0)?[0].entry, original.entry);
    // Respect bounded backoff even after authority becomes available.
    assert_eq!(run(&store, &state, &client, now)?, 0);
    assert_eq!(listener.accept().err().map(|e| e.kind()), Some(std::io::ErrorKind::WouldBlock));
    let b = Arc::new(RouterCore::new());
    let destination = Arc::new(RouterRedbStore::open(dir.0.join("destination.redb"))?);
    listener.set_nonblocking(false)?;
    let (b_worker, destination_worker) = (Arc::clone(&b), Arc::clone(&destination));
    let server = std::thread::spawn(move || {
        drain_tests::destination_reply(&listener, &b_worker, &destination_worker, false)
    });
    assert_eq!(run(&store, &state, &client, held.next_attempt)?, 1);
    assert_eq!(store.migration_drain_page("moving", 0)?, []);
    server.join().map_err(|_| "destination worker")??;
    let delivered = b.resume("moving", 0, 10);
    assert_eq!(delivered.len(), 1);
    let mut expected = original.entry.envelope;
    state.refresh_registered_envelope_authority(&mut expected)?;
    expected
        .ext
        .ext
        .insert(ramflux_node_core::HOME_NODE_FORWARD_COUNT_EXT_KEY.into(), serde_json::json!(1));
    assert_eq!(delivered[0].envelope, expected);
    let progress = store.migration_backlog_progress(
        &held.account_anchor,
        &held.migration_id,
        ramflux_node_core::MigrationRole::Source,
    )?;
    assert_eq!((progress.remaining, progress.evidence_required, progress.forwarded), (0, 0, 1));
    Ok(())
}

#[test]
fn poison_entry_does_not_stop_other_accounts_drain() -> Result {
    let _guard = window_tests::FORWARD_IO.lock().map_err(|_| "forward IO fixture lock")?;
    let dir = migration_tests::directory()?;
    let path = dir.0.join("accounts.redb");
    let now = drain_tests::seed(&path, 1)?;
    // A different account has retained work whose routing evidence is unavailable.
    // Its key precedes the healthy account, so aborting on its refusal masks healthy work.
    let poison = {
        let db = redb::Database::create(&path)?;
        let tx = db.begin_write()?;
        let mut entries =
            tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_drain_entries_v1"))?;
        let (_, bytes) = entries.iter()?.next().ok_or("healthy row")??;
        let mut row: MigrationDrainEntry = serde_json::from_slice(bytes.value())?;
        drop(bytes);
        row.account_anchor = "unavailable-account".into();
        row.migration_id = "unavailable-migration".into();
        row.entry.target_delivery_id = "a".into();
        row.entry.envelope = migration_tests::envelope("a", "poison")?;
        row.entry.envelope.signed.signature = "poison".into();
        entries
            .insert("delivery/v1/YQ/00000000000000000001", serde_json::to_vec(&row)?.as_slice())?;
        drop(entries);
        let cursor = ramflux_node_core::MigrationBacklogCursor {
            account_anchor: row.account_anchor.clone(),
            migration_id: row.migration_id.clone(),
            target_delivery_id: "a".into(),
            high_water: 1,
            next_seq: 1,
            progress: ramflux_protocol::home_migration::BacklogProgress {
                scheduled: 1,
                remaining: 1,
                ..Default::default()
            },
        };
        let key = serde_json::to_string(&(&row.account_anchor, &row.migration_id, "a"))?;
        tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("migration_backlog_cursor_v1"))?
            .insert(key.as_str(), serde_json::to_vec(&cursor)?.as_slice())?;
        tx.commit()?;
        row
    };
    let store = RouterRedbStore::open(&path)?;
    assert_eq!(store.migration_drain_work_page("")?[0].1, poison);
    let state = RouterCore::new();
    let b = Arc::new(RouterCore::new());
    let destination = Arc::new(RouterRedbStore::open(dir.0.join("destination.redb"))?);
    let (listener, client) = listener()?;
    listener.set_nonblocking(false)?;
    let (b_worker, destination_worker) = (Arc::clone(&b), Arc::clone(&destination));
    let server = std::thread::spawn(move || {
        drain_tests::destination_reply(&listener, &b_worker, &destination_worker, false)
    });
    assert_eq!(run(&store, &state, &client, now)?, 2);
    assert_eq!(store.migration_drain_page("moving", 0)?, []);
    server.join().map_err(|_| "destination worker")??;
    assert_eq!(b.resume("moving", 0, 10).len(), 1);
    let held = store.migration_drain_page("a", 0)?.remove(0);
    assert_eq!(held.entry, poison.entry);
    assert_eq!(held.state, MigrationDrainState::Held);
    assert!(held.next_attempt > now);
    drop(store);
    let store = RouterRedbStore::open(path)?;
    assert_eq!(store.migration_drain_page("a", 0)?[0], held);
    Ok(())
}

#[test]
fn permanent_drain_refusal_requires_destination_signature_and_matching_tuple() -> Result {
    let dir = migration_tests::directory()?;
    let path = dir.0.join("refused.redb");
    let now = drain_tests::seed(&path, 1)?;
    let store = RouterRedbStore::open(path)?;
    let state = RouterCore::new();
    let row = store.migration_drain_page("moving", 0)?.remove(0);
    let source = state.authenticated_envelope_source_from(
        &row.entry.envelope,
        Some(&store),
        ramflux_node_core::RouterEnvelopeOrigin::Federation,
    )?;
    let ramflux_node_core::RouterForwardPreparation::Forward(reservation) = state
        .prepare_committed_home_forward(&store, &source, row.entry.envelope.clone(), now, 2)?
    else {
        return Err("forward plan".into());
    };
    let plan = reservation.plan().ok_or("plan")?;
    let mut nack = ramflux_protocol::Nack {
        schema: "ramflux.nack.v1".into(),
        version: 1,
        domain: "ramflux.nack.v1".into(),
        ext: ramflux_protocol::Ext::default(),
        signed: row.entry.envelope.signed.clone(),
        nack_id: "permanent".into(),
        envelope_id: row.entry.envelope.envelope_id.clone(),
        receiver_device_id: "moving".into(),
        reason: ramflux_protocol::NackReason::RevokedCapability,
        received_at: i64::try_from(now)?,
        retry_after: None,
        proof_hash: None,
        new_home_node_hint: None,
    };
    nack.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(&nack)?,
        [9; 32],
    );
    let reply = ramflux_node_core::FederatedEnvelopeForwardResponse {
        accepted: false,
        source_node_id: "A".into(),
        target_node_id: plan.new_home_node.clone(),
        delivery: ramflux_node_core::EnvelopeSubmitResponse {
            migration_refusal: None,
            outcome: "rejected_security".into(),
            target_delivery_id: "moving".into(),
            inbox_seq: None,
            cursor: None,
            nack: Some(nack),
        },
    };
    assert!(crate::migration_drain::signed_permanent_refusal(plan, &reply));
    for alteration in 0..5 {
        let mut invalid = reply.clone();
        match alteration {
            0 => invalid.delivery.nack.as_mut().ok_or("nack")?.signed.signature = "forged".into(),
            1 => invalid.delivery.nack.as_mut().ok_or("nack")?.envelope_id = "other".into(),
            2 => invalid.delivery.target_delivery_id = "other".into(),
            3 => invalid.target_node_id = "other".into(),
            _ => invalid.delivery.nack = None,
        }
        assert!(!crate::migration_drain::signed_permanent_refusal(plan, &invalid));
    }
    let mut retryable = reply.clone();
    let nack = retryable.delivery.nack.as_mut().ok_or("nack")?;
    nack.reason = ramflux_protocol::NackReason::RateLimited;
    nack.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::signed_bytes(nack)?,
        [9; 32],
    );
    assert!(!crate::migration_drain::signed_permanent_refusal(plan, &retryable));
    store.settle_migration_drain(&row, ramflux_node_core::MigrationDrainOutcome::Rejected, now)?;
    let mut attempted = false;
    assert_eq!(
        crate::migration_drain::tick(&store, &mut String::new(), now + 1, |_, _| {
            attempted = true;
            Ok(ramflux_node_core::MigrationDrainOutcome::Held)
        })?,
        0
    );
    assert!(!attempted, "rejected entries must not retry");
    let retained = store.migration_drain_page("moving", 0)?.remove(0);
    assert_eq!(retained.entry, row.entry);
    assert_eq!(retained.state, MigrationDrainState::Rejected);
    let progress = store.migration_backlog_progress(
        &row.account_anchor,
        &row.migration_id,
        ramflux_node_core::MigrationRole::Source,
    )?;
    assert_eq!((progress.remaining, progress.rejected, progress.forwarded), (1, 1, 0));
    Ok(())
}
