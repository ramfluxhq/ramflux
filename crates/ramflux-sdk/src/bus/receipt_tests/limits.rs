// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retry bounds, revoked destinations and atomic admission never acknowledge unstored messages.
use super::{
    fixture::{self, Shared, Spec, TestResult},
    *,
};
use crate::client::delivery_receipts::{PREFIX, Work};
struct Pending {
    a: Spec,
    b: Spec,
    mail: Shared,
    receiver: LocalBusAccountState,
    key: String,
    root: ramflux_test_support::TestPath,
}
async fn pending(name: &str) -> Result<Pending, Box<dyn std::error::Error>> {
    let root = runtime_tests::root(name);
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let mut source = a.account(None, mail.clone())?;
    let mut engine = source.session_client().await?;
    a.send_text(&source.client, &mut engine, a.message(&b, "first"), b"first").await?;
    drop(engine);
    drop(source);
    let receipt = crate::client::delivery_receipts::id(
        &a.conversation(&b)?,
        &a.event("first")?,
        &b.identity()?,
    )?;
    mail.lock().map_err(|_| "mailbox")?.reject_id = Some(format!("receipt_evt_{receipt}"));
    let mut receiver = b.account(None, mail.clone())?;
    crate::bus::sync_driver::run(&mut receiver).await?;
    super::super::background::test_flush(&mut receiver).await?;
    let key = receiver
        .client
        .account_db()?
        .actor_state_key_page(PREFIX, 256)?
        .into_iter()
        .next()
        .ok_or("pending")?;
    Ok(Pending { a, b, mail, receiver, key, root })
}
fn ready(p: &Pending) -> Result<Work, SdkError> {
    let mut work = p
        .receiver
        .client
        .account_db()?
        .load_actor_state::<Work>(&p.key)?
        .ok_or(SdkError::IdentityRootMissing)?;
    work.next_at = 0;
    p.receiver.client.account_db()?.persist_actor_state(&p.key, &work)?;
    Ok(work)
}
fn backlog(client: &RamfluxClient, a: &Spec, b: &Spec) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let root = db
        .client_record("device", &a.device)?
        .and_then(|row| row["principal_commitment"].as_str().map(str::to_owned));
    for n in 0..256 {
        db.persist_actor_state(
            &format!("{PREFIX}placeholder-{n}"),
            &Work {
                status_id: format!("old-{n}"),
                conversation: "thread".into(),
                message: format!("old-{n}"),
                wire_message: None,
                receiver: b.identity()?.storage_key().into(),
                sender: a.identity()?.storage_key().into(),
                root: root.clone(),
                at: now_unix_timestamp(),
                sealed_at: now_unix_timestamp(),
                retry_from: now_unix_timestamp(),
                attempts: 1,
                next_at: now_unix_timestamp() + 60,
                packet: None,
            },
        )?;
    }
    Ok(())
}
#[tokio::test]
async fn a_failed_receipt_is_backed_off_without_blocking_another_message_and_stops_after_eight_attempts()
-> TestResult {
    let mut p = Box::pin(pending("receipt-bounds")).await?;
    let mut first =
        p.receiver.client.account_db()?.load_actor_state::<Work>(&p.key)?.ok_or("first work")?;
    assert_eq!(first.attempts, 1);
    assert!(first.next_at > first.at);
    // This test advances retries explicitly with ready(). Unrelated crypto/storage work must
    // not consume an attempt merely because the real wall clock crossed the backoff deadline.
    first.next_at = i64::MAX;
    p.receiver.client.account_db()?.persist_actor_state(&p.key, &first)?;
    assert_eq!(super::super::background::test_flush(&mut p.receiver).await?, 0);
    assert_eq!(
        p.mail
            .lock()
            .map_err(|_| "mailbox")?
            .submissions
            .iter()
            .filter(|e| e.source_device_id == p.b.device)
            .count(),
        1
    );
    // Hold the first receipt so the sync below cannot retry it on a slow runner.
    let mut held = ready(&p)?;
    held.next_at = now_unix_timestamp() + 3600;
    p.receiver.client.account_db()?.persist_actor_state(&p.key, &held)?;
    let mut sender = p.a.account(None, p.mail.clone())?;
    let mut engine = sender.session_client().await?;
    p.a.send_text(&sender.client, &mut engine, p.a.message(&p.b, "second"), b"second").await?;
    drop(engine);
    drop(sender);
    crate::bus::sync_driver::run(&mut p.receiver).await?;
    super::super::background::test_flush(&mut p.receiver).await?;
    assert_eq!(
        p.receiver
            .client
            .delivery_receipt_status(
                &p.a.conversation(&p.b)?,
                &p.a.event("second")?,
                &p.b.identity()?
            )?
            .ok_or("second status")?["state"],
        "sent"
    );
    for attempts in 2..=8 {
        ready(&p)?;
        assert_eq!(super::super::background::test_flush(&mut p.receiver).await?, 0);
        let work =
            p.receiver.client.account_db()?.load_actor_state::<Work>(&p.key)?.ok_or("work")?;
        assert_eq!(work.attempts, attempts);
        assert!(work.next_at > now_unix_timestamp());
    }
    ready(&p)?;
    assert_eq!(super::super::background::test_flush(&mut p.receiver).await?, 0);
    assert_eq!(
        p.receiver
            .client
            .delivery_receipt_status(
                &p.a.conversation(&p.b)?,
                &p.a.event("first")?,
                &p.b.identity()?
            )?
            .ok_or("terminal")?["state"],
        "failed"
    );
    assert_eq!(p.receiver.client.account_db()?.actor_state_usage(PREFIX)?.0, 0);
    let second_id = format!(
        "receipt_evt_{}",
        crate::client::delivery_receipts::id(
            &p.a.conversation(&p.b)?,
            &p.a.event("second")?,
            &p.b.identity()?
        )?
    );
    let packets = p
        .mail
        .lock()
        .map_err(|_| "mailbox")?
        .submissions
        .iter()
        .filter(|e| e.source_device_id == p.b.device && e.envelope_id != second_id)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(packets.len(), 8);
    assert!(packets.windows(2).all(|pair| pair[0] == pair[1]));
    let failures = p
        .receiver
        .client
        .account_db()?
        .journal_after(0, 128)?
        .into_iter()
        .filter(|e| e.topic == "message.delivery_receipt.failed")
        .count();
    assert_eq!(failures, 1);
    drop(p.receiver);
    Ok(())
}
#[tokio::test]
async fn expired_revoked_or_rebound_receipts_are_retired_without_reusing_a_prepared_packet()
-> TestResult {
    for reason in ["expired", "revoked", "rebound"] {
        let mut p = Box::pin(pending(&format!("receipt-{reason}"))).await?;
        let mut work = ready(&p)?;
        if reason == "expired" {
            work.at = now_unix_timestamp() - 601;
            work.retry_from = work.at;
            p.receiver.client.account_db()?.persist_actor_state(&p.key, &work)?;
        } else if reason == "revoked" {
            p.receiver.client.account_db()?.persist_actor_state(
                &format!("device/revoked/{}", p.a.identity()?.storage_key()),
                &true,
            )?;
        } else {
            let mut foreign = Spec::new(&p.root, "mallory", 71);
            foreign.device.clone_from(&p.a.device);
            p.b.trust(&p.receiver.client, &foreign)?;
            work.sender = foreign.identity()?.storage_key().into();
            p.receiver.client.account_db()?.persist_actor_state(&p.key, &work)?;
        }
        assert_eq!(super::super::background::test_flush(&mut p.receiver).await?, 0);
        assert_eq!(
            p.mail
                .lock()
                .map_err(|_| "mailbox")?
                .submissions
                .iter()
                .filter(|e| e.source_device_id == p.b.device)
                .count(),
            1,
            "terminal receipt reason: {reason}"
        );
        assert_eq!(
            p.receiver
                .client
                .delivery_receipt_status(
                    &p.a.conversation(&p.b)?,
                    &p.a.event("first")?,
                    &p.b.identity()?
                )?
                .ok_or("terminal")?["state"],
            "failed"
        );
        drop(p.receiver);
        std::fs::remove_dir_all(p.root)?;
    }
    Ok(())
}
#[tokio::test]
async fn a_receipt_backlog_never_blocks_the_authenticated_dm_commit() -> TestResult {
    let root = runtime_tests::root("receipt-admission");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let mut source = a.account(None, mail.clone())?;
    let mut engine = source.session_client().await?;
    let entry = a.send_text(&source.client, &mut engine, a.message(&b, "first"), b"first").await?;
    drop(engine);
    drop(source);
    let mut receiver = b.account(None, mail)?;
    let mut engine = receiver.session_client().await?;
    let pool = receiver.relay_quic_pool()?;
    backlog(&receiver.client, &a, &b)?;
    receiver.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
    assert_eq!(
        receiver
            .client
            .generated_message_detail(&a.conversation(&b)?, &a.event("first")?)?
            .message
            .text
            .as_deref(),
        Some("first"),
        "authenticated generated plaintext must commit behind the receipt backlog"
    );
    assert_eq!(receiver.client.account_db()?.actor_state_usage(PREFIX)?.0, 257);
    drop(engine);
    drop(receiver);
    Ok(())
}

#[tokio::test]
async fn group_storage_and_its_receipt_remain_atomic_with_a_large_backlog() -> TestResult {
    let root = runtime_tests::root("receipt-group-admission");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let source = a.client(None)?;
    let target = b.client(None)?;
    a.prepare_group(&source, "group", "thread", &[(&b, &target)])?;
    let mut account = a.account(None, mail.clone())?;
    let id =
        Box::pin(a.send_group_text(&mut account, "group", "group-admission", "group body")).await?;
    target.import_group_sender_key_distribution(
        &account.client.export_group_sender_key_distribution("group", &a.device)?,
    )?;
    drop(source);
    drop(target);
    let mut receiver = b.account(None, mail.clone())?;
    let entry = mail
        .lock()
        .map_err(|_| "mailbox")?
        .messages
        .iter()
        .rev()
        .find(|entry| entry.target_delivery_id == receiver.target_delivery_id)
        .cloned()
        .ok_or("group delivery")?;
    let mut engine = receiver.session_client().await?;
    let pool = receiver.relay_quic_pool()?;
    backlog(&receiver.client, &a, &b)?;
    let aborted = Box::pin(receiver.client.apply_routed_entry_joining(
        &mut engine,
        &pool,
        &entry,
        None,
        |client, write| {
            client.account_db()?.write_transaction(|| {
                client.persist_routed_projection_for_fixture(write)?;
                Err(SdkError::LocalBus("injected commit abort".into()))
            })
        },
    ))
    .await;
    assert!(
        matches!(aborted, Err(SdkError::LocalBus(reason)) if reason == "injected commit abort"),
        "native group receive must reach the transactional abort"
    );
    assert!(
        receiver.client.direct_message_by_id(&id)?.is_none(),
        "aborted group projection leaked"
    );
    assert!(
        receiver.client.account_db()?.message_content(&id)?.is_none(),
        "aborted generated plaintext leaked"
    );
    assert_eq!(
        receiver.client.account_db()?.actor_state_usage(PREFIX)?.0,
        256,
        "receipt must roll back with the group message"
    );
    Box::pin(receiver.client.apply_routed_entry(&mut engine, &pool, &entry, false)).await?;
    assert_eq!(
        receiver.client.generated_message_detail("thread", &id)?.message.text.as_deref(),
        Some("group body"),
        "committed native group content must reach the durable reader"
    );
    assert_eq!(
        receiver.client.account_db()?.actor_state_usage(PREFIX)?.0,
        257,
        "one receipt must commit with the native group message"
    );
    Ok(())
}
#[tokio::test]
async fn own_principal_messages_never_stage_a_peer_delivery_receipt() -> TestResult {
    Box::pin(crate::client::native_test_support::live_own_copy::exercise(false)).await
}

#[tokio::test]
async fn a_page_of_backed_off_receipts_cannot_hide_later_due_work() -> TestResult {
    let mut p = Box::pin(pending("receipt-paged-progress")).await?;
    let mut work = ready(&p)?;
    p.receiver.client.account_db()?.remove_actor_state(&p.key)?;
    p.receiver.client.account_db()?.remove_actor_state(super::super::SCAN_CURSOR)?;
    let due_key = format!("{PREFIX}zzzz");
    p.receiver.client.account_db()?.persist_actor_state(&due_key, &work)?;
    work.next_at = now_unix_timestamp() + 3600;
    for n in 0..256 {
        p.receiver
            .client
            .account_db()?
            .persist_actor_state(&format!("{PREFIX}blocked-{n:03}"), &work)?;
    }
    p.mail.lock().map_err(|_| "mailbox")?.reject_id = None;
    assert_eq!(super::super::flush(&mut p.receiver).await?, 0);
    assert_eq!(super::super::flush(&mut p.receiver).await?, 1);
    assert_eq!(
        p.receiver
            .client
            .delivery_receipt_status(
                &p.a.conversation(&p.b)?,
                &p.a.event("first")?,
                &p.b.identity()?
            )?
            .ok_or("sent")?["state"],
        "sent"
    );
    assert!(!p.receiver.client.account_db()?.actor_state_exists(&due_key)?);
    drop(p.receiver);
    Ok(())
}

#[tokio::test]
async fn stalled_receipts_cannot_consume_the_whole_sync_pass_or_prevent_message_storage()
-> TestResult {
    let root = runtime_tests::root("receipt-stall-progress");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let mut source = a.account(None, mail.clone())?;
    let mut engine = source.session_client().await?;
    for id in ["first", "second"] {
        a.send_text(&source.client, &mut engine, a.message(&b, id), id.as_bytes()).await?;
    }
    drop(engine);
    drop(source);
    mail.lock().map_err(|_| "mailbox")?.stall_receipts = true;
    let mut receiver = b.account(None, mail)?;
    // Start the deadline after setup and measure timer behavior on the paused runtime clock.
    // Database/crypto work under host load must not consume the receipt courier deadline.
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(6), async {
        crate::bus::sync_driver::run(&mut receiver).await?;
        super::super::background::test_flush(&mut receiver).await
    })
    .await??;
    assert!(started.elapsed() >= Duration::from_secs(3));
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(
        receiver
            .connection
            .as_ref()
            .is_none_or(crate::bus::connection_manager::ConnectionHandle::retirement_requested),
        "the stalled receipt session must be retired"
    );
    for id in ["first", "second"] {
        assert_eq!(
            receiver
                .client
                .generated_message_detail(&a.conversation(&b)?, &a.event(id)?)?
                .message
                .text
                .as_deref(),
            Some(id)
        );
    }
    let db = receiver.client.account_db()?;
    let mut attempts = Vec::new();
    for key in db.actor_state_key_page(PREFIX, 256)? {
        attempts.push(db.load_actor_state::<Work>(&key)?.ok_or("work")?.attempts);
    }
    attempts.sort_unstable();
    assert_eq!(attempts, vec![0, 1]);
    drop(receiver);
    Ok(())
}

#[tokio::test]
async fn an_empty_receipt_queue_never_allocates_journal_events_or_requires_a_live_connection()
-> TestResult {
    let root = runtime_tests::root("empty-receipt-queue");
    let spec = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    let mut account = spec.account(None, mail)?;
    account.engine = None;
    for previous_cursor in [None, Some(format!("{PREFIX}retired"))] {
        if let Some(cursor) = previous_cursor {
            account.client.account_db()?.persist_actor_state(SCAN_CURSOR, &cursor)?;
        }
        let before = account.client.account_db()?.journal_bounds()?.head_seq;
        let usage = account.client.account_db()?.actor_state_usage("delivery-receipt/")?;
        for _ in 0..32 {
            assert_eq!(flush(&mut account).await?, 0);
            assert_eq!(account.client.account_db()?.journal_bounds()?.head_seq, before);
            assert_eq!(account.client.account_db()?.actor_state_usage("delivery-receipt/")?, usage);
            assert!(account.connection.as_ref().is_none_or(
                crate::bus::connection_manager::ConnectionHandle::retirement_requested
            ));
        }
    }
    drop(account);
    Ok(())
}

#[tokio::test]
async fn a_receipt_deadline_retires_the_session_and_throttles_other_queue_entries() -> TestResult {
    let mut p = Box::pin(pending("receipt-deadline-retire")).await?;
    p.mail.lock().map_err(|_| "mailbox")?.stall_receipts = true;
    let mut work = ready(&p)?;
    work.packet = None;
    p.receiver.client.account_db()?.persist_actor_state(&p.key, &work)?;
    assert_eq!(super::super::background::test_flush(&mut p.receiver).await?, 0);
    assert!(
        p.receiver
            .connection
            .as_ref()
            .is_none_or(crate::bus::connection_manager::ConnectionHandle::retirement_requested),
        "deadline must explicitly retire the uncertain session"
    );
    let attempts =
        p.receiver.client.account_db()?.load_actor_state::<Work>(&p.key)?.ok_or("work")?.attempts;
    ready(&p)?;
    assert_eq!(super::super::background::test_flush(&mut p.receiver).await?, 0);
    assert!(
        p.receiver
            .connection
            .as_ref()
            .is_none_or(crate::bus::connection_manager::ConnectionHandle::retirement_requested)
    );
    assert_eq!(
        p.receiver.client.account_db()?.load_actor_state::<Work>(&p.key)?.ok_or("work")?.attempts,
        attempts,
        "cooldown prevents another connect attempt"
    );
    drop(p.receiver);
    Ok(())
}

#[tokio::test]
async fn an_explicit_receipt_request_restages_failed_work_and_the_courier_delivers_it() -> TestResult
{
    for legacy in [false, true] {
        let mut p = Box::pin(pending(if legacy {
            "receipt-explicit-retry-legacy"
        } else {
            "receipt-explicit-retry"
        }))
        .await?;
        let mut work = ready(&p)?;
        work.attempts = 8;
        p.receiver.client.account_db()?.persist_actor_state(&p.key, &work)?;
        assert_eq!(flush(&mut p.receiver).await?, 0);
        assert!(!p.receiver.client.account_db()?.actor_state_exists(&p.key)?);
        if legacy {
            let status_key = format!("delivery-receipt/status/{}", work.status_id);
            let mut status: serde_json::Value =
                p.receiver.client.account_db()?.load_actor_state(&status_key)?.ok_or("status")?;
            status.as_object_mut().ok_or("status object")?.remove("retry_work");
            p.receiver.client.account_db()?.persist_actor_state(&status_key, &status)?;
        }
        // Dispatch the real explicit method, without a manual target route.
        let mut state = LocalBusDaemonState {
            account_index: None,
            nodes: crate::node::NodeStore::load(&p.root, &[])?,
            config: LocalBusConfig::new(p.root.join("socket"), &p.root),
            accounts: BTreeMap::new(),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        };
        state.accounts.insert(p.b.principal.clone(), p.receiver);
        let (outbound, _) = mpsc::channel(1);
        let connection = LocalBusConnectionState::new(1, outbound);
        let request = LocalBusFrame::request(
            "retry",
            Some(p.b.principal.clone()),
            "test",
            "message.receipt.delivered",
            json!({"conversation_id":p.a.conversation(&p.b)?,"message_id":p.a.event("first")?,"receiver_device_id":p.b.device}),
        );
        let response =
            crate::bus::dispatch::dispatch_message_bus_request(&request, &mut state, &connection)
                .await?;
        assert_eq!(response.response_body["delivery_receipt_state"], "pending");
        assert!(response.response_body["delivered_at"].as_i64().is_some());
        assert_eq!(response.response_body["ttl_seconds"], 300);
        p.mail.lock().map_err(|_| "mailbox")?.reject_id = None;
        let receiver = state.accounts.get_mut(&p.b.principal).ok_or("receiver")?;
        let retry = receiver
            .client
            .account_db()?
            .load_actor_state::<Work>(&p.key)?
            .ok_or("restaged work")?;
        assert_eq!(retry.attempts, 0);
        assert_eq!(retry.sealed_at, retry.at, "a restage inside the TTL keeps the envelope time");
        assert_eq!(flush(receiver).await?, 1, "legacy={legacy}: the restaged receipt is delivered");
        assert_eq!(
            receiver
                .client
                .delivery_receipt_status(
                    &p.a.conversation(&p.b)?,
                    &p.a.event("first")?,
                    &p.b.identity()?
                )?
                .ok_or("status")?["state"],
            "sent"
        );
        drop(state);
        std::fs::remove_dir_all(p.root)?;
    }
    Ok(())
}

#[tokio::test]
async fn an_explicit_retry_across_a_second_boundary_resends_the_cached_receipt_packet() -> TestResult
{
    let start = now_unix_timestamp();
    let _clock = crate::time::FixedClock::set(start);
    let mut p = Box::pin(pending("receipt-retry-boundary")).await?;
    let mut work = ready(&p)?;
    assert_eq!(work.at, start, "the receipt identity is the time of its first seal");
    work.attempts = 8;
    p.receiver.client.account_db()?.persist_actor_state(&p.key, &work)?;
    assert_eq!(flush(&mut p.receiver).await?, 0);
    assert!(!p.receiver.client.account_db()?.actor_state_exists(&p.key)?, "work retired as failed");
    let first_seal = p
        .mail
        .lock()
        .map_err(|_| "mailbox")?
        .submissions
        .last()
        .cloned()
        .ok_or("the first attempt reached the gateway and was refused")?;
    // The retry lands in a later second than the first seal.
    crate::time::FixedClock::advance_to(start + 5);
    p.mail.lock().map_err(|_| "mailbox")?.reject_id = None;
    let restaged = p.receiver.client.restage_failed_delivery_receipt(
        &p.a.conversation(&p.b)?,
        &p.a.event("first")?,
        &p.b.identity()?,
    )?;
    assert_eq!(restaged, Some(start), "the restaged receipt keeps its original identity time");
    let retry = p.receiver.client.account_db()?.load_actor_state::<Work>(&p.key)?.ok_or("work")?;
    assert_eq!((retry.at, retry.retry_from, retry.attempts), (start, start + 5, 0));
    assert_eq!(flush(&mut p.receiver).await?, 1, "the retry sends instead of ReplayMismatch");
    let sent = p
        .mail
        .lock()
        .map_err(|_| "mailbox")?
        .submissions
        .last()
        .cloned()
        .ok_or("the retry reached the gateway")?;
    assert_eq!(sent, first_seal, "the exact cached packet is retransmitted");
    drop(p.receiver);
    Ok(())
}

/// Wall-clock deadline for a whole scenario, cleanup included: the scenario future and its
/// fixtures are dropped on expiry, so no temporary directory outlives a timeout.
async fn bounded(
    name: &str,
    scenario: impl std::future::Future<Output = TestResult>,
) -> TestResult {
    match tokio::time::timeout(Duration::from_secs(90), scenario).await {
        Ok(outcome) => outcome,
        Err(_) => Err(format!("{name} exceeded its 90 s deadline").into()),
    }
}

fn install_gateway_guard(p: &Pending) -> TestResult {
    let mut mail = p.mail.lock().map_err(|_| "mailbox")?;
    mail.guard = Some(ramflux_node_core::NodeReplayGuardState::new());
    mail.guard_sources = vec![p.a.identity()?, p.b.identity()?];
    mail.reject_id = None;
    Ok(())
}

/// Exhausts the attempts of the first receipt so it ends `failed`, and returns its first seal.
async fn fail_first_receipt(
    p: &mut Pending,
    start: i64,
) -> Result<ramflux_protocol::Envelope, Box<dyn std::error::Error>> {
    let mut work = ready(p)?;
    assert_eq!(work.at, start, "the receipt identity is the time of its first seal");
    assert_eq!(work.sealed_at, start, "the first envelope is created at the identity time");
    work.attempts = 8;
    p.receiver.client.account_db()?.persist_actor_state(&p.key, &work)?;
    assert_eq!(flush(&mut p.receiver).await?, 0);
    assert!(!p.receiver.client.account_db()?.actor_state_exists(&p.key)?, "work retired as failed");
    Ok(p.mail
        .lock()
        .map_err(|_| "mailbox")?
        .submissions
        .last()
        .cloned()
        .ok_or("the first attempt reached the gateway and was refused")?)
}

#[tokio::test]
async fn a_receipt_retry_within_the_envelope_ttl_sends_identical_bytes_through_the_real_gateway_guard()
-> TestResult {
    Box::pin(bounded(stringify!(a_receipt_retry_within_the_envelope_ttl_sends_identical_bytes_through_the_real_gateway_guard), Box::pin(a_receipt_retry_within_the_envelope_ttl_sends_identical_bytes_through_the_real_gateway_guard_scenario()))).await
}

async fn a_receipt_retry_within_the_envelope_ttl_sends_identical_bytes_through_the_real_gateway_guard_scenario()
-> TestResult {
    let start = now_unix_timestamp();
    let _clock = crate::time::FixedClock::set(start);
    let mut p = Box::pin(pending("receipt-retry-within-ttl")).await?;
    let first_seal = fail_first_receipt(&mut p, start).await?;
    install_gateway_guard(&p)?;
    crate::time::FixedClock::advance_to(start + 300);
    let restaged = p.receiver.client.restage_failed_delivery_receipt(
        &p.a.conversation(&p.b)?,
        &p.a.event("first")?,
        &p.b.identity()?,
    )?;
    assert_eq!(restaged, Some(start));
    assert_eq!(flush(&mut p.receiver).await?, 1, "the real gateway guard accepts the retry");
    let sent = p.mail.lock().map_err(|_| "mailbox")?.submissions.last().cloned().ok_or("sent")?;
    assert_eq!(sent, first_seal, "within the TTL the cached sealed bytes are resent unchanged");
    drop(p.receiver);
    Ok(())
}

#[tokio::test]
async fn a_receipt_retry_after_the_envelope_ttl_is_resealed_with_the_same_identity_and_recorded_once()
-> TestResult {
    Box::pin(bounded(stringify!(a_receipt_retry_after_the_envelope_ttl_is_resealed_with_the_same_identity_and_recorded_once), Box::pin(a_receipt_retry_after_the_envelope_ttl_is_resealed_with_the_same_identity_and_recorded_once_scenario()))).await
}

async fn a_receipt_retry_after_the_envelope_ttl_is_resealed_with_the_same_identity_and_recorded_once_scenario()
-> TestResult {
    let start = now_unix_timestamp();
    let _clock = crate::time::FixedClock::set(start);
    let mut p = Box::pin(pending("receipt-retry-after-ttl")).await?;
    let first_seal = fail_first_receipt(&mut p, start).await?;
    install_gateway_guard(&p)?;
    let later = start + 601;
    crate::time::FixedClock::advance_to(later);
    // The real guard refuses the stale envelope, which is exactly why a retry must re-seal.
    let mut stale = ramflux_node_core::NodeReplayGuardState::new();
    let stale_refusal =
        stale.accept_envelope_once(&p.b.identity()?, &first_seal, later).err().ok_or("stale")?;
    assert!(
        matches!(stale_refusal, ramflux_node_core::NodeCoreError::TtlExpired { .. }),
        "the cached envelope is past created_at + ttl: {stale_refusal}"
    );
    let restaged = p.receiver.client.restage_failed_delivery_receipt(
        &p.a.conversation(&p.b)?,
        &p.a.event("first")?,
        &p.b.identity()?,
    )?;
    assert_eq!(restaged, Some(start), "the logical receipt identity is unchanged");
    assert_eq!(flush(&mut p.receiver).await?, 1, "the real gateway guard accepts the fresh seal");
    let sent = p.mail.lock().map_err(|_| "mailbox")?.submissions.last().cloned().ok_or("sent")?;
    assert_ne!(sent, first_seal, "the expired envelope is re-sealed");
    assert_eq!(sent.created_at, later, "the transport carries a fresh created_at");
    assert_eq!(sent.envelope_id, first_seal.envelope_id, "the receipt envelope id is stable");
    assert_eq!(
        p.receiver
            .client
            .delivery_receipt_status(
                &p.a.conversation(&p.b)?,
                &p.a.event("first")?,
                &p.b.identity()?
            )?
            .ok_or("status")?["delivered_at"],
        start,
        "delivered_at keeps the identity time"
    );
    // The recipient deduplicates by the logical identity: exactly one delivered receipt.
    let mut alice = p.a.account(None, p.mail.clone())?;
    crate::bus::sync_driver::run(&mut alice).await?;
    let row = alice.client.direct_message_by_id(&p.a.event("first")?)?.ok_or("alice row")?;
    assert_eq!(row.receipts.len(), 1, "the recipient records exactly one receipt");
    assert_eq!(row.receipts[0].state, "delivered");
    drop(alice);
    drop(p.receiver);
    Ok(())
}

#[tokio::test]
async fn a_backwards_clock_step_cannot_extend_the_receipt_gateway_cooldown() -> TestResult {
    let mut p = Box::pin(pending("receipt-clock-step")).await?;
    ready(&p)?;
    p.mail.lock().map_err(|_| "mailbox")?.reject_id = None;
    p.receiver
        .client
        .account_db()?
        .persist_actor_state(GATEWAY_RETRY_AT, &now_unix_timestamp().saturating_add(3600))?;
    assert_eq!(flush(&mut p.receiver).await?, 1);
    assert!(!p.receiver.client.account_db()?.actor_state_exists(GATEWAY_RETRY_AT)?);
    drop(p.receiver);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_receipt_retention_metadata_does_not_abort_the_sync_pass() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut p = Box::pin(pending("receipt-retention-failure")).await?;
            ready(&p)?;
            p.mail.lock().map_err(|_| "mailbox")?.reject_id = None;
            p.receiver.client.account_db()?.persist_actor_state(
                "delivery-receipt/retention-cursor",
                &json!(["invalid legacy cursor"]),
            )?;
            assert!(
                p.receiver
                    .client
                    .account_db()?
                    .retain_delivery_receipts(now_unix_timestamp(), 128)
                    .is_err()
            );
            crate::bus::sync_driver::run(&mut p.receiver).await?;
            assert!(super::super::background::test_flush(&mut p.receiver).await? >= 1);
            assert!(!p.receiver.client.account_db()?.actor_state_exists(&p.key)?);
            assert_eq!(
                p.receiver
                    .client
                    .delivery_receipt_status(
                        &p.a.conversation(&p.b)?,
                        &p.a.event("first")?,
                        &p.b.identity()?
                    )?
                    .ok_or("status")?["state"],
                "sent"
            );
            drop(p.receiver);
            std::fs::remove_dir_all(p.root)?;
            Ok(())
        }))
        .await
}
