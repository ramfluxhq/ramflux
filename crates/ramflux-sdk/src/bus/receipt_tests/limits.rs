// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retry bounds, revoked destinations and atomic admission never acknowledge unstored messages.
use super::{
    fixture::{self, Shared, Spec, TestResult},
    *,
};
use crate::client::delivery_receipts::{PREFIX, Work};
struct Pending {
    root: PathBuf,
    a: Spec,
    b: Spec,
    mail: Shared,
    receiver: LocalBusAccountState,
    key: String,
}
async fn pending(name: &str) -> Result<Pending, Box<dyn std::error::Error>> {
    let root = runtime_tests::root(name);
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let mut source = a.account(None, mail.clone())?;
    let mut engine = source.take_live_engine().await?;
    source
        .client
        .send_plaintext_direct_message_without_franking(
            &mut engine,
            a.message(&b, "first"),
            b"first",
            crate::client::routed::Route::direct(),
        )
        .await?;
    drop(engine);
    drop(source);
    let receipt = crate::client::delivery_receipts::id("thread", "first", &b.identity()?)?;
    mail.lock().map_err(|_| "mailbox")?.reject_id = Some(format!("receipt_evt_{receipt}"));
    let mut receiver = b.account(None, mail.clone())?;
    crate::bus::sync_driver::run(&mut receiver).await?;
    let key = receiver
        .client
        .account_db()?
        .actor_state_key_page(PREFIX, 256)?
        .into_iter()
        .next()
        .ok_or("pending")?;
    Ok(Pending { root, a, b, mail, receiver, key })
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
    assert_eq!(super::super::flush(&mut p.receiver).await?, 0);
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
    let mut engine = sender.take_live_engine().await?;
    sender
        .client
        .send_plaintext_direct_message_without_franking(
            &mut engine,
            p.a.message(&p.b, "second"),
            b"second",
            crate::client::routed::Route::direct(),
        )
        .await?;
    drop(engine);
    drop(sender);
    crate::bus::sync_driver::run(&mut p.receiver).await?;
    assert_eq!(
        p.receiver
            .client
            .delivery_receipt_status("thread", "second", &p.b.identity()?)?
            .ok_or("second status")?["state"],
        "sent"
    );
    for attempts in 2..=8 {
        ready(&p)?;
        assert_eq!(super::super::flush(&mut p.receiver).await?, 0);
        let work =
            p.receiver.client.account_db()?.load_actor_state::<Work>(&p.key)?.ok_or("work")?;
        assert_eq!(work.attempts, attempts);
        assert!(work.next_at > now_unix_timestamp());
    }
    ready(&p)?;
    assert_eq!(super::super::flush(&mut p.receiver).await?, 0);
    assert_eq!(
        p.receiver
            .client
            .delivery_receipt_status("thread", "first", &p.b.identity()?)?
            .ok_or("terminal")?["state"],
        "failed"
    );
    assert_eq!(p.receiver.client.account_db()?.actor_state_usage(PREFIX)?.0, 0);
    let second_id = format!(
        "receipt_evt_{}",
        crate::client::delivery_receipts::id("thread", "second", &p.b.identity()?)?
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
    std::fs::remove_dir_all(p.root)?;
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
        assert_eq!(super::super::flush(&mut p.receiver).await?, 0);
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
                .delivery_receipt_status("thread", "first", &p.b.identity()?)?
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
    let mut engine = source.take_live_engine().await?;
    let entry = source
        .client
        .send_plaintext_direct_message_without_franking(
            &mut engine,
            a.message(&b, "first"),
            b"first",
            crate::client::routed::Route::direct(),
        )
        .await?;
    drop(engine);
    drop(source);
    let mut receiver = b.account(None, mail)?;
    let mut engine = receiver.take_live_engine().await?;
    let pool = receiver.relay_quic_pool()?;
    backlog(&receiver.client, &a, &b)?;
    receiver.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
    assert_eq!(receiver.client.account_db()?.message_content("first")?, Some(b"first".to_vec()));
    assert_eq!(receiver.client.account_db()?.actor_state_usage(PREFIX)?.0, 257);
    drop(engine);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
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
    let receiver = b.client(None)?;
    for (spec, client) in [(&a, &source), (&b, &receiver)] {
        spec.trust(client, &a)?;
        spec.trust(client, &b)?;
        client.create_group("group", a.identity()?.storage_key())?;
        client.add_group_member_with_root(
            "group",
            &b.device,
            "member",
            b.identity()?.root_commitment(),
        )?;
    }
    receiver.import_group_sender_key_distribution(
        &source.export_group_sender_key_distribution("group", &a.device)?,
    )?;
    let raw = source.encrypt_group_message("group", &a.device, b"group body")?;
    let group: SdkGroupEncryptedEnvelope = serde_json::from_slice(&raw)?;
    let mut account = a.account(None, mail)?;
    let mut engine = account.take_live_engine().await?;
    let mut message = a.message(&b, "group-admission");
    let sealed = source
        .seal_routed_as(
            &mut engine,
            &message,
            &raw,
            crate::client::routed::Route::group_message("group"),
        )
        .await?;
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    let entry = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: b.device.clone(),
        envelope: gateway_direct_message_envelope(&engine.config, &message, None)?,
    };
    backlog(&receiver, &a, &b)?;
    let db = receiver.account_db()?;
    let aborted = db.write_transaction(|| -> Result<(), SdkError> {
        receiver.append_or_pending_group_message(
            "thread",
            "group-admission",
            &entry,
            &raw,
            &group,
        )?;
        Err(SdkError::LocalBus("injected commit abort".into()))
    });
    assert!(aborted.is_err());
    assert!(receiver.direct_message_by_id("group-admission")?.is_none());
    assert!(db.message_content("group-admission")?.is_none());
    assert_eq!(db.actor_state_usage(PREFIX)?.0, 256);
    assert_eq!(
        receiver.append_or_pending_group_message(
            "thread",
            "group-admission",
            &entry,
            &raw,
            &group
        )?,
        b"group body"
    );
    assert_eq!(db.message_content("group-admission")?, Some(b"group body".to_vec()));
    drop(engine);
    drop(account);
    drop(source);
    drop(receiver);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn own_principal_messages_never_stage_a_peer_delivery_receipt() -> TestResult {
    let root = runtime_tests::root("receipt-own-exclusion");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mail: Shared = Arc::new(Mutex::default());
    fixture::seed_pair(&a, &b)?;
    let mut source = a.account(None, mail)?;
    let engine = source.take_live_engine().await?;
    let mut message = a.message(&a, "own-message");
    message.recipient_device_id = Some("own-sibling".into());
    let entry = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: "own-sibling".into(),
        envelope: gateway_direct_message_envelope(&engine.config, &message, None)?,
    };
    source.client.stage_delivery_receipt("thread", "own-message", &entry)?;
    assert_eq!(source.client.account_db()?.actor_state_usage(PREFIX)?.0, 0);
    drop(engine);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
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
            .delivery_receipt_status("thread", "first", &p.b.identity()?)?
            .ok_or("sent")?["state"],
        "sent"
    );
    assert!(!p.receiver.client.account_db()?.actor_state_exists(&due_key)?);
    drop(p.receiver);
    std::fs::remove_dir_all(p.root)?;
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
    let mut engine = source.take_live_engine().await?;
    for id in ["first", "second"] {
        source
            .client
            .send_plaintext_direct_message_without_franking(
                &mut engine,
                a.message(&b, id),
                id.as_bytes(),
                crate::client::routed::Route::direct(),
            )
            .await?;
    }
    drop(engine);
    drop(source);
    mail.lock().map_err(|_| "mailbox")?.stall_receipts = true;
    let mut receiver = b.account(None, mail)?;
    tokio::time::timeout(Duration::from_secs(6), crate::bus::sync_driver::run(&mut receiver))
        .await??;
    for id in ["first", "second"] {
        assert_eq!(
            receiver.client.account_db()?.message_content(id)?,
            Some(id.as_bytes().to_vec())
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
    std::fs::remove_dir_all(root)?;
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
            assert!(account.engine.is_none());
        }
    }
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn a_receipt_deadline_retires_the_session_and_throttles_other_queue_entries() -> TestResult {
    let mut p = Box::pin(pending("receipt-deadline-retire")).await?;
    p.mail.lock().map_err(|_| "mailbox")?.stall_receipts = true;
    let mut work = ready(&p)?;
    work.packet = None;
    p.receiver.client.account_db()?.persist_actor_state(&p.key, &work)?;
    assert_eq!(flush(&mut p.receiver).await?, 0);
    assert!(p.receiver.engine.is_none(), "deadline must explicitly retire the uncertain session");
    let attempts =
        p.receiver.client.account_db()?.load_actor_state::<Work>(&p.key)?.ok_or("work")?.attempts;
    ready(&p)?;
    assert_eq!(flush(&mut p.receiver).await?, 0);
    assert!(p.receiver.engine.is_none());
    assert_eq!(
        p.receiver.client.account_db()?.load_actor_state::<Work>(&p.key)?.ok_or("work")?.attempts,
        attempts,
        "cooldown prevents another connect attempt"
    );
    drop(p.receiver);
    std::fs::remove_dir_all(p.root)?;
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
            json!({"conversation_id":"thread","message_id":"first","receiver_device_id":p.b.device}),
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
        assert!(retry.packet.is_none());
        assert_eq!(flush(receiver).await?, 1);
        assert_eq!(
            receiver
                .client
                .delivery_receipt_status("thread", "first", &p.b.identity()?)?
                .ok_or("status")?["state"],
            "sent"
        );
        drop(state);
        std::fs::remove_dir_all(p.root)?;
    }
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
    std::fs::remove_dir_all(p.root)?;
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
            assert!(crate::bus::sync_driver::run(&mut p.receiver).await? >= 1);
            assert!(!p.receiver.client.account_db()?.actor_state_exists(&p.key)?);
            assert_eq!(
                p.receiver
                    .client
                    .delivery_receipt_status("thread", "first", &p.b.identity()?)?
                    .ok_or("status")?["state"],
                "sent"
            );
            drop(p.receiver);
            std::fs::remove_dir_all(p.root)?;
            Ok(())
        }))
        .await
}
