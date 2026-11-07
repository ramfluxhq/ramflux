// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::too_many_lines, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! `sender_refusal_policy_task`: typed gateway refusals on the task courier (S3) and the
//! interactive task delivery (S4), through the real account actor, courier workers and a real
//! account DB reopen. Every expectation is an exact literal.
use super::fixture::{Case, Fixture};
use super::*;
use super::{
    Shutdown, ack, approval, approval_request, carrier, forward, intervention, runtime, serving,
};
use crate::bus::task_courier::{Item, TaskCourier};
use crate::bus::task_courier_apply::conflict_terminal;
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Row {
    Forward,
    Ack,
    Request,
    Decision,
}

impl Row {
    const fn key(self) -> &'static str {
        match self {
            Self::Forward => "task/forward/policy",
            Self::Ack => "task/ack/policy",
            Self::Request => "task/approval_out/policy",
            Self::Decision => "task/approval_decision_out/policy",
        }
    }
}

/// What a scenario leaves behind for assertions.
struct Done {
    account: LocalBusAccountState,
    attempts: Vec<ramflux_protocol::Envelope>,
    gateway: Arc<Mutex<super::fixture::Gateway>>,
    root: PathBuf,
    _peers: (LocalBusAccountState, LocalBusAccountState),
}

/// A real reopen: the account DB handle is dropped and unlocked again from disk.
fn reopen(account: &mut LocalBusAccountState) -> Case {
    account.client.active_account_db = None;
    account.client.unlock_account("sender", b"actor-test-secret")?;
    Ok(())
}

/// Runs the account actor until `done` holds for the committed row (or only lingers when
/// `done` is `None`), then stops it and returns the account.
async fn drive(
    account: LocalBusAccountState,
    root: &std::path::Path,
    done: Option<Box<dyn Fn(&AccountDb) -> Result<bool, SdkError>>>,
) -> Case<LocalBusAccountState> {
    let reader = account.client.account_db()?.open_reader()?;
    let (mut actor, _sender, stop, mut events) = runtime(account, &root.join("source"));
    if let Some(courier) = actor.courier.take() {
        courier.stop().await;
    }
    actor.courier = Some(TaskCourier::start());
    let driver = async {
        let _shutdown = Shutdown(stop.clone());
        super::pass(&mut events).await?;
        if let Some(done) = done {
            let mut waited = 0;
            while !done(&reader)? {
                assert!(waited < 300, "the courier never reached the expected state");
                waited += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        } else {
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (served, result) = tokio::join!(serving(&mut actor), driver);
    served?;
    result?;
    actor.state.accounts.remove("sender").ok_or_else(|| "account".into())
}

fn attempts_of(db: &AccountDb, key: &str) -> Result<Option<u64>, SdkError> {
    Ok(db
        .load_actor_state::<serde_json::Value>(key)?
        .map(|row| row["attempts"].as_u64().unwrap_or(0)))
}

async fn scenario(row: Row, nack: Option<&str>, nack_after: usize, conflict: bool) -> Case<Done> {
    let fixture = Box::pin(Fixture::new("courier-refusal-policy")).await?;
    let healthy = carrier(&fixture.source, "healthy", "healthy-task")?;
    let key = row.key();
    match row {
        Row::Ack => ack(&fixture.source, key, &healthy)?,
        Row::Forward => forward(&fixture.source, key, &healthy)?,
        Row::Request | Row::Decision => {
            // The approval needs the projected task: project it through a forward job, then
            // drop that job so only the approval row is under test.
            forward(&fixture.source, "task/forward/seed", &healthy)?;
            fixture.source.client.account_db()?.delete_task_state("task/forward/seed")?;
            intervention(&fixture.source, &fixture.peer)?;
            let request = approval_request(&fixture.source)?;
            let payload = if row == Row::Request {
                approval::Payload::Request { request }
            } else {
                approval::Payload::Decision { request, approved: false, grant_signature: None }
            };
            let packet = fixture.source.client.sign_task_approval(payload)?;
            fixture
                .source
                .client
                .account_db()?
                .persist_actor_state(key, &approval::Job { packet, attempts: 0, next_at: 0 })?;
        }
    }
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.nack_submit = nack.map(str::to_owned);
        gateway.nack_after = nack_after;
    }
    let Fixture { root, source, peer, sibling, gateway, .. } = fixture;
    let terminal_decision = row == Row::Decision && conflict;
    let done: Box<dyn Fn(&AccountDb) -> Result<bool, SdkError>> = if conflict && !terminal_decision
    {
        Box::new(move |db| Ok(!db.actor_state_exists(key)?))
    } else if terminal_decision {
        Box::new(move |db| Ok(attempts_of(db, key)? == Some(8)))
    } else {
        Box::new(move |db| Ok(attempts_of(db, key)?.is_some_and(|n| n >= 1)))
    };
    let mut account = drive(source, &root, Some(done)).await?;
    reopen(&mut account)?;
    let attempts = gateway.lock().map_err(|_| "gateway")?.attempts.clone();
    Ok(Done { account, attempts, gateway, root, _peers: (peer, sibling) })
}

/// After a reopen, a second actor run against a gateway that accepts everything writes nothing.
async fn assert_no_resend(done: &mut Done, expected: usize) -> Case {
    {
        let mut gateway = done.gateway.lock().map_err(|_| "gateway")?;
        gateway.nack_submit = None;
    }
    let account = std::mem::replace(&mut done.account, placeholder()?);
    done.account = drive(account, &done.root, None).await?;
    assert_eq!(done.gateway.lock().map_err(|_| "gateway")?.attempts.len(), expected);
    Ok(())
}

fn placeholder() -> Result<LocalBusAccountState, SdkError> {
    crate::bus::runtime_tests::account(
        &crate::bus::runtime_tests::root("courier-refusal-placeholder"),
        "placeholder",
        None,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )
}

fn dead(db: &AccountDb) -> Result<Vec<serde_json::Value>, SdkError> {
    Ok(db
        .task_record_page::<serde_json::Value>("task/courier_dead/", "task/courier_dead/", 16)?
        .into_iter()
        .map(|(_, value)| value)
        .collect())
}

fn failures(db: &AccountDb) -> Result<Vec<serde_json::Value>, SdkError> {
    Ok(db
        .task_record_page::<serde_json::Value>(
            "task/courier_failure/",
            "task/courier_failure/",
            16,
        )?
        .into_iter()
        .map(|(_, value)| value)
        .collect())
}

#[tokio::test]
async fn sender_refusal_policy_task() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let _guard = crate::bus::dispatch::task_transport::manifest_test_lock().lock().await;
            conflict_rows().await?;
            deferral_rows().await?;
            stale_revision_row().await?;
            Box::pin(task_delivery_rows()).await
        }))
        .await
}

async fn conflict_rows() -> Case {
    // (a1) Forward and (a2) Ack rows: the job is gone, one dead record carries the exact
    // reason, the count is 1, and nothing is resent after a reopen.
    for row in [Row::Forward, Row::Ack] {
        let mut done = Box::pin(scenario(row, Some("idempotency_conflict"), 0, true)).await?;
        let db = done.account.client.account_db()?;
        assert!(!db.actor_state_exists(row.key())?);
        let records = dead(db)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["reason"], "submit_conflict");
        assert_eq!(records[0]["id"], row.key());
        assert_eq!(db.load_actor_state::<u64>("task/courier_dead_count")?, Some(1));
        assert_eq!(failures(db)?.len(), 0);
        assert_eq!(done.attempts.len(), 1, "one submit was written");
        assert_eq!(
            crate::bus::task_courier_queue::manifest_requests(&mut done.account)?.len(),
            0,
            "nothing selects the retired row"
        );
        assert_no_resend(&mut done, 1).await?;
    }

    // (a4) Approval Request + Conflict: job gone, dead record, no decision row touched.
    let mut done = Box::pin(scenario(Row::Request, Some("idempotency_conflict"), 0, true)).await?;
    let db = done.account.client.account_db()?;
    assert!(!db.actor_state_exists(Row::Request.key())?);
    assert_eq!(dead(db)?.len(), 1);
    assert_eq!(dead(db)?[0]["reason"], "submit_conflict");
    assert_eq!(done.account.client.task_approval_decision_rows()?.len(), 0);
    assert_no_resend(&mut done, 1).await?;

    // (a3) Approval Decision + Conflict: the signed job stays under its key, ineligible
    // (`attempts = 8`), the receipt is `failed / submit_conflict`, no dead record exists, and
    // nothing is resent after a reopen.
    let mut done = Box::pin(scenario(Row::Decision, Some("idempotency_conflict"), 0, true)).await?;
    let db = done.account.client.account_db()?;
    let job: approval::Job =
        db.load_actor_state(Row::Decision.key())?.ok_or("the decision job was dropped")?;
    assert_eq!(job.attempts, 8);
    let rows = done.account.client.task_approval_decision_rows()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["delivery_state"], "failed");
    assert_eq!(rows[0]["reason_code"], "submit_conflict");
    assert_eq!(dead(db)?.len(), 0);
    let records = failures(db)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["reason"], "submit_conflict");
    assert_eq!(records[0]["attempts"], 8);
    assert_eq!(done.attempts.len(), 1);
    assert_no_resend(&mut done, 1).await?;
    // (a3b) A manual retry with the same choice re-enqueues the unchanged signed decision
    // once, and the courier then delivers it.
    let id = job.packet.id()?;
    let retried =
        done.account.client.decide_task_approval(&format!("task_approval_{id}"), false)?;
    assert_eq!(retried["delivery_state"], "pending");
    let again: approval::Job =
        done.account.client.account_db()?.load_actor_state(Row::Decision.key())?.ok_or("job")?;
    assert_eq!(again.attempts, 0);
    assert_eq!(serde_json::to_value(&again.packet)?, serde_json::to_value(&job.packet)?);
    reopen(&mut done.account)?;
    let account = std::mem::replace(&mut done.account, placeholder()?);
    done.account = drive(
        account,
        &done.root,
        Some(Box::new(|db| Ok(!db.actor_state_exists(Row::Decision.key())?))),
    )
    .await?;
    assert_eq!(done.gateway.lock().map_err(|_| "gateway")?.attempts.len(), 2);
    // (a3d) the opposite choice is refused as consumed.
    let refused = done.account.client.decide_task_approval(&format!("task_approval_{id}"), true);
    assert!(refused.is_err());

    // (a6) A multi-envelope plan with the conflict on the 2nd envelope: the job is terminal
    // and the envelopes after the 2nd are never sent.
    let done = Box::pin(scenario(Row::Ack, Some("idempotency_conflict"), 1, true)).await?;
    assert_eq!(done.attempts.len(), 2, "the conflict came on the second envelope");
    let db = done.account.client.account_db()?;
    assert!(!db.actor_state_exists(Row::Ack.key())?);
    assert_eq!(dead(db)?.len(), 1);
    Ok(())
}

async fn deferral_rows() -> Case {
    // (b) Capacity on a Forward row, (c) RetrySafe on an Approval Request row, (d) an
    // unclassified failure on a Forward row: today's charged retry, the row kept.
    for (row, nack) in [
        (Row::Forward, "capacity_retry_after"),
        (Row::Request, "aborted_retry_safe"),
        (Row::Forward, "rejected_security"),
    ] {
        let before = now_unix_timestamp();
        let mut done = Box::pin(scenario(row, Some(nack), 0, false)).await?;
        let db = done.account.client.account_db()?;
        let saved: serde_json::Value = db.load_actor_state(row.key())?.ok_or("row kept")?;
        assert_eq!(saved["attempts"], 1, "{nack}");
        let next = saved["next_at"].as_i64().ok_or("next_at")?;
        assert!(next >= before + 2, "{nack}: next_at {next}");
        let records = failures(db)?;
        assert_eq!(records.len(), 1, "{nack}");
        assert_eq!(records[0]["reason"], "application");
        assert_eq!(records[0]["attempts"], 1);
        assert_eq!(dead(db)?.len(), 0);
        assert_eq!(done.attempts.len(), 1, "{nack}");
        assert_no_resend(&mut done, 1).await?;
    }
    Ok(())
}

async fn stale_revision_row() -> Case {
    // (a5) The job is rewritten between plan and result: `conflict_terminal` changes nothing.
    let fixture = Box::pin(Fixture::new("courier-refusal-stale")).await?;
    let healthy = carrier(&fixture.source, "healthy", "healthy-task")?;
    forward(&fixture.source, Row::Forward.key(), &healthy)?;
    let (_, revision) =
        crate::bus::task_courier_queue::load(&fixture.source, Row::Forward.key())?.ok_or("job")?;
    let item =
        Item { key: Row::Forward.key().into(), revision, requests: Vec::new(), failure: None };
    let mut job: crate::client::task::control::ForwardJob =
        fixture.source.client.account_db()?.load_actor_state(Row::Forward.key())?.ok_or("job")?;
    job.attempts = 3;
    fixture.source.client.account_db()?.persist_actor_state(Row::Forward.key(), &job)?;
    conflict_terminal(&fixture.source, &item)?;
    let db = fixture.source.client.account_db()?;
    assert_eq!(attempts_of(db, Row::Forward.key())?, Some(3));
    assert_eq!(dead(db)?.len(), 0);
    assert_eq!(db.load_actor_state::<u64>("task/courier_dead_count")?, None);
    std::fs::remove_dir_all(&fixture.root)?;
    Ok(())
}

async fn task_delivery_rows() -> Case {
    // (e1) S4 Conflict and (e2) S4 Capacity: the interactive send fails with the gateway's
    // exact reason and the task takes its existing `failed / task_transport_error` branch;
    // no courier row is created and nothing is resent.
    for nack in ["idempotency_conflict", "capacity_retry_after"] {
        let mut fixture = Box::pin(Fixture::new("courier-refusal-s4")).await?;
        let first = carrier(&fixture.source, "healthy", "healthy-task")?;
        fixture.gateway.lock().map_err(|_| "gateway")?.nack_submit = Some(nack.to_owned());
        let result = crate::bus::dispatch::task_transport::send(&mut fixture.source, &first).await;
        assert!(
            matches!(&result, Err(SdkError::GatewaySessionRejected(reason)) if reason == nack),
            "{nack}: {result:?}"
        );
        let view: serde_json::Value = fixture
            .source
            .client
            .account_db()?
            .load_actor_state(&crate::client::task::scoped("view", "healthy", "healthy-task")?)?
            .ok_or("task view")?;
        assert_eq!(view["delivery_state"], "failed", "{nack}");
        assert_eq!(view["delivery_error"], "task_transport_error", "{nack}");
        let db = fixture.source.client.account_db()?;
        for prefix in ["task/ack/", "task/forward/", "task/approval_out/"] {
            assert_eq!(db.actor_state_key_page(prefix, 4)?.len(), 0, "{nack}: {prefix}");
        }
        assert_eq!(fixture.gateway.lock().map_err(|_| "gateway")?.attempts.len(), 1, "{nack}");
        fixture.gateway.lock().map_err(|_| "gateway")?.nack_submit = None;
        let _ = fixture.peer;
        std::fs::remove_dir_all(&fixture.root)?;
    }
    Ok(())
}
