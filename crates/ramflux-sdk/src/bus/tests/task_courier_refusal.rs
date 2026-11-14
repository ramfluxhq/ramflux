// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::large_futures,
    clippy::type_complexity
)]

//! `sender_refusal_policy_task`: typed gateway refusals on the task courier (S3) and the
//! interactive task delivery (S4), through the real account actor, courier workers and a real
//! account DB reopen. Every expectation is an exact literal.
//!
//! Time is controlled, not waited for: the SDK clock is frozen and advanced explicitly, and the
//! courier runs only the passes the test allows, each acknowledged by its `Finished` event. The
//! only waits are condition polls on committed rows with a 15 s hanging guard that panics.
use super::fixture::{Case, Fixture};
use super::*;
use super::{
    Shutdown, ack, approval, approval_request, carrier, forward, intervention, pass, runtime,
    serving,
};
use crate::bus::task_courier::{Item, TaskCourier};
use crate::bus::task_courier_apply::conflict_terminal;
use crate::bus::task_courier_queue as queue;
use ramflux_storage::durability_test_hooks::{Registration, observe};
use tokio::sync::watch;

#[path = "task_courier_refusal_decision.rs"]
mod decision;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Row {
    Forward,
    Ack,
    Request,
}

impl Row {
    const fn key(self) -> &'static str {
        match self {
            Self::Forward => "task/forward/policy",
            Self::Ack => "task/ack/policy",
            Self::Request => "task/approval_out/policy",
        }
    }
}

/// What a scenario's actor waits for after its single allowed pass.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The row is gone: delivered or quarantined.
    Gone,
    /// The row was charged once and kept.
    Charged,
    /// The write is stalled and times out: the envelope was written once, the session is
    /// retired, and the unchanged row is selected and delivered by a later pass.
    TimedOut,
}

/// The scripted gateway and fixture for one scenario.
#[derive(Clone, Copy)]
struct Script {
    nack: Option<&'static str>,
    /// The first this-many submits are accepted before `nack` applies.
    after: usize,
    /// The gateway reads each submit and never answers it.
    stall: bool,
    /// The conversation has three delivery targets instead of two.
    three: bool,
    /// The gateway frame timeout of the sender session.
    frame_wait: Option<Duration>,
    expect: Expect,
}

const CONFLICT: &str = "idempotency_conflict";

impl Script {
    const fn conflict() -> Self {
        Self {
            nack: Some(CONFLICT),
            after: 0,
            stall: false,
            three: false,
            frame_wait: None,
            expect: Expect::Gone,
        }
    }

    const fn charged(nack: &'static str) -> Self {
        Self { nack: Some(nack), expect: Expect::Charged, ..Self::conflict() }
    }
}

/// What a scenario leaves behind for assertions.
struct Done {
    account: LocalBusAccountState,
    gateway: Arc<Mutex<super::fixture::Gateway>>,
    /// The frozen clock the scenario started at.
    start: i64,
    cut: Option<Cut>,
    _peers: Vec<LocalBusAccountState>,
    root: ramflux_test_support::TestPath,
}

impl Done {
    fn wire(&self) -> usize {
        self.gateway.lock().unwrap().attempts.len()
    }
}

/// A real reopen: the account DB handle is dropped and unlocked again from disk.
fn reopen(account: &mut LocalBusAccountState) -> Case {
    account.client.active_account_db = None;
    account.client.unlock_account("sender", b"actor-test-secret")?;
    Ok(())
}

/// A live account actor whose courier runs only the passes the test allows.
struct Run {
    sender: mpsc::Sender<AccountCommand>,
    events: mpsc::UnboundedReceiver<CourierEvent>,
    reader: AccountDb,
    wake: mpsc::Sender<()>,
    control: watch::Sender<u64>,
    allowed: u64,
}

impl Run {
    /// A local-bus command through the actor, with the typed error kept.
    async fn call(
        &self,
        method: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        let (reply, received) = oneshot::channel();
        let (outbound, _) = mpsc::channel(1);
        self.sender
            .send(AccountCommand {
                admission: None,
                private: None,
                request: LocalBusFrame::request(
                    method,
                    Some("sender".into()),
                    "test",
                    method,
                    body,
                ),
                connection_id: 1,
                topics: BTreeSet::new(),
                attended: true,
                nodes: None,
                outbound: outbound.into(),
                reply: Some(reply),
            })
            .await
            .expect("the actor stopped");
        tokio::time::timeout(Duration::from_secs(15), received)
            .await
            .expect("no actor reply within 15 s")
            .expect("the actor dropped the reply")
            .map(|response| response.body)
    }

    /// Allows exactly one more courier pass and returns the items it prepared once the
    /// pass is acknowledged as `Finished`.
    async fn step(&mut self) -> Case<Vec<(String, u32, bool)>> {
        self.allowed += 1;
        self.control.send(self.allowed)?;
        let _ = self.wake.try_send(());
        let items = pass(&mut self.events).await?;
        assert!(
            items.iter().all(|(_, _, charged)| !charged),
            "a preparation was charged: {items:?}"
        );
        Ok(items)
    }

    /// `count` acknowledged passes that select nothing.
    async fn idle(&mut self, count: usize) -> Case {
        for _ in 0..count {
            let items = self.step().await?;
            assert!(items.is_empty(), "an idle pass selected {items:?}");
        }
        Ok(())
    }

    /// Polls committed rows until `done` holds; a 15 s hanging guard panics with the rows.
    async fn until(&self, what: &str, done: impl Fn(&AccountDb) -> Result<bool, SdkError>) -> Case {
        let guard = tokio::time::Instant::now() + Duration::from_secs(15);
        while !done(&self.reader)? {
            assert!(
                tokio::time::Instant::now() < guard,
                "{what}: never reached; rows {:?}",
                rows(&self.reader)?
            );
            tokio::task::yield_now().await;
        }
        Ok(())
    }
}

fn rows(db: &AccountDb) -> Result<Vec<(String, serde_json::Value, serde_json::Value)>, SdkError> {
    Ok(db
        .task_record_page::<serde_json::Value>("task/", "task/", 40)?
        .into_iter()
        .map(|(key, value)| (key, value["attempts"].clone(), value["reason"].clone()))
        .collect())
}

/// Runs one account actor with a courier that waits for explicit passes, drives `body`
/// against it, then stops it and returns the account.
async fn with_actor(
    account: LocalBusAccountState,
    root: &std::path::Path,
    timeouts: impl FnOnce(&mut crate::bus::runtime_limits::RuntimeTimeouts),
    body: impl AsyncFnOnce(&mut Run) -> Case,
) -> Case<LocalBusAccountState> {
    let reader = account.client.account_db()?.open_reader()?;
    let (mut actor, sender, stop, events) = runtime(account, &root.join("source"));
    timeouts(&mut actor.timeouts);
    if let Some(courier) = actor.courier.take() {
        courier.stop().await;
    }
    let courier = TaskCourier::with_limits(Duration::from_secs(5), 4);
    let control = courier.test_pass_control();
    control.send(0)?;
    let wake = courier.wake_sender();
    actor.courier = Some(courier);
    let mut run = Run { sender, events, reader, wake, control, allowed: 0 };
    let driver = async {
        let _shutdown = Shutdown(stop.clone());
        body(&mut run).await?;
        stop.send(true)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (served, result) = tokio::join!(serving(&mut actor), driver);
    served?;
    result?;
    // A real shutdown retires the connection manager; a stale one would keep sending its
    // checkpoints to this actor's closed channel when the account is served again.
    actor.stop_connection().await;
    actor.state.accounts.remove("sender").ok_or_else(|| "account".into())
}

fn attempts_of(db: &AccountDb, key: &str) -> Result<Option<u64>, SdkError> {
    Ok(db
        .load_actor_state::<serde_json::Value>(key)?
        .map(|row| row["attempts"].as_u64().unwrap_or(0)))
}

fn records(db: &AccountDb, prefix: &str) -> Result<Vec<serde_json::Value>, SdkError> {
    Ok(db
        .task_record_page::<serde_json::Value>(prefix, prefix, 16)?
        .into_iter()
        .map(|(_, value)| value)
        .collect())
}

fn dead(db: &AccountDb) -> Result<Vec<serde_json::Value>, SdkError> {
    records(db, "task/courier_dead/")
}

fn failures(db: &AccountDb) -> Result<Vec<serde_json::Value>, SdkError> {
    records(db, "task/courier_failure/")
}

/// Every durable fact a terminal conflict transition writes, read at one instant.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Shape {
    job: Option<u64>,
    dead: usize,
    dead_count: Option<u64>,
    failures: usize,
    receipt: Option<(String, Option<String>)>,
    /// `task.changed` journal entries whose `reason_code` is `submit_conflict`.
    conflicts: usize,
}

impl Shape {
    fn of(db: &AccountDb, key: &str) -> Result<Self, SdkError> {
        let receipt = records(db, "task/approval_receipt/").map(|rows| {
            rows.first().map(|row| {
                (
                    row["delivery_state"].as_str().unwrap_or_default().to_owned(),
                    row["reason_code"].as_str().map(str::to_owned),
                )
            })
        })?;
        Ok(Self {
            job: attempts_of(db, key)?,
            dead: dead(db)?.len(),
            dead_count: db.load_actor_state::<u64>("task/courier_dead_count")?,
            failures: failures(db)?.len(),
            receipt,
            conflicts: db
                .journal_after(0, 128)?
                .iter()
                .filter(|event| {
                    event.topic == "task.changed" && event.body["reason_code"] == "submit_conflict"
                })
                .count(),
        })
    }

    /// An Ack, Forward or Approval Request row before its conflict.
    const fn queued() -> Self {
        Self { job: Some(0), dead: 0, dead_count: None, failures: 0, receipt: None, conflicts: 0 }
    }

    /// The same row after: gone, one dead record, count 1.
    fn quarantined() -> Self {
        Self { job: None, dead: 1, dead_count: Some(1), ..Self::queued() }
    }
}

/// An observer between each SQL `RELEASE` and the outer `COMMIT` of the account DB: it reads
/// the committed rows through an independent connection at every boundary.
struct Cut {
    seen: Arc<Mutex<Vec<(String, bool, Shape)>>>,
    _registration: Registration,
}

impl Cut {
    fn install(db: &AccountDb, key: &str) -> Case<Self> {
        let reader = Mutex::new(db.open_reader()?);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let key = key.to_owned();
        let registration = observe(
            db.path.clone(),
            Arc::new(move |sql, completed, _autocommit| {
                if !(sql.starts_with("RELEASE") || sql == "COMMIT") {
                    return Ok(());
                }
                // The observer also fires for the reader's own commits: skip those.
                let Ok(reader) = reader.try_lock() else { return Ok(()) };
                if let Ok(shape) = Shape::of(&reader, &key) {
                    log.lock().unwrap().push((sql.to_owned(), completed, shape));
                }
                Ok(())
            }),
        )?;
        Ok(Self { seen, _registration: registration })
    }

    /// The transition is one commit: every boundary saw the complete old or the complete new
    /// state, a `RELEASE` was seen before it, and the new state first appears at the `COMMIT`.
    fn assert_atomic(&self, old: &Shape, new: &Shape) {
        let seen = self.seen.lock().unwrap();
        assert!(
            seen.iter().all(|(_, _, shape)| shape == old || shape == new),
            "a boundary saw a partial state: {seen:#?}"
        );
        let first = seen
            .iter()
            .position(|(_, _, shape)| shape == new)
            .unwrap_or_else(|| panic!("the new state was never observed: {seen:#?}"));
        assert!(
            seen[first..].iter().all(|(_, _, shape)| shape == new),
            "the state went back: {seen:#?}"
        );
        assert_eq!((seen[first].0.as_str(), seen[first].1), ("COMMIT", true), "{seen:#?}");
        assert_eq!(
            (seen[first - 1].0.as_str(), seen[first - 1].1),
            ("COMMIT", false),
            "the last boundary before the new state is the pending outer COMMIT: {seen:#?}"
        );
        assert!(
            seen[..first].iter().any(|(sql, done, _)| sql.starts_with("RELEASE") && *done),
            "no RELEASE boundary before the commit: {seen:#?}"
        );
    }
}

async fn scenario(row: Row, script: Script) -> Case<Done> {
    let start = now_unix_timestamp();
    let fixture =
        Box::pin(Fixture::build("courier-refusal-policy", script.three, script.frame_wait)).await?;
    let healthy = carrier(&fixture.source, "healthy", "healthy-task")?;
    let key = row.key();
    match row {
        Row::Ack => ack(&fixture.source, key, &healthy)?,
        Row::Forward => forward(&fixture.source, key, &healthy)?,
        Row::Request => {
            // The approval needs the projected task: project it through a forward job, then
            // drop that job so only the approval row is under test.
            forward(&fixture.source, "task/forward/seed", &healthy)?;
            fixture.source.client.account_db()?.delete_task_state("task/forward/seed")?;
            intervention(&fixture.source, &fixture.peer)?;
            let request = approval_request(&fixture.source)?;
            let packet =
                fixture.source.client.sign_task_approval(approval::Payload::Request { request })?;
            fixture
                .source
                .client
                .account_db()?
                .persist_actor_state(key, &approval::Job { packet, attempts: 0, next_at: 0 })?;
        }
    }
    {
        let mut gateway = fixture.gateway.lock().map_err(|_| "gateway")?;
        gateway.nack_submit = script.nack.map(str::to_owned);
        gateway.nack_after = script.after;
        gateway.stall_submit = script.stall;
    }
    let Fixture { root, source, peer, sibling, peer2, gateway, .. } = fixture;
    let cut = if script.nack == Some(CONFLICT) {
        Some(Cut::install(source.client.account_db()?, key)?)
    } else {
        None
    };
    let account = with_actor(
        source,
        &root,
        |timeouts| {
            if let Some(wait) = script.frame_wait {
                timeouts.task_submit = wait * 10;
            }
        },
        async |run| {
            let items = run.step().await?;
            assert_eq!(items, vec![(key.to_owned(), 0, false)], "one eligible row, never charged");
            if script.expect == Expect::TimedOut {
                return timed_out(run, &gateway, key).await;
            }
            run.until(
                &format!(
                    "the {key} row settles (nack {:?}, stall {}, after {})",
                    script.nack, script.stall, script.after
                ),
                |db| match script.expect {
                    Expect::Gone => Ok(!db.actor_state_exists(key)?),
                    Expect::Charged => Ok(attempts_of(db, key)?.is_some_and(|n| n >= 1)),
                    Expect::TimedOut => Ok(false),
                },
            )
            .await
        },
    )
    .await?;
    let mut account = account;
    reopen(&mut account)?;
    let mut peers = vec![peer, sibling];
    peers.extend(peer2);
    Ok(Done { account, gateway, start, cut, _peers: peers, root })
}

/// The first write stalls and the sender's frame times out: the envelope was written once, the
/// session is retired (so its late result is for a stale connection and is dropped), the row is
/// untouched and eligible, and passes keep selecting it until one delivers it on a fresh session.
async fn timed_out(
    run: &mut Run,
    gateway: &Arc<Mutex<super::fixture::Gateway>>,
    key: &str,
) -> Case {
    let guard = tokio::time::Instant::now() + Duration::from_secs(15);
    while gateway.lock().unwrap().attempts.is_empty() {
        assert!(tokio::time::Instant::now() < guard, "the stalled write never reached the gateway");
        tokio::task::yield_now().await;
    }
    gateway.lock().unwrap().stall_submit = false;
    while gateway.lock().unwrap().attempts.len() < 2 {
        assert!(tokio::time::Instant::now() < guard, "the row was never selected and resent");
        let items = run.step().await?;
        assert!(items.iter().all(|item| item.0 == key && item.1 == 0), "{items:?}");
    }
    run.until("the resent row is delivered", |db| Ok(!db.actor_state_exists(key)?)).await
}

/// After a reopen, three acknowledged passes against a gateway that accepts everything select
/// nothing and write nothing.
async fn assert_idle(done: &mut Done, wire: usize) -> Case {
    {
        let mut gateway = done.gateway.lock().map_err(|_| "gateway")?;
        gateway.nack_submit = None;
        gateway.stall_submit = false;
    }
    let account = std::mem::replace(&mut done.account, placeholder()?);
    done.account = with_actor(account, &done.root, |_| {}, async |run| run.idle(3).await).await?;
    assert_eq!(done.wire(), wire);
    assert_eq!(queue::manifest_requests(&mut done.account)?.len(), 0, "nothing selects the row");
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

#[tokio::test]
async fn sender_refusal_policy_task() -> Case {
    let _clock = crate::time::FixedClock::set(now_unix_timestamp());
    LocalSet::new()
        .run_until(Box::pin(async {
            let _guard = crate::bus::dispatch::task_transport::manifest_test_lock().lock().await;
            conflict_rows().await?;
            Box::pin(decision::lifecycle_rows()).await?;
            envelope_rows().await?;
            deferral_rows().await?;
            stale_revision_row().await?;
            Box::pin(task_delivery_rows()).await
        }))
        .await
}

async fn conflict_rows() -> Case {
    // (a1) Forward, (a2) Ack and (a4) Approval Request rows: the job is gone, one dead record
    // carries the exact reason, the count is 1, no failure record exists, one submit was
    // written, the whole transition was one commit, and nothing is resent after a reopen.
    for row in [Row::Forward, Row::Ack, Row::Request] {
        let mut done = Box::pin(scenario(row, Script::conflict())).await?;
        let db = done.account.client.account_db()?;
        assert!(!db.actor_state_exists(row.key())?);
        let records = dead(db)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["reason"], "submit_conflict");
        assert_eq!(records[0]["id"], row.key());
        assert_eq!(db.load_actor_state::<u64>("task/courier_dead_count")?, Some(1));
        assert_eq!(failures(db)?.len(), 0);
        assert_eq!(done.account.client.task_approval_decision_rows()?.len(), 0, "no receipt");
        assert_eq!(done.wire(), 1, "one submit was written");
        done.cut.as_ref().ok_or("cut")?.assert_atomic(&Shape::queued(), &Shape::quarantined());
        assert_idle(&mut done, 1).await?;
    }
    Ok(())
}

async fn envelope_rows() -> Case {
    // (a6) An Ack plan has three envelopes (sibling, peer, second peer). The control accepts
    // all three; the conflict on the 2nd stops the plan, so the 3rd is never sent.
    let control = Script { nack: None, three: true, ..Script::conflict() };
    let mut done = Box::pin(scenario(Row::Ack, control)).await?;
    assert_eq!(done.wire(), 3, "the control delivers every envelope");
    let db = done.account.client.account_db()?;
    assert!(!db.actor_state_exists(Row::Ack.key())?);
    assert_eq!(dead(db)?.len(), 0);
    assert_eq!(failures(db)?.len(), 0);
    assert_eq!(db.actor_state_key_page("task/ack_sent/", 4)?.len(), 1, "the ack is marked sent");
    assert_idle(&mut done, 3).await?;

    let second = Script { after: 1, three: true, ..Script::conflict() };
    let mut done = Box::pin(scenario(Row::Ack, second)).await?;
    assert_eq!(done.wire(), 2, "the conflict came on the second envelope; the third was not sent");
    let db = done.account.client.account_db()?;
    assert!(!db.actor_state_exists(Row::Ack.key())?);
    assert_eq!(dead(db)?.len(), 1);
    assert_eq!(dead(db)?[0]["reason"], "submit_conflict");
    assert_eq!(db.actor_state_key_page("task/ack_sent/", 4)?.len(), 0, "never marked sent");
    done.cut.as_ref().ok_or("cut")?.assert_atomic(&Shape::queued(), &Shape::quarantined());
    assert_idle(&mut done, 2).await
}

async fn deferral_rows() -> Case {
    // (b) Capacity on a Forward row and (c) RetrySafe on an Approval Request row: today's
    // charged retry, the row kept, next attempt exactly 2 s after the frozen clock, and not
    // before.
    for (row, name, script) in [
        (Row::Forward, "capacity", Script::charged("capacity_retry_after")),
        (Row::Request, "retry_safe", Script::charged("aborted_retry_safe")),
    ] {
        let mut done = Box::pin(scenario(row, script)).await?;
        let db = done.account.client.account_db()?;
        let saved: serde_json::Value = db.load_actor_state(row.key())?.ok_or("row kept")?;
        assert_eq!(saved["attempts"], 1, "{name}");
        assert_eq!(saved["next_at"], done.start + 2, "{name}");
        let records = failures(db)?;
        assert_eq!(records.len(), 1, "{name}");
        assert_eq!(records[0]["reason"], "application", "{name}");
        assert_eq!(records[0]["attempts"], 1, "{name}");
        assert_eq!(dead(db)?.len(), 0, "{name}");
        assert_eq!(done.wire(), 1, "{name}: the envelope was written once");
        // Not eligible until the clock is advanced through the backoff.
        for at in [done.start, done.start + 1] {
            crate::time::FixedClock::advance_to(at);
            assert!(queue::item(&done.account, row.key(), at)?.is_none(), "{name} at {at}");
        }
        crate::time::FixedClock::advance_to(done.start + 2);
        assert!(queue::item(&done.account, row.key(), done.start + 2)?.is_some(), "{name}");
        // Once eligible and accepted, the retry is delivered exactly once more.
        {
            let mut gateway = done.gateway.lock().map_err(|_| "gateway")?;
            gateway.nack_submit = None;
        }
        let account = std::mem::replace(&mut done.account, placeholder()?);
        done.account = with_actor(
            account,
            &done.root,
            |_| {},
            async |run| {
                let items = run.step().await?;
                assert_eq!(items, vec![(row.key().to_owned(), 1, false)]);
                run.until("the retry is delivered", |db| Ok(!db.actor_state_exists(row.key())?))
                    .await
            },
        )
        .await?;
        assert_eq!(done.wire(), 2, "{name}");
        crate::time::FixedClock::advance_to(done.start);
    }
    // (d) A real frame timeout after the write on a Forward row.
    let timeout = Script {
        nack: None,
        stall: true,
        frame_wait: Some(Duration::from_millis(300)),
        expect: Expect::TimedOut,
        ..Script::conflict()
    };
    let mut done = Box::pin(scenario(Row::Forward, timeout)).await?;
    let db = done.account.client.account_db()?;
    assert!(!db.actor_state_exists(Row::Forward.key())?, "the resent row completed");
    assert_eq!(dead(db)?.len(), 0, "an uncertain write is never terminal");
    assert_eq!(done.wire(), 2, "written once, stalled, then resent once");
    assert_idle(&mut done, 2).await
}

async fn stale_revision_row() -> Case {
    // (a5) The job is rewritten between plan and result: `conflict_terminal` changes nothing.
    let fixture = Box::pin(Fixture::new("courier-refusal-stale")).await?;
    let healthy = carrier(&fixture.source, "healthy", "healthy-task")?;
    forward(&fixture.source, Row::Forward.key(), &healthy)?;
    let (_, revision) = queue::load(&fixture.source, Row::Forward.key())?.ok_or("job")?;
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
    // no courier row is created. After a real reopen, acknowledged courier passes select
    // nothing and nothing is resent: S4 never auto-resubmits.
    for nack in [CONFLICT, "capacity_retry_after"] {
        let mut fixture = Box::pin(Fixture::new("courier-refusal-s4")).await?;
        let first = carrier(&fixture.source, "healthy", "healthy-task")?;
        fixture.gateway.lock().map_err(|_| "gateway")?.nack_submit = Some(nack.to_owned());
        let result = crate::bus::dispatch::task_transport::send(&mut fixture.source, &first).await;
        assert!(
            matches!(&result, Err(SdkError::GatewaySessionRejected(reason)) if reason == nack),
            "{nack}: {result:?}"
        );
        let view_key = crate::client::task::scoped("view", "healthy", "healthy-task")?;
        let expect_failed = |db: &AccountDb| -> Case {
            let view: serde_json::Value = db.load_actor_state(&view_key)?.ok_or("task view")?;
            assert_eq!(view["delivery_state"], "failed", "{nack}");
            assert_eq!(view["delivery_error"], "task_transport_error", "{nack}");
            for prefix in ["task/ack/", "task/forward/", "task/approval_out/"] {
                assert_eq!(db.actor_state_key_page(prefix, 4)?.len(), 0, "{nack}: {prefix}");
            }
            Ok(())
        };
        expect_failed(fixture.source.client.account_db()?)?;
        assert_eq!(fixture.gateway.lock().map_err(|_| "gateway")?.attempts.len(), 1, "{nack}");
        reopen(&mut fixture.source)?;
        expect_failed(fixture.source.client.account_db()?)?;
        fixture.gateway.lock().map_err(|_| "gateway")?.nack_submit = None;
        let root = fixture.root.clone();
        let account =
            with_actor(fixture.source, &root, |_| {}, async |run| run.idle(3).await).await?;
        expect_failed(account.client.account_db()?)?;
        assert_eq!(fixture.gateway.lock().map_err(|_| "gateway")?.attempts.len(), 1, "{nack}");
        std::fs::remove_dir_all(&root)?;
    }
    Ok(())
}
