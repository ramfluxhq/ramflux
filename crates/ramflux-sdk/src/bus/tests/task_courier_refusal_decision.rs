// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::too_many_lines, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The Approval Decision lifecycle of `sender_refusal_policy_task` (r4 section 2.3): the user
//! decides through `grant.approve` / `grant.deny` on the live actor, a gateway conflict makes
//! the receipt `failed / submit_conflict` while the signed job is kept, and an explicit retry
//! re-enqueues it once. Courier passes are allowed one at a time and the clock is frozen.
use super::*;
use crate::client::task::approval::Job;
use serde_json::{Value, json};

/// A requester account holding one incoming approval request, driven through the actor.
struct Life {
    account: LocalBusAccountState,
    root: PathBuf,
    gateway: Arc<Mutex<super::super::fixture::Gateway>>,
    approved: bool,
    scoped: String,
    id: String,
    key: String,
    start: i64,
    _peers: Vec<LocalBusAccountState>,
}

impl Life {
    const fn method(&self) -> &'static str {
        if self.approved { "grant.approve" } else { "grant.deny" }
    }

    const fn opposite(&self) -> &'static str {
        if self.approved { "grant.deny" } else { "grant.approve" }
    }

    fn body(&self) -> Value {
        json!({"approval_id": self.scoped})
    }

    fn wire(&self) -> usize {
        self.gateway.lock().unwrap().attempts.len()
    }

    fn arm(&self, nack: Option<&str>) {
        self.gateway.lock().unwrap().nack_submit = nack.map(str::to_owned);
    }

    /// Runs `body` on a fresh actor over this account and keeps the returned account.
    async fn run(&mut self, body: impl AsyncFnOnce(&mut Run, &Self) -> Case) -> Case {
        let account = std::mem::replace(&mut self.account, placeholder()?);
        let me = &*self;
        let account =
            with_actor(account, &me.root, |_| {}, async |run| body(run, me).await).await?;
        self.account = account;
        Ok(())
    }
}

async fn start(approved: bool) -> Case<Life> {
    let fixture = Box::pin(Fixture::new("courier-refusal-decision")).await?;
    let healthy = carrier(&fixture.source, "healthy", "healthy-task")?;
    forward(&fixture.source, "task/forward/seed", &healthy)?;
    fixture.source.client.account_db()?.delete_task_state("task/forward/seed")?;
    intervention(&fixture.source, &fixture.peer)?;
    // A valid, displayable request from the assignee: the requester account receives it.
    let mut request = approval_request(&fixture.source)?;
    let arguments = json!({"command":"echo approved"});
    let hash = ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::MCP_GRANT,
        &ramflux_protocol::canonical_json_bytes(&arguments)?,
    );
    request.approval.details = json!({"arguments":arguments,"arguments_hash":hash});
    request.grant_body.arguments_hash = Some(hash);
    let packet = fixture.peer.client.sign_task_approval(approval::Payload::Request { request })?;
    let id = packet.id()?;
    fixture.source.client.accept_task_approval(&packet)?;
    let Fixture { root, source, peer, sibling, gateway, .. } = fixture;
    Ok(Life {
        account: source,
        root,
        gateway,
        approved,
        scoped: format!("task_approval_{id}"),
        key: crate::client::task::key("approval_decision_out", &id),
        id,
        start: now_unix_timestamp(),
        _peers: vec![peer, sibling],
    })
}

fn job_of(db: &AccountDb, key: &str) -> Case<Job> {
    Ok(db.load_actor_state(key)?.ok_or("the decision job is gone")?)
}

fn receipt_of(db: &AccountDb) -> Case<Value> {
    let rows = records(db, "task/approval_receipt/")?;
    assert_eq!(rows.len(), 1, "exactly one receipt");
    Ok(rows.into_iter().next().unwrap())
}

fn pending() -> Shape {
    Shape { job: Some(0), receipt: Some(("pending".into(), None)), ..Shape::queued() }
}

/// The (a3) state after `conflicts` explicit conflicts: the job kept ineligible, the receipt
/// failed, one diagnostic, no dead record, one journal entry per conflict.
fn conflicted(conflicts: usize) -> Shape {
    Shape {
        job: Some(8),
        failures: 1,
        receipt: Some(("failed".into(), Some("submit_conflict".into()))),
        conflicts,
        ..Shape::queued()
    }
}

fn view_rows(view: &Value) -> Vec<Value> {
    view["approval_decisions"].as_array().cloned().unwrap_or_default()
}

/// (a3) Decision job + Conflict through the actor; returns the signed packet bytes.
async fn to_conflict(life: &mut Life) -> Case<Vec<u8>> {
    life.arm(Some(CONFLICT));
    let mut original = Vec::new();
    life.run(async |run, me| {
        let decided = run.call(me.method(), me.body()).await?;
        assert_eq!(decided["delivery_state"], "pending");
        assert_eq!(decided["reason_code"], Value::Null);
        assert_eq!(decided["status"], if me.approved { "approved" } else { "denied" });
        let queued = job_of(&run.reader, &me.key)?;
        assert_eq!(queued.attempts, 0);
        original = queued.packet.bytes()?;
        assert_eq!(Shape::of(&run.reader, &me.key)?, pending());
        let cut = Cut::install(&run.reader, &me.key)?;
        let items = run.step().await?;
        assert_eq!(items, vec![(me.key.clone(), 0, false)]);
        run.until("the decision conflict", |db| Ok(attempts_of(db, &me.key)? == Some(8))).await?;
        // One commit: every RELEASE/COMMIT boundary saw the complete old or complete new state.
        cut.assert_atomic(&pending(), &conflicted(1));
        assert_eq!(Shape::of(&run.reader, &me.key)?, conflicted(1));
        let kept = job_of(&run.reader, &me.key)?;
        assert_eq!(kept.packet.bytes()?, original, "the retained signed bytes are the original");
        let diagnostics = failures(&run.reader)?;
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0]["reason"], "submit_conflict");
        assert_eq!(diagnostics[0]["attempts"], 8);
        assert_eq!(diagnostics[0]["id"], me.key);
        // The single `task.changed / submit_conflict` journal entry.
        let journal: Vec<_> = run
            .reader
            .journal_after(0, 128)?
            .into_iter()
            .filter(|event| {
                event.topic == "task.changed" && event.body["reason_code"] == "submit_conflict"
            })
            .collect();
        assert_eq!(journal.len(), 1);
        assert_eq!(journal[0].body["delivery_state"], "failed");
        assert_eq!(journal[0].body["approval_id"], me.scoped);
        assert_eq!(journal[0].body["task_id"], "healthy-task");
        assert_eq!(journal[0].body["conversation_id"], "healthy");
        assert_eq!(me.gateway.lock().unwrap().attempts.len(), 1);
        // Visible to readers and never selected again.
        let view = run
            .call("task.get", json!({"conversation_id":"healthy","task_id":"healthy-task"}))
            .await?;
        let shown = view_rows(&view);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0]["delivery_state"], "failed");
        assert_eq!(shown[0]["reason_code"], "submit_conflict");
        run.idle(2).await?;
        assert_eq!(me.gateway.lock().unwrap().attempts.len(), 1, "no automatic resend");
        Ok(())
    })
    .await?;
    reopen(&mut life.account)?;
    // After a real reopen the same state is read from disk, nothing selects it, and the wire
    // count is still 1.
    let db = life.account.client.account_db()?;
    assert_eq!(Shape::of(db, &life.key)?, conflicted(1));
    assert_eq!(job_of(db, &life.key)?.packet.bytes()?, original);
    let rows = life.account.client.task_approval_decision_rows()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["delivery_state"], "failed");
    assert_eq!(rows[0]["reason_code"], "submit_conflict");
    assert_eq!(queue::manifest_requests(&mut life.account)?.len(), 0);
    assert_eq!(life.wire(), 1);
    Ok(original)
}

/// (a3b) to (a3d): decided, conflicted, then retried to success.
async fn retry_success(approved: bool) -> Case {
    let mut life = Box::pin(start(approved)).await?;
    let original = to_conflict(&mut life).await?;
    let failed_revision =
        receipt_of(life.account.client.account_db()?)?["revision"].as_u64().unwrap();
    let start = life.start;
    life.run(async |run, me| {
        let view = run
            .call("task.get", json!({"conversation_id":"healthy","task_id":"healthy-task"}))
            .await?;
        assert_eq!(view_rows(&view).len(), 1);
        run.idle(1).await?;
        // (a3d) the opposite choice is refused as consumed; receipt, job and wire are unchanged.
        let before = (
            receipt_of(&run.reader)?,
            job_of(&run.reader, &me.key)?.attempts,
            job_of(&run.reader, &me.key)?.packet.bytes()?,
        );
        let refused = run.call(me.opposite(), me.body()).await;
        assert!(
            matches!(
                &refused,
                Err(SdkError::TaskRefused { reason: crate::TaskRefusalCode::DecisionConsumed, .. })
            ),
            "{refused:?}"
        );
        let after = (
            receipt_of(&run.reader)?,
            job_of(&run.reader, &me.key)?.attempts,
            job_of(&run.reader, &me.key)?.packet.bytes()?,
        );
        assert_eq!(before, after);
        assert_eq!(me.gateway.lock().unwrap().attempts.len(), 1);
        // (a3c) the same choice re-enqueues once: one revision bump, `attempts = 0` written once
        // (a rewrite after the clock moved would carry the later `next_at`), no wire send.
        let first = run.call(me.method(), me.body()).await?;
        assert_eq!(first["delivery_state"], "pending");
        assert_eq!(first["reason_code"], Value::Null);
        let queued = receipt_of(&run.reader)?;
        assert_eq!(queued["revision"], failed_revision + 1);
        let job = job_of(&run.reader, &me.key)?;
        assert_eq!((job.attempts, job.next_at), (0, start));
        assert_eq!(job.packet.bytes()?, original, "the unchanged signed packet");
        crate::time::FixedClock::advance_to(start + 5);
        let second = run.call(me.method(), me.body()).await?;
        assert_eq!(second, first);
        assert_eq!(receipt_of(&run.reader)?, queued, "the duplicate wrote no receipt");
        let job = job_of(&run.reader, &me.key)?;
        assert_eq!((job.attempts, job.next_at), (0, start), "the duplicate wrote no job");
        assert_eq!(me.gateway.lock().unwrap().attempts.len(), 1);
        Ok(())
    })
    .await?;
    // (a3b) the pending state survives a second real reopen: eligible again, receipt pending.
    reopen(&mut life.account)?;
    let db = life.account.client.account_db()?;
    assert_eq!(Shape::of(db, &life.key)?, Shape { conflicts: 1, failures: 1, ..pending() });
    let job = job_of(db, &life.key)?;
    assert_eq!((job.attempts, job.next_at), (0, start));
    assert!(queue::item(&life.account, &life.key, start + 5)?.is_some());
    assert_eq!(life.wire(), 1);
    // The courier sends exactly once more, gets success, and the row completes.
    life.arm(None);
    life.run(async |run, me| {
        let items = run.step().await?;
        assert_eq!(items, vec![(me.key.clone(), 0, false)]);
        run.until("the decision is delivered", |db| Ok(!db.actor_state_exists(&me.key)?)).await?;
        assert_eq!(
            Shape::of(&run.reader, &me.key)?,
            Shape {
                job: None,
                failures: 1,
                receipt: Some(("submitted".into(), None)),
                conflicts: 1,
                ..Shape::queued()
            }
        );
        for namespace in ["approval_in", "approval_decision_in", "approval_decision_out"] {
            let stored = crate::client::task::key(namespace, &me.id);
            assert!(!run.reader.actor_state_exists(&stored)?, "{namespace} row remains");
        }
        // The conflicted send stopped after envelope 1; the retry sends the whole two-envelope plan.
        assert_eq!(me.gateway.lock().unwrap().attempts.len(), 3);
        run.idle(2).await?;
        assert_eq!(me.gateway.lock().unwrap().attempts.len(), 3, "delivered exactly once more");
        Ok(())
    })
    .await?;
    crate::time::FixedClock::advance_to(start);
    Ok(())
}

/// (a3e) A conflict after a manual retry returns to the (a3) state; the wire count is exactly
/// the number of explicit retries plus 1.
async fn repeat_conflict() -> Case {
    let mut life = Box::pin(start(true)).await?;
    let original = to_conflict(&mut life).await?;
    for retries in 1..=2_usize {
        reopen(&mut life.account)?;
        life.run(async |run, me| {
            let decided = run.call(me.method(), me.body()).await?;
            assert_eq!(decided["delivery_state"], "pending");
            assert_eq!(job_of(&run.reader, &me.key)?.attempts, 0);
            assert_eq!(me.gateway.lock().unwrap().attempts.len(), retries);
            let items = run.step().await?;
            assert_eq!(items, vec![(me.key.clone(), 0, false)]);
            run.until("the repeated conflict", |db| Ok(attempts_of(db, &me.key)? == Some(8)))
                .await?;
            assert_eq!(Shape::of(&run.reader, &me.key)?, conflicted(retries + 1));
            assert_eq!(job_of(&run.reader, &me.key)?.packet.bytes()?, original);
            assert_eq!(me.gateway.lock().unwrap().attempts.len(), retries + 1);
            run.idle(2).await?;
            assert_eq!(
                me.gateway.lock().unwrap().attempts.len(),
                retries + 1,
                "no automatic attempt between explicit retries"
            );
            Ok(())
        })
        .await?;
    }
    assert_eq!(life.wire(), 3, "two explicit retries plus the first send");
    Ok(())
}

pub(super) async fn lifecycle_rows() -> Case {
    // (a3)-(a3d) for an approve decision and a deny decision, then (a3e). The request-payload
    // row (a3f) is `conflict_rows`: an Approval Request is quarantined and creates no receipt.
    for approved in [true, false] {
        retry_success(approved).await?;
    }
    repeat_conflict().await
}
