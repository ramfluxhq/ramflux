// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Binding contract tests against a scripted port: cancellation around the claim, a lost
//! reply after send admission, credit back-pressure, lag, and idempotent close.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::port::{CorePort, PortRequest, PortSubscription, UpdateSink};
use crate::{
    CancelHandle, ClaimKind, CoreConfig, CoreError, CoreRequest, CoreResponse, CoreState,
    ExecuteOutcome, HostHandshake, ListenerError, NetworkChange, RamfluxCore, SubscribeFilter, SubscriptionEnd,
    SuspendEvidence, UpdateListener, UpdateRow, UpdateState, WaiterEnd, binding_api_version, code,
    descriptor_fingerprint,
};

/// A port that parks every request so the test decides when (and whether) it is claimed.
#[derive(Default)]
struct ScriptedPort {
    parked: Mutex<Vec<PortRequest>>,
    sinks: Mutex<Vec<Arc<dyn UpdateSink>>>,
    /// Effects of executed mutations, counted per claim that succeeded.
    effects: AtomicU32,
    stops: AtomicU32,
    cancelled_streams: Arc<AtomicU32>,
}

struct ScriptedStream(Arc<AtomicU32>);
impl PortSubscription for ScriptedStream {
    fn cancel(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl ScriptedPort {
    fn take(&self) -> Option<PortRequest> {
        self.parked.lock().ok().and_then(|mut parked| parked.pop())
    }

    /// Run the parked request the way a supervisor does: claim, then effect, then reply.
    fn run(&self, kind: ClaimKind, reply: bool) -> bool {
        let Some(parked) = self.take() else {
            return false;
        };
        if !parked.gate.try_claim(kind) {
            return false;
        }
        self.effects.fetch_add(1, Ordering::SeqCst);
        if reply {
            parked.reply.send(Ok(CoreResponse {
                method: parked.request.method.clone(),
                account_id: parked.request.account_id.clone(),
                body_json: "{}".to_owned(),
                operation_id: parked.request.operation_id.clone(),
            }));
        }
        true
    }
}

impl CorePort for ScriptedPort {
    fn start(&self) -> Result<(), CoreError> {
        Ok(())
    }
    fn suspend(&self) -> Result<SuspendEvidence, CoreError> {
        Ok(SuspendEvidence { supervisor_joined: true, data_root_lock_released: true, elapsed_ms: 1 })
    }
    fn resume(&self) -> Result<(), CoreError> {
        Ok(())
    }
    fn stop(&self) -> Result<(), CoreError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn state(&self) -> CoreState {
        CoreState::Running
    }
    fn network_changed(&self, _change: NetworkChange) {}
    fn submit(&self, request: PortRequest) -> Result<(), CoreError> {
        if request.request.method == "refuse.admission" {
            return Err(CoreError::plain(code::RATE_LIMITED, "admission full"));
        }
        self.parked
            .lock()
            .map_err(|_| CoreError::plain(code::INTERNAL, "poisoned"))?
            .push(request);
        Ok(())
    }
    fn subscribe(
        &self,
        _filter: SubscribeFilter,
        sink: Arc<dyn UpdateSink>,
    ) -> Result<Box<dyn PortSubscription>, CoreError> {
        self.sinks.lock().map_err(|_| CoreError::plain(code::INTERNAL, "poisoned"))?.push(sink);
        Ok(Box::new(ScriptedStream(Arc::clone(&self.cancelled_streams))))
    }
}

fn config(max_pending_updates: u32) -> CoreConfig {
    CoreConfig {
        data_root: "/nonexistent".to_owned(),
        handshake: HostHandshake {
            api: binding_api_version(),
            descriptor_fingerprint: descriptor_fingerprint(),
            capabilities: vec!["execute.v1".to_owned()],
        },
        max_pending_updates,
    }
}

fn send_request(operation_id: &str) -> CoreRequest {
    CoreRequest {
        method: "message.submit".to_owned(),
        account_id: Some("acct".to_owned()),
        body_json: "{}".to_owned(),
        deadline_ms: 30_000,
        operation_id: Some(operation_id.to_owned()),
    }
}

fn core(port: &Arc<ScriptedPort>, max_pending: u32) -> Result<Arc<RamfluxCore>, CoreError> {
    let as_port: Arc<dyn CorePort> = Arc::clone(port) as Arc<dyn CorePort>;
    RamfluxCore::with_port(as_port, &config(max_pending))
}

#[tokio::test]
async fn cancel_before_claim_has_no_effect_and_the_core_can_never_claim_later()
-> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 8)?;
    let cancel = CancelHandle::new();
    let call = tokio::spawn({
        let core = Arc::clone(&core);
        let cancel = Arc::clone(&cancel);
        async move { core.execute(send_request("op-1"), cancel).await }
    });
    tokio::task::yield_now().await;
    cancel.cancel();
    let outcome = call.await.map_err(|error| CoreError::plain(code::INTERNAL, error.to_string()))??;
    assert_eq!(outcome, ExecuteOutcome::EndedBeforeClaim { end: WaiterEnd::Cancelled });
    // The supervisor reaches the request only now: the claim must fail and nothing runs.
    assert!(!port.run(ClaimKind::Ordinary, true));
    assert_eq!(port.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn cancel_after_lifecycle_claim_keeps_the_execution_and_reports_unknown_not_no_effect()
-> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 8)?;
    let cancel = CancelHandle::new();
    let call = tokio::spawn({
        let core = Arc::clone(&core);
        let cancel = Arc::clone(&cancel);
        async move { core.execute(send_request("op-life"), cancel).await }
    });
    tokio::task::yield_now().await;
    // Claim without replying: the supervisor owns the lifecycle operation and still runs it.
    let parked = port.take();
    assert!(parked.as_ref().is_some_and(|parked| parked.gate.try_claim(ClaimKind::Lifecycle)));
    cancel.cancel();
    let outcome = call.await.map_err(|error| CoreError::plain(code::INTERNAL, error.to_string()))??;
    assert_eq!(
        outcome,
        ExecuteOutcome::EndedAfterClaim {
            end: WaiterEnd::Cancelled,
            operation_id: Some("op-life".to_owned()),
            lifecycle: true,
        }
    );
    // The retained execution completes later without a waiter; sending the reply is harmless.
    if let Some(parked) = parked {
        parked.reply.send(Err(CoreError::plain(code::INTERNAL, "late")));
    }
    Ok(())
}

#[tokio::test]
async fn lost_reply_after_send_admission_is_unknown_and_is_never_executed_twice()
-> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 8)?;
    let call = tokio::spawn({
        let core = Arc::clone(&core);
        async move { core.execute(send_request("op-send"), CancelHandle::new()).await }
    });
    tokio::task::yield_now().await;
    // Admitted, effect applied, reply dropped (for example the core was suspended).
    assert!(port.run(ClaimKind::Ordinary, false));
    let outcome = call.await.map_err(|error| CoreError::plain(code::INTERNAL, error.to_string()))??;
    assert_eq!(
        outcome,
        ExecuteOutcome::EndedAfterClaim {
            end: WaiterEnd::ReplyLost,
            operation_id: Some("op-send".to_owned()),
            lifecycle: false,
        }
    );
    // The binding did not resubmit: exactly one effect, nothing parked, same operation key.
    assert_eq!(port.effects.load(Ordering::SeqCst), 1);
    assert!(port.take().is_none());
    Ok(())
}

#[tokio::test]
async fn reply_dropped_before_any_claim_is_proven_no_effect() -> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 8)?;
    let call = tokio::spawn({
        let core = Arc::clone(&core);
        async move { core.execute(send_request("op-drop"), CancelHandle::new()).await }
    });
    tokio::task::yield_now().await;
    drop(port.take());
    let outcome = call.await.map_err(|error| CoreError::plain(code::INTERNAL, error.to_string()))??;
    assert_eq!(outcome, ExecuteOutcome::EndedBeforeClaim { end: WaiterEnd::ReplyLost });
    Ok(())
}

#[tokio::test]
async fn deadline_before_claim_ends_the_waiter_and_blocks_a_later_claim() -> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 8)?;
    let mut request = send_request("op-late");
    request.deadline_ms = 20;
    let outcome = core.execute(request, CancelHandle::new()).await?;
    assert_eq!(outcome, ExecuteOutcome::EndedBeforeClaim { end: WaiterEnd::Deadline });
    assert!(!port.run(ClaimKind::Ordinary, true));
    Ok(())
}

#[tokio::test]
async fn completed_reply_and_refused_admission_keep_their_types() -> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 8)?;
    let call = tokio::spawn({
        let core = Arc::clone(&core);
        async move { core.execute(send_request("op-ok"), CancelHandle::new()).await }
    });
    tokio::task::yield_now().await;
    assert!(port.run(ClaimKind::Ordinary, true));
    let outcome = call.await.map_err(|error| CoreError::plain(code::INTERNAL, error.to_string()))??;
    assert!(matches!(outcome, ExecuteOutcome::Completed { .. }));

    let mut refused = send_request("op-refused");
    refused.method = "refuse.admission".to_owned();
    let error = core.execute(refused, CancelHandle::new()).await;
    assert_eq!(error.map_err(|error| error.code()), Err(code::RATE_LIMITED));

    let already = CancelHandle::new();
    already.cancel();
    let outcome = core.execute(send_request("op-pre"), already).await?;
    assert_eq!(outcome, ExecuteOutcome::EndedBeforeClaim { end: WaiterEnd::Cancelled });
    Ok(())
}

/// A row the recording listener refuses, to exercise the failure path.
const POISON_ROW: u64 = 666;

enum Seen {
    Rows(Vec<u64>),
    Lag(u64, u64),
    End(SubscriptionEnd),
}

struct Recorder(Mutex<Sender<Seen>>);
impl UpdateListener for Recorder {
    fn on_updates(&self, rows: Vec<UpdateRow>) -> Result<(), ListenerError> {
        if rows.iter().any(|row| row.journal_sequence == POISON_ROW) {
            return Err(ListenerError::Failed { message: "poison".to_owned() });
        }
        if let Ok(sender) = self.0.lock() {
            let _ = sender.send(Seen::Rows(rows.iter().map(|row| row.journal_sequence).collect()));
        }
        Ok(())
    }
    fn on_lag(
        &self,
        resume_after_journal_sequence: u64,
        skipped_rows: u64,
    ) -> Result<(), ListenerError> {
        if let Ok(sender) = self.0.lock() {
            let _ = sender.send(Seen::Lag(resume_after_journal_sequence, skipped_rows));
        }
        Ok(())
    }
    fn on_end(&self, end: SubscriptionEnd) -> Result<(), ListenerError> {
        if let Ok(sender) = self.0.lock() {
            let _ = sender.send(Seen::End(end));
        }
        Ok(())
    }
}

fn row(sequence: u64) -> UpdateRow {
    UpdateRow {
        topic: "message.update".to_owned(),
        account_id: Some("acct".to_owned()),
        journal_sequence: sequence,
        identity_json: None,
        state: UpdateState::Unsupported { json: "{}".to_owned() },
    }
}

fn recorder() -> (Arc<dyn UpdateListener>, Receiver<Seen>) {
    let (sender, receiver) = channel();
    (Arc::new(Recorder(Mutex::new(sender))), receiver)
}

fn filter(initial_credit: u32) -> SubscribeFilter {
    SubscribeFilter {
        account_id: Some("acct".to_owned()),
        topics: vec!["message.update".to_owned()],
        after_journal_sequence: None,
        initial_credit,
    }
}

const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(150);

#[test]
fn rows_are_delivered_only_within_granted_credit_and_in_order() -> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 16)?;
    let (listener, seen) = recorder();
    let stream = core.subscribe(filter(2), listener)?;
    let sink = port.sinks.lock().ok().and_then(|sinks| sinks.first().cloned());
    let Some(sink) = sink else {
        return Err(CoreError::plain(code::INTERNAL, "no sink"));
    };
    for sequence in 1..=5 {
        sink.offer(row(sequence));
    }
    let mut delivered = Vec::new();
    while delivered.len() < 2 {
        match seen.recv_timeout(WAIT) {
            Ok(Seen::Rows(rows)) => delivered.extend(rows),
            _ => return Err(CoreError::plain(code::INTERNAL, "expected rows")),
        }
    }
    assert_eq!(delivered, vec![1, 2]);
    // No credit left: nothing more arrives, and it is not a lag.
    assert!(seen.recv_timeout(QUIET).is_err());
    stream.grant(10);
    while delivered.len() < 5 {
        match seen.recv_timeout(WAIT) {
            Ok(Seen::Rows(rows)) => delivered.extend(rows),
            _ => return Err(CoreError::plain(code::INTERNAL, "expected rows after grant")),
        }
    }
    assert_eq!(delivered, vec![1, 2, 3, 4, 5]);
    stream.cancel();
    stream.cancel();
    assert!(matches!(seen.recv_timeout(WAIT), Ok(Seen::End(SubscriptionEnd::Cancelled))));
    assert!(seen.recv_timeout(QUIET).is_err());
    assert_eq!(port.cancelled_streams.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn a_full_queue_reports_lag_with_the_journal_resume_point_instead_of_dropping_silently()
-> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 3)?;
    let (listener, seen) = recorder();
    let stream = core.subscribe(filter(1), listener)?;
    let sink = port.sinks.lock().ok().and_then(|sinks| sinks.first().cloned());
    let Some(sink) = sink else {
        return Err(CoreError::plain(code::INTERNAL, "no sink"));
    };
    sink.offer(row(1));
    assert!(matches!(seen.recv_timeout(WAIT), Ok(Seen::Rows(rows)) if rows == vec![1]));
    // No credit: rows 2..=4 fill the queue, row 5 overflows it.
    for sequence in 2..=5 {
        sink.offer(row(sequence));
    }
    assert!(matches!(seen.recv_timeout(WAIT), Ok(Seen::Lag(1, 4))));
    // After the lag notice the stream continues at the live edge once credit is granted.
    sink.offer(row(6));
    stream.grant(4);
    assert!(matches!(seen.recv_timeout(WAIT), Ok(Seen::Rows(rows)) if rows == vec![6]));
    Ok(())
}

#[test]
fn a_failing_listener_ends_the_stream_as_failed_and_cancels_the_core_side()
-> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 4)?;
    let (listener, seen) = recorder();
    let stream = core.subscribe(filter(4), listener)?;
    let sink = port.sinks.lock().ok().and_then(|sinks| sinks.first().cloned());
    let Some(sink) = sink else {
        return Err(CoreError::plain(code::INTERNAL, "no sink"));
    };
    sink.offer(row(POISON_ROW));
    assert!(matches!(seen.recv_timeout(WAIT), Ok(Seen::End(SubscriptionEnd::Failed))));
    assert!(stream.is_ended());
    assert_eq!(port.cancelled_streams.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn suspend_ends_streams_and_close_is_idempotent() -> Result<(), CoreError> {
    let port = Arc::new(ScriptedPort::default());
    let core = core(&port, 4)?;
    let (listener, seen) = recorder();
    let stream = core.subscribe(filter(1), listener)?;
    let evidence = core.suspend()?;
    assert!(evidence.data_root_lock_released);
    assert!(matches!(seen.recv_timeout(WAIT), Ok(Seen::End(SubscriptionEnd::Suspended))));
    assert!(stream.is_ended());
    core.close()?;
    core.close()?;
    assert_eq!(port.stops.load(Ordering::SeqCst), 1);
    assert!(core.start().is_err());
    Ok(())
}

#[test]
fn open_without_a_compatible_host_version_is_refused_before_any_port_exists() {
    let mut config = config(4);
    config.handshake.api.major += 1;
    let refused = RamfluxCore::open(config);
    assert_eq!(refused.map(|_| ()).map_err(|error| error.code()), Err(code::UNSUPPORTED_VERSION));
}
