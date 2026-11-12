// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The shim's own thread: it owns the in-process connections, and C callers wait outside it.
//!
//! A C caller never runs a future. It queues a job, then blocks on a plain channel with a
//! bounded deadline. The stage word decides, exactly once, whether a request was handed to
//! the supervisor before its waiter gave up, which is the difference between "no effect"
//! and "effect unknown".

use super::ceremony::{self, CeremonyJob};
use super::error::{Effect, V2Error, V2Result};
use super::host::CoreHost;
use super::subscription::{SubscribeJob, pump};
use super::super::RamfluxErrorCode;
use crate::{LocalBusClient, LocalBusFrame, SdkError};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

/// Jobs that may wait for the driver. A full queue is an immediate `RateLimited`.
const JOB_QUEUE: usize = 64;
/// How often a waiter looks at its cancel handle and its deadline.
const WAIT_SLICE: Duration = Duration::from_millis(20);
/// Time a waiter allows past the request deadline for the answer to cross the carrier.
pub(super) const WAITER_GRACE: Duration = Duration::from_secs(5);
/// Longest time `close` waits for the driver thread.
const JOIN_DEADLINE: Duration = Duration::from_secs(5);

const QUEUED: u8 = 0;
const SENT: u8 = 1;
const ABANDONED: u8 = 2;

/// Who owns a queued request: its waiter until the driver claims it for sending.
#[derive(Default)]
pub(super) struct Stage(AtomicU8);

impl Stage {
    /// Driver side. `true` exactly when the waiter had not given up.
    fn claim_send(&self) -> bool {
        self.0.compare_exchange(QUEUED, SENT, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Waiter side. `None` effect exactly when the driver had not claimed the request.
    pub(super) fn abandon(&self) -> Effect {
        match self.0.compare_exchange(QUEUED, ABANDONED, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) | Err(ABANDONED) => Effect::None,
            Err(_) => Effect::Unknown,
        }
    }
}

/// Shared by a cancel handle and every request that names it.
#[derive(Default)]
pub(super) struct CancelFlag(AtomicBool);

impl CancelFlag {
    pub(super) fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub(super) struct ExecuteJob {
    /// Taken exactly once, when the driver sends it.
    pub(super) frame: Option<LocalBusFrame>,
    pub(super) stage: Arc<Stage>,
    pub(super) reply: SyncSender<Result<LocalBusFrame, SdkError>>,
}

impl Drop for ExecuteJob {
    fn drop(&mut self) {
        // A request that was never sent may still carry a passphrase or a seed.
        if let Some(frame) = self.frame.as_mut() {
            wipe(&mut frame.body);
        }
    }
}

/// Erase every string and number of a request body that will not be sent.
fn wipe(value: &mut serde_json::Value) {
    use zeroize::Zeroize;
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(values) => values.iter_mut().for_each(wipe),
        serde_json::Value::Object(fields) => fields.values_mut().for_each(wipe),
        serde_json::Value::Number(_) => *value = serde_json::Value::Null,
        serde_json::Value::Null | serde_json::Value::Bool(_) => {}
    }
}

pub(super) enum Job {
    Execute(ExecuteJob),
    Subscribe(SubscribeJob),
    Ceremony(CeremonyJob),
    /// Drop every connection before the supervisor is suspended or stopped.
    Disconnect(SyncSender<()>),
    Shutdown,
}

pub(super) struct Driver {
    jobs: mpsc::Sender<Job>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    finished: Mutex<Receiver<()>>,
}

impl Driver {
    pub(super) fn start(host: Arc<dyn CoreHost>) -> V2Result<Self> {
        let (jobs, receiver) = mpsc::channel(JOB_QUEUE);
        let (finished_tx, finished) = sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("ramflux-cabi-v2".to_owned())
            .spawn(move || {
                run(&host, receiver);
                let _ignored = finished_tx.send(());
            })
            .map_err(|source| V2Error::new(RamfluxErrorCode::Internal, source.to_string()))?;
        Ok(Self { jobs, thread: Mutex::new(Some(thread)), finished: Mutex::new(finished) })
    }

    /// Queue a job without blocking. A full queue admits nothing.
    pub(super) fn submit(&self, job: Job) -> V2Result<()> {
        self.jobs.try_send(job).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                let mut busy = V2Error::new(RamfluxErrorCode::RateLimited, "request queue is full")
                    .with_reason("busy");
                busy.retry_after_ms = Some(50);
                busy
            }
            mpsc::error::TrySendError::Closed(_) => V2Error::closed(Effect::None),
        })
    }

    /// Ask the driver to drop its connections and wait until it did.
    pub(super) fn disconnect(&self, deadline: Duration) -> V2Result<()> {
        let (done, wait) = sync_channel(1);
        self.submit(Job::Disconnect(done))?;
        wait.recv_timeout(deadline).map_err(|_| {
            V2Error::new(RamfluxErrorCode::Timeout, "shim did not release its connections")
        })
    }

    /// Stop the thread. Idempotent; in-flight waiters see `closed` with effect unknown.
    pub(super) fn shutdown(&self) {
        let _ignored = self.jobs.try_send(Job::Shutdown);
        let Ok(mut thread) = self.thread.lock() else {
            return;
        };
        let Some(handle) = thread.take() else {
            return;
        };
        let finished =
            self.finished.lock().is_ok_and(|done| done.recv_timeout(JOIN_DEADLINE).is_ok());
        if finished {
            let _ignored = handle.join();
        }
        // A thread that did not finish in time is left detached rather than blocking the
        // host forever; it holds only its own connections and exits when they close.
    }
}

fn run(host: &Arc<dyn CoreHost>, mut jobs: mpsc::Receiver<Job>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_time().build() else {
        // Dropping the receiver makes every later submit report `closed`.
        return;
    };
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        let connection: Rc<RefCell<Option<LocalBusClient>>> = Rc::new(RefCell::new(None));
        // Bumped on every disconnect so subscription pumps end with their connection.
        let (generation, _) = watch::channel(0_u64);
        while let Some(job) = jobs.recv().await {
            match job {
                Job::Execute(job) => match shared_connection(host, &connection) {
                    Ok(client) => {
                        tokio::task::spawn_local(execute(client, job));
                    }
                    Err(error) => {
                        // Nothing was sent. The waiter maps the stage to "no effect".
                        let _ignored = job.reply.try_send(Err(error));
                    }
                },
                Job::Subscribe(job) => {
                    // One connection per subscription: its event stream is not shared.
                    let client = host.connect();
                    tokio::task::spawn_local(pump(client, job, generation.subscribe()));
                }
                Job::Ceremony(job) => {
                    // A dedicated connection: ceremony secrets never share the ordinary one.
                    let client = host.connect_creation();
                    tokio::task::spawn_local(ceremony::run(
                        client,
                        job.steps,
                        generation.subscribe(),
                    ));
                }
                Job::Disconnect(done) => {
                    connection.borrow_mut().take();
                    generation.send_modify(|value| *value = value.wrapping_add(1));
                    let _ignored = done.try_send(());
                }
                Job::Shutdown => break,
            }
        }
        generation.send_modify(|value| *value = value.wrapping_add(1));
    });
}

fn shared_connection(
    host: &Arc<dyn CoreHost>,
    slot: &Rc<RefCell<Option<LocalBusClient>>>,
) -> Result<LocalBusClient, SdkError> {
    if let Some(client) = slot.borrow().as_ref() {
        return Ok(client.clone());
    }
    let client = host.connect()?;
    *slot.borrow_mut() = Some(client.clone());
    Ok(client)
}

async fn execute(client: LocalBusClient, mut job: ExecuteJob) {
    if !job.stage.claim_send() {
        // The waiter cancelled or timed out first: the frame is dropped unsent.
        return;
    }
    let Some(frame) = job.frame.take() else {
        return;
    };
    // The client erases the body once it is encoded.
    let result = client.request_frame_response(frame).await;
    let _ignored = job.reply.try_send(result);
}

/// Block the calling thread until the answer, the deadline or a cancellation.
pub(super) fn wait_reply(
    reply: &Receiver<Result<LocalBusFrame, SdkError>>,
    stage: &Stage,
    cancel: Option<&CancelFlag>,
    wait_until: Instant,
) -> V2Result<LocalBusFrame> {
    loop {
        match reply.recv_timeout(WAIT_SLICE) {
            Ok(Ok(frame)) => return Ok(frame),
            Ok(Err(error)) => {
                // An error before the claim is local; after it the frame may have run.
                return Err(V2Error::from_sdk(&error, stage.abandon()));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(V2Error::closed(stage.abandon()));
            }
            Err(RecvTimeoutError::Timeout) => {
                if cancel.is_some_and(CancelFlag::is_cancelled) {
                    return Err(V2Error::cancelled(stage.abandon()));
                }
                if Instant::now() >= wait_until {
                    return Err(V2Error::deadline(stage.abandon()));
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests_support {
    /// The driver's claim, for tests of the waiter's view of it.
    pub(in super::super) fn claim(stage: &super::Stage) -> bool {
        stage.claim_send()
    }
}
