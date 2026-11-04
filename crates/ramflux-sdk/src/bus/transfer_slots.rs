// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, cancellable relay jobs; durable checkpoints remain owned by the account actor.

use super::runtime_limits::{TRANSFER_QUEUE, TRANSFER_SLOTS};
use crate::SdkError;
use std::{collections::VecDeque, future::Future, pin::Pin, sync::Arc};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinSet;

#[cfg(test)]
pub(crate) mod test_hooks;

type Job = Pin<Box<dyn Future<Output = ()> + Send>>;

struct QueuedJob {
    future: Job,
    cancelled: watch::Receiver<bool>,
    queue_place: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub(crate) struct TransferSlots {
    queue: mpsc::Sender<QueuedJob>,
    places: Arc<Semaphore>,
    changed: Arc<Notify>,
    shutdown: watch::Sender<bool>,
    finished: watch::Receiver<bool>,
}

/// Owns a queue place before the actor reserves a durable operation.
pub(crate) struct TransferPermit {
    channel: mpsc::OwnedPermit<QueuedJob>,
    queue_place: OwnedSemaphorePermit,
    changed: Arc<Notify>,
}

pub(crate) struct JobHandle<T> {
    result: Option<oneshot::Receiver<Result<T, SdkError>>>,
    cancel: watch::Sender<bool>,
    finished: watch::Receiver<bool>,
    generation: u64,
    changed: Arc<Notify>,
}

impl TransferSlots {
    pub(crate) fn start() -> Self {
        let (queue, receive) = mpsc::channel(TRANSFER_QUEUE);
        let (shutdown, stop) = watch::channel(false);
        let (done, finished) = watch::channel(false);
        let changed = Arc::new(Notify::new());
        let notified = Arc::clone(&changed);
        tokio::spawn(async move {
            let _finished = Finished(done);
            run(receive, stop, notified).await;
        });
        Self {
            queue,
            places: Arc::new(Semaphore::new(TRANSFER_QUEUE)),
            changed,
            shutdown,
            finished,
        }
    }

    pub(crate) fn reserve(&self) -> Result<TransferPermit, SdkError> {
        if *self.finished.borrow() || *self.shutdown.borrow() {
            return Err(cancelled());
        }
        let queue_place = Arc::clone(&self.places).try_acquire_owned().map_err(|_| full())?;
        self.queue
            .clone()
            .try_reserve_owned()
            .map(|channel| TransferPermit {
                channel,
                queue_place,
                changed: Arc::clone(&self.changed),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => full(),
                mpsc::error::TrySendError::Closed(_) => cancelled(),
            })
    }

    pub(crate) fn submit<T, F>(&self, job: ReservedTransferJob<F>) -> JobHandle<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, SdkError>> + Send + 'static,
    {
        debug_assert!(Arc::ptr_eq(&self.changed, &job.permit.changed));
        job.permit.submit(job.generation, job.future)
    }

    pub(crate) async fn stop(&self) {
        self.shutdown.send_replace(true);
        let mut finished = self.finished.clone();
        while !*finished.borrow_and_update() {
            if finished.changed().await.is_err() {
                break;
            }
        }
    }
}

pub(crate) struct ReservedTransferJob<F> {
    permit: TransferPermit,
    generation: u64,
    future: F,
}

impl TransferPermit {
    pub(crate) fn bind<F>(self, generation: u64, future: F) -> ReservedTransferJob<F> {
        ReservedTransferJob { permit: self, generation, future }
    }
    pub(crate) fn submit<T, F>(self, generation: u64, job: F) -> JobHandle<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, SdkError>> + Send + 'static,
    {
        let (reply, result) = oneshot::channel();
        let (cancel, mut cancellation) = watch::channel(false);
        let (finished, done) = watch::channel(false);
        // Construct the guard before enqueue: dropping a queued job also finishes its handle.
        let finished = Finished(finished);
        let queued_cancellation = cancellation.clone();
        self.channel.send(QueuedJob {
            queue_place: self.queue_place,
            cancelled: queued_cancellation,
            future: Box::pin(async move {
                let _finished = finished;
                let result = if *cancellation.borrow() {
                    Err(cancelled())
                } else {
                    tokio::select! {
                        biased;
                        _ = cancellation.changed() => Err(cancelled()),
                        result = job => result,
                    }
                };
                let _ = reply.send(result);
            }),
        });
        JobHandle {
            result: Some(result),
            cancel,
            finished: done,
            generation,
            changed: self.changed,
        }
    }
}

impl<T> JobHandle<T> {
    #[cfg(test)]
    pub(crate) fn finished_for_test(&self) -> watch::Receiver<bool> {
        self.finished.clone()
    }
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn is_finished(&self) -> bool {
        *self.finished.borrow()
    }
    pub(crate) fn cancel(&self) {
        self.cancel.send_replace(true);
        self.changed.notify_one();
    }
    pub(crate) async fn wait(&mut self) -> Result<T, SdkError> {
        let result = self.result.take().ok_or_else(cancelled)?;
        result.await.map_err(|_| cancelled())?
    }
}

impl<T> Drop for JobHandle<T> {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
        self.changed.notify_one();
    }
}

struct Finished(watch::Sender<bool>);
impl Drop for Finished {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

async fn run(
    mut input: mpsc::Receiver<QueuedJob>,
    mut shutdown: watch::Receiver<bool>,
    changed: Arc<Notify>,
) {
    let mut jobs = JoinSet::new();
    let mut queued: VecDeque<QueuedJob> = VecDeque::new();
    loop {
        queued.retain(|job| !*job.cancelled.borrow());
        while jobs.len() < TRANSFER_SLOTS {
            let Some(job) = queued.pop_front() else {
                break;
            };
            drop(job.queue_place);
            jobs.spawn(job.future);
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            () = changed.notified() => {},
            result = jobs.join_next(), if !jobs.is_empty() => {
                if let Some(Err(error)) = result { tracing::warn!(%error, "transfer task stopped"); }
            }
            job = input.recv(), if queued.len() < TRANSFER_QUEUE => {
                let Some(job) = job else { break; };
                queued.push_back(job);
            }
        }
    }
    input.close();
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    queued.clear();
    while input.try_recv().is_ok() {}
}

fn full() -> SdkError {
    ramflux_transport::TransportError::BackpressureRejected {
        capacity: TRANSFER_QUEUE as u64,
        in_flight: TRANSFER_QUEUE as u64,
    }
    .into()
}

fn cancelled() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}

#[cfg(test)]
mod tests;
