// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-owned checkpoints are held before persistence without occupying the account writer.

#![cfg_attr(
    not(feature = "itest-local-mint"),
    expect(dead_code, reason = "Used by local-mint transfer fixtures")
)]

use crate::SdkError;
use crate::bus::account_runtime::{fetches::FetchCheckpoint, uploads::Checkpoint};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

pub(crate) struct Held {
    checkpoint: Checkpoint,
    sender: mpsc::Sender<Checkpoint>,
}
impl Held {
    pub(crate) fn import_ack_is_open(&self) -> bool {
        matches!(&self.checkpoint,Checkpoint::Fetch(FetchCheckpoint::Import { ack,.. }) if !ack.is_closed())
    }
    pub(crate) fn fetch_reply_is_open(&self) -> bool {
        match &self.checkpoint {
            Checkpoint::Fetch(
                FetchCheckpoint::Import { ack, .. }
                | FetchCheckpoint::Ack { ack, .. }
                | FetchCheckpoint::Slot { ack, .. },
            ) => !ack.is_closed(),
            Checkpoint::Fetch(FetchCheckpoint::Authorize { ack, .. }) => !ack.is_closed(),
            _ => false,
        }
    }
    pub(in crate::bus) async fn release_to_actor(
        self,
        actor: &crate::bus::actor::AccountActor,
    ) -> Result<(), SdkError> {
        actor.inject_transfer_checkpoint(self.checkpoint).await
    }
    pub(crate) async fn release(self) -> Result<(), SdkError> {
        self.sender.send(self.checkpoint).await.map_err(|_| SdkError::AccountDbNotUnlocked)
    }
    pub(crate) fn upload_ack_is_open(&self) -> bool {
        match &self.checkpoint {
            Checkpoint::Progress { ack, .. } => !ack.is_closed(),
            _ => false,
        }
    }
    pub(crate) fn replace_upload_ack(&mut self) -> Option<oneshot::Receiver<Result<(), SdkError>>> {
        if let Checkpoint::Progress { ack, .. } = &mut self.checkpoint {
            let (sender, receiver) = oneshot::channel();
            *ack = sender;
            Some(receiver)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
enum At {
    Upload(u32),
    Import,
    Ack(u32),
    Authorize,
    Slot,
}
pub(crate) struct Hook {
    selected: Mutex<Option<At>>,
    held: mpsc::UnboundedSender<Held>,
    jobs: Mutex<Vec<tokio::sync::watch::Receiver<bool>>>,
    before_upload: Mutex<Option<UploadStart>>,
    lock_workers_finished: Mutex<Option<bool>>,
}
struct UploadStart {
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}
impl Hook {
    pub(crate) fn upload_start() -> (Arc<Self>, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, waiting) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let (held, _) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                selected: Mutex::new(None),
                held,
                jobs: Mutex::new(Vec::new()),
                before_upload: Mutex::new(Some(UploadStart { entered, release: released })),
                lock_workers_finished: Mutex::new(None),
            }),
            waiting,
            release,
        )
    }
    pub(crate) async fn before_upload(&self) -> Result<(), SdkError> {
        let pause =
            self.before_upload.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(pause) = pause {
            let _ = pause.entered.send(());
            pause.release.await.map_err(|_| SdkError::AccountDbNotUnlocked)?;
        }
        Ok(())
    }
    pub(crate) fn upload_chunk(index: u32) -> (Arc<Self>, mpsc::UnboundedReceiver<Held>) {
        Self::at(At::Upload(index))
    }
    pub(crate) fn fetch_import() -> (Arc<Self>, mpsc::UnboundedReceiver<Held>) {
        Self::at(At::Import)
    }
    pub(crate) fn fetch_ack(index: u32) -> (Arc<Self>, mpsc::UnboundedReceiver<Held>) {
        Self::at(At::Ack(index))
    }
    pub(crate) fn fetch_slot() -> (Arc<Self>, mpsc::UnboundedReceiver<Held>) {
        Self::at(At::Slot)
    }
    pub(crate) fn fetch_authorize() -> (Arc<Self>, mpsc::UnboundedReceiver<Held>) {
        Self::at(At::Authorize)
    }
    fn at(at: At) -> (Arc<Self>, mpsc::UnboundedReceiver<Held>) {
        let (held, receive) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                selected: Mutex::new(Some(at)),
                held,
                jobs: Mutex::new(Vec::new()),
                before_upload: Mutex::new(None),
                lock_workers_finished: Mutex::new(None),
            }),
            receive,
        )
    }
    pub(crate) fn observe_job(&self, finished: tokio::sync::watch::Receiver<bool>) {
        self.jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(finished);
    }
    pub(crate) fn all_jobs_finished(&self) -> bool {
        let jobs = self.jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        !jobs.is_empty() && jobs.iter().all(|done| *done.borrow())
    }
    // Observe the explicit lifecycle join before final actor teardown can cancel a job too.
    pub(crate) fn observe_lock_workers(&self) {
        *self.lock_workers_finished.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(self.all_jobs_finished());
    }
    pub(crate) fn lock_workers_finished(&self) -> Option<bool> {
        *self.lock_workers_finished.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(crate) fn first_job_finished(&self) -> bool {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .first()
            .is_some_and(|done| *done.borrow())
    }
    pub(in crate::bus) fn intercept(
        &self,
        checkpoint: Checkpoint,
        sender: mpsc::Sender<Checkpoint>,
    ) -> Option<Checkpoint> {
        let mut selected = self.selected.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let matches = match (*selected, &checkpoint) {
            (Some(At::Upload(index)), Checkpoint::Progress { progress, .. }) => {
                progress.chunk_index == Some(index)
            }
            (Some(At::Import), Checkpoint::Fetch(FetchCheckpoint::Import { .. }))
            | (Some(At::Authorize), Checkpoint::Fetch(FetchCheckpoint::Authorize { .. }))
            | (Some(At::Slot), Checkpoint::Fetch(FetchCheckpoint::Slot { .. })) => true,
            (
                Some(At::Ack(index)),
                Checkpoint::Fetch(FetchCheckpoint::Ack { index: received, .. }),
            ) => index == *received,
            _ => false,
        };
        if !matches {
            return Some(checkpoint);
        }
        *selected = None;
        match self.held.send(Held { checkpoint, sender }) {
            Ok(()) => None,
            Err(error) => Some(error.0.checkpoint),
        }
    }
}
