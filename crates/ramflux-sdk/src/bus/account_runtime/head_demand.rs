// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Priority for the authority head an active command has already demanded.
//!
//! The demand counts as a queued command, so directory and backfill pause
//! between commits. A demanded head Apply waits in its own one-slot channel
//! and is taken before generic overflow. Prepare may still use the shared
//! queue. A commit already running is not interrupted.

use super::AccountRuntime;
use crate::SdkError;
use crate::bus::connection_manager::AccountWork;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

thread_local! {
    static DEMANDS: Cell<u32> = const { Cell::new(0) };
    static PREFER_DEPTH: Cell<u8> = const { Cell::new(0) };
}

/// Held while `prepare_command_heads` is waiting on stale roots.
pub(super) struct HeadDemand {
    waiting: Arc<AtomicUsize>,
}

impl HeadDemand {
    pub(super) fn arm(waiting: &Arc<AtomicUsize>) -> Self {
        waiting.fetch_add(1, Ordering::Release);
        DEMANDS.with(|cell| cell.set(cell.get().saturating_add(1)));
        Self { waiting: Arc::clone(waiting) }
    }
}

impl Drop for HeadDemand {
    fn drop(&mut self) {
        DEMANDS.with(|cell| cell.set(cell.get().saturating_sub(1)));
        let _ = self
            .waiting
            .try_update(Ordering::AcqRel, Ordering::Acquire, |queued| queued.checked_sub(1));
    }
}

pub(super) fn demand_active() -> bool {
    DEMANDS.with(|cell| cell.get() > 0)
}

fn is_head_refresh(work: &AccountWork) -> bool {
    matches!(
        work,
        AccountWork::Directory(work)
            if matches!(
                work.as_ref(),
                crate::bus::couriers::directory::DirectoryWork::HeadRefresh(_)
            )
    )
}

/// A demanded head Apply, then deferred generic work, then the shared queue.
///
/// Popping a queued item returns immediately, so a cancelled `select` cannot
/// lose it: the pop and the `Ready` happen in the same poll. The runtime keeps
/// the completion sender; a closed slot must not starve the shared queue.
pub(super) async fn recv(
    deferred: &mut std::collections::VecDeque<AccountWork>,
    completion: &mut tokio::sync::mpsc::Receiver<AccountWork>,
    incoming: &mut tokio::sync::mpsc::Receiver<AccountWork>,
) -> Option<AccountWork> {
    match completion.try_recv() {
        Ok(work) => return Some(work),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
            if let Some(work) = deferred.pop_front() {
                return Some(work);
            }
            return incoming.recv().await;
        }
        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
    }
    if let Some(work) = deferred.pop_front() {
        return Some(work);
    }
    tokio::select! {
        biased;
        work = completion.recv() => work,
        work = incoming.recv() => work,
    }
}

struct PreferGuard;

impl PreferGuard {
    fn enter() -> Option<Self> {
        if PREFER_DEPTH.with(Cell::get) > 0 {
            return None;
        }
        PREFER_DEPTH.with(|cell| cell.set(1));
        Some(Self)
    }
}

impl Drop for PreferGuard {
    fn drop(&mut self) {
        PREFER_DEPTH.with(|cell| cell.set(0));
    }
}

impl AccountRuntime {
    /// Applies a queued head Apply, then demanded head-refresh work on the shared queue.
    pub(super) async fn prefer_demanded_head(&mut self) -> Result<(), SdkError> {
        // A pause frees the Apply slot even when no command is waiting.
        self.service_head_completion().await?;
        if !demand_active() {
            return Ok(());
        }
        let pulled = {
            let Some(_guard) = PreferGuard::enter() else {
                return Ok(());
            };
            self.pull_head_priority().await
        };
        let (heads, rest) = pulled?;
        for work in heads {
            // Boxed: this apply can pause and call back into `prefer_demanded_head`.
            Box::pin(self.apply_connection_work(work)).await?;
        }
        for work in rest {
            self.defer_or_apply(work).await?;
        }
        Ok(())
    }

    /// One connection item observed while a head demand is active.
    pub(super) async fn admit_during_head_demand(
        &mut self,
        work: AccountWork,
    ) -> Result<(), SdkError> {
        if is_head_refresh(&work) {
            Box::pin(self.apply_connection_work(work)).await?;
        } else {
            self.defer_or_apply(work).await?;
        }
        self.prefer_demanded_head().await
    }

    pub(super) fn defer_paused(&mut self, work: AccountWork) {
        self.deferred.push_front(work);
    }

    async fn defer_or_apply(&mut self, work: AccountWork) -> Result<(), SdkError> {
        // The in-progress job may also be pushed in front, so the cap is the
        // queue depth plus that one resumed item. A running transaction is not
        // interrupted; the head is applied before generic overflow starts.
        if self.deferred.len() < super::CONNECTION_WORK_QUEUE + 1 {
            self.deferred.push_back(work);
            return Ok(());
        }
        self.service_head_completion().await?;
        Box::pin(self.apply_connection_work(work)).await
    }

    /// One queued head Apply. Empty and disconnected are both idle.
    pub(super) async fn service_head_completion(&mut self) -> Result<(), SdkError> {
        if let Ok(work) = self.head_rx.try_recv() {
            Box::pin(self.apply_connection_work(work)).await?;
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) async fn recv_connection_work(&mut self) -> Option<AccountWork> {
        recv(&mut self.deferred, &mut self.head_rx, &mut self.connection_work).await
    }

    #[cfg(test)]
    pub(crate) fn try_recv_connection_work(
        &mut self,
    ) -> Result<AccountWork, tokio::sync::mpsc::error::TryRecvError> {
        match self.head_rx.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => self.connection_work.try_recv(),
            other => other,
        }
    }

    async fn pull_head_priority(
        &mut self,
    ) -> Result<(Vec<AccountWork>, Vec<AccountWork>), SdkError> {
        let mut held = Vec::new();
        for _ in 0..super::CONNECTION_WORK_QUEUE {
            match self.connection_work.try_recv() {
                Ok(work) => held.push(work),
                Err(error) => {
                    // An empty disconnected queue cannot deliver the demanded head.
                    if held.is_empty()
                        && matches!(error, tokio::sync::mpsc::error::TryRecvError::Disconnected)
                    {
                        return Err(SdkError::NetworkingPending);
                    }
                    break;
                }
            }
        }
        if held.len() == super::CONNECTION_WORK_QUEUE {
            // A shared-queue head (no dedicated sender) may be blocked in `send`.
            tokio::task::yield_now().await;
            if let Ok(work) = self.connection_work.try_recv() {
                held.push(work);
            }
        }
        let mut heads = Vec::new();
        let mut rest = Vec::new();
        for work in held {
            if is_head_refresh(&work) {
                heads.push(work);
            } else {
                rest.push(work);
            }
        }
        Ok((heads, rest))
    }
}
