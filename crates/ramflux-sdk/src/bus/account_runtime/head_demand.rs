// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Priority for the authority head an active command has already demanded.
//!
//! The demand counts as a queued command, so directory and backfill pause
//! between commits. Head-refresh work already in the connection queue, or
//! blocked only because that queue is full, is applied before other work.
//! The pull is the queue depth plus the one sender waiting on a full queue.

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

/// Deferred generic connection work, then the live queue.
///
/// Popping the deferred item returns immediately, so a cancelled `select`
/// cannot lose it: the pop and the `Ready` happen in the same poll.
pub(super) async fn recv(
    deferred: &mut std::collections::VecDeque<AccountWork>,
    incoming: &mut tokio::sync::mpsc::Receiver<AccountWork>,
) -> Option<AccountWork> {
    if let Some(work) = deferred.pop_front() {
        return Some(work);
    }
    incoming.recv().await
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
    /// Applies queued head-refresh work before other connection work.
    pub(super) async fn prefer_demanded_head(&mut self) -> Result<(), SdkError> {
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
        // queue depth plus that one resumed item.
        if self.deferred.len() < super::CONNECTION_WORK_QUEUE + 1 {
            self.deferred.push_back(work);
            return Ok(());
        }
        Box::pin(self.apply_connection_work(work)).await
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
            // The head Apply may be blocked in `send` until this pull frees a slot.
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
