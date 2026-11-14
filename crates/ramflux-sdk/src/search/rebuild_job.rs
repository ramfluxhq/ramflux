// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Volatile job ownership survives caller cancellation and fences reused correlation IDs.
use super::{Admission, LocalSearch, SearchError};
use crate::search::admission::Requests;
use crate::{RamfluxClient, SdkError};
use ramflux_storage::local_search::{
    SearchControl, SearchIndexStatus, SearchRebuildProgress, SearchRebuildState,
};
use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub(super) type Jobs = Arc<Mutex<Option<(u64, String, Arc<AtomicBool>)>>>;
pub(super) type Progress = Arc<Mutex<Option<SearchRebuildProgress>>>;
pub(crate) struct RebuildTicket {
    jobs: Jobs,
    progress: Progress,
    active: Requests,
    owner: u64,
    id: String,
    token: Arc<AtomicBool>,
}
impl RebuildTicket {
    fn finish(&self, state: SearchRebuildState) {
        let claimed = {
            let mut jobs = self.jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if jobs.as_ref().is_some_and(|(owner, id, token)| {
                *owner == self.owner && id == &self.id && Arc::ptr_eq(token, &self.token)
            }) {
                jobs.take();
                true
            } else {
                false
            }
        };
        if claimed {
            *self.progress.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(SearchRebuildProgress { job_id: self.id.as_str().into(), state });
            self.token.store(true, Ordering::Release);
            if let Some(request) = self
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&(self.owner, self.id.clone()))
            {
                request.cancel();
            }
        }
    }
}
impl Drop for RebuildTicket {
    fn drop(&mut self) {
        self.finish(SearchRebuildState::Paused);
    }
}
impl LocalSearch {
    pub(crate) fn start_rebuild(&self, owner: u64, id: &str) -> Result<RebuildTicket, SdkError> {
        if id.is_empty() || id.len() > 128 {
            return Err(SearchError::InvalidQuery.into());
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(SearchError::AccountLocked.into());
        }
        let mut jobs = self.rebuild.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if jobs.is_some() {
            return Err(SearchError::Capacity.into());
        }
        let token = Arc::new(AtomicBool::new(false));
        *jobs = Some((owner, id.to_owned(), Arc::clone(&token)));
        *self.rebuild_progress.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(SearchRebuildProgress { job_id: id.into(), state: SearchRebuildState::Queued });
        self.quota_paused.store(false, Ordering::Release);
        Ok(RebuildTicket {
            jobs: Arc::clone(&self.rebuild),
            progress: Arc::clone(&self.rebuild_progress),
            active: Arc::clone(&self.active),
            owner,
            id: id.to_owned(),
            token,
        })
    }
    /// # Errors
    /// Old unlock epochs cannot cancel a newly admitted maintenance lease.
    pub fn cancel_rebuild(&self, owner: u64, unlock_epoch: u64, id: &str) -> Result<(), SdkError> {
        if unlock_epoch != self.unlock {
            return Err(SearchError::CursorStale.into());
        }
        if id.is_empty() || id.len() > 128 {
            return Err(SearchError::InvalidQuery.into());
        }
        let selected = {
            let mut jobs = self.rebuild.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if jobs.as_ref().is_some_and(|(client, job, _)| *client == owner && job == id) {
                jobs.take()
            } else {
                None
            }
        };
        if let Some((_, _, token)) = selected {
            token.store(true, Ordering::Release);
            self.cancel_request(owner, id);
            *self.rebuild_progress.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(SearchRebuildProgress {
                    job_id: id.into(),
                    state: SearchRebuildState::Cancelled,
                });
        }
        Ok(())
    }
    pub(crate) async fn run_rebuild_with<F, Fut>(
        &self,
        ticket: RebuildTicket,
        mut batch: F,
    ) -> Result<(), SdkError>
    where
        F: FnMut(Admission, bool) -> Fut,
        Fut: Future<Output = Result<bool, SdkError>>,
    {
        let owner = ticket.owner;
        let id = ticket.id.clone();
        let run = async {
            let mut reset = true;
            while !ticket.token.load(Ordering::Acquire) {
                let admission = self.admit(owner, &id).await?;
                *self.rebuild_progress.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(SearchRebuildProgress {
                        job_id: id.as_str().into(),
                        state: SearchRebuildState::Running,
                    });
                let done = batch(admission, reset).await?;
                reset = false;
                if done {
                    return Ok::<_, SdkError>(true);
                }
                tokio::task::yield_now().await;
            }
            Ok(false)
        };
        let result = tokio::time::timeout(Duration::from_secs(30), run).await;
        let state = match &result {
            Ok(Ok(true)) if self.quota_paused.load(Ordering::Acquire) => {
                SearchRebuildState::QuotaLimited
            }
            Ok(Ok(true)) => SearchRebuildState::Complete,
            Ok(Ok(false)) => SearchRebuildState::Cancelled,
            Ok(Err(_)) => SearchRebuildState::Failed,
            Err(_) => SearchRebuildState::Paused,
        };
        ticket.finish(state);
        match result {
            Ok(result) => result.map(|_| ()),
            Err(_) => Ok(()),
        }
    }
    /// Runs the same bounded maintenance loop as bus dispatch, with a 30-second lease.
    /// # Errors
    /// Returns admission/storage errors; cancellation and timeout retain resumable ID work.
    pub async fn rebuild(
        &self,
        client: &RamfluxClient,
        owner: u64,
        id: &str,
    ) -> Result<SearchIndexStatus, SdkError> {
        self.epoch(client, &SearchControl::new())?;
        let ticket = self.start_rebuild(owner, id)?;
        self.run_rebuild_with(ticket, |admission, reset| async move {
            self.rebuild_batch(client, owner, id, &admission, reset)
        })
        .await?;
        self.index_status(client)
    }
}
