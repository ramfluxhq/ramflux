// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Content-free reply tokens cross the outbound queue; plaintext stays revocable here.
use super::{Admission, LocalSearch, SearchCompletion};
use crate::{RamfluxClient, SdkError};
use ramflux_storage::local_search::{
    SearchControl, SearchError, SearchIndexStatus, SearchPage, SearchText,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
impl LocalSearch {
    pub(super) fn install_observer(&mut self) -> Result<(), SdkError> {
        let cursors = Arc::downgrade(&self.cursors);
        let pending = Arc::downgrade(&self.pending);
        self.observer = Some(self.watch.observe(
            format!("runtime/{}", self.unlock),
            Arc::new(move || {
                if let Some(cursors) = cursors.upgrade() {
                    cursors.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
                }
                if let Some(pending) = pending.upgrade() {
                    for (_, completion, _) in
                        pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner).values()
                    {
                        completion
                            .page
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take();
                    }
                }
            }),
        )?);
        Ok(())
    }
    pub(super) fn clear_pending(&self) {
        let retired = std::mem::take(
            &mut *self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        drop(retired);
    }
    pub(crate) fn queue_completion(
        &self,
        owner: u64,
        completion: SearchCompletion,
    ) -> Result<serde_json::Value, SdkError> {
        let mut pending = self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending.len() >= 3 {
            return Err(SearchError::Capacity.into());
        }
        let token =
            SearchText::from(ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?));
        let body = serde_json::json!({"search_completion":token.expose()});
        let old = pending.insert(token, (owner, completion, Instant::now()));
        drop(pending);
        drop(old);
        Ok(body)
    }
    pub(crate) fn take_completion(
        &self,
        owner: u64,
        token: &str,
    ) -> Result<SearchCompletion, SdkError> {
        let mut pending = self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending.get(token).is_none_or(|(client, _, _)| *client != owner) {
            return Err(SearchError::CursorStale.into());
        }
        let (_, completion, created) = pending.remove(token).ok_or(SearchError::CursorStale)?;
        drop(pending);
        if created.elapsed() >= Duration::from_secs(60) {
            return Err(SearchError::CursorStale.into());
        }
        Ok(completion)
    }
    pub(crate) fn disconnect(&self, owner: u64) {
        let job = self
            .rebuild
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|job| job.owner == owner)
            .map(|job| job.id.clone());
        if let Some(job) = job {
            let _ = self.cancel_rebuild(owner, self.unlock, &job);
        }
        self.cursors.lock().unwrap_or_else(std::sync::PoisonError::into_inner).disconnect(owner);
        let retired = {
            let mut pending =
                self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let keys = pending
                .iter()
                .filter(|(_, (client, _, _))| *client == owner)
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            keys.into_iter().filter_map(|key| pending.remove(&key)).collect::<Vec<_>>()
        };
        drop(retired);
        for ((client, _), control) in
            self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter()
        {
            if *client == owner {
                control.cancel();
            }
        }
    }
    /// Reports coverage and the current volatile maintenance lease.
    /// # Errors
    /// Refuses a locked/replaced account or incompatible index without serving stale status.
    pub fn index_status(&self, client: &RamfluxClient) -> Result<SearchIndexStatus, SdkError> {
        let control = SearchControl::new();
        let epoch = self.epoch(client, &control)?;
        let mut status = client.account_db()?.search_index_status(&self.activation, &control)?;
        status.view_epoch = Some(epoch);
        status.rebuild =
            self.rebuild_progress.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        Ok(status)
    }
}

impl LocalSearch {
    pub(super) fn register_completion(
        &self,
        client: &RamfluxClient,
        (owner, request): (u64, &str),
        page: SearchPage,
        (stamp, expires_at): (u64, Option<i64>),
        admission: Admission,
    ) -> Result<SearchCompletion, SdkError> {
        let generation =
            i64::try_from(page.view_epoch.erasure).map_err(|_| SearchError::IndexUnavailable)?;
        let page = Arc::new(Mutex::new(Some(page)));
        let clear = Arc::clone(&page);
        let cursors = Arc::clone(&self.cursors);
        let pending = Arc::downgrade(&self.pending);
        let registration = self.watch.register(
            format!("reply/{owner}/{request}"),
            stamp,
            Arc::new(move || {
                clear.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
                cursors.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
                if let Some(pending) = pending.upgrade() {
                    for (_, completion, _) in
                        pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner).values()
                    {
                        completion
                            .page
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take();
                    }
                }
            }),
        )?;
        let clear = Arc::clone(&page);
        let erasure = client.account_db()?.register_privacy_resource(
            &format!("search/{owner}/{request}"),
            generation,
            Arc::new(move || {
                clear.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
                Ok(())
            }),
        )?;
        Ok(SearchCompletion {
            page,
            watch: Arc::clone(&self.watch),
            stamp,
            clock: client.account_db()?.search_clock(&self.activation),
            expires_at,
            _watch: registration,
            _erasure: erasure,
            admission,
        })
    }
}
