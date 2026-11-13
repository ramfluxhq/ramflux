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
    pub(crate) fn start_rebuild(
        &self,
        owner: u64,
        id: &str,
    ) -> Result<Arc<std::sync::atomic::AtomicBool>, SdkError> {
        if id.is_empty() || id.len() > 128 {
            return Err(SearchError::InvalidQuery.into());
        }
        let mut rebuild = self.rebuild.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if rebuild.is_some() {
            return Err(SearchError::Capacity.into());
        }
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *rebuild = Some((owner, id.to_owned(), Arc::clone(&cancelled)));
        Ok(cancelled)
    }
    pub(crate) fn cancel_rebuild(&self, owner: u64, id: &str) {
        let mut rebuild = self.rebuild.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if rebuild.as_ref().is_some_and(|(client, job, _)| *client == owner && job == id)
            && let Some((_, _, cancelled)) = rebuild.take()
        {
            cancelled.store(true, std::sync::atomic::Ordering::Release);
            self.cancel(owner, id);
        }
    }
    pub(crate) fn finish_rebuild(
        &self,
        owner: u64,
        id: &str,
        token: &Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut rebuild = self.rebuild.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if rebuild.as_ref().is_some_and(|(client, job, current)| {
            *client == owner && job == id && Arc::ptr_eq(current, token)
        }) {
            rebuild.take();
        }
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
            .filter(|(client, _, _)| *client == owner)
            .map(|(_, id, _)| id.clone());
        if let Some(job) = job {
            self.cancel_rebuild(owner, &job);
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
    pub(crate) fn status(&self, client: &RamfluxClient) -> Result<SearchIndexStatus, SdkError> {
        let control = SearchControl::new();
        let mut status = client.account_db()?.search_index_status(&self.activation, &control)?;
        status.view_epoch = Some(self.epoch(client, &control)?);
        Ok(status)
    }
}

impl LocalSearch {
    pub(super) fn register_completion(
        &self,
        client: &RamfluxClient,
        (owner, request): (u64, &str),
        page: SearchPage,
        stamp: u64,
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
            _watch: registration,
            _erasure: erasure,
            admission,
        })
    }
}
