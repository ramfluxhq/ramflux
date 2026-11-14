// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit-before-reply invalidation. Callbacks must never re-enter a database worker.
use super::{SearchError, SearchResult};
use rusqlite::OptionalExtension as _;
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

type Callback = Arc<dyn Fn() + Send + Sync>;
struct State {
    identity: Option<(i64, i64)>,
    callbacks: BTreeMap<String, Callback>,
    observers: BTreeMap<String, Callback>,
}
pub struct SearchWatch {
    state: Mutex<State>,
    stamp: AtomicU64,
    closed: AtomicBool,
}
impl Default for SearchWatch {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                identity: None,
                callbacks: BTreeMap::new(),
                observers: BTreeMap::new(),
            }),
            stamp: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }
}
pub struct SearchRegistration {
    watch: Arc<SearchWatch>,
    id: String,
    persistent: bool,
}
impl Drop for SearchRegistration {
    fn drop(&mut self) {
        let mut state = self.watch.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.persistent {
            state.observers.remove(&self.id);
        } else {
            state.callbacks.remove(&self.id);
        }
    }
}
impl SearchWatch {
    #[must_use]
    pub fn stamp(&self) -> u64 {
        self.stamp.load(Ordering::Acquire)
    }
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.invalidate();
    }
    /// # Errors
    /// Refuses stale epochs, duplicate resource IDs and bounded-registry saturation.
    pub fn register(
        self: &Arc<Self>,
        id: String,
        expected: u64,
        callback: Callback,
    ) -> SearchResult<SearchRegistration> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_closed() || expected == u64::MAX {
            return Err(SearchError::IndexUnavailable);
        }
        if expected != self.stamp() {
            return Err(SearchError::CursorStale);
        }
        if id.len() > 256 || state.callbacks.len() >= 1_024 || state.callbacks.contains_key(&id) {
            return Err(SearchError::Capacity);
        }
        state.callbacks.insert(id.clone(), callback);
        Ok(SearchRegistration { watch: Arc::clone(self), id, persistent: false })
    }
    /// Registers a persistent ID-only runtime observer; callbacks never re-enter SQL.
    /// # Errors
    /// Refuses registry saturation, duplicate IDs and exhausted stamps.
    pub fn observe(
        self: &Arc<Self>,
        id: String,
        callback: Callback,
    ) -> SearchResult<SearchRegistration> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_closed()
            || self.stamp() == u64::MAX
            || id.len() > 256
            || state.observers.len() >= 128
            || state.observers.contains_key(&id)
        {
            return Err(SearchError::Capacity);
        }
        state.observers.insert(id.clone(), callback);
        Ok(SearchRegistration { watch: Arc::clone(self), id, persistent: true })
    }
    pub(crate) fn refresh(&self, db: &rusqlite::Connection) {
        if self.is_closed() || !db.is_autocommit() {
            return;
        }
        let identity = db
            .query_row(
                "SELECT epoch,revision FROM local_search_state WHERE singleton=1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .unwrap_or(None);
        let callbacks = {
            let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.identity == identity {
                return;
            }
            state.identity = identity;
            let _ = self.stamp.try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_add(1))
            });
            let mut callbacks =
                std::mem::take(&mut state.callbacks).into_values().collect::<Vec<_>>();
            callbacks.extend(state.observers.values().cloned());
            callbacks
        };
        for callback in callbacks {
            callback();
        }
    }
    pub fn invalidate(&self) {
        let callbacks = {
            let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = self.stamp.try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_add(1))
            });
            let mut callbacks =
                std::mem::take(&mut state.callbacks).into_values().collect::<Vec<_>>();
            callbacks.extend(state.observers.values().cloned());
            callbacks
        };
        for callback in callbacks {
            callback();
        }
    }
}
