// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scoped search execution, authoritative hydration and volatile reply ownership.
use super::{admission::Admission, cursor::Cursors, hydration};
use crate::{RamfluxClient, SdkError};
use ramflux_storage::local_search::{
    MAX_REBUILD_BYTES, SearchAccountIncarnation, SearchActivation, SearchControl, SearchError,
    SearchPage, SearchQuery, SearchRegistration, SearchResult, SearchText, SearchViewEpoch,
    SearchWatch,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
#[path = "execution.rs"]
mod execution;
#[path = "pending.rs"]
mod pending;
#[path = "rebuild_job.rs"]
pub(crate) mod rebuild_job;
type Runtimes = BTreeMap<SearchAccountIncarnation, Weak<LocalSearch>>;
type Pending = Arc<Mutex<BTreeMap<SearchText, (u64, SearchCompletion, Instant)>>>;

pub struct LocalSearch {
    activation: SearchActivation,
    incarnation: SearchAccountIncarnation,
    account: String,
    path: std::path::PathBuf,
    publication_epoch: i64,
    closed: std::sync::atomic::AtomicBool,
    unlock: u64,
    watch: Arc<SearchWatch>,
    account_permit: Arc<tokio::sync::Semaphore>,
    active: super::admission::Requests,
    cursors: Arc<Mutex<Cursors>>,
    pending: Pending,
    observer: Option<SearchRegistration>,
    rebuild: rebuild_job::Jobs,
    rebuild_progress: rebuild_job::Progress,
    quota_paused: std::sync::atomic::AtomicBool,
}
/// Keeps reply plaintext revocable until the binding's final publication boundary.
pub struct SearchCompletion {
    page: Arc<Mutex<Option<SearchPage>>>,
    watch: Arc<SearchWatch>,
    stamp: u64,
    clock: ramflux_storage::AccountClock,
    expires_at: Option<i64>,
    _watch: SearchRegistration,
    _erasure: ramflux_storage::PrivacyResourceRegistration,
    admission: Admission,
}
impl SearchCompletion {
    /// # Errors
    /// Refuses a queued reply invalidated during encoding.
    pub fn check_current(&self) -> SearchResult<()> {
        if self.watch.is_closed()
            || self.watch.stamp() != self.stamp
            || self.expires_at.is_some_and(|expiry| self.clock.now_unix() >= expiry)
        {
            return Err(SearchError::CursorStale);
        }
        self.admission.control.check()
    }
    /// # Errors
    /// Invalidated or already consumed pages are never returned from a pending completion.
    pub fn take(&self) -> SearchResult<SearchPage> {
        let mut page = self.page.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.watch.is_closed()
            || self.watch.stamp() != self.stamp
            || self.expires_at.is_some_and(|expiry| self.clock.now_unix() >= expiry)
        {
            page.take();
            return Err(SearchError::CursorStale);
        }
        if let Err(error) = self.admission.control.check() {
            page.take();
            return Err(error);
        }
        page.take().ok_or(SearchError::CursorStale)
    }
}
impl LocalSearch {
    /// Refuses dormant capability before acquiring an account database.
    /// # Errors
    /// Returns the configured capability refusal or encrypted-engine initialization errors.
    pub fn open(client: &RamfluxClient) -> Result<Arc<Self>, SdkError> {
        let activation = SearchActivation::configured()?;
        Self::initialize(client, activation)
    }
    fn initialize(
        client: &RamfluxClient,
        activation: SearchActivation,
    ) -> Result<Arc<Self>, SdkError> {
        Self::for_db(client.account_db()?, activation)
    }
    pub(crate) fn for_db(
        db: &ramflux_storage::AccountDb,
        activation: SearchActivation,
    ) -> Result<Arc<Self>, SdkError> {
        static RUNTIMES: OnceLock<Mutex<Runtimes>> = OnceLock::new();
        let mut runtimes = RUNTIMES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runtimes.retain(|_, runtime| runtime.strong_count() > 0);
        let incarnation = db.search_incarnation(&activation);
        if let Some(runtime) = runtimes.get(&incarnation).and_then(Weak::upgrade) {
            if runtime.watch.is_closed()
                || runtime.closed.load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(SearchError::AccountLocked.into());
            }
            return Ok(runtime);
        }
        if runtimes.len() >= 128 {
            return Err(SearchError::Capacity.into());
        }
        let watch = db.search_prepare(&activation)?;
        let random = ramflux_crypto::random_32()?;
        let unlock = u64::from_le_bytes(
            random
                .get(..8)
                .ok_or(SearchError::IndexUnavailable)?
                .try_into()
                .map_err(|_| SearchError::IndexUnavailable)?,
        );
        let publication_epoch = db.search_revision(&activation, &SearchControl::new())?.epoch;
        let mut service = Self {
            activation,
            incarnation: incarnation.clone(),
            account: db.local_account_id.clone(),
            path: db.path.clone(),
            publication_epoch,
            closed: std::sync::atomic::AtomicBool::new(false),
            unlock,
            watch,
            account_permit: Arc::new(tokio::sync::Semaphore::new(1)),
            active: Arc::new(Mutex::new(BTreeMap::new())),
            cursors: Arc::new(Mutex::new(Cursors::default())),
            pending: Arc::new(Mutex::new(BTreeMap::new())),
            observer: None,
            rebuild: Arc::new(Mutex::new(None)),
            rebuild_progress: Arc::new(Mutex::new(None)),
            quota_paused: std::sync::atomic::AtomicBool::new(false),
        };
        service.install_observer()?;
        let service = Arc::new(service);
        runtimes.insert(incarnation, Arc::downgrade(&service));
        Ok(service)
    }
    pub(crate) async fn admit(&self, owner: u64, id: &str) -> Result<Admission, SdkError> {
        if self.watch.is_closed() || self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(SearchError::AccountLocked.into());
        }
        Ok(Admission::acquire(Arc::clone(&self.active), &self.account_permit, owner, id).await?)
    }
    /// Runs a typed Rust query using the shared bounded admission and completion contract.
    /// # Errors
    /// Returns admission, authoritative source, deadline or index failures.
    pub async fn query(
        &self,
        client: &RamfluxClient,
        owner: u64,
        request: &SearchQuery,
    ) -> Result<SearchCompletion, SdkError> {
        request.validate()?;
        let admission = self.admit(owner, &request.request_id).await?;
        self.execute_query(client, owner, request, admission)
    }
    /// Drops every local query/cursor at the account lock/publication boundary.
    pub fn invalidate(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::Release);
        self.account_permit.close();
        self.invalidate_views();
    }
    pub(crate) fn invalidate_views(&self) {
        if let Some(job) =
            self.rebuild.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
        {
            job.token.store(true, std::sync::atomic::Ordering::Release);
            self.cancel_request(job.owner, &job.work);
            *self.rebuild_progress.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(ramflux_storage::local_search::SearchRebuildProgress {
                    job_id: job.id.as_str().into(),
                    state: ramflux_storage::local_search::SearchRebuildState::Cancelled,
                });
        }
        self.watch.invalidate();
        self.clear_pending();
        self.cursors.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
        for control in
            self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).values()
        {
            control.cancel();
        }
    }
    /// # Errors
    /// Old-unlock cancellation cannot affect a request admitted by a new account instance.
    pub fn cancel(&self, client: u64, unlock_epoch: u64, request_id: &str) -> SearchResult<()> {
        if request_id.is_empty() || request_id.len() > 128 {
            return Err(SearchError::InvalidQuery);
        }
        if unlock_epoch != self.unlock {
            return Err(SearchError::CursorStale);
        }
        self.cancel_request(client, request_id);
        Ok(())
    }
    #[must_use]
    pub fn unlock_epoch(&self) -> u64 {
        self.unlock
    }
    fn cancel_request(&self, client: u64, request_id: &str) {
        let control = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(client, request_id.to_owned()))
            .cloned();
        if let Some(control) = control {
            control.cancel();
        }
        self.cancel_pending(client, request_id);
    }
    pub fn close_cursor(&self, client: u64, token: &str) {
        self.cursors.lock().unwrap_or_else(std::sync::PoisonError::into_inner).close(client, token);
    }
    fn epoch(
        &self,
        client: &RamfluxClient,
        control: &SearchControl,
    ) -> Result<SearchViewEpoch, SdkError> {
        if self.watch.is_closed() || self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(SearchError::AccountLocked.into());
        }
        let db = client.account_db()?;
        if db.search_incarnation(&self.activation) != self.incarnation
            || db.local_account_id != self.account
            || db.path != self.path
        {
            return Err(SearchError::AccountLocked.into());
        }
        let revision = db.search_revision(&self.activation, control)?;
        if revision.epoch != self.publication_epoch {
            return Err(SearchError::CursorStale.into());
        }
        Ok(SearchViewEpoch {
            unlock: self.unlock,
            publication: u64::try_from(revision.epoch)
                .map_err(|_| SearchError::IndexUnavailable)?,
            erasure: u64::try_from(db.privacy_erasure_generation()?)
                .map_err(|_| SearchError::IndexUnavailable)?,
            index: u64::try_from(revision.revision).map_err(|_| SearchError::IndexUnavailable)?,
        })
    }
    /// Performs one foreground-friendly maintenance batch, preserving a format-bound checkpoint.
    /// # Errors
    /// Quotas produce partial coverage; cancellation and privacy races leave resumable ID work.
    pub(crate) fn rebuild_batch(
        &self,
        client: &RamfluxClient,
        owner: u64,
        job: &str,
        admission: &Admission,
        reset: bool,
    ) -> Result<bool, SdkError> {
        if job.is_empty() || job.len() > 128 {
            return Err(SearchError::InvalidQuery.into());
        }
        if !admission.belongs_to(owner, job) {
            return Err(SearchError::PermissionDenied.into());
        }
        let control = &admission.control;
        self.epoch(client, control)?;
        let db = client.account_db()?;
        if reset {
            db.search_rebuild_reset(&self.activation, control)?;
        }
        let Some(batch) = db.search_rebuild_batch(&self.activation, control)? else {
            return Ok(true);
        };
        let start = Instant::now();
        let mut bytes = 0usize;
        let mut last = None;
        for key in &batch.keys {
            if start.elapsed() >= Duration::from_millis(20) || bytes >= MAX_REBUILD_BYTES {
                break;
            }
            let sources =
                match hydration::sources(client, &self.activation, batch.kind, key, control) {
                    Ok(sources) => sources,
                    Err(SdkError::Search(SearchError::Capacity)) => {
                        db.search_mark_partial(&self.activation, false, control)?;
                        last = Some(key.clone());
                        continue;
                    }
                    Err(error) => return Err(error),
                };
            let source_bytes = sources
                .iter()
                .fold(0usize, |total, source| total.saturating_add(source.text.expose().len()));
            if source_bytes > MAX_REBUILD_BYTES {
                db.search_mark_partial(&self.activation, false, control)?;
                last = Some(key.clone());
                continue;
            }
            if bytes.saturating_add(source_bytes) > MAX_REBUILD_BYTES {
                break;
            }
            bytes = bytes.saturating_add(source_bytes);
            for source in sources {
                match db.search_replace(&self.activation, source, batch.canonical, control) {
                    Err(SearchError::Capacity) => {
                        db.search_mark_partial(&self.activation, true, control)?;
                        self.quota_paused.store(true, std::sync::atomic::Ordering::Release);
                        return Ok(true);
                    }
                    result => result?,
                }
            }
            last = Some(key.clone());
        }
        db.search_rebuild_advance(&self.activation, batch, last, control)?;
        Ok(false)
    }
}
impl Drop for LocalSearch {
    fn drop(&mut self) {
        self.invalidate();
    }
}
