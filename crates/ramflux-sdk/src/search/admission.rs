// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Three admitted requests/account: one executor and two cancellable queued requests.
use ramflux_storage::local_search::{SearchControl, SearchError, SearchResult};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone)]
pub(super) struct RequestControl {
    pub control: SearchControl,
    wake: Arc<tokio::sync::Notify>,
}
impl RequestControl {
    pub fn cancel(&self) {
        self.control.cancel();
        self.wake.notify_one();
    }
}
pub(super) type Requests = Arc<Mutex<BTreeMap<(u64, String), RequestControl>>>;
pub(crate) struct Admission {
    pub control: SearchControl,
    active: Requests,
    key: (u64, String),
    global: Option<tokio::sync::OwnedSemaphorePermit>,
    account: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Admission {
    pub(super) async fn acquire(
        active: Requests,
        account: &Arc<tokio::sync::Semaphore>,
        client: u64,
        id: &str,
    ) -> SearchResult<Self> {
        static GLOBAL: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        let request = RequestControl {
            control: SearchControl::new(),
            wake: Arc::new(tokio::sync::Notify::new()),
        };
        let key = (client, id.to_owned());
        {
            let mut requests = active.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if id.is_empty() || id.len() > 128 {
                return Err(SearchError::InvalidQuery);
            }
            if requests.len() >= 3 || requests.contains_key(&key) {
                return Err(SearchError::Capacity);
            }
            requests.insert(key.clone(), request.clone());
        }
        let mut admission =
            Self { control: request.control.clone(), active, key, global: None, account: None };
        let acquire = async {
            admission.account = Some(
                Arc::clone(account)
                    .acquire_owned()
                    .await
                    .map_err(|_| SearchError::AccountLocked)?,
            );
            admission.global = Some(
                GLOBAL
                    .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| SearchError::IndexUnavailable)?,
            );
            Ok::<_, SearchError>(())
        };
        tokio::select! {
            result=tokio::time::timeout(std::time::Duration::from_millis(100),acquire)=>result.map_err(|_|SearchError::Deadline)??,
            ()=request.wake.notified()=>return Err(SearchError::Cancelled),
        }
        admission.control.check()?;
        Ok(admission)
    }
    pub(super) fn belongs_to(&self, client: u64, id: &str) -> bool {
        self.key.0 == client && self.key.1 == id
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        self.control.cancel();
        self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&self.key);
    }
}
