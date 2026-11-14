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
        if id.is_empty() || id.len() > 128 {
            return Err(SearchError::InvalidQuery);
        }
        static GLOBAL: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        let request = RequestControl {
            control: SearchControl::new(),
            wake: Arc::new(tokio::sync::Notify::new()),
        };
        let key = (client, id.to_owned());
        {
            let mut requests = active.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
            biased;
            ()=request.wake.notified()=>return Err(SearchError::Cancelled),
            result=tokio::time::timeout(std::time::Duration::from_millis(100),acquire)=>result.map_err(|_|SearchError::Deadline)??,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future as _, task::Poll};
    #[tokio::test(flavor = "current_thread")]
    async fn local_search_admission_caps_and_out_of_queue_cancellation()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let active = Arc::new(Mutex::new(BTreeMap::new()));
            let account = Arc::new(tokio::sync::Semaphore::new(1));
            let first = Admission::acquire(Arc::clone(&active), &account, 7, "executing").await?;
            let mut second =
                Box::pin(Admission::acquire(Arc::clone(&active), &account, 7, "queued-1"));
            let mut third =
                Box::pin(Admission::acquire(Arc::clone(&active), &account, 7, "queued-2"));
            std::future::poll_fn(|cx| {
                assert!(
                    second.as_mut().poll(cx).is_pending(),
                    "one account must not execute two queries"
                );
                assert!(
                    third.as_mut().poll(cx).is_pending(),
                    "second queued query must remain outside SQL"
                );
                Poll::Ready(())
            })
            .await;
            assert!(
                matches!(
                    Admission::acquire(Arc::clone(&active), &account, 7, "overflow").await,
                    Err(SearchError::Capacity)
                ),
                "fourth account request must be rejected before enqueue"
            );
            {
                let requests = active.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                assert_eq!(
                    requests.len(),
                    3,
                    "one executing plus two queued requests is the entire account budget"
                );
                requests.get(&(7, "queued-1".into())).ok_or("queued-1 registration")?.cancel();
                requests.get(&(7, "queued-2".into())).ok_or("queued-2 registration")?.cancel();
            }
            assert!(
                matches!(second.await, Err(SearchError::Cancelled)),
                "cancellation must wake a queued request while the executor remains held"
            );
            assert!(
                matches!(third.await, Err(SearchError::Cancelled)),
                "cancellation must not wait for the SQL worker queue"
            );
            drop(first);
            assert!(
                active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty(),
                "completion/cancellation must release every admission record"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await??;
        Ok(())
    }
}
