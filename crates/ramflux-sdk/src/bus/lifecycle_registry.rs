// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic local lifecycle ownership and shared completion, bounded independently of receipts.

use super::actor::ActorResponse;
use super::lifecycle::Receipt;
use crate::SdkError;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::watch;

type Completion = Option<Result<ActorResponse, Arc<SdkError>>>;
type Key = (String, String);
#[derive(Default, Clone)]
pub(super) struct Registry(Rc<RefCell<HashMap<Key, Entry>>>);
struct Entry {
    fingerprint: String,
    completion: watch::Sender<Completion>,
}
pub(super) struct Guard {
    registry: Registry,
    key: Key,
    completion: watch::Sender<Completion>,
}
pub(super) enum Admission {
    Join(watch::Receiver<Completion>),
    Own(Guard, watch::Receiver<Completion>),
}
impl Registry {
    pub(super) fn admit(&self, receipt: &Receipt) -> Result<Admission, SdkError> {
        let key = (receipt.scope.clone(), receipt.operation.clone());
        let mut entries = self.0.borrow_mut();
        if let Some(entry) = entries.get(&key) {
            if entry.fingerprint != receipt.fingerprint {
                return Err(ramflux_storage::StorageError::EventIdConflict(
                    receipt.operation.clone(),
                )
                .into());
            }
            return Ok(Admission::Join(entry.completion.subscribe()));
        }
        if entries.len() >= 256 {
            return Err(SdkError::LocalBusRefused {
                code: "Unavailable".into(),
                message: "lifecycle registry is full; retry later".into(),
                body: Box::new(serde_json::json!({"details":{"retryable":true}})),
            });
        }
        let (completion, receive) = watch::channel(None);
        entries.insert(
            key.clone(),
            Entry { fingerprint: receipt.fingerprint.clone(), completion: completion.clone() },
        );
        Ok(Admission::Own(Guard { registry: self.clone(), key, completion }, receive))
    }
}
impl Guard {
    pub(super) fn complete(&self, result: Result<ActorResponse, SdkError>) {
        self.completion.send_replace(Some(result.map_err(Arc::new)));
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.registry.0.borrow_mut().remove(&self.key);
    }
}
pub(super) async fn wait(
    mut receive: watch::Receiver<Completion>,
) -> Result<ActorResponse, SdkError> {
    loop {
        if let Some(result) = receive.borrow_and_update().clone() {
            return result.map_err(SdkError::LifecycleShared);
        }
        receive
            .changed()
            .await
            .map_err(|_| SdkError::LocalBus("lifecycle task cancelled".into()))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt(id: usize) -> Receipt {
        Receipt {
            scope: "alice".into(),
            operation: id.to_string(),
            fingerprint: "intent".into(),
            cached: None,
        }
    }
    type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;
    fn own(registry: &Registry, id: usize) -> Case<Guard> {
        match registry.admit(&receipt(id))? {
            Admission::Own(guard, _) => Ok(guard),
            Admission::Join(_) => Err("unexpected join".into()),
        }
    }
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::panic)] // Deliberately unwind a task to exercise the ownership guard.
    async fn registry_is_bounded_and_released() -> Case {
        tokio::task::LocalSet::new()
            .run_until(async {
                let registry = Registry::default();
                let mut guards = (0..256).map(|id| own(&registry, id)).collect::<Case<Vec<_>>>()?;
                let error = registry.admit(&receipt(256)).err().ok_or("capacity accepted")?;
                let body = super::super::io::local_bus_error_body(&error);
                assert_eq!(body.code, "Unavailable");
                assert_eq!(body.details.ok_or("missing retry details")?["retryable"], true);
                assert!(matches!(registry.admit(&receipt(0)), Ok(Admission::Join(_))));
                let guard = guards.pop().ok_or("missing guard")?;
                guard.complete(Ok(ActorResponse {
                    body: serde_json::json!({"ok":true}),
                    events: vec![],
                    nodes: None,
                }));
                drop(guard);
                let guard = own(&registry, 256)?;
                guard.complete(Err(SdkError::LocalBus("failed".into())));
                drop(guard);
                let guard = own(&registry, 256)?;
                let task = tokio::task::spawn_local(async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                });
                task.abort();
                assert!(task.await.err().ok_or("task not aborted")?.is_cancelled());
                let guard = own(&registry, 256)?;
                let task = tokio::task::spawn_local(async move {
                    let _guard = guard;
                    panic!("registry unwind probe");
                });
                assert!(task.await.err().ok_or("task did not panic")?.is_panic());
                drop(own(&registry, 256)?);
                drop(guards);
                assert!(registry.0.borrow().is_empty());
                Ok(())
            })
            .await
    }
}
