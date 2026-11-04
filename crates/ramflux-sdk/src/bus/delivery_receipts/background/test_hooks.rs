// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact-envelope receipt network doubles retain the production prepare/network/apply runner.

use crate::SdkError;
use crate::client::routed::SendMaterial;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct Hook {
    pub entered: Notify,
    pub release: Notify,
    used: AtomicBool,
    applied: AtomicBool,
}
fn registry() -> &'static Mutex<HashMap<String, Arc<Hook>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<Hook>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}
pub(crate) struct Registration {
    id: String,
    hook: Arc<Hook>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut hooks = registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if hooks.get(&self.id).is_some_and(|current| Arc::ptr_eq(current, &self.hook)) {
            hooks.remove(&self.id);
        }
    }
}
pub(crate) fn register(id: String) -> (Registration, Arc<Hook>) {
    let hook = Arc::new(Hook::default());
    let previous = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(id.clone(), Arc::clone(&hook));
    assert!(previous.is_none(), "receipt test network keys must be unique");
    (Registration { id, hook: Arc::clone(&hook) }, hook)
}
fn lookup(id: Option<&str>) -> Option<Arc<Hook>> {
    registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id?).cloned()
}
pub(super) async fn network(id: Option<&str>) -> Option<Result<SendMaterial, SdkError>> {
    let hook = lookup(id)?;
    if hook.used.swap(true, Ordering::AcqRel) {
        return None;
    }
    hook.entered.notify_one();
    hook.release.notified().await;
    Some(Err(ramflux_transport::TransportError::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "injected receipt network failure",
    ))
    .into()))
}
pub(super) fn applied(id: Option<&str>) {
    if let Some(hook) = lookup(id) {
        hook.applied.store(true, Ordering::Release);
    }
}
impl Hook {
    pub(crate) fn has_applied(&self) -> bool {
        self.applied.load(Ordering::Acquire)
    }
}
