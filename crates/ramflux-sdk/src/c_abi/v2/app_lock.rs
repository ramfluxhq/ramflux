// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Erase native queued plaintext before the daemon acknowledges app lock.
use super::state::{MAX_EVENTS, ResultSlot, Shared};
use crate::bus::app_lock_fence::Observer;
use zeroize::Zeroizing;
impl Observer for Shared {
    fn locked(&self, account: &str) {
        if let Ok(operations) = self.operations.lock() {
            for operation in operations.values() {
                if let Ok(mut state) = operation.state.lock()
                    && state.access.as_ref().is_some_and(|access| access.affects(account))
                {
                    state.slot = ResultSlot::Frozen;
                    state.result = Some(locked_bytes());
                }
            }
        }
        if let Ok(mut subscription) = self.subscription.lock()
            && let Ok(mut events) = self.events.lock()
            && events.account_id.as_deref().is_none_or(|id| id == account)
        {
            *subscription = None;
            events.active = false;
            events.queue.clear();
            events.bytes = 0;
            events.resync = false;
        }
    }
}
impl Shared {
    pub(super) fn push_control(&self, bytes: Vec<u8>) {
        if let Ok(mut controls) = self.controls.lock() {
            if controls.len() >= MAX_EVENTS {
                controls.clear();
            }
            controls.push_back(Zeroizing::new(bytes));
        }
    }
}
pub(super) fn locked_bytes() -> Zeroizing<Vec<u8>> {
    let status = super::super::RamfluxErrorCode::AuthFailed as i32;
    Zeroizing::new(format!(r#"{{"code":{status},"name":"AuthFailed","reason":"app_locked","reason_code":"app_locked","effects":"unknown"}}"#).into_bytes())
}

pub(super) fn capture_access(
    shared: &Shared,
    method: &str,
    account: Option<&str>,
) -> Result<Option<crate::bus::app_lock_fence::Token>, crate::SdkError> {
    if crate::bus::app_lock_fence::control(method) {
        return Ok(None);
    }
    shared
        .app_fences
        .get()
        .map(|fences| fences.token(crate::bus::app_lock_fence::scope(method, account)))
        .transpose()
}
