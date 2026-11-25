// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded handle state, terminal storage and independent event credit.

use super::{RamfluxV2Status, failure};
use crate::SdkError;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

pub(super) const MAX_OPERATIONS: usize = 64;
pub(super) const MAX_EVENTS: usize = 64;
pub(super) const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(super) struct Operation {
    pub state: Mutex<OperationState>,
}

#[derive(Default, PartialEq, Eq)]
pub(super) enum OperationKind {
    #[default]
    Request,
    Subscription,
    SubscriptionClose,
}

/// Suspend published the terminal result. A later bus response must not replace it.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum ResultSlot {
    #[default]
    Open,
    Frozen,
}

#[derive(Default)]
pub(super) struct OperationState {
    /// Echoed in the completion as `trace_id` (C-8).
    pub trace_id: Option<String>,
    pub admitted: bool,
    pub kind: OperationKind,
    pub cancelled: bool,
    pub detached: bool,
    pub slot: ResultSlot,
    pub result: Option<Zeroizing<Vec<u8>>>,
    pub access: Option<crate::bus::app_lock_fence::Token>,
}

pub(super) struct Event {
    pub generation: u64,
    pub bytes: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
pub(super) struct Events {
    pub queue: VecDeque<Event>,
    pub bytes: usize,
    pub resync: bool,
    pub generation: u64,
    pub active: bool,
    pub account_id: Option<String>,
}

#[derive(Default)]
pub(super) struct Shared {
    pub app_fences: std::sync::OnceLock<Arc<crate::bus::app_lock_fence::Fences>>,
    pub controls: Mutex<VecDeque<Zeroizing<Vec<u8>>>>,
    pub allow_secret_exports: std::sync::atomic::AtomicBool,
    pub allow_raw_messages: std::sync::atomic::AtomicBool,
    pub operations: Mutex<BTreeMap<u64, Arc<Operation>>>,
    pub events: Mutex<Events>,
    pub closed: std::sync::atomic::AtomicBool,
    pub suspended: std::sync::atomic::AtomicBool,
    pub subscription: Mutex<Option<u64>>,
    pub host_key: Mutex<Option<HostKeyFn>>,
    pub credentials: super::credential::Bridge,
}

/// In-process provider-key callback. `user` is an opaque pointer supplied by the host.
#[derive(Clone, Copy)]
pub(super) struct HostKeyFn {
    pub call:
        extern "C" fn(*const u8, usize, *mut u8, usize, *mut usize, *mut std::ffi::c_void) -> i32,
    pub user: usize,
}

impl Shared {
    fn trace_of(&self, id: u64) -> Option<String> {
        let operations = self.operations.lock().ok()?;
        let operation = operations.get(&id)?;
        let state = operation.state.lock().ok()?;
        state.trace_id.clone()
    }
    pub fn complete(&self, id: u64, mut value: serde_json::Value) {
        super::native_error::completion(&mut value);
        crate::diag::logging::refusal(&value);
        if let Some(trace) = self.trace_of(id)
            && let Some(map) = value.as_object_mut()
        {
            map.insert("trace_id".into(), serde_json::json!(trace));
        }
        let success = value.get("code").and_then(serde_json::Value::as_i64) == Some(0);
        let encoded = Zeroizing::new(
            serde_json::to_vec(&value)
                .unwrap_or_else(|_| br#"{"code":16,"name":"Internal","reason":"internal_error","reason_code":"internal_error","effects":"unknown"}"#.to_vec()),
        );
        crate::bus::inprocess::erase_value(&mut value);
        let Ok(mut operations) = self.operations.lock() else { return };
        self.credentials.forget(id);
        let Some(operation) = operations.get(&id) else { return };
        let Ok(mut subscription) = self.subscription.lock() else { return };
        let detached = if let Ok(mut state) = operation.state.lock() {
            if state.slot == ResultSlot::Frozen {
                state.detached
            } else {
                if (state.kind == OperationKind::SubscriptionClose && success)
                    || (state.kind == OperationKind::Subscription
                        && !success
                        && *subscription == Some(id))
                {
                    *subscription = None;
                    self.deactivate_generation();
                }
                state.result = Some(encoded);
                state.detached
            }
        } else {
            false
        };
        if detached {
            operations.remove(&id);
        }
    }

    pub fn failed(&self, id: u64, error: &SdkError) {
        self.complete(
            id,
            serde_json::json!({
                "code": super::super::sdk_error_code(error) as i32,
                "effects": "unknown"
            }),
        );
    }

    pub fn activate_generation(&self, generation: u64, account_id: Option<String>) {
        if let Ok(mut events) = self.events.lock() {
            events.queue.clear();
            events.bytes = 0;
            events.resync = false;
            events.generation = generation;
            events.active = generation != 0;
            events.account_id = account_id;
        }
    }

    pub fn deactivate_generation(&self) {
        if let Ok(mut events) = self.events.lock() {
            events.active = false;
            events.queue.clear();
            events.bytes = 0;
            events.resync = false;
        }
    }

    pub fn push_event(&self, bytes: Vec<u8>, generation: u64) {
        let bytes = Zeroizing::new(bytes);
        let Ok(mut events) = self.events.lock() else { return };
        if !events.active || generation == 0 || events.resync {
            return;
        }
        if generation != events.generation {
            crate::diag::events::abi_event("abi.event.drop", generation, "stale_generation");
            return;
        }
        if events.queue.len() >= MAX_EVENTS
            || bytes.len() > MAX_EVENT_BYTES.saturating_sub(events.bytes)
        {
            events.queue.clear();
            events.bytes = 0;
            events.resync = true;
            crate::diag::events::abi_event("abi.event.resync", generation, "credit_exhausted");
            return;
        }
        events.bytes += bytes.len();
        events.queue.push_back(Event { generation, bytes });
    }

    pub fn cancel_for_suspend(&self) {
        self.suspended.store(true, std::sync::atomic::Ordering::Release);
        let Ok(operations) = self.operations.lock() else { return };
        for operation in operations.values() {
            let Ok(mut state) = operation.state.lock() else { continue };
            if state.result.is_some() {
                continue;
            }
            let effects = if state.admitted { "unknown" } else { "none" };
            state.slot = ResultSlot::Frozen;
            state.result = Some(suspended_bytes(effects));
        }
    }

    pub(super) fn finish_suspend(&self) {
        if let Ok(mut subscription) = self.subscription.lock() {
            *subscription = None;
        }
        self.deactivate_generation();
    }

    pub fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::Release);
        self.credentials.clear_username();
        let ids = self
            .operations
            .lock()
            .map(|ops| ops.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        for id in ids {
            let unfinished = self
                .operations
                .lock()
                .ok()
                .and_then(|ops| ops.get(&id).cloned())
                .is_some_and(|op| op.state.lock().is_ok_and(|state| state.result.is_none()));
            if unfinished {
                self.complete(id, failure(RamfluxV2Status::Closed, "unknown"));
            }
        }
    }
}

pub(super) fn suspended_bytes(effects: &str) -> Zeroizing<Vec<u8>> {
    let mut value = failure(RamfluxV2Status::Suspended, effects);
    let encoded = Zeroizing::new(
        serde_json::to_vec(&value)
            .unwrap_or_else(|_| br#"{"code":30,"effects":"unknown"}"#.to_vec()),
    );
    crate::bus::inprocess::erase_value(&mut value);
    encoded
}
