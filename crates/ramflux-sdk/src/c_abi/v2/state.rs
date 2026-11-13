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

#[derive(Default)]
pub(super) struct OperationState {
    pub admitted: bool,
    pub subscription: bool,
    pub cancelled: bool,
    pub detached: bool,
    pub result: Option<Zeroizing<Vec<u8>>>,
}

#[derive(Default)]
pub(super) struct Events {
    pub queue: VecDeque<Zeroizing<Vec<u8>>>,
    pub bytes: usize,
    pub resync: bool,
}

#[derive(Default)]
pub(super) struct Shared {
    pub operations: Mutex<BTreeMap<u64, Arc<Operation>>>,
    pub events: Mutex<Events>,
    pub closed: std::sync::atomic::AtomicBool,
    pub subscription: Mutex<Option<u64>>,
}

impl Shared {
    pub fn complete(&self, id: u64, value: serde_json::Value) {
        let Ok(mut operations) = self.operations.lock() else { return };
        let Some(operation) = operations.get(&id) else { return };
        let detached = if let Ok(mut state) = operation.state.lock() {
            state.result = Some(Zeroizing::new(serde_json::to_vec(&value).unwrap_or_else(|_| {
                br#"{"code":16,"message":"completion encoding failed"}"#.to_vec()
            })));
            state.detached
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
                "message": error.to_string(), "effects": "unknown"
            }),
        );
    }

    pub fn push_event(&self, bytes: Vec<u8>) {
        let Ok(mut events) = self.events.lock() else { return };
        if events.resync {
            return;
        }
        if events.queue.len() >= MAX_EVENTS
            || bytes.len() > MAX_EVENT_BYTES.saturating_sub(events.bytes)
        {
            events.queue.clear();
            events.bytes = 0;
            events.resync = true;
            return;
        }
        events.bytes += bytes.len();
        events.queue.push_back(Zeroizing::new(bytes));
    }

    pub fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::Release);
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
                self.complete(id, failure(RamfluxV2Status::Closed, "carrier closed", "unknown"));
            }
        }
    }
}
