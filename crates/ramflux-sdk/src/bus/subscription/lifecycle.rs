// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Journal tails retain their cursor while the actor replaces readers during suspend.

use super::super::actor::AccountActor;
use crate::{LocalBusFrame, SdkError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

pub(in crate::bus) struct StreamReaders {
    actor: AccountActor,
    background: Arc<AtomicBool>,
}

impl StreamReaders {
    pub(in crate::bus) fn new(actor: AccountActor, background: Arc<AtomicBool>) -> Self {
        Self { actor, background }
    }

    pub(super) async fn request(
        &self,
        request: LocalBusFrame,
    ) -> Result<serde_json::Value, SdkError> {
        loop {
            if self.background.load(Ordering::Acquire) {
                // Use the existing tail cadence without touching any parked descriptor.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            let readers = self.actor.reader_pool()?;
            let result = readers.request(request.clone()).await;
            if self.background.load(Ordering::Acquire) {
                continue;
            }
            if result.is_err()
                && self.actor.reader_pool().is_ok_and(|current| !readers.same_pool(&current))
            {
                // This read raced a completed suspend rollback. Retry the same cursor on
                // its replacement owner; errors on an unchanged pool still emit lagged.
                continue;
            }
            return result;
        }
    }
}
