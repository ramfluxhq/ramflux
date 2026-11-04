// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compatibility surface for the admission retry policy consumed by the resident manager.

use crate::{SdkError, custody::retry::Budget};
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct AdmissionRetry {
    not_before: Option<Instant>,
}

impl AdmissionRetry {
    pub(super) const fn new() -> Self {
        Self { not_before: None }
    }
    pub(super) fn record(&mut self, error: &SdkError, now: Instant) {
        let delay = match super::super::native_account::networking_reason(error) {
            Some(
                crate::AccountNetworkingReason::NodeBusy { retry_after_ms, .. }
                | crate::AccountNetworkingReason::NodeUnreachable { retry_after_ms },
            ) => retry_after_ms,
            _ => crate::node::NODE_RETRY_AFTER_MS,
        };
        let next = now + Duration::from_millis(delay);
        self.not_before = Some(self.not_before.map_or(next, |old| old.max(next)));
    }
    pub(super) const fn not_before(&self) -> Option<Instant> {
        self.not_before
    }
    pub(super) fn begin_attempt(&mut self) -> Budget {
        debug_assert!(self.not_before.is_none_or(|until| until <= Instant::now()));
        Budget::new()
    }
}
