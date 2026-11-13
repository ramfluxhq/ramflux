// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The production H2 boundary has no exportable boolean permission.

use ramflux_node_core::{NodeCoreError, NotifyRedbStore, PreparedProviderPush};

pub(super) trait SendBoundary {
    fn issue<T>(
        &mut self,
        issue: impl FnOnce() -> Result<T, NodeCoreError>,
    ) -> Result<T, NodeCoreError>;
}

pub(super) struct WakeBoundary<'a> {
    pub store: &'a NotifyRedbStore,
    pub prepared: &'a PreparedProviderPush,
}
impl SendBoundary for WakeBoundary<'_> {
    fn issue<T>(
        &mut self,
        issue: impl FnOnce() -> Result<T, NodeCoreError>,
    ) -> Result<T, NodeCoreError> {
        self.store.issue_provider_push(self.prepared, issue).map_err(|error| {
            if matches!(error, NodeCoreError::SendAuthority(_)) {
                super::wake_send_dropped()
            } else {
                error
            }
        })
    }
}

/// Used for OAuth (which carries no wake) and the existing transport-only fixtures.
pub(super) struct Checked<F>(pub F);
impl<F: FnMut() -> Result<bool, NodeCoreError>> SendBoundary for Checked<F> {
    fn issue<T>(
        &mut self,
        issue: impl FnOnce() -> Result<T, NodeCoreError>,
    ) -> Result<T, NodeCoreError> {
        if !(self.0)()? {
            return Err(super::wake_send_dropped());
        }
        issue()
    }
}
