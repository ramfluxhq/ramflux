// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Draft lifecycle: a sent draft is cleared on every own device by an explicit clear.
use super::{RamfluxClient, SdkError, g};

impl RamfluxClient {
    /// Issue the explicit `DRAFT_CLEAR` once the drafted message has been sent.
    /// The winning clear retires every queued copy of the draft body; the courier then
    /// publishes the clear to all own devices. Returns `None` when no draft is set.
    /// # Errors
    /// Returns authority, revision and storage failures of the local change.
    pub fn clear_self_sync_draft_after_send(
        &self,
        conversation: &str,
    ) -> Result<Option<g::SelfSync>, SdkError> {
        crate::client::target_selection::require_schema_v1()?;
        let clear = g::SelfSync { operation: 3, revision: 1, ..Default::default() };
        let Some(state) = self.self_sync_state(conversation, &clear)? else {
            return Ok(None);
        };
        // Only a live draft is cleared; repeating the send never re-issues a revision.
        if state.value.operation != 2 {
            return Ok(None);
        }
        match self.change_self_sync(conversation, clear) {
            Ok(value) => Ok(Some(value)),
            Err(SdkError::ObjectErased) => Ok(None),
            Err(error) => Err(error),
        }
    }
}
