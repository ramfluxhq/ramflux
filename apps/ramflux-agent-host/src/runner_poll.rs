// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Poll the bounded inbox and provider work without per-conversation pacing.
use crate::{AgentBus, AgentHost, EngineProvider, Error, OutputRefusal, Result};
use serde_json::json;

impl<E: EngineProvider> AgentHost<E> {
    /// Poll the authenticated inbox and recheck due surface actions without sleeping per conversation.
    ///
    /// # Errors
    /// Returns only identity/storage loss or a transport/stream failure requiring reconnect.
    pub(crate) async fn poll(&mut self, bus: &mut impl AgentBus, now_ms: u64) -> Result<()> {
        self.poll_with(bus, now_ms, true).await
    }

    /// `jobs` is false when the bus tick is inside the job-status gap.
    /// Inbox maintenance and approval drive still run.
    pub(crate) async fn poll_with(
        &mut self,
        bus: &mut impl AgentBus,
        now_ms: u64,
        jobs: bool,
    ) -> Result<()> {
        if let Err(error) = bus
            .request("message.receive", json!({"limit":32,"auto_fetch_attachments":false}), None)
            .await
        {
            if error.stops_host() || matches!(error, Error::Bus | Error::Resync) {
                return Err(error);
            }
            let refusal = OutputRefusal {
                group_reason: None,
                conversation_id: String::new(),
                surface_id: None,
                reason: crate::runner_policy::refusal(&error),
            };
            if self.state.last_refusal.as_ref() != Some(&refusal) {
                self.state.last_refusal = Some(refusal);
                self.store.save(&self.state)?;
            }
        }
        self.recover_pending(bus).await?;
        let seq = self.state.cursor.unwrap_or(0);
        let provider_events = if jobs { self.engine.poll(now_ms).await? } else { Vec::new() };
        self.save_engine_state_if_changed()?;
        self.handle_engine_events(bus, provider_events, seq, now_ms).await?;
        let approval_events = self.drive_approvals(bus, now_ms).await?;
        self.handle_engine_events(bus, approval_events, seq, now_ms).await?;
        Ok(())
    }
}
