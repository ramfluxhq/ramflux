// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Isolate event refusals from host identity/storage failures and bound replay receipts.
use crate::{AgentHost, EngineProvider, Error, OutputRefusal, Result};
use ramflux_sdk::{LocalBusFrame, SurfaceRefusalCode as Code};
impl<E: EngineProvider> AgentHost<E> {
    pub(crate) fn remember_action(&mut self, key: String) {
        if !self.state.handled_actions.contains(&key) {
            if self.state.handled_actions.len() >= 2048 {
                self.state.handled_actions.remove(0);
            }
            self.state.handled_actions.push(key);
        }
    }
    pub(crate) fn finish_event(
        &mut self,
        result: Result<()>,
        event: &LocalBusFrame,
        seq: u64,
    ) -> Result<()> {
        match result {
            Ok(()) => Ok(()),
            Err(error)
                if error.stops_host()
                    || matches!(error, Error::Bus | Error::Resync | Error::RateLimited { .. }) =>
            {
                Err(error)
            }
            Err(error) => {
                eprintln!("agent host skipped event: {error}");
                if let Some(pending) = self.state.pending.clone() {
                    self.stop_surface_output(&pending, refusal(&error))?;
                } else {
                    self.state.last_refusal = Some(OutputRefusal {
                        group_reason: None,
                        conversation_id: event.body["conversation_id"]
                            .as_str()
                            .or_else(|| event.body["message"]["conversation_id"].as_str())
                            .unwrap_or_default()
                            .chars()
                            .take(1024)
                            .collect(),
                        surface_id: None,
                        reason: refusal(&error),
                    });
                }
                self.state.cursor = Some(self.state.cursor.unwrap_or(0).max(seq));
                self.store.save(&self.state)
            }
        }
    }
}
pub(crate) const fn refusal(error: &Error) -> Code {
    match error {
        Error::SurfaceRefused(code) => *code,
        Error::Unauthorized => Code::NotPermitted,
        Error::Limit => Code::TooLarge,
        _ => Code::InvalidRequest,
    }
}
