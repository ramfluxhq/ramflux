// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Session history erase for the typed PRX client.

use super::{Error, MAX_ERASE_RECEIPTS, PrxEngine, Result, StoredHistory};
use ramflux_prx_client::HistoryErased;

impl PrxEngine {
    /// Erases the PRX session stored for this conversation. A missing session, a missing
    /// client, or a remote refusal leaves the host running. The stored id is the console id
    /// PRX assigned, or the caller key this host sent for a named agent.
    pub(super) async fn erase_mapped(&mut self, conversation_id: &str) -> Result<()> {
        if self.state.history_erased.contains_key(conversation_id) {
            return Ok(());
        }
        let Some(client) = &self.typed else {
            return Ok(());
        };
        let session = super::caller_session_key(conversation_id);
        if self.state.history_erased.len() >= MAX_ERASE_RECEIPTS {
            return Err(Error::State);
        }
        let caps = match client.capabilities().await {
            Ok(caps) => caps,
            Err(error) => {
                eprintln!("agent host history erase failed: {}", erase_failure(&error));
                return Ok(());
            }
        };
        let prefix = stable_key("rf-hist-", conversation_id);
        let erased = match client.erase_session_history(&caps, &session, &prefix).await {
            Ok(erased) => erased,
            Err(error) => {
                eprintln!("agent host history erase failed: {}", erase_failure(&error));
                return Ok(());
            }
        };
        self.state.history_erased.insert(conversation_id.to_owned(), stored_rows(&erased));
        Ok(())
    }
}

fn stored_rows(erased: &[HistoryErased]) -> Vec<StoredHistory> {
    erased
        .iter()
        .map(|row| StoredHistory {
            erase_id: row.erase_id.clone(),
            generation: row.generation,
            remaining: row.remaining,
            incarnation: row.incarnation.clone(),
            session: row.scope.session.clone(),
            agent: row.scope.agent.clone(),
            scope_incarnation: row.scope.incarnation.clone(),
            forgotten_created: row.forgotten.map(|item| item.created),
            forgotten_touched: row.forgotten.map(|item| item.touched),
        })
        .collect()
}

fn erase_failure(error: &ramflux_prx_client::PrxError) -> String {
    use ramflux_prx_client::PrxError;
    match error {
        PrxError::Api { status, code, .. } => format!("api {status} {code:?}"),
        PrxError::Protocol { reason } => format!("protocol {reason}"),
        PrxError::Unavailable => "unavailable".to_owned(),
        PrxError::RateLimited { .. } => "rate_limited".to_owned(),
        PrxError::AgentBusy { .. } => "agent_busy".to_owned(),
        PrxError::AgentBudgetExhausted { .. } => "agent_budget_exhausted".to_owned(),
        PrxError::ProviderNotReady { status, .. } => format!("provider_not_ready {status}"),
        PrxError::Timeout => "timeout".to_owned(),
        PrxError::OutcomeUnknown { http_status } => format!("outcome_unknown {http_status:?}"),
        PrxError::Config { reason } => format!("config {reason}"),
        PrxError::Unsupported { token, available_but_off } => {
            format!("unsupported {token} off={available_but_off}")
        }
    }
}

pub(super) fn stable_key(prefix: &str, material: &str) -> String {
    let mut acc: u128 = 0xcbf2_9ce4_8422_2325;
    for byte in material.bytes() {
        acc ^= u128::from(byte);
        acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{prefix}{acc:032x}")
}
