// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Nonblocking command admission while the session and authority heads become ready.

use super::{AccountRuntime, head_demand::HeadDemand, head_refresh};
use crate::SdkError;
use crate::bus::actor::AccountCommand;
use crate::bus::command_admission::CommandAdmission;
use crate::bus::connection_manager::{ConnectionHandle, NetworkingState};
use crate::bus::mutation_intent::MutationIntent;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Instant;

pub(super) struct NetworkWait {
    pub deadline: Instant,
    pub changed: watch::Receiver<u64>,
    // Writer priority only: this does not occupy either command mailbox.
    pub _demand: Option<HeadDemand>,
}

impl AccountRuntime {
    /// Production admission is one synchronous poll, with an already-ready result future.
    #[cfg(not(test))]
    pub(super) fn prepare_network_step(
        &mut self,
        command: &mut AccountCommand,
    ) -> std::future::Ready<Result<Option<NetworkWait>, SdkError>> {
        std::future::ready(self.prepare_network(command))
    }

    /// Direct component fixtures retain their existing inline executor without a mailbox.
    #[cfg(test)]
    pub(super) async fn prepare_network_step(
        &mut self,
        command: &mut AccountCommand,
    ) -> Result<Option<NetworkWait>, SdkError> {
        if command.admission.is_none() {
            self.prepare_command_network(command).await?;
            return Ok(None);
        }
        self.prepare_network(command)
    }

    pub(super) fn prepare_network(
        &mut self,
        command: &mut AccountCommand,
    ) -> Result<Option<NetworkWait>, SdkError> {
        let Some(connection) = self.network_connection(command)? else {
            return Ok(None);
        };
        // Internal commands can enter directly, without a caller's admission object.
        let admission = command.admission.get_or_insert_with(|| {
            let admission = Arc::new(CommandAdmission::new(Instant::now(), &self.timeouts));
            let _ = admission.claim();
            admission
        });
        let attachment_enable = command.request.method == "attachment.enable";
        let deadline = if attachment_enable {
            admission.command_deadline
        } else {
            admission.admitted_at + self.timeouts.network_wait
        };
        // Subscribe before checking readiness or enqueueing a head request.
        let changed = connection.snapshot_watch();
        let live = connection.snapshot().state == NetworkingState::Live;
        if attachment_enable {
            admission.set_readiness_pending(!live);
        }
        if !live {
            #[cfg(test)]
            if let Some(gate) = &self.state.config.test_network_command_gate {
                gate.waiting.notify_one();
            }
            return if Instant::now() >= deadline {
                Err(connection.pending())
            } else {
                Ok(Some(NetworkWait { deadline, changed, _demand: None }))
            };
        }
        let since = admission.network_started();
        self.refuse_ineligible_explicit_send(command)?;
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(None);
        };
        let roots = head_refresh::stale_roots_since(account, &command.request, Some(since))?;
        if let Some(error) = account.head_refresh.take_demanded_foreign(&roots, since) {
            return Err(error);
        }
        if roots.is_empty() {
            if command.request.method == "group.read" {
                let prepared =
                    crate::bus::push_receiver::apply_w1::receive_executor_bound(account)?
                        && account.client.account_db()?.due_inbox_retry_rows(i64::MAX)?.is_empty();
                let _ = head_refresh::RECEIVE_PREPARED.try_with(|value| value.set(prepared));
            }
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Err(head_refresh::pending(account));
        }
        for root in roots {
            if !account.head_refresh.enqueue(root) {
                return Err(head_refresh::pending(account));
            }
        }
        Ok(Some(NetworkWait {
            deadline,
            changed,
            _demand: Some(HeadDemand::arm(&self.command_waiting)),
        }))
    }

    fn network_connection(
        &self,
        command: &AccountCommand,
    ) -> Result<Option<ConnectionHandle>, SdkError> {
        let Some(account) = self.state.accounts.get(&self.id) else {
            return Ok(None);
        };
        if !crate::bus::method_table::account_requires_network(&command.request, account) {
            return Ok(None);
        }
        let intent = MutationIntent::new(&command.request)?;
        if intent.lookup(account.client.account_db()?)?.is_some()
            || command.request.method == "object.fetch"
        {
            return Ok(None);
        }
        if intent.key.is_none()
            && command.request.method == "object.put.finish"
            && crate::bus::dispatch::object::lookup_finish_receipt(account, &command.request)?
                .is_some()
        {
            return Ok(None);
        }
        account.connection.clone().map(Some).ok_or(SdkError::NetworkingPending)
    }
}
