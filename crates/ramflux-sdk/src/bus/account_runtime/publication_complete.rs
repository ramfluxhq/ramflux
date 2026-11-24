// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Command replies parked until their durable outbox prefix reaches the journal.

use super::{AccountRuntime, stopped};
use crate::bus::actor::{AccountCommand, ActorResponse};
use crate::{LocalBusFrame, SdkError};
use tokio::sync::{oneshot, watch};

pub(super) struct Completion {
    request: LocalBusFrame,
    result: Result<ActorResponse, SdkError>,
    reply: oneshot::Sender<Result<ActorResponse, SdkError>>,
    through: Option<i64>,
    started: tokio::time::Instant,
    wake: Option<watch::Sender<u64>>,
}

impl AccountRuntime {
    pub(super) fn park_completion(
        &mut self,
        request: &LocalBusFrame,
        result: Result<ActorResponse, SdkError>,
        reply: oneshot::Sender<Result<ActorResponse, SdkError>>,
    ) {
        let through = (|| {
            let account = self.state.accounts.get(&self.id).ok_or_else(stopped)?;
            if let Some(pool) = self.readers.lock().map_err(|_| stopped())?.as_ref() {
                pool.set_identity(account.client.owned_device_identity().ok())?;
                pool.set_account_view(&self.state, &self.id)?;
            }
            account.client.account_db()?.pending_outbox_head().map_err(SdkError::from)
        })();
        let through = match through {
            Ok(through) => through,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        tracing::debug!(phase = "outbox_wait", event = "park", method = %request.method,
            "account command phase");
        self.publications.push_back(Completion {
            request: request.clone(),
            result,
            reply,
            through,
            started: tokio::time::Instant::now(),
            wake: None,
        });
    }

    /// An expiry snapshot must reach the journal before another command can replace it.
    pub(super) fn defer_expiry_command(
        &mut self,
        command: AccountCommand,
        reply: oneshot::Sender<Result<ActorResponse, SdkError>>,
    ) -> Option<(AccountCommand, oneshot::Sender<Result<ActorResponse, SdkError>>)> {
        let Some(through) = self.networking_expiry_pending else { return Some((command, reply)) };
        let pending = (|| {
            let account = self.state.accounts.get(&self.id).ok_or_else(stopped)?;
            Ok::<_, SdkError>(
                account
                    .client
                    .account_db()?
                    .pending_outbox(1)?
                    .first()
                    .is_some_and(|entry| entry.sequence <= through),
            )
        })();
        match pending {
            Ok(false) => return Some((command, reply)),
            Err(error) => {
                let _ = reply.send(Err(error));
                return None;
            }
            Ok(true) => {}
        }
        let (completed, result) = oneshot::channel();
        let (wake, changed) = watch::channel(0);
        self.publications.push_back(Completion {
            request: LocalBusFrame::request(
                "sync",
                Some(self.id.clone()),
                "runtime",
                "sync.run",
                serde_json::json!({}),
            ),
            result: Ok(ActorResponse {
                body: serde_json::Value::Null,
                events: Vec::new(),
                nodes: None,
                owner_copy: None,
            }),
            reply: completed,
            through: Some(through),
            started: tokio::time::Instant::now(),
            wake: Some(wake),
        });
        let deadline = command.admission.as_ref().map_or_else(
            || tokio::time::Instant::now() + self.timeouts.command,
            |admission| admission.command_deadline,
        );
        super::command_park::park_journal(&self.id, command, reply, deadline, changed, result);
        None
    }

    /// One durable row per actor turn. Commands always precede the next row.
    pub(super) fn advance_publications(&mut self) -> Result<(), SdkError> {
        let Some(pending) = self.publications.front() else { return Ok(()) };
        let Some(account) = self.state.accounts.get(&self.id) else {
            self.publications.clear();
            return Ok(());
        };
        let db = account.client.account_db()?;
        let progressed = (|| {
            let next = db.pending_outbox(1)?.first().map(|entry| entry.sequence);
            if next.zip(pending.through).is_some_and(|(next, through)| next <= through) {
                let expiry = self
                    .networking_expiry_pending
                    .map(|sequence| (sequence, self.networking_expiry_request()));
                super::super::events::publish_slice(
                    &account.client,
                    &self.id,
                    &pending.request,
                    expiry.as_ref().map(|(sequence, frame)| (*sequence, frame)),
                    &self.events,
                )?;
                return Ok(false);
            }
            // A preceding drain may have journaled this command's entire prefix.
            // Sticky decision acknowledgement still belongs to this request.
            super::super::events::acknowledge_decision(db, &pending.request)?;
            super::super::journal::retention(db)?;
            Ok(true)
        })();
        match progressed {
            Ok(false) => Ok(()),
            Ok(true) => self.finish_publication(None),
            Err(error) => self.finish_publication(Some(error)),
        }
    }

    fn finish_publication(&mut self, error: Option<SdkError>) -> Result<(), SdkError> {
        let Some(pending) = self.publications.pop_front() else { return Err(stopped()) };
        tracing::debug!(phase = "outbox_wait", event = "complete", method = %pending.request.method,
            elapsed_ms = u64::try_from(pending.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "account command phase");
        let result = match error {
            None => pending.result,
            Some(error) if pending.result.is_ok() && pending.request.method == "agent.progress" => {
                tracing::warn!(
                    error_code = crate::prelude::local_bus_error_code(&error),
                    "agent progress publication deferred; owner copy remains"
                );
                pending.result
            }
            Some(error) => Err(error),
        };
        let _ = pending.reply.send(result);
        if let Some(wake) = pending.wake {
            let _ = wake.send(1);
        }
        Ok(())
    }
}
