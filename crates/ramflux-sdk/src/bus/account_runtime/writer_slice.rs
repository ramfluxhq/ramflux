// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One queued command between durable writer checkpoints.

use super::AccountRuntime;
use crate::SdkError;
use crate::bus::actor::AccountCommand;
use crate::bus::connection_manager::{ReceiveEntry, ReceiveTurn};
use crate::bus::contact_backpressure::Backpressure;
use crate::client::routed::PreparedInbound;
use crate::prelude::LocalBusFrame;
use std::cell::RefCell;
use std::sync::atomic::Ordering;

pub(crate) struct ApplyResume {
    pub turn: ReceiveTurn,
    pub prepared: ReceiveEntry,
    pub source: Option<PreparedInbound>,
    pub backpressure: Box<Backpressure>,
    pub attempts: u32,
}

thread_local! {
    static APPLY_RESUME: RefCell<Option<ApplyResume>> = const { RefCell::new(None) };
}

pub(crate) fn stash_apply(resume: ApplyResume) {
    let _ = APPLY_RESUME.try_with(|slot| {
        if let Ok(mut guard) = slot.try_borrow_mut() {
            *guard = Some(resume);
        }
    });
}

pub(crate) fn take_apply() -> Option<ApplyResume> {
    APPLY_RESUME
        .try_with(|slot| slot.try_borrow_mut().ok().and_then(|mut guard| guard.take()))
        .ok()
        .flatten()
}

pub(crate) fn is_writer_pause(error: &SdkError) -> bool {
    matches!(error, SdkError::WriterPause)
}

impl AccountRuntime {
    pub(super) fn note_command_taken(&self) {
        let _ = self
            .command_waiting
            .try_update(Ordering::AcqRel, Ordering::Acquire, |queued| queued.checked_sub(1));
    }

    pub(super) fn take_waiting_command(&mut self) -> Option<AccountCommand> {
        let command = self
            .lifecycle
            .try_recv()
            .inspect(|_| {
                self.preempt.borrow_and_update();
            })
            .ok()
            .or_else(|| self.ready_commands.take())
            .or_else(|| self.receiver.try_recv().ok());
        if command.is_some() {
            self.note_command_taken();
        }
        command
    }

    pub(super) async fn service_one_command(&mut self) -> Result<(), SdkError> {
        if self.command_waiting.load(Ordering::Acquire) == 0 {
            return Ok(());
        }
        let Some(_guard) = ramflux_storage::writer_budget::ServiceGuard::enter() else {
            return Ok(());
        };
        let Some(command) = self.take_waiting_command() else {
            return Ok(());
        };
        // Boxed so a page or directory attempt can service this command without
        // an infinitely sized future.
        super::publication_park::set_final(false);
        Box::pin(self.apply(command)).await.map(|_| ())
    }

    /// Drains the outbox, but returns to queued commands between commits.
    ///
    /// The caller resumes until the outbox is durable. A reply stays unsent
    /// across that pause, so acknowledgement still follows durability.
    pub(super) async fn publish_yielding(
        &mut self,
        request: &LocalBusFrame,
    ) -> Result<(), SdkError> {
        let mut yielded = false;
        loop {
            ramflux_storage::writer_budget::begin_attempt();
            let result = {
                let _yield = super::super::events::OutboxYield::enter();
                self.publish(request).await
            };
            match result {
                Err(error) if is_writer_pause(&error) => {
                    yielded = true;
                    self.service_waiting_commands().await?;
                }
                Ok(()) if yielded => return self.acknowledge_yielded_decision(request),
                other => return other,
            }
        }
    }

    /// A nested drain can finish this command's rows under another method.
    /// The decision acknowledgement still belongs to this request.
    fn acknowledge_yielded_decision(&self, request: &LocalBusFrame) -> Result<(), SdkError> {
        let Some(account) = self.state.accounts.get(&self.id) else {
            return Ok(());
        };
        super::super::events::acknowledge_decision(account.client.account_db()?, request)
    }

    /// Applies each command that was queued before this call. A command that
    /// arrives while one is running waits for the next slice.
    pub(super) async fn service_waiting_commands(&mut self) -> Result<(), SdkError> {
        let mut stalled = 0_u8;
        while self.command_waiting.load(Ordering::Acquire) > 0 {
            let before = self.command_waiting.load(Ordering::Acquire);
            self.service_one_command().await?;
            if self.command_waiting.load(Ordering::Acquire) >= before {
                stalled = stalled.saturating_add(1);
                if stalled >= 2 {
                    break;
                }
            } else {
                stalled = 0;
            }
        }
        Ok(())
    }
}
