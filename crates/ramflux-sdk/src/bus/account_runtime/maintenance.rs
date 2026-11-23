// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The account writer yields cancellable maintenance to its next ordered command.
use super::AccountRuntime;
use crate::bus::actor::AccountCommand;
use tokio::sync::mpsc;

pub(super) enum Maintenance {
    Completed(bool),
    Command(Box<AccountCommand>),
    Username(Box<super::username_calls::Completion>),
    Interrupted,
    Stopped,
}
impl AccountRuntime {
    pub(super) async fn maintain_until_command(&mut self) -> Maintenance {
        // Move the existing mailbox into this select, retaining its sender and FIFO order.
        // Sync never reads the mailbox; the closed replacement is unobservable to callers.
        let (_, empty) = mpsc::channel(1);
        let mut commands = std::mem::replace(&mut self.receiver, empty);
        let mut usernames = std::mem::take(&mut self.username);
        let mut shutdown = self.shutdown.clone();
        let mut preempt = self.preempt.clone();
        let outcome = tokio::select! {
            biased;
            _ = shutdown.changed() => Maintenance::Stopped,
            _ = preempt.changed() => Maintenance::Interrupted,
            command = commands.recv() => match command {
                Some(command) => Maintenance::Command(Box::new(command)),
                None => Maintenance::Stopped,
            },
            completion = usernames.receive() => match completion {
                Some(completion) => Maintenance::Username(Box::new(completion)),
                None => Maintenance::Interrupted,
            },
            result = self.sync() => Maintenance::Completed(match result {
                Ok(active) => active,
                Err(error) => {
                    tracing::warn!(account_id = %self.id, %error,
                        error_code = crate::prelude::local_bus_error_code(&error),
                        "background synchronization deferred; account remains open");
                    false
                }
            }),
        };
        self.receiver = commands;
        self.username = usernames;
        if matches!(outcome, Maintenance::Interrupted) {
            self.preempt.borrow_and_update();
        }
        outcome
    }
}
