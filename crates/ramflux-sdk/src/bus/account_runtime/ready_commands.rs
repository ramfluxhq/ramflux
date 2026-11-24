// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Claimed mailbox commands waiting for the current preparation checkpoint.

use crate::bus::actor::AccountCommand;
use tokio::sync::mpsc;

const READY_CAPACITY: usize = 64;

pub(super) struct Queue {
    sender: mpsc::Sender<AccountCommand>,
    receiver: mpsc::Receiver<AccountCommand>,
}

impl Default for Queue {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel(READY_CAPACITY);
        Self { sender, receiver }
    }
}

impl Queue {
    pub(super) fn sender(&self) -> mpsc::Sender<AccountCommand> {
        self.sender.clone()
    }

    pub(super) fn take(&mut self) -> Option<AccountCommand> {
        self.receiver.try_recv().ok()
    }
}

/// Reserve separate bounded space before taking a command from the real mailbox.
/// Cancelling this receive consumes neither a command nor a reserved slot.
pub(super) async fn receive(
    sender: &mpsc::Sender<AccountCommand>,
    mailbox: &mut mpsc::Receiver<AccountCommand>,
) -> Option<(mpsc::OwnedPermit<AccountCommand>, AccountCommand)> {
    let permit = sender.clone().reserve_owned().await.ok()?;
    let command = mailbox.recv().await?;
    Some((permit, command))
}

pub(super) fn retain(permit: mpsc::OwnedPermit<AccountCommand>, command: AccountCommand) {
    if let Some(admission) = &command.admission {
        // Claim against the original residence deadline. An already expired command
        // remains expired and will be discarded by the ordinary admission check.
        let _ = admission.claim();
    }
    tracing::debug!(phase = "actor_prepare", event = "command_claimed",
        method = %command.request.method, "account command phase");
    permit.send(command);
}
