// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Park one account actor. Production runs one actor on this thread, so the flag is that actor's.

use super::AccountRuntime;
use crate::bus::actor::{AccountCommand, AgentPrivate, PrivateCommand};
use crate::prelude::*;
use std::cell::Cell;

thread_local! {
    static FILES_RELEASED: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn files_released() -> bool {
    FILES_RELEASED.with(Cell::get)
}

#[cfg(feature = "c-abi")]
fn set_files_released(released: bool) {
    FILES_RELEASED.with(|flag| flag.set(released));
}

pub(super) fn is_file_command(private: &PrivateCommand) -> bool {
    file_command(private)
}

/// `ReleaseFiles` and `ReopenFiles` exist only on the C ABI suspend path.
#[cfg(feature = "c-abi")]
fn file_command(private: &PrivateCommand) -> bool {
    matches!(private, PrivateCommand::ReleaseFiles { .. } | PrivateCommand::ReopenFiles { .. })
}

#[cfg(not(feature = "c-abi"))]
fn file_command(_private: &PrivateCommand) -> bool {
    false
}

pub(super) fn reject_suspended(command: &mut AccountCommand) {
    if let Some(private) = command.private.take() {
        reject_private(private);
    }
    if let Some(reply) = command.reply.take() {
        let _ = reply.send(Err(super::super::background::client_suspended()));
    }
}

impl AccountRuntime {
    pub(super) async fn background_or_prepare(
        &mut self,
    ) -> Result<Option<(Option<tokio::time::Instant>, Option<tokio::time::Instant>)>, SdkError>
    {
        if files_released() && self.wait_while_released().await? {
            return Ok(None);
        }
        // A pipelined `message.read` would otherwise skip connection work. Apply one resumed
        // receive item before the next read so the peer reply becomes visible inside the window.
        self.kick_resumed_receive();
        self.apply_resumed_receive().await?;
        Ok(Some(self.prepare_receive_turn().await?))
    }

    #[cfg(feature = "c-abi")]
    pub(super) async fn release_for_suspend(&mut self) -> Result<(), SdkError> {
        self.resume_receive_until = None;
        self.stop_connection().await;
        self.stop_courier().await;
        self.transfers.stop().await;
        self.username.stop().await;
        self.pairing.stop().await;
        if let Ok(readers) = self.readers.lock()
            && let Some(pool) = readers.as_ref()
        {
            pool.mark_suspend();
        }
        self.close_readers().await;
        self.ledger = None;
        let released = self.drop_open_files();
        set_files_released(true);
        released
    }

    #[cfg(feature = "c-abi")]
    pub(super) fn reopen_from_suspend(&mut self) -> Result<(), SdkError> {
        if !files_released() {
            return Ok(());
        }
        self.reopen_account_db()?;
        if let Some(account) = self.state.accounts.get_mut(&self.id) {
            account.head_refresh.release_after_suspend();
        }
        if self.state.accounts.contains_key(&self.id) {
            self.initialize_readers()?;
            self.start_courier();
            self.start_username_delivery();
            self.start_connection()?;
        }
        // The connected catch-up runs before a peer can reply. Keep asking until that reply
        // has had time to arrive; the push safety sweep is otherwise 900s.
        self.resume_receive_until =
            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(30));
        set_files_released(false);
        self.kick_resumed_receive();
        Ok(())
    }

    fn resume_window_open(&mut self) -> bool {
        let Some(until) = self.resume_receive_until else {
            return false;
        };
        if tokio::time::Instant::now() >= until {
            self.resume_receive_until = None;
            return false;
        }
        true
    }

    fn kick_resumed_receive(&mut self) {
        if !self.resume_window_open() {
            return;
        }
        let Some(account) = self.state.accounts.get(&self.id) else {
            return;
        };
        if let Some(connection) = &account.connection {
            connection.redrive_receive();
        }
    }

    fn take_pending_work(&mut self) -> Option<crate::bus::connection_manager::AccountWork> {
        if let Ok(work) = self.head_rx.try_recv() {
            return Some(work);
        }
        if let Some(work) = self.deferred.pop_front() {
            return Some(work);
        }
        self.connection_work.try_recv().ok()
    }

    async fn apply_resumed_receive(&mut self) -> Result<(), SdkError> {
        if !self.resume_window_open() {
            return Ok(());
        }
        if let Some(work) = self.take_pending_work() {
            self.apply_connection_work(work).await?;
        }
        Ok(())
    }

    #[cfg(feature = "c-abi")]
    fn drop_open_files(&mut self) -> Result<(), SdkError> {
        if let Some(account) = self.state.accounts.get_mut(&self.id) {
            account.object_put_spools.clear();
            account.object_get_spools.clear();
            account.relay_quic_pool = None;
        }
        let Some(account) = self.state.accounts.get(&self.id) else {
            return Ok(());
        };
        let Ok(db) = account.client.account_db() else {
            return Ok(());
        };
        db.release_files().map_err(SdkError::from)
    }

    #[cfg(feature = "c-abi")]
    fn reopen_account_db(&self) -> Result<(), SdkError> {
        let Some(account) = self.state.accounts.get(&self.id) else {
            return Ok(());
        };
        let Ok(db) = account.client.account_db() else {
            return Ok(());
        };
        db.reopen_files().map_err(SdkError::from)
    }

    async fn wait_while_released(&mut self) -> Result<bool, SdkError> {
        loop {
            if *self.shutdown.borrow() {
                return Ok(true);
            }
            if let Some(command) = self.ready_commands.take() {
                self.note_command_taken();
                if self.command_while_released(command) {
                    return Ok(false);
                }
                continue;
            }
            let command = tokio::select! {
                biased;
                _ = self.shutdown.changed() => return Ok(true),
                command = self.lifecycle.recv() => {
                    self.preempt.borrow_and_update();
                    command
                }
                command = self.receiver.recv() => command,
            };
            let Some(command) = command else {
                return Ok(true);
            };
            // Every enqueue increments command_waiting, including lifecycle commands.
            // The parked loop owns dequeue just as the normal serve loop does.
            self.note_command_taken();
            if self.command_while_released(command) {
                return Ok(false);
            }
        }
    }

    fn command_while_released(&mut self, command: AccountCommand) -> bool {
        apply_released_command(self, command)
    }
}

#[cfg(feature = "c-abi")]
fn apply_released_command(runtime: &mut AccountRuntime, mut command: AccountCommand) -> bool {
    match command.private.take() {
        Some(PrivateCommand::ReopenFiles { reply }) => {
            let result = runtime.reopen_from_suspend();
            let resumed = result.is_ok();
            let _ = reply.send(result);
            resumed
        }
        Some(PrivateCommand::ReleaseFiles { reply }) => {
            let _ = reply.send(Ok(()));
            false
        }
        Some(other) => {
            reject_private(other);
            reject_reply(command.reply.take());
            false
        }
        None => {
            reject_reply(command.reply.take());
            false
        }
    }
}

#[cfg(not(feature = "c-abi"))]
fn apply_released_command(_runtime: &mut AccountRuntime, mut command: AccountCommand) -> bool {
    if let Some(other) = command.private.take() {
        reject_private(other);
    }
    reject_reply(command.reply.take());
    false
}

fn reject_reply(
    reply: Option<
        tokio::sync::oneshot::Sender<Result<super::super::actor::ActorResponse, SdkError>>,
    >,
) {
    if let Some(reply) = reply {
        let _ = reply.send(Err(super::super::background::client_suspended()));
    }
}

fn reject_private(private: PrivateCommand) {
    let error = super::super::background::client_suspended();
    match private {
        PrivateCommand::Media { reply, .. } => {
            let _ = reply.send(Err(super::super::background::client_suspended()));
        }
        PrivateCommand::SearchRebuild { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        PrivateCommand::NativeUnlock { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        PrivateCommand::SilentDeviceWrap { reply } => {
            let _ = reply.send(Err(error));
        }
        PrivateCommand::Capture(reply) => {
            let _ = reply.send(Err(error));
        }
        PrivateCommand::AuthorizeBackup { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        PrivateCommand::Agent(command) => reject_agent(*command, error),
        PrivateCommand::ProjectActivity { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        #[cfg(feature = "c-abi")]
        PrivateCommand::ReleaseFiles { reply } | PrivateCommand::ReopenFiles { reply } => {
            let _ = reply.send(Ok(()));
        }
        #[cfg(test)]
        PrivateCommand::HoldLocalMutation { entered, release } => {
            let _ = entered.send(tokio::time::Instant::now());
            drop(release);
        }
        #[cfg(test)]
        PrivateCommand::ReleasePreSendHold { reply } => {
            let _ = reply.send(Err(error));
        }
    }
}

fn reject_agent(command: AgentPrivate, error: SdkError) {
    match command {
        AgentPrivate::Creation { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        AgentPrivate::HomeNode { reply } => {
            let _ = reply.send(Err(error));
        }
        AgentPrivate::Admission { reply } => {
            let _ = reply.send(Err(error));
        }
        AgentPrivate::Call { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        AgentPrivate::Gateway { reply } => {
            let _ = reply.send(Err(error));
        }
        AgentPrivate::SettleAdmission { reply } => {
            let _ = reply.send(Err(error));
        }
    }
}
