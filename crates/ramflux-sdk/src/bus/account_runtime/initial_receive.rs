// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Defer native DM lookup until this generation has applied its initial receive pass.

use super::AccountRuntime;
use crate::SdkError;
use crate::bus::actor::{AccountCommand, ActorResponse};
use crate::bus::connection_manager::ConnectionHandle;
use tokio::sync::oneshot;
use tokio::time::Instant;

type Reply = oneshot::Sender<Result<ActorResponse, SdkError>>;

impl AccountRuntime {
    pub(super) fn defer_initial_receive(
        &self,
        command: AccountCommand,
        reply: Reply,
    ) -> Option<(AccountCommand, Reply)> {
        let Some((deadline, connection, generation)) = self.initial_receive_wait(&command) else {
            return Some((command, reply));
        };
        // No mutation or operation receipt has been reserved. The actor can apply the
        // bootstrap page while this command retains its original admission deadline.
        super::command_park::park_receive(command, reply, deadline, connection, generation);
        None
    }

    fn initial_receive_wait(
        &self,
        command: &AccountCommand,
    ) -> Option<(Instant, Box<ConnectionHandle>, u64)> {
        if command.request.method != "conversation.send" || super::command_park::is_final() {
            return None;
        }
        let conversation = command.request.body.get("conversation_id")?.as_str()?;
        if !conversation.starts_with("dm:")
            || !crate::client::agent_activity::conversation_ok(conversation)
        {
            return None;
        }
        let deadline = command.admission.as_ref()?.command_deadline;
        if Instant::now() >= deadline {
            return None;
        }
        let account = self.state.accounts.get(&self.id)?;
        account.client.born_v3_account.as_ref()?;
        let connection = account.connection.as_ref()?;
        let generation = connection.generation();
        if !connection.initial_receive_pending(generation) {
            return None;
        }
        // Cached conversations keep their ordinary admission, including during a reconnect.
        if account
            .client
            .account_db()
            .ok()?
            .client_record("conversation", conversation)
            .ok()?
            .is_some()
        {
            return None;
        }
        Some((deadline, Box::new(connection.clone()), generation))
    }
}
