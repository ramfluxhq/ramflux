// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Claimed commands, lifecycle preemption, and bounded ordinary dispatch.

use super::{AccountRuntime, stopped};
use crate::bus::actor::AccountCommand;
use crate::prelude::*;

#[cfg(test)]
async fn wait_receive_gate(hook: Option<super::ReceiveGateHook>) {
    if let Some((entered, release)) = hook {
        let _ = entered.send(());
        let _ = release.await;
    }
}

impl AccountRuntime {
    async fn cancel_native_unlock(&mut self) -> Result<(), SdkError> {
        self.stop_connection().await;
        self.stop_courier().await;
        self.close_readers().await;
        crate::custody::pairing::remove_actor_and_drain(&self.state.config.data_root, &self.id)
            .await?;
        self.state.accounts.remove(&self.id);
        Ok(())
    }

    fn authorize_backup(&self, generation: i64) -> Result<(), SdkError> {
        let account = local_bus_account(&self.state, &self.id)?;
        if account.client.account_db()?.privacy_erasure_generation()? != generation {
            return Err(SdkError::ObjectErased);
        }
        Ok(())
    }

    fn capture_backup(&self) -> Result<super::super::backup_jobs::CapturedAccount, SdkError> {
        let account = local_bus_account(&self.state, &self.id)?;
        let reader = account.client.account_db()?.open_backup_reader()?;
        let identity = super::super::backup_jobs::capture_identity(
            &account.client,
            &self.state.config.data_root,
            &self.id,
        )?;
        let erasure_generation = reader.privacy_erasure_generation()?;
        Ok(super::super::backup_jobs::CapturedAccount {
            reader,
            identity,
            erasure_generation,
            actor: None,
        })
    }

    async fn preempt_network_tasks(&mut self) -> Result<(), SdkError> {
        self.transfers.stop().await;
        if let Some(account) = self.state.accounts.get(&self.id) {
            account.client.recover_received_attachment_fetches()?;
        }
        if let Some(handle) =
            self.state.accounts.get(&self.id).and_then(|account| account.connection.clone())
        {
            handle.stop_with_reason(super::super::connection_manager::DisconnectReason::Lock).await;
        }
        self.stop_connection().await;
        self.stop_courier().await;
        self.close_readers().await;
        Ok(())
    }

    async fn apply_private(
        &mut self,
        backup: super::super::actor::PrivateCommand,
        request: &LocalBusFrame,
    ) -> Result<(), SdkError> {
        match backup {
            #[cfg(test)]
            super::super::actor::PrivateCommand::HoldLocalMutation { entered, release } => {
                let _ = entered.send(tokio::time::Instant::now());
                let _ = release.await;
            }
            #[cfg(test)]
            super::super::actor::PrivateCommand::ReleasePreSendHold { reply } => {
                let result = self
                    .state
                    .accounts
                    .get_mut(&self.id)
                    .and_then(|account| account.test_pre_send_hold.take())
                    .ok_or_else(|| SdkError::LocalBus("fixture pre-send hold missing".into()))
                    .and_then(|hold| hold.release().map_err(SdkError::from));
                let _ = reply.send(result);
            }
            super::super::actor::PrivateCommand::NativeUnlock {
                passphrase,
                home_node_id,
                reply,
            } => {
                if !reply.is_closed() {
                    let result = super::super::native_account::unlock(
                        &mut self.state,
                        &self.id,
                        passphrase,
                        home_node_id,
                    );
                    if reply.is_closed() {
                        self.cancel_native_unlock().await?;
                        return Ok(());
                    }
                    let result = match self.initialize_readers() {
                        Ok(()) => result,
                        Err(error) => Err(error),
                    };
                    self.start_connection()?;
                    self.start_courier();
                    let result = result.and_then(|_| {
                        super::super::native_account::response(local_bus_account(
                            &self.state,
                            &self.id,
                        )?)
                    });
                    let result = match self.publish(request).await {
                        Ok(()) => result,
                        Err(error) => Err(error),
                    };
                    let _ = reply.send(result);
                }
            }
            super::super::actor::PrivateCommand::AuthorizeBackup { generation, reply } => {
                let result = self.authorize_backup(generation);
                let _ = reply.send(result);
            }
            super::super::actor::PrivateCommand::Capture(reply) => {
                if !reply.is_closed() {
                    let result = self.capture_backup();
                    let _ = reply.send(result);
                }
            }
        }
        Ok(())
    }
    pub(super) async fn apply(&mut self, command: AccountCommand) -> Result<bool, SdkError> {
        super::head_refresh::RECEIVE_PREPARED
            .scope(std::cell::Cell::new(false), self.apply_command(command))
            .await
    }

    async fn apply_command(&mut self, mut command: AccountCommand) -> Result<bool, SdkError> {
        self.refresh_networking_expiry().await;
        if command.admission.as_ref().is_some_and(|admission| !admission.claim()) {
            return Ok(false);
        }

        #[cfg(test)]
        super::super::lifecycle::hold_claimed(&self.state.config, &command).await;
        if let Some(backup) = command.private.take() {
            self.apply_private(backup, &command.request).await?;
            return Ok(false);
        }
        if *self.shutdown.borrow() {
            return Ok(true);
        }
        let mut reply = command.reply.take().ok_or_else(stopped)?;
        if reply.is_closed() {
            return Ok(false);
        }
        let lifecycle =
            super::super::method_table::classify(&command.request.method).is_some_and(|method| {
                method.route == super::super::method_table::MethodRoute::Lifecycle
            });
        if lifecycle {
            self.preempt_network_tasks().await?;
        }
        if !lifecycle {
            let mut shutdown = self.shutdown.clone();
            let mut preempt = self.preempt.clone();
            let gate = tokio::select! {
                biased;
                _=shutdown.changed()=>return Ok(true),
                _=preempt.changed()=>{
                    let error=self.state.accounts.get(&self.id).and_then(|account|account.connection.as_ref()).map_or(SdkError::NetworkingPending,super::super::connection_manager::ConnectionHandle::pending);
                    let _=reply.send(Err(error));return Ok(false);
                },
                ()=reply.closed()=>return Ok(false),
                gate=self.prepare_command_network(&command)=>gate,
            };
            if let Err(error) = gate {
                let _ = reply.send(Err(error));
                return Ok(false);
            }
        }
        if command.request.method == "object.fetch" {
            self.start_fetch(command, reply);
            return Ok(false);
        }
        if command.request.method == "object.put.finish" {
            self.start_upload(command, reply).await?;
            return Ok(false);
        }
        #[cfg(test)]
        let receive_gate_hook = self.receive_gate_hook.take();
        let mut stopping = false;
        let mut cancelled = false;
        let mut preempted = false;
        let result = if lifecycle {
            super::super::mutations::execute(&mut self.state, &self.id, &command).await
        } else {
            tokio::select! {
                biased;
                _ = self.shutdown.changed() => { stopping = true; Err(stopped()) },
                _ = self.preempt.changed() => {cancelled = true;preempted=true;Err(stopped())},
                () = reply.closed() => { cancelled = true; Err(stopped()) },
                result = async {
                    #[cfg(test)]
                    wait_receive_gate(receive_gate_hook).await;
                    let deadline=command.admission.as_ref().map_or_else(||tokio::time::Instant::now()+self.timeouts.command,|admission|admission.command_deadline);
                    super::super::command_admission::COMMAND_CONTEXT.scope(deadline, tokio::time::timeout_at(deadline,super::super::mutations::execute(&mut self.state,&self.id,&command))).await
                        .map_err(|_|super::super::command_admission::unavailable("account command deadline expired"))?
                } => result,
            }
        };
        if let Some(account) = self.state.accounts.get_mut(&self.id) {
            super::super::control_state::trim(account);
        }
        if stopping {
            return Ok(true);
        }
        if cancelled {
            if preempted {
                let error = self
                    .state
                    .accounts
                    .get(&self.id)
                    .and_then(|account| account.connection.as_ref())
                    .map_or(
                        SdkError::NetworkingPending,
                        super::super::connection_manager::ConnectionHandle::pending,
                    );
                let _ = reply.send(Err(error));
            }
            self.publish_after_cancel(&command.request).await;
            return Ok(false);
        }
        self.complete_command(&command, result, reply).await
    }

    async fn publish_after_cancel(&self, request: &LocalBusFrame) {
        if super::super::generated_typing::is_transient(&request.method, &request.body) {
            return;
        }
        if let Err(error) = self.publish(request).await {
            tracing::warn!(account_id = %self.id, %error,
                "cancelled request publication deferred; account remains open");
        }
    }

    async fn complete_command(
        &mut self,
        command: &AccountCommand,
        result: Result<super::super::actor::ActorResponse, SdkError>,
        reply: tokio::sync::oneshot::Sender<Result<super::super::actor::ActorResponse, SdkError>>,
    ) -> Result<bool, SdkError> {
        if super::super::generated_typing::is_transient(
            &command.request.method,
            &command.request.body,
        ) {
            let _ = reply.send(result);
            return Ok(false);
        }
        let result = match self.initialize_readers() {
            Ok(()) => result,
            Err(error) => Err(error),
        };
        self.start_connection()?;
        self.start_courier();
        if let Some(courier) = &self.courier {
            courier.signal();
        }
        if let Some(connection) =
            self.state.accounts.get(&self.id).and_then(|account| account.connection.as_ref())
        {
            connection.wake_couriers();
        }
        let result = match self.publish(&command.request).await {
            Ok(()) => result,
            Err(error) => Err(error),
        };
        let _ = reply.send(result);
        Ok(command.request.method == "account.lock" && self.state.accounts.is_empty())
    }
}
