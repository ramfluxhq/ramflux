// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Claimed commands, lifecycle preemption, and bounded ordinary dispatch.

use super::super::publication_wait::{Dispatch, dispatch};
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
    fn preemption_error(&self) -> SdkError {
        self.state.accounts.get(&self.id).and_then(|account| account.connection.as_ref()).map_or(
            SdkError::NetworkingPending,
            super::super::connection_manager::ConnectionHandle::pending,
        )
    }

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
        self.username.stop().await;
        self.pairing.stop().await;
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
            super::super::actor::PrivateCommand::NativeUnlock { secret, home_node_id, reply } => {
                if !reply.is_closed() {
                    let result = super::super::native_account::unlock(
                        &mut self.state,
                        &self.id,
                        secret,
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
                    self.start_connection_or_defer();
                    self.start_courier();
                    let result = result.and_then(|_| {
                        super::super::native_account::response(local_bus_account(
                            &self.state,
                            &self.id,
                        )?)
                    });
                    let result = match self.publish_yielding(request).await {
                        Ok(()) => result,
                        Err(error) => Err(error),
                    };
                    let _ = reply.send(result);
                }
            }
            super::super::actor::PrivateCommand::SearchRebuild {
                owner,
                job,
                admission,
                reset,
                reply,
            } => {
                if !reply.is_closed() {
                    let result = (|| {
                        let pool = self
                            .readers
                            .lock()
                            .map_err(|_| stopped())?
                            .clone()
                            .ok_or_else(stopped)?;
                        let runtime = pool.search_runtime()?;
                        let account = local_bus_account(&self.state, &self.id)?;
                        runtime.rebuild_batch(&account.client, owner, &job, &admission, reset)
                    })();
                    let _ = reply.send(result);
                }
            }
            super::super::actor::PrivateCommand::AuthorizeBackup { generation, reply } => {
                let result = self.authorize_backup(generation);
                let _ = reply.send(result);
            }
            super::super::actor::PrivateCommand::ProjectActivity { activity, reply } => {
                if !reply.is_closed() {
                    let _ = reply.send(self.store_owner_activity(*activity));
                }
            }
            super::super::actor::PrivateCommand::Agent(command) => self.apply_agent(*command),
            super::super::actor::PrivateCommand::Capture(reply) => {
                if !reply.is_closed() {
                    let result = self.capture_backup();
                    let _ = reply.send(result);
                }
            }
            #[cfg(feature = "c-abi")]
            super::super::actor::PrivateCommand::ReleaseFiles { reply } => {
                let _ = reply.send(self.release_for_suspend().await);
            }
            #[cfg(feature = "c-abi")]
            super::super::actor::PrivateCommand::ReopenFiles { reply } => {
                let _ = reply.send(self.reopen_from_suspend());
            }
        }
        Ok(())
    }
    pub(super) async fn apply(&mut self, command: AccountCommand) -> Result<bool, SdkError> {
        let method = command.request.method.clone();
        let started = tokio::time::Instant::now();
        tracing::debug!(
            phase = "actor_hold",
            event = "begin",
            method = %method,
            "account command phase"
        );
        let stop = super::head_refresh::RECEIVE_PREPARED
            .scope(std::cell::Cell::new(false), self.apply_command(command))
            .await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        tracing::debug!(
            phase = "actor_hold",
            event = "end",
            method = %method,
            elapsed_ms,
            "account command phase"
        );
        super::publication_park::set_final(false);
        stop
    }

    async fn park_command(&mut self, command: &mut AccountCommand) -> Result<bool, SdkError> {
        if command.private.as_ref().is_some_and(super::background::is_file_command) {
            let Some(backup) = command.private.take() else { return Ok(false) };
            self.apply_private(backup, &command.request).await?;
            return Ok(true);
        }
        if self.state.config.background.load(std::sync::atomic::Ordering::Acquire) {
            super::background::reject_suspended(command);
            return Ok(true);
        }
        Ok(false)
    }

    async fn apply_command(&mut self, mut command: AccountCommand) -> Result<bool, SdkError> {
        if self.park_command(&mut command).await? {
            return Ok(false);
        }
        self.refresh_networking_expiry().await;
        if !admit(&command) {
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
        if self.pairing.busy(&command.request.method) {
            let _ = reply.send(Err(SdkError::PairingCode("Busy")));
            return Ok(false);
        }
        if !lifecycle {
            let mut shutdown = self.shutdown.clone();
            let mut preempt = self.preempt.clone();
            let gate = tokio::select! {
                biased;
                _=shutdown.changed()=>return Ok(true),
                _=preempt.changed()=>{
                    let error=self.preemption_error();
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
        if owned_command(&command.request.method) {
            self.start_owned_command(command, reply).await?;
            return Ok(false);
        }
        if super::super::username_directory::handles(&command.request.method) {
            // Boxed: the username handler's future would otherwise enlarge every account command future on the stack.
            Box::pin(self.start_username(command, reply)).await;
            return Ok(false);
        }
        #[cfg(test)]
        let receive_gate_hook = self.receive_gate_hook.take();
        let command_timeout = self.timeouts.command;
        let (dispatched, stopping, cancelled, preempted) = self
            .ordinary_dispatch(
                &command,
                &mut reply,
                lifecycle,
                command_timeout,
                #[cfg(test)]
                receive_gate_hook,
            )
            .await;
        if let Some(account) = self.state.accounts.get_mut(&self.id) {
            super::super::control_state::trim(account);
        }
        if stopping {
            return Ok(true);
        }
        if cancelled {
            if preempted {
                let error = self.preemption_error();
                let _ = reply.send(Err(error));
            }
            self.publish_after_cancel(&command.request).await;
            return Ok(false);
        }
        match dispatched {
            Dispatch::Park { deadline } if !reply.is_closed() => {
                super::publication_park::park(command, reply, deadline);
                Ok(false)
            }
            Dispatch::Park { .. } => Ok(false),
            Dispatch::Done(result) => self.complete_command(&command, result, reply).await,
        }
    }

    async fn ordinary_dispatch(
        &mut self,
        command: &AccountCommand,
        reply: &mut tokio::sync::oneshot::Sender<
            Result<super::super::actor::ActorResponse, SdkError>,
        >,
        lifecycle: bool,
        command_timeout: std::time::Duration,
        #[cfg(test)] receive_gate_hook: Option<super::ReceiveGateHook>,
    ) -> (Dispatch, bool, bool, bool) {
        let mut stopping = false;
        let mut cancelled = false;
        let mut preempted = false;
        let dispatched = if lifecycle {
            Dispatch::Done(
                super::super::mutations::execute(&mut self.state, &self.id, command).await,
            )
        } else {
            let final_attempt = super::publication_park::is_final();
            tokio::select! {
                biased;
                _ = self.shutdown.changed() => {
                    stopping = true;
                    Dispatch::Done(Err(stopped()))
                },
                _ = self.preempt.changed() => {
                    cancelled = true;
                    preempted = true;
                    Dispatch::Done(Err(stopped()))
                },
                () = reply.closed() => {
                    cancelled = true;
                    Dispatch::Done(Err(stopped()))
                },
                result = async {
                    #[cfg(test)]
                    wait_receive_gate(receive_gate_hook).await;
                    dispatch(&mut self.state, &self.id, command, command_timeout, final_attempt).await
                } => result,
            }
        };
        (dispatched, stopping, cancelled, preempted)
    }

    async fn publish_after_cancel(&mut self, request: &LocalBusFrame) {
        if super::super::generated_typing::is_transient(&request.method, &request.body) {
            return;
        }
        if let Err(error) = self.publish_yielding(request).await {
            tracing::warn!(account_id = %self.id, %error,
                "cancelled request publication deferred; account remains open");
        }
    }

    pub(super) async fn complete_command(
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
        self.start_connection_or_defer();
        self.start_courier();
        if let Some(courier) = &self.courier {
            courier.signal();
        }
        if let Some(connection) =
            self.state.accounts.get(&self.id).and_then(|account| account.connection.as_ref())
        {
            connection.wake_couriers();
        }
        let result = match self.publish_yielding(&command.request).await {
            Ok(()) => result,
            // The progress row is already committed. A later outbox wake can fail
            // with the writer pause, which the bus reports as ValidationFailed.
            // The host does not retry that code, so the owner copy must still go out.
            Err(error) if result.is_ok() && command.request.method == "agent.progress" => {
                tracing::warn!(
                    account_id = %self.id,
                    %error,
                    "agent progress publication deferred; owner copy remains"
                );
                result
            }
            Err(error) => Err(error),
        };
        let _ = reply.send(result);
        Ok(matches!(command.request.method.as_str(), "account.lock" | "account.sign_out")
            && self.state.accounts.is_empty())
    }
}

impl AccountRuntime {
    fn store_owner_activity(
        &self,
        activity: super::super::actor::OwnerActivity,
    ) -> Result<(), SdkError> {
        if activity.owner_id != self.id {
            tracing::warn!(
                owner_id = %activity.owner_id,
                account_id = %self.id,
                reason_code = "owner_actor_mismatch",
                "agent activity owner copy was not stored"
            );
            return Err(SdkError::AccountNotOpen(activity.owner_id));
        }
        // This thread's pause scope belongs to whichever account last armed it.
        // The copy is one short command; a foreign scope must not refuse it.
        let _guard = ramflux_storage::writer_budget::ServiceGuard::enter();
        let client = &local_bus_account(&self.state, &self.id)?.client;
        crate::client::agent_activity::store_owner_copy(
            client,
            &activity.state_kind,
            activity.record,
        )
    }

    pub(super) async fn start_owned_command(
        &mut self,
        command: AccountCommand,
        reply: tokio::sync::oneshot::Sender<Result<super::super::actor::ActorResponse, SdkError>>,
    ) -> Result<(), SdkError> {
        match command.request.method.as_str() {
            "device.transfer.begin"
            | "device.transfer.status"
            | "device.pair.join"
            | "device.transfer.join" => {
                Box::pin(self.start_pairing_begin(command, reply)).await;
            }
            "object.fetch" => self.start_fetch(command, reply),
            "object.put.finish" => self.start_upload(command, reply).await?,
            _ => return Err(SdkError::LocalBus("unknown owned account command".into())),
        }
        Ok(())
    }
}

fn admit(command: &AccountCommand) -> bool {
    match &command.admission {
        None => true,
        Some(admission) => admission.claim() || admission.is_claimed(),
    }
}

fn owned_command(method: &str) -> bool {
    matches!(
        method,
        "device.transfer.begin"
            | "device.transfer.status"
            | "device.pair.join"
            | "device.transfer.join"
            | "object.fetch"
            | "object.put.finish"
    )
}
