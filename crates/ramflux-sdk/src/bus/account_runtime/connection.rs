// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-writer preparation and conditional application of connection outcomes.

use super::AccountRuntime;
use crate::bus::{
    actor::AccountCommand,
    connection_manager::{AccountWork, SessionMetadata},
    mutation_intent::MutationIntent,
};
use crate::prelude::{
    SdkError, local_bus_account_manifest_path, now_unix_timestamp, read_local_bus_account_manifest,
    write_local_bus_account_manifest,
};
use tokio::time::{Instant, timeout_at};

impl AccountRuntime {
    pub(super) fn start_connection(&mut self) -> Result<(), SdkError> {
        if let Some(account) = self.state.accounts.get_mut(&self.id) {
            self.transfers.restart();
            account.timeouts = self.timeouts.clone();
            account.transfer_slots = Some(self.transfers.slots.clone());
            account.connection_work = Some(self.connection_sender.clone());
            if let Err(error) = account.start_connection() {
                tracing::warn!(%error, "account connection manager startup deferred; account remains open");
            }
        }
        if let Some(pool) = self.readers.lock().map_err(|_| super::stopped())?.as_ref() {
            pool.set_account_view(&self.state, &self.id)?;
        }
        Ok(())
    }
    pub(super) async fn stop_connection(&mut self) {
        if let Some(handle) =
            self.state.accounts.get_mut(&self.id).and_then(|account| account.connection.take())
        {
            handle.stop().await;
        }
    }

    pub(super) async fn prepare_command_network(
        &mut self,
        command: &AccountCommand,
    ) -> Result<(), SdkError> {
        let Some(account) = self.state.accounts.get(&self.id) else {
            return Ok(());
        };
        if !super::super::method_table::account_requires_network(&command.request, account) {
            return Ok(());
        }
        let intent = MutationIntent::new(&command.request)?;
        if intent.lookup(account.client.account_db()?)?.is_some() {
            return Ok(());
        }
        if intent.key.is_none()
            && command.request.method == "object.put.finish"
            && super::super::dispatch::object::lookup_finish_receipt(account, &command.request)?
                .is_some()
        {
            return Ok(());
        }
        if command.request.method == "object.fetch" {
            let body: crate::bus::protocol::LocalBusObjectFetchRequest =
                serde_json::from_value(command.request.body.clone())?;
            if account
                .client
                .lookup_received_attachment_operation(&body.object_id, &body.operation_id)?
                .is_some()
            {
                return Ok(());
            }
        }
        let handle = account.connection.clone().ok_or(SdkError::NetworkingPending)?;
        let admitted_at =
            command.admission.as_ref().map_or_else(Instant::now, |admission| admission.admitted_at);
        let ready = handle.require_live_since(admitted_at, self.timeouts.network_wait);
        tokio::pin!(ready);
        loop {
            tokio::select! {
                biased;
                ready=&mut ready=>return ready,
                work=self.connection_work.recv()=>{if let Some(work)=work {self.apply_connection_work(work).await?;}}
            }
        }
    }

    pub(super) async fn apply_connection_work(
        &mut self,
        work: AccountWork,
    ) -> Result<(), SdkError> {
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(());
        };
        let Some(handle) = account.connection.clone() else {
            return Ok(());
        };
        match work {
            AccountWork::Fatal { generation, error } => {
                if generation == handle.generation() {
                    return Err(error);
                }
            }
            AccountWork::Courier(work) => {
                if work.generation == handle.generation() {
                    work.apply(account);
                }
            }
            AccountWork::Contacts(work) => {
                if work.generation() == handle.generation() {
                    crate::client::contact_requests::apply_background(account, *work);
                }
            }
            AccountWork::OwnCopy(work) => {
                if work.generation() == handle.generation() {
                    super::super::own_device_copy::apply_background(account, *work);
                }
            }
            AccountWork::Receipts(work) => {
                if work.generation() == handle.generation() {
                    super::super::delivery_receipts::apply_background(account, *work);
                }
            }
            AccountWork::Directory(work) => self.apply_directory_work(*work)?,
            AccountWork::ReceivePrepare { generation, trigger, reply } => {
                if generation != handle.generation() || reply.is_closed() {
                    return Ok(());
                }
                tracing::trace!(?trigger, generation, "preparing stored receive cursor");
                let result = super::super::sync_driver::prepare_receive(account);
                let _ = reply.send(result);
            }
            AccountWork::ReceiveApply { generation, entry, source, backpressure, reply } => {
                if generation != handle.generation() || reply.is_closed() {
                    return Ok(());
                }
                self.apply_receive_entry(*entry, source, backpressure, reply).await?;
            }

            AccountWork::ReceiveAck { generation, state, cursor, mut backpressure, reply } => {
                if generation == handle.generation() && !reply.is_closed() {
                    #[cfg(test)]
                    let _ack_work = account.client.account_db()?.observe_ack_work();
                    let result = super::super::sync_driver::finish_prepared_ack(
                        account,
                        &state,
                        *cursor,
                        &mut backpressure,
                    );
                    let _ = reply.send(result.map(|accepted| (accepted, backpressure)));
                }
            }
            AccountWork::Metadata { metadata } => {
                if metadata.generation == handle.generation()
                    && account.session_route_matches(&metadata.config)
                {
                    account.apply_resume_metadata(metadata.config);
                    account.persist_push_route_seq();
                    account.forget_confirmed_push_clear();
                }
            }
            AccountWork::Observation { event } => observe_connection(event),

            AccountWork::Prepare { generation, deadline, reply } => {
                if reply.is_closed()
                    || generation != handle.generation()
                    || Instant::now() >= deadline
                {
                    return Ok(());
                }
                let result = prepare_account_connection(account, &self.id, deadline).await;
                let _ = reply.send(result);
            }
            AccountWork::Connected { metadata, reply } => {
                if reply.is_closed() || metadata.generation != handle.generation() {
                    return Ok(());
                }
                let result = self.install_connection(*metadata).await;
                let _ = reply.send(result);
            }
            AccountWork::Failed { generation, error } => {
                if generation == handle.generation() && account.client.born_v3_account.is_some() {
                    super::super::native_account::record_networking(account, Some(&error))?;
                }
            }
        }
        if let Some(pool) = self.readers.lock().map_err(|_| super::stopped())?.as_ref() {
            pool.set_account_view(&self.state, &self.id)?;
        }
        Ok(())
    }

    async fn apply_receive_entry(
        &mut self,
        entry: super::super::connection_manager::ReceiveEntry,
        source: super::super::sync_driver::source::PreparedSource,
        backpressure: Box<super::super::contact_backpressure::Backpressure>,
        reply: tokio::sync::oneshot::Sender<
            Result<super::super::connection_manager::ReceiveApplied, SdkError>,
        >,
    ) -> Result<(), SdkError> {
        let account =
            self.state.accounts.get_mut(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        #[cfg(test)]
        let started = {
            if let Some(handle) = &account.connection {
                handle.test_record_receive("apply-start", std::time::Duration::ZERO);
            }
            std::time::Instant::now()
        };
        let result =
            super::super::sync_driver::apply_prepared_receive(account, entry, source, backpressure)
                .await;
        #[cfg(test)]
        if let Some(handle) = &account.connection {
            handle.test_record_receive("apply", started.elapsed());
        }
        if let Some(handle) = &account.connection {
            handle.wake_couriers();
        }
        let request = crate::LocalBusFrame::request(
            "receive",
            Some(self.id.clone()),
            "sync",
            "sync.run",
            serde_json::json!({}),
        );
        #[cfg(test)]
        let started = std::time::Instant::now();
        self.publish(&request).await?;
        #[cfg(test)]
        if let Some(handle) =
            self.state.accounts.get(&self.id).and_then(|account| account.connection.as_ref())
        {
            handle.test_record_receive("publish", started.elapsed());
        }
        let _ = reply.send(result);
        Ok(())
    }

    async fn install_connection(&mut self, metadata: SessionMetadata) -> Result<(), SdkError> {
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Err(SdkError::NetworkingPending);
        };
        account.gateway_config = metadata.config;
        account.target_delivery_id.clone_from(&account.gateway_config.target_delivery_id);
        if account.client.born_v3_account.is_some() {
            short_step(
                account.timeouts.network_wait,
                super::super::native_account::finish_connection(account),
            )
            .await?;
            super::super::native_account::record_networking(account, None)?;
        } else {
            let root = account.client.account_index()?.root();
            let path = local_bus_account_manifest_path(root, &self.id);
            if let Ok(mut manifest) = read_local_bus_account_manifest(&path)
                && manifest.activation_pending
            {
                manifest.activation_pending = false;
                write_local_bus_account_manifest(root, &manifest)?;
                account.activation_pending = false;
            }
        }
        account.finish_restored_resume_checkpoint(true)?;
        account.client.complete_backup_activation()?;
        account.persist_push_route_seq();
        self.start_courier();
        Ok(())
    }
}

async fn short_step<T>(
    limit: std::time::Duration,
    future: impl std::future::Future<Output = Result<T, SdkError>>,
) -> Result<T, SdkError> {
    tokio::time::timeout(limit, future).await.map_err(|_| attempt_timeout())?
}
fn attempt_timeout() -> SdkError {
    SdkError::NodeTimeout { retry_after_ms: crate::node::NODE_RETRY_AFTER_MS }
}

async fn prepare_account_connection(
    account: &mut crate::bus::state::LocalBusAccountState,
    id: &str,
    deadline: Instant,
) -> Result<crate::GatewaySessionConfig, SdkError> {
    timeout_at(deadline, async {
        if account.client.born_v3_account.is_some() {
            account.prepare_native_branch().await?;
        } else {
            let root = account.client.account_index()?.root().to_path_buf();
            let path = local_bus_account_manifest_path(&root, id);
            if let Ok(manifest) = read_local_bus_account_manifest(&path) {
                let refresh_due = account.client.own_proof_refresh_due(now_unix_timestamp())?;
                if manifest.activation_pending || refresh_due {
                    short_step(
                        account.timeouts.network_wait,
                        account.client.initialize_and_publish_prekey_bundle_via_gateway_request(
                            &account.gateway_config,
                            &manifest.principal_commitment,
                            &manifest.device_id,
                            &manifest.target_delivery_id,
                            manifest.device_seed,
                        ),
                    )
                    .await?;
                    short_step(
                        account.timeouts.network_wait,
                        account.client.cache_verified_device_manifest(
                            &account.gateway_config,
                            &manifest.principal_commitment,
                            "account.create",
                        ),
                    )
                    .await?;
                }
            }
        }
        account.connection_config()
    })
    .await
    .map_err(|_| attempt_timeout())
    .and_then(std::convert::identity)
}

fn observe_connection(event: crate::bus::connection_manager::ConnectionEvent) {
    use super::super::connection_manager::ConnectionEvent;
    match event {
        ConnectionEvent::Connected { session_id, resumed, generation } => {
            tracing::debug!(session_id, resumed, generation, "account session connected");
        }
        ConnectionEvent::Disconnected { reason, generation } => {
            tracing::debug!(?reason, generation, "account session disconnected");
        }
        ConnectionEvent::AttemptFailed { reason, retry_after_ms, generation } => {
            tracing::debug!(
                reason,
                retry_after_ms,
                generation,
                "account connection attempt deferred"
            );
        }
    }
}
