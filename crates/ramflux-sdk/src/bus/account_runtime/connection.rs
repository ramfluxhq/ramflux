// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-writer preparation and conditional application of connection outcomes.

use super::AccountRuntime;
use crate::bus::state::LocalBusAccountState;
use crate::bus::{
    actor::AccountCommand,
    connection_manager::{AccountWork, ReceiveTurn, SessionMetadata},
    mutation_intent::MutationIntent,
};
use crate::prelude::{
    SdkError, local_bus_account_manifest_path, read_local_bus_account_manifest,
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
            #[cfg(test)]
            if self.state.config.test_session_connector.is_some() {
                account.test_connector.clone_from(&self.state.config.test_session_connector);
            }
            if self.ledger.is_none()
                && let Ok(db) = account.client.account_db()
            {
                let key = format!("{}:{}", db.path.display(), db.local_account_id);
                self.ledger =
                    Some(crate::bus::push_receiver::executor::LedgerExecutor::bind_actor(key)?);
            }
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
        self.clear_transient_host();
        self.transient = super::transient::TransientHost::default();
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
        // Fetch prepares its durable failure receipt before admission.
        if command.request.method == "object.fetch" {
            return Ok(());
        }
        let handle = account.connection.clone().ok_or(SdkError::NetworkingPending)?;
        let admitted_at =
            command.admission.as_ref().map_or_else(Instant::now, |admission| admission.admitted_at);
        #[cfg(test)]
        if let Some(gate) = &self.state.config.test_network_command_gate {
            gate.waiting.notify_one();
        }
        let ready = handle.require_live_since(admitted_at, self.timeouts.network_wait);
        tokio::pin!(ready);
        loop {
            tokio::select! {
                biased;
                ready=&mut ready=>{ready?;break;},
                work=self.connection_work.recv()=>{if let Some(work)=work {
                    #[cfg(test)]
                    let outcome = matches!(&work, AccountWork::Connected { .. } | AccountWork::Failed { .. });
                    self.apply_connection_work(work).await?;
                    #[cfg(test)]
                    if outcome && let Some(gate) = &self.state.config.test_network_command_gate {
                        gate.applied.notify_one();
                        let _ = gate.release.acquire().await;
                    }
                }}
            }
        }
        self.prepare_command_heads(command, admitted_at).await
    }

    pub(super) async fn apply_connection_work(
        &mut self,
        work: AccountWork,
    ) -> Result<(), SdkError> {
        let publish_networking = self.apply_connection_work_inner(work).await?;
        if let Some(pool) = self.readers.lock().map_err(|_| super::stopped())?.as_ref() {
            pool.set_account_view(&self.state, &self.id)?;
        }
        if publish_networking {
            let request = crate::LocalBusFrame::request(
                "networking",
                Some(self.id.clone()),
                "account",
                "account.status",
                serde_json::json!({}),
            );
            self.publish(&request).await?;
        }
        Ok(())
    }

    /// Test seam: forwards one `SettleRetained` input into the real receive-turn arm.
    #[cfg(test)]
    pub(crate) async fn settle_retained_for_test(
        &mut self,
        generation: u64,
        turn: crate::bus::connection_manager::ReceiveTurn,
        sequence: u64,
        reply: tokio::sync::oneshot::Sender<Result<(), SdkError>>,
    ) -> Result<(), SdkError> {
        self.apply_connection_work(AccountWork::SettleRetained {
            generation,
            turn: Box::new(turn),
            sequence,
            reply,
        })
        .await
    }

    async fn apply_connection_work_inner(&mut self, work: AccountWork) -> Result<bool, SdkError> {
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(false);
        };
        let Some(handle) = account.connection.clone() else {
            return Ok(false);
        };
        let mut publish_networking = false;
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
            AccountWork::PrepareReceiveEpoch { .. }
            | AccountWork::ResetReceiveEpoch { .. }
            | AccountWork::PrepareReceive { .. }
            | AccountWork::ApplyPage { .. }
            | AccountWork::SettleRetained { .. }
            | AccountWork::ReceiveObservation { .. }
            | AccountWork::StageIntake { .. } => {
                return self.apply_receive_turn(&handle, work).await;
            }
            AccountWork::AckPermit { .. }
            | AccountWork::AckResults { .. }
            | AccountWork::AckFlush { .. } => {
                return Ok(self.apply_ack_work(&handle, work));
            }
            AccountWork::Metadata { metadata } => apply_metadata(account, &handle, *metadata),
            AccountWork::Prepare { generation, deadline, reply } => {
                if reply.is_closed()
                    || generation != handle.generation()
                    || Instant::now() >= deadline
                {
                    return Ok(false);
                }
                let result = prepare_account_connection(account, deadline).await;
                let _ = reply.send(result);
            }
            AccountWork::Connected { metadata, reply } => {
                if reply.is_closed() || metadata.generation != handle.generation() {
                    return Ok(false);
                }
                publish_networking = true;
                let result = self.install_connection(*metadata).await;
                let _ = reply.send(result);
            }
            AccountWork::Failed { generation, error } => {
                if generation == handle.generation() && account.client.born_v3_account.is_some() {
                    super::super::native_account::record_networking(account, Some(&error))?;
                    publish_networking = true;
                }
            }
        }
        Ok(publish_networking)
    }

    fn apply_ack_work(
        &mut self,
        handle: &crate::bus::connection_manager::ConnectionHandle,
        work: AccountWork,
    ) -> bool {
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return false;
        };
        match work {
            AccountWork::AckPermit { generation, turn, sequence, reply } => {
                if generation != handle.generation() || reply.is_closed() {
                    return false;
                }
                let _ = reply.send(apply_ack_permit(account, handle.generation(), &turn, sequence));
            }
            AccountWork::AckResults {
                generation,
                turn,
                state,
                cursor,
                mut backpressure,
                reply,
            } => {
                if generation != handle.generation() || reply.is_closed() {
                    return false;
                }
                let result = apply_ack_results(
                    account,
                    handle.generation(),
                    turn.as_deref(),
                    &state,
                    *cursor,
                    &mut backpressure,
                );
                let _ = reply.send(result.map(|accepted| (accepted, backpressure)));
            }
            AccountWork::AckFlush { generation, force, now, results, lookups, reply } => {
                if generation != handle.generation() || reply.is_closed() {
                    return false;
                }
                let _ = reply.send(apply_ack_flush(
                    account,
                    handle.generation(),
                    force,
                    now,
                    results,
                    lookups,
                ));
            }
            _ => {}
        }
        false
    }

    async fn apply_receive_turn(
        &mut self,
        handle: &crate::bus::connection_manager::ConnectionHandle,
        work: AccountWork,
    ) -> Result<bool, SdkError> {
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(false);
        };
        match work {
            AccountWork::PrepareReceiveEpoch { generation, incarnation, reply } => {
                if generation != handle.generation() || reply.is_closed() {
                    return Ok(false);
                }
                let _ = reply.send(account.client.prepare_receive_epoch(
                    &account.target_delivery_id,
                    &incarnation,
                    generation,
                ));
            }
            AccountWork::ResetReceiveEpoch { generation, turn, incarnation, page, reply } => {
                if generation != handle.generation() || reply.is_closed() {
                    return Ok(false);
                }
                let _ = reply.send(account.client.reset_receive_epoch(
                    &turn,
                    &incarnation,
                    &page,
                    handle.generation(),
                ));
            }
            AccountWork::PrepareReceive { generation, trigger, reply } => {
                if generation != handle.generation() || reply.is_closed() {
                    return Ok(false);
                }
                tracing::trace!(?trigger, generation, "preparing stored receive cursor");
                let result = super::super::sync_driver::source::w0::prepare_receive_turn(
                    account,
                    generation,
                    handle.generation(),
                    trigger,
                );
                let _ = reply.send(result);
            }
            AccountWork::ApplyPage { generation, turn, entry, source, backpressure, reply } => {
                return self
                    .drive_apply_page(handle, generation, turn, *entry, source, backpressure, reply)
                    .await;
            }
            AccountWork::SettleRetained { generation, turn, sequence, reply } => {
                if generation != handle.generation() || reply.is_closed() {
                    return Ok(false);
                }
                let result = settle_retained(account, handle.generation(), &turn, sequence);
                let _ = reply.send(result);
            }
            AccountWork::ReceiveObservation { generation, event } => {
                // Every event updates the networking status from the CURRENT snapshot, whatever
                // generation it carries: the worker bumps the snapshot generation right after it
                // emits Disconnected/AttemptFailed, so a late event must still publish. Only disk
                // recovery is generation-gated (PrepareReceive drops a stale generation).
                tracing::trace!(generation, current = handle.generation(), "receive observation");
                return Ok(record_observation(
                    account,
                    handle,
                    event,
                    &mut self.networking_observation_warned,
                ));
            }
            work @ AccountWork::StageIntake { .. } => {
                reply_stage_intake(account, handle, work);
            }
            _ => return Ok(false),
        }
        Ok(false)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors AccountWork::ApplyPage fields onto the activated W1 driver"
    )]
    async fn drive_apply_page(
        &mut self,
        handle: &crate::bus::connection_manager::ConnectionHandle,
        generation: u64,
        turn: Option<Box<super::super::connection_manager::ReceiveTurn>>,
        entry: super::super::connection_manager::ReceiveEntry,
        source: super::super::sync_driver::source::PreparedSource,
        backpressure: Box<super::super::contact_backpressure::Backpressure>,
        reply: tokio::sync::oneshot::Sender<
            Result<super::super::connection_manager::ReceiveApplied, SdkError>,
        >,
    ) -> Result<bool, SdkError> {
        if generation != handle.generation() || reply.is_closed() {
            return Ok(false);
        }
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(false);
        };
        let target = entry.entry.target_delivery_id.clone();
        let active = match ledger_is_active(account, handle.generation(), &target) {
            Ok(active) => active,
            Err(error) => {
                let _ = reply.send(Err(error));
                return Ok(false);
            }
        };
        if !active {
            self.apply_receive_entry(generation, entry, source, backpressure, reply).await?;
            return Ok(false);
        }
        let turn = match page_turn(account, generation, &target, turn) {
            Ok(turn) => turn,
            Err(error) => {
                let _ = reply.send(Err(error));
                return Ok(false);
            }
        };
        let current = handle.clone();
        #[cfg(test)]
        let started = {
            if let Some(handle) = &account.connection {
                handle.test_record_receive("apply-start", std::time::Duration::ZERO);
            }
            std::time::Instant::now()
        };
        let result = Box::pin(super::super::push_receiver::apply_w1::apply_page(
            account,
            &turn,
            &|| current.generation(),
            entry,
            source,
            backpressure,
        ))
        .await;
        let result = match result {
            Ok(applied) => {
                super::super::push_receiver::apply_w1::replay_projected(account).map(|()| applied)
            }
            Err(error) => Err(error),
        };
        #[cfg(test)]
        if result.is_ok()
            && let Some(handle) = &account.connection
        {
            handle.test_record_receive("apply", started.elapsed());
            handle.test_record_receive("projection", started.elapsed());
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
        let published = std::time::Instant::now();
        self.publish(&request).await?;
        #[cfg(test)]
        if let Some(handle) =
            self.state.accounts.get(&self.id).and_then(|account| account.connection.as_ref())
        {
            handle.test_record_receive("publish", published.elapsed());
        }
        let _ = reply.send(result);
        Ok(false)
    }

    async fn apply_receive_entry(
        &mut self,
        generation: u64,
        entry: super::super::connection_manager::ReceiveEntry,
        source: super::super::sync_driver::source::PreparedSource,
        backpressure: Box<super::super::contact_backpressure::Backpressure>,
        reply: tokio::sync::oneshot::Sender<
            Result<super::super::connection_manager::ReceiveApplied, SdkError>,
        >,
    ) -> Result<(), SdkError> {
        let account =
            self.state.accounts.get_mut(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        let turn = match super::super::sync_driver::source::w0::actor_turn(account, generation) {
            Ok(turn) => turn,
            Err(error) => {
                let _ = reply.send(Err(error));
                return Ok(());
            }
        };
        if let Err(error) =
            super::super::sync_driver::source::w0::refuse_legacy_receive_unless_ledger_turn(
                account,
                turn.as_ref(),
            )
        {
            let _ = reply.send(Err(error));
            return Ok(());
        }
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
        let result = self.install_connection_inner(metadata).await;
        if let Err(error) = &result
            && let Some(account) = self.state.accounts.get_mut(&self.id)
            && account.client.born_v3_account.is_some()
        {
            super::super::native_account::record_networking(account, Some(error))?;
        }
        result
    }

    async fn install_connection_inner(
        &mut self,
        metadata: SessionMetadata,
    ) -> Result<(), SdkError> {
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Err(SdkError::NetworkingPending);
        };
        let verified = metadata.mode.push_incarnation().map(str::to_owned);
        account.gateway_config = metadata.config;
        account.target_delivery_id.clone_from(&account.gateway_config.target_delivery_id);
        account
            .client
            .first_activate_receive_ledger(&account.target_delivery_id, verified.as_deref())?;
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

fn ledger_is_active(
    account: &mut LocalBusAccountState,
    generation: u64,
    target: &str,
) -> Result<bool, SdkError> {
    match &account.receive_active_cache {
        Some((cached_gen, cached_target, active))
            if *cached_gen == generation && cached_target == target =>
        {
            return Ok(*active);
        }
        _ => {}
    }
    let active =
        super::super::push_receiver::apply_w1::is_active(account.client.account_db()?, target)?;
    account.receive_active_cache = Some((generation, target.to_owned(), active));
    Ok(active)
}

fn page_turn(
    account: &LocalBusAccountState,
    generation: u64,
    target: &str,
    turn: Option<Box<ReceiveTurn>>,
) -> Result<ReceiveTurn, SdkError> {
    let db = account.client.account_db()?;
    let mut turn = match turn {
        Some(turn) => *turn,
        None => super::super::push_receiver::apply_w1::capture_turn(db, generation, target)?,
    };
    super::super::push_receiver::apply_w1::refresh_cursor(db, &mut turn)?;
    Ok(turn)
}

async fn short_step<T>(
    limit: std::time::Duration,
    future: impl std::future::Future<Output = Result<T, SdkError>>,
) -> Result<T, SdkError> {
    tokio::time::timeout(limit, future).await.map_err(|_| attempt_timeout())?
}

pub(crate) fn apply_ack_flush(
    account: &LocalBusAccountState,
    generation: u64,
    force: bool,
    now: i64,
    results: Option<crate::bus::connection_manager::AckFlushResults>,
    lookups: Option<Vec<(u64, crate::bus::push_receiver::compat::OwnedLookup)>>,
) -> Result<crate::bus::connection_manager::AckFlushReply, SdkError> {
    use crate::bus::connection_manager::{AckFlushReply, CompatAckPlan};
    use crate::bus::push_receiver::ack_batch::SourceWa;
    use crate::bus::push_receiver::compat::{AckDecision, authorize_legacy_ack};
    use ramflux_storage::{ReceiveAckApply, ReceiveAckOutcome};
    let db = account.client.account_db()?;
    let target = account.target_delivery_id.as_str();
    if !super::super::push_receiver::apply_w1::is_active(db, target)? {
        return Ok(AckFlushReply::Inactive);
    }
    let turn = super::super::push_receiver::apply_w1::capture_turn(db, generation, target)?;
    if let Some(lookups) = lookups {
        let capable_e = match account.bound_session_mode() {
            Some(crate::gateway::session_push::SessionMode::Push { incarnation }) => {
                Some(incarnation.as_str().to_owned())
            }
            _ => None,
        };
        let mut plans = Vec::with_capacity(lookups.len());
        for (sequence, lookup) in lookups {
            let decision = authorize_legacy_ack(
                db,
                target,
                &turn.incarnation,
                sequence,
                capable_e.as_deref(),
                &lookup.as_reply(),
            )?;
            let plan = match decision {
                AckDecision::Authorize => CompatAckPlan {
                    sequence,
                    envelope_id: match lookup {
                        crate::bus::push_receiver::compat::OwnedLookup::Entry {
                            envelope_id,
                            ..
                        } => Some(envelope_id),
                        _ => None,
                    },
                    outcome: ReceiveAckOutcome::Acked,
                },
                AckDecision::SettleAbsent => CompatAckPlan {
                    sequence,
                    envelope_id: None,
                    outcome: ReceiveAckOutcome::AlreadySettled,
                },
                AckDecision::RetainBackoff => CompatAckPlan {
                    sequence,
                    envelope_id: None,
                    outcome: ReceiveAckOutcome::Transient,
                },
                AckDecision::Suspend | AckDecision::RefuseSequenceAlone => CompatAckPlan {
                    sequence,
                    envelope_id: None,
                    outcome: ReceiveAckOutcome::Uncertain,
                },
            };
            plans.push(plan);
        }
        return Ok(AckFlushReply::Authorized { plans });
    }
    match results {
        None => {
            let sequences =
                SourceWa { expected: turn.expected(), generation }.select(db, now, force)?;
            Ok(AckFlushReply::Selected { incarnation: turn.incarnation, sequences })
        }
        Some(rows) => {
            let applied = SourceWa { expected: turn.expected(), generation }.apply(
                db,
                ReceiveAckApply {
                    incarnation: &rows.incarnation,
                    sequences: &rows.sequences,
                    results: &rows.results,
                    now,
                },
            )?;
            Ok(AckFlushReply::Applied(applied))
        }
    }
}

fn apply_ack_permit(
    account: &crate::bus::state::LocalBusAccountState,
    generation: u64,
    turn: &crate::bus::connection_manager::ReceiveTurn,
    sequence: u64,
) -> Result<super::lifecycle_fence::AckRecord, SdkError> {
    account
        .client
        .account_db()
        .and_then(|db| super::lifecycle_fence::ack_permit(db, generation, turn, sequence))
}

fn apply_ack_results(
    account: &crate::bus::state::LocalBusAccountState,
    handle_generation: u64,
    turn: Option<&crate::bus::connection_manager::ReceiveTurn>,
    state: &crate::bus::sync_driver::AckState,
    cursor: Result<crate::GatewayCursor, SdkError>,
    backpressure: &mut crate::bus::contact_backpressure::Backpressure,
) -> Result<bool, SdkError> {
    #[cfg(test)]
    let _ack_work = account.client.account_db()?.observe_ack_work();
    let Some(turn) = turn else {
        return super::super::sync_driver::finish_prepared_ack(
            account,
            state,
            cursor,
            backpressure,
        );
    };
    let cursor_ok = cursor.is_ok();
    let record = super::lifecycle_fence::ack_results(
        account.client.account_db()?,
        handle_generation,
        turn,
        state.entry.inbox_seq,
        cursor_ok,
    )?;
    cursor?;
    Ok(matches!(record, super::lifecycle_fence::AckRecord::Recorded) && state.accepted)
}

fn attempt_timeout() -> SdkError {
    SdkError::NodeTimeout { retry_after_ms: crate::node::NODE_RETRY_AFTER_MS }
}

async fn prepare_account_connection(
    account: &mut crate::bus::state::LocalBusAccountState,
    deadline: Instant,
) -> Result<crate::GatewaySessionConfig, SdkError> {
    timeout_at(deadline, async {
        if account.client.born_v3_account.is_some() {
            account.prepare_native_branch().await?;
        } else {
            account.refresh_legacy_authorization().await?;
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

fn record_observation(
    account: &crate::bus::state::LocalBusAccountState,
    handle: &crate::bus::connection_manager::ConnectionHandle,
    event: crate::bus::connection_manager::ConnectionEvent,
    warned: &mut bool,
) -> bool {
    observe_connection(event);
    if account.client.born_v3_account.is_none() {
        return false;
    }
    if let Err(error) = refresh_receive_status(account, handle)
        && !*warned
    {
        tracing::warn!(%error, "receive snapshot counters deferred; account remains open");
        *warned = true;
    }
    match super::super::networking_events::record_session(account, &handle.snapshot()) {
        Ok(changed) => {
            *warned = false;
            changed
        }
        Err(error) => {
            if !*warned {
                tracing::warn!(%error,
                    "networking observation persistence deferred; account remains open");
                *warned = true;
            }
            false
        }
    }
}

fn refresh_receive_status(
    account: &crate::bus::state::LocalBusAccountState,
    handle: &crate::bus::connection_manager::ConnectionHandle,
) -> Result<(), SdkError> {
    use crate::bus::connection_manager::ReceiveStatus;
    // A missing account DB is the observation-persist outage; skip counters so
    // `record_session` still reports "networking observation persistence deferred".
    let db = match account.client.account_db() {
        Err(SdkError::AccountDbNotUnlocked) => return Ok(()),
        other => other?,
    };
    let receive = match db.receive_activation()? {
        ramflux_storage::ReceiveActivation::Inactive => None,
        ramflux_storage::ReceiveActivation::Activated => {
            let counters = db.receive_status_counters(&account.target_delivery_id)?;
            let mode = handle.session_mode();
            Some(ReceiveStatus {
                mode: mode.receive_label().to_owned(),
                last_catch_up_at: handle.last_catch_up_at_ms(),
                catch_ups_total: handle.catch_ups_total(),
                inbox_gaps_total: counters.inbox_gaps_total,
                legacy_unverified_total: counters.legacy_unverified_total,
                ack_intents_pending: counters.ack_intents_pending,
                held_entries: counters.held_entries,
                paused_reason: handle.compat_session().paused_reason.map(str::to_owned),
                incarnation: counters.incarnation,
                inbox_resets_total: counters.inbox_resets_total,
                held_evicted_total: counters.held_evicted_total,
                incarnation_unverified: counters.incarnation_unverified,
                fallback_clock_unverified: handle.fallback_clock_unverified()
                    || counters.incarnation_unverified_flag,
            })
        }
    };
    handle.set_receive_status(receive);
    Ok(())
}

fn apply_metadata(
    account: &mut crate::bus::state::LocalBusAccountState,
    handle: &crate::bus::connection_manager::ConnectionHandle,
    metadata: SessionMetadata,
) {
    if metadata.generation == handle.generation() && account.session_route_matches(&metadata.config)
    {
        account.apply_resume_metadata(metadata.config);
        account.persist_push_route_seq();
        account.forget_confirmed_push_clear();
    }
}

fn reply_stage_intake(
    account: &LocalBusAccountState,
    handle: &crate::bus::connection_manager::ConnectionHandle,
    work: AccountWork,
) {
    let AccountWork::StageIntake { generation, entry, incarnation, retain_until, reply } = work
    else {
        return;
    };
    if generation != handle.generation() || reply.is_closed() {
        return;
    }
    let _ = reply.send(crate::bus::push_receiver::intake::stage_on_actor(
        account,
        generation,
        &entry,
        &incarnation,
        retain_until,
    ));
}

/// WS settlement of a retained terminal entry inside the lifecycle fence (moved out of
/// `apply_receive_turn` unchanged to keep it under the line limit).
pub(crate) fn settle_retained(
    account: &mut LocalBusAccountState,
    generation: u64,
    turn: &super::super::connection_manager::ReceiveTurn,
    sequence: u64,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    let expected = turn.expected();
    super::lifecycle_fence::commit(db, generation, expected, |tx| {
        let key = tx.work_admission_key(sequence)?;
        match crate::bus::sync_driver::source::ws::SourceWs::settle_in(
            tx,
            ramflux_storage::ReceiveSettle {
                sequence,
                kind: ramflux_storage::ReceiveSettleKind::Terminal,
            },
        )? {
            ramflux_storage::ReceiveSettleResult::Settled => {
                if let Some(key) = key {
                    crate::client::reply_outbox::ReplyOutbox::prune_marker_in(tx, &key)?;
                }
                Ok(())
            }
            ramflux_storage::ReceiveSettleResult::Held => Ok(()),
            ramflux_storage::ReceiveSettleResult::Paused => {
                Err(ramflux_storage::StorageError::Integrity("settle retained paused"))
            }
        }
    })
    .map_err(SdkError::from)
}
