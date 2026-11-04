// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deferred attachment jobs and durable F0-F6 handshakes on the account writer.

use super::{AccountRuntime, uploads::Checkpoint};
use crate::bus::{
    actor::{AccountCommand, ActorResponse},
    connection_manager::{ConnectionHandle, SessionClient, SessionMetadata},
    transfer_slots::{JobHandle, TransferPermit},
};
use crate::client::{
    FetchBinding, FetchFence, FetchPreparation,
    object::fetch_job::{FetchChunk, FetchCipher, FetchInput},
};
use crate::{LocalBusFrame, SdkError};
use std::sync::Arc;
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, timeout_at},
};

type Reply = oneshot::Sender<Result<ActorResponse, SdkError>>;
pub(super) struct Fetch {
    pub handle: JobHandle<()>,
    binding: FetchBinding,
    input: Arc<FetchInput>,
    request: LocalBusFrame,
    imported: bool,
    ack_required: bool,
    slot_committed: bool,
    outcome: Option<Result<ActorResponse, SdkError>>,
}
pub(in crate::bus) enum FetchCheckpoint {
    Chunk {
        generation: u64,
        fence: Arc<FetchFence>,
        input: Arc<FetchInput>,
        chunk: Box<FetchChunk>,
        ack: oneshot::Sender<Result<(), SdkError>>,
    },
    Import {
        job_id: u64,
        generation: u64,
        cipher: Box<FetchCipher>,
        ack: oneshot::Sender<Result<(), SdkError>>,
    },
    Authorize {
        job_id: u64,
        generation: u64,
        ack: oneshot::Sender<Result<bool, SdkError>>,
    },
    Ack {
        generation: u64,
        fence: Arc<FetchFence>,
        index: u32,
        ack: oneshot::Sender<Result<(), SdkError>>,
    },
    Slot {
        job_id: u64,
        generation: u64,
        ack: oneshot::Sender<Result<(), SdkError>>,
    },
    Complete {
        job_id: u64,
        generation: u64,
        error: Option<SdkError>,
        ack: oneshot::Sender<Result<(), SdkError>>,
    },
    Release {
        job_id: u64,
        generation: u64,
        reply: Option<Reply>,
    },
}
struct FetchJob {
    id: u64,
    generation: u64,
    fence: Arc<FetchFence>,
    input: Arc<FetchInput>,
    connection: ConnectionHandle,
    metadata: SessionMetadata,
    pool: Arc<ramflux_transport::RelayQuicPool>,
    deadline: Instant,
    checkpoints: mpsc::Sender<Checkpoint>,
}
struct PreparedJob {
    context: FetchJob,
    record: FetchRecord,
    permit: TransferPermit,
}
struct FetchRecord {
    binding: FetchBinding,
    input: Arc<FetchInput>,
    request: LocalBusFrame,
}
enum Dispatch {
    Complete(serde_json::Value),
    Queued(Box<PreparedJob>),
}

impl AccountRuntime {
    pub(super) fn reap_fetch_jobs(&mut self) {
        let finished = self
            .transfers
            .fetches
            .iter()
            .filter(|(_, fetch)| fetch.handle.is_finished() && fetch.outcome.is_none())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in finished {
            if let Some(fetch) = self.transfers.fetches.remove(&id)
                && let Some(account) = self.state.accounts.get(&self.id)
                && let Err(error) = account.client.finish_received_attachment_job(
                    &fetch.binding,
                    Some(&SdkError::GatewaySessionNotEstablished),
                )
            {
                tracing::debug!(%error,"cancelled fetch reconciliation deferred");
            }
        }
    }

    pub(super) fn start_next_fetch(&mut self) -> Result<bool, SdkError> {
        let Some(account) = self.state.accounts.get(&self.id) else {
            return Ok(false);
        };
        if account.connection.as_ref().is_none_or(|connection| {
            connection.snapshot().state != super::super::connection_manager::NetworkingState::Live
        }) {
            return Ok(false);
        }
        let Some(id) = super::super::attachment_scheduler::next(account)? else {
            return Ok(false);
        };
        if self
            .transfers
            .fetches
            .values()
            .any(|fetch| fetch.binding.fence.selector == id && !fetch.handle.is_finished())
        {
            return Ok(false);
        }
        let operation = format!(
            "sync-fetch:{}",
            ramflux_crypto::blake3_256_base64url("ramflux.sync.attachment.v1", id.as_bytes())
        );
        let request = LocalBusFrame::request(
            "background-fetch",
            Some(self.id.clone()),
            "object",
            "object.fetch",
            serde_json::json!({"object_id":id,"operation_id":operation}),
        );
        self.submit_fetch(request, None, Instant::now() + self.timeouts.fetch);
        Ok(true)
    }
    pub(super) fn start_fetch(&mut self, command: AccountCommand, reply: Reply) {
        let deadline = command.admission.as_ref().map_or_else(
            || Instant::now() + self.timeouts.command,
            |admission| admission.command_deadline,
        );
        self.submit_fetch(command.request, Some(reply), deadline);
    }
    fn submit_fetch(&mut self, request: LocalBusFrame, reply: Option<Reply>, deadline: Instant) {
        match self.prepare_fetch(request, deadline, reply.is_none()) {
            Err(error) => {
                if let Some(reply) = reply {
                    let _ = reply.send(Err(error));
                } else {
                    tracing::debug!(%error,"attachment prefetch deferred");
                }
            }
            Ok(Dispatch::Complete(body)) => {
                if let Some(reply) = reply {
                    let _ = reply.send(Ok(ActorResponse { body, events: Vec::new(), nodes: None }));
                }
            }
            Ok(Dispatch::Queued(job)) => {
                let job = *job;
                let id = job.context.id;
                let generation = job.context.generation;
                let handle = self
                    .transfers
                    .slots
                    .submit(job.permit.bind(generation, run(job.context, reply)));
                #[cfg(test)]
                if let Some(hook) = self
                    .state
                    .accounts
                    .get(&self.id)
                    .and_then(|account| account.test_transfer_hook.as_ref())
                {
                    hook.observe_job(handle.finished_for_test());
                }
                self.transfers.fetches.insert(
                    id,
                    Fetch {
                        handle,
                        binding: job.record.binding,
                        input: job.record.input,
                        request: job.record.request,
                        imported: false,
                        ack_required: false,
                        slot_committed: false,
                        outcome: None,
                    },
                );
            }
        }
    }
    fn prepare_fetch(
        &mut self,
        request: LocalBusFrame,
        deadline: Instant,
        automatic: bool,
    ) -> Result<Dispatch, SdkError> {
        super::super::read_model::validate(&request)?;
        let _intent = super::super::mutation_intent::MutationIntent::new(&request)?;
        let body: crate::bus::protocol::LocalBusObjectFetchRequest =
            serde_json::from_value(request.body.clone())?;
        let account =
            self.state.accounts.get_mut(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?;
        if let Some(receipt) = account
            .client
            .lookup_received_attachment_operation(&body.object_id, &body.operation_id)?
        {
            return Ok(Dispatch::Complete(receipt));
        }
        if self.transfers.fetches.values().any(|fetch| {
            fetch.binding.fence.selector == body.object_id && !fetch.handle.is_finished()
        }) {
            return Err(super::super::command_admission::unavailable(
                "attachment fetch already in progress",
            ));
        }
        self.transfers.restart();
        let permit = self.transfers.slots.reserve()?;
        if automatic {
            super::super::attachment_scheduler::started(account, &body.object_id)?;
        }
        self.transfers.next = self
            .transfers
            .next
            .checked_add(1)
            .ok_or_else(|| SdkError::LocalBus("transfer job sequence exhausted".into()))?;
        let binding = match account
            .client
            .prepare_received_attachment_job(&body.object_id, &body.operation_id)?
        {
            FetchPreparation::Complete(receipt) => return Ok(Dispatch::Complete(receipt)),
            FetchPreparation::Ready(binding) => *binding,
        };
        let input = match account.client.prepare_fetch_input(&binding) {
            Ok(input) => {
                #[cfg(feature = "itest-local-mint")]
                let input = {
                    let mut input = input;
                    input.http_timeout = self.timeouts.relay_http;
                    input
                };
                Arc::new(input)
            }
            Err(error) => {
                return account
                    .client
                    .finish_received_attachment_job(&binding, Some(&error))
                    .map(Dispatch::Complete);
            }
        };
        let pool = account.relay_quic_pool()?;
        let connection = account.connection.clone().ok_or(SdkError::NetworkingPending)?;
        let metadata = connection.metadata().ok_or(SdkError::NetworkingPending)?;
        let generation = connection.generation();
        let id = self.transfers.next;
        let context = FetchJob {
            id,
            generation,
            fence: Arc::new(binding.fence.clone()),
            input: Arc::clone(&input),
            connection,
            metadata,
            pool,
            deadline,
            checkpoints: self.transfers.checkpoints.clone(),
        };
        Ok(Dispatch::Queued(Box::new(PreparedJob {
            context,
            record: FetchRecord { binding, input, request },
            permit,
        })))
    }

    pub(super) fn apply_fetch_checkpoint(&mut self, message: FetchCheckpoint) {
        match message {
            FetchCheckpoint::Chunk { generation, fence, input, chunk, ack } => {
                let result = self
                    .check_fetch_input(generation, &fence)
                    .and_then(|account| account.client.persist_fetch_chunk(&input, &chunk));
                let _ = ack.send(result);
            }
            FetchCheckpoint::Import { job_id, generation, cipher, ack } => {
                let result = self.import_fetch(job_id, generation, &cipher);
                let _ = ack.send(result);
            }
            FetchCheckpoint::Authorize { job_id, generation, ack } => {
                let result = self.authorize_fetch(job_id, generation);
                let _ = ack.send(result);
            }
            FetchCheckpoint::Ack { generation, fence, index, ack } => {
                let result = self.check_fetch_input(generation, &fence).and_then(|account| {
                    account.client.persist_received_attachment_ack(&fence.reference, index)
                });
                let _ = ack.send(result);
            }
            FetchCheckpoint::Slot { job_id, generation, ack } => {
                let result = self.commit_fetch_slot(job_id, generation);
                let _ = ack.send(result);
            }
            FetchCheckpoint::Complete { job_id, generation, error, ack } => {
                let result = self.finish_fetch(job_id, generation, error.as_ref());
                let _ = ack.send(result);
            }
            FetchCheckpoint::Release { job_id, generation, reply } => {
                let outcome = self
                    .transfers
                    .fetches
                    .remove(&job_id)
                    .and_then(|mut fetch| fetch.outcome.take())
                    .unwrap_or_else(|| Err(stopped()));
                if let Some(reply) = reply {
                    let current = self
                        .state
                        .accounts
                        .get(&self.id)
                        .and_then(|account| account.connection.as_ref())
                        .is_some_and(|connection| connection.generation() == generation);
                    let _ = reply.send(if current { outcome } else { Err(stopped()) });
                }
            }
        }
    }

    fn check_fetch_input(
        &self,
        generation: u64,
        fence: &FetchFence,
    ) -> Result<&crate::bus::state::LocalBusAccountState, SdkError> {
        let account = self.state.accounts.get(&self.id).ok_or_else(stopped)?;
        if account
            .connection
            .as_ref()
            .is_none_or(|connection| connection.generation() != generation)
        {
            return Err(stopped());
        }
        account.client.check_fetch_fence(fence)?;
        Ok(account)
    }
    fn valid_fetch(
        &self,
        id: u64,
        generation: u64,
    ) -> Result<(&crate::bus::state::LocalBusAccountState, &Fetch), SdkError> {
        let fetch = self.transfers.fetches.get(&id).ok_or_else(stopped)?;
        let account = self.check_fetch_input(generation, &fetch.binding.fence)?;
        if fetch.handle.generation() != generation {
            return Err(stopped());
        }
        Ok((account, fetch))
    }
    fn import_fetch(
        &mut self,
        id: u64,
        generation: u64,
        cipher: &FetchCipher,
    ) -> Result<(), SdkError> {
        self.valid_fetch(id, generation)?;
        let fetch = self.transfers.fetches.get(&id).ok_or_else(stopped)?;
        let account = self.state.accounts.get_mut(&self.id).ok_or_else(stopped)?;
        account.client.persist_fetch_cipher(&fetch.input, cipher)?;
        self.transfers.fetches.get_mut(&id).ok_or_else(stopped)?.imported = true;
        Ok(())
    }
    fn authorize_fetch(&mut self, id: u64, generation: u64) -> Result<bool, SdkError> {
        let (account, fetch) = self.valid_fetch(id, generation)?;
        if !fetch.imported {
            return Err(SdkError::InboundPending("attachment import is not durable".into()));
        }
        let required = account.client.authorize_fetch_ack(&fetch.input)?;
        self.transfers.fetches.get_mut(&id).ok_or_else(stopped)?.ack_required = required;
        Ok(required)
    }
    fn commit_fetch_slot(&mut self, id: u64, generation: u64) -> Result<(), SdkError> {
        let (account, fetch) = self.valid_fetch(id, generation)?;
        if !fetch.imported {
            return Err(SdkError::InboundPending("attachment import is not durable".into()));
        }
        if fetch.ack_required
            && account
                .client
                .confirmed_received_attachment_indexes(&fetch.binding.fence.reference)?
                .len()
                != usize::try_from(fetch.input.manifest.total_chunks).unwrap_or(usize::MAX)
        {
            return Err(SdkError::InboundPending("attachment ACKs are not durable".into()));
        }
        account.client.commit_prepared_attachment_slot(&fetch.binding)?;
        self.transfers.fetches.get_mut(&id).ok_or_else(stopped)?.slot_committed = true;
        Ok(())
    }
    fn finish_fetch(
        &mut self,
        id: u64,
        generation: u64,
        error: Option<&SdkError>,
    ) -> Result<(), SdkError> {
        let (account, fetch) = self.valid_fetch(id, generation)?;
        if error.is_none() && !fetch.slot_committed {
            return Err(SdkError::InboundPending("attachment slot is not durable".into()));
        }
        let body = account.client.account_db()?.write_transaction(|| {
            let body = account.client.finish_received_attachment_job(&fetch.binding, error)?;
            super::super::read_model::capture(account, &fetch.request, &body)?;
            Ok::<_, SdkError>(body)
        })?;
        self.transfers.fetches.get_mut(&id).ok_or_else(stopped)?.outcome =
            Some(Ok(ActorResponse { body, events: Vec::new(), nodes: None }));
        Ok(())
    }
}

async fn run(context: FetchJob, mut reply: Option<Reply>) -> Result<(), SdkError> {
    let FetchJob {
        id,
        generation,
        fence,
        input,
        connection,
        metadata,
        pool,
        deadline,
        checkpoints,
    } = context;
    let mut engine = SessionClient::new(connection, metadata, deadline);
    let network = run_network(
        &mut engine,
        FetchNetwork {
            id,
            generation,
            fence: &fence,
            input: &input,
            pool: &pool,
            checkpoints: &checkpoints,
        },
    );
    let disconnected = async {
        match reply.as_mut() {
            Some(reply) => reply.closed().await,
            None => std::future::pending().await,
        }
    };
    let result = tokio::select! {biased;()=disconnected=>return Err(stopped()),result=timeout_at(deadline,network)=>result.map_err(|_|SdkError::LocalBus("attachment fetch deadline exceeded".into())).and_then(std::convert::identity)};
    let (ack, response) = oneshot::channel();
    checkpoints
        .send(Checkpoint::Fetch(FetchCheckpoint::Complete {
            job_id: id,
            generation,
            error: result.err(),
            ack,
        }))
        .await
        .map_err(|_| stopped())?;
    if let Err(error) = response.await.map_err(|_| stopped()).and_then(std::convert::identity) {
        if let Some(reply) = reply {
            let _ = reply.send(Err(error));
        }
        return Ok(());
    }
    checkpoints
        .send(Checkpoint::Fetch(FetchCheckpoint::Release { job_id: id, generation, reply }))
        .await
        .map_err(|_| stopped())
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}

struct FetchNetwork<'a> {
    id: u64,
    generation: u64,
    fence: &'a Arc<FetchFence>,
    input: &'a Arc<FetchInput>,
    pool: &'a Arc<ramflux_transport::RelayQuicPool>,
    checkpoints: &'a mpsc::Sender<Checkpoint>,
}
async fn run_network(
    engine: &mut SessionClient,
    network: FetchNetwork<'_>,
) -> Result<(), SdkError> {
    let FetchNetwork { id, generation, fence, input, pool, checkpoints } = network;
    let cipher = crate::client::object::fetch_job::download(engine, pool, input, |chunk| {
        let checkpoints = checkpoints.clone();
        let fence = Arc::clone(fence);
        let input = Arc::clone(input);
        async move {
            let (ack, response) = oneshot::channel();
            checkpoints
                .send(Checkpoint::Fetch(FetchCheckpoint::Chunk {
                    generation,
                    fence,
                    input,
                    chunk: Box::new(chunk),
                    ack,
                }))
                .await
                .map_err(|_| stopped())?;
            response.await.map_err(|_| stopped())?
        }
    })
    .await?;
    let (ack, response) = oneshot::channel();
    checkpoints
        .send(Checkpoint::Fetch(FetchCheckpoint::Import {
            job_id: id,
            generation,
            cipher: Box::new(cipher),
            ack,
        }))
        .await
        .map_err(|_| stopped())?;
    response.await.map_err(|_| stopped())??;
    #[cfg(feature = "itest-rfd-fault")]
    crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::GranteeImport).await?;
    let (ack, response) = oneshot::channel();
    checkpoints
        .send(Checkpoint::Fetch(FetchCheckpoint::Authorize { job_id: id, generation, ack }))
        .await
        .map_err(|_| stopped())?;
    if response.await.map_err(|_| stopped())?? {
        for index in 0..input.manifest.total_chunks {
            if input.confirmed.contains(&index) {
                continue;
            }
            crate::client::object::fetch_job::acknowledge(engine, pool, input, index).await?;
            let (ack, response) = oneshot::channel();
            checkpoints
                .send(Checkpoint::Fetch(FetchCheckpoint::Ack {
                    generation,
                    fence: Arc::clone(fence),
                    index,
                    ack,
                }))
                .await
                .map_err(|_| stopped())?;
            response.await.map_err(|_| stopped())??;
        }
    }
    let (ack, response) = oneshot::channel();
    checkpoints
        .send(Checkpoint::Fetch(FetchCheckpoint::Slot { job_id: id, generation, ack }))
        .await
        .map_err(|_| stopped())?;
    response.await.map_err(|_| stopped())?
}
