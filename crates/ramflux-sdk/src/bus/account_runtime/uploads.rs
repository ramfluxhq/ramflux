// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deferred upload replies and writer-owned U1/U2/U3 checkpoints.

use super::AccountRuntime;
use crate::bus::{
    actor::{AccountCommand, ActorResponse},
    dispatch::object::{FinishSpool, PreparedPut, PutBinding},
    mutation_intent::MutationIntent,
    transfer_slots::{JobHandle, TransferSlots},
};
use crate::client::object::upload_job::{UploadInput, UploadProgress};
use crate::prelude::{
    LocalBusAccountState, LocalBusFrame, OBJECT_OPERATION_LOCAL_COMMITTED, OBJECT_TRANSFER_UPLOAD,
    SdkError, local_bus_account_mut, object_transfer_status,
};
use std::{collections::BTreeMap, sync::Arc};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, timeout_at},
};

type Reply = oneshot::Sender<Result<ActorResponse, SdkError>>;

pub(super) struct Transfers {
    pub(super) slots: TransferSlots,
    jobs: BTreeMap<u64, Upload>,
    pub(super) fetches: BTreeMap<u64, super::fetches::Fetch>,
    pub(super) next: u64,
    pub(super) checkpoints: mpsc::Sender<Checkpoint>,
    pub(super) receive: mpsc::Receiver<Checkpoint>,
    stopped: bool,
}
struct Upload {
    handle: JobHandle<()>,
    binding: Arc<PutBinding>,
    request: LocalBusFrame,
    outcome: Option<Result<ActorResponse, SdkError>>,
}

pub(super) enum Checkpoint {
    Fetch(super::fetches::FetchCheckpoint),
    Progress {
        job_id: u64,
        generation: u64,
        binding: Arc<PutBinding>,
        input: Arc<UploadInput>,
        progress: UploadProgress,
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
        reply: Reply,
    },
}

struct UploadRecord {
    binding: Arc<PutBinding>,
    request: LocalBusFrame,
}
enum UploadDispatch {
    Complete(serde_json::Value),
    Queued(Box<PreparedUpload>),
}
struct PreparedUpload {
    context: UploadJob,
    record: UploadRecord,
    permit: super::super::transfer_slots::TransferPermit,
}
struct UploadJob {
    job_id: u64,
    generation: u64,
    binding: Arc<PutBinding>,
    input: Option<Arc<UploadInput>>,
    connection: Option<super::super::connection_manager::ConnectionHandle>,
    metadata: Option<super::super::connection_manager::SessionMetadata>,
    pool: Option<Arc<ramflux_transport::RelayQuicPool>>,
    deadline: Instant,
    spool: FinishSpool,
    checkpoints: mpsc::Sender<Checkpoint>,
}

impl Transfers {
    pub(super) fn start() -> Self {
        let (checkpoints, receive) = mpsc::channel(super::super::runtime_limits::TRANSFER_SLOTS);
        Self {
            slots: TransferSlots::start(),
            jobs: BTreeMap::new(),
            fetches: BTreeMap::new(),
            next: 0,
            checkpoints,
            receive,
            stopped: false,
        }
    }
    pub(super) fn restart(&mut self) {
        if self.stopped {
            self.slots = TransferSlots::start();
            self.stopped = false;
        }
    }
    pub(super) async fn stop(&mut self) {
        for upload in self.jobs.values() {
            upload.handle.cancel();
        }
        for fetch in self.fetches.values() {
            fetch.handle.cancel();
        }
        self.slots.stop().await;
        for upload in self.jobs.values_mut() {
            if upload.handle.is_finished() {
                let _ = upload.handle.wait().await;
            }
        }
        for fetch in self.fetches.values_mut() {
            if fetch.handle.is_finished() {
                let _ = fetch.handle.wait().await;
            }
        }
        self.jobs.clear();
        self.fetches.clear();
        self.stopped = true;
    }
}

impl AccountRuntime {
    pub(super) fn reap_upload_jobs(&mut self) {
        let finished = self
            .transfers
            .jobs
            .iter()
            .filter(|(_, upload)| upload.handle.is_finished() && upload.outcome.is_none())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in finished {
            if let Some(upload) = self.transfers.jobs.remove(&id)
                && let Some(account) = self.state.accounts.get(&self.id)
            {
                let error = super::super::command_admission::unavailable(
                    "upload interrupted; retry object.put.finish",
                );
                if let Err(error) = super::super::dispatch::object::apply_put_job(
                    account,
                    &upload.binding,
                    None,
                    Some(&error),
                ) {
                    tracing::debug!(%error,"cancelled upload reconciliation deferred");
                }
            }
        }
    }

    pub(super) async fn start_upload(
        &mut self,
        command: AccountCommand,
        reply: Reply,
    ) -> Result<(), SdkError> {
        let prepared = self.prepare_upload(command).await;
        match prepared {
            Err(error) => {
                let _ = reply.send(Err(error));
            }
            Ok(UploadDispatch::Complete(body)) => {
                let _ = reply.send(Ok(ActorResponse { body, events: Vec::new(), nodes: None }));
            }
            Ok(UploadDispatch::Queued(prepared)) => {
                let PreparedUpload { context, record, permit } = *prepared;
                let job_id = context.job_id;
                let generation = context.generation;
                let handle = self
                    .transfers
                    .slots
                    .submit(permit.bind(generation, upload_job(context, reply)));
                self.transfers.jobs.insert(
                    job_id,
                    Upload {
                        handle,
                        binding: record.binding,
                        request: record.request,
                        outcome: None,
                    },
                );
            }
        }
        self.initialize_readers()?;
        if let Some(pool) = self.readers.lock().map_err(|_| super::stopped())?.as_ref() {
            pool.set_account_view(&self.state, &self.id)?;
        }
        Ok(())
    }

    async fn prepare_upload(
        &mut self,
        command: AccountCommand,
    ) -> Result<UploadDispatch, SdkError> {
        self.transfers.restart();
        let account = local_bus_account_mut(&mut self.state, &self.id)?;
        super::super::read_model::validate(&command.request)?;
        let intent = MutationIntent::new(&command.request)?;
        if let Some(body) = intent.lookup(account.client.account_db()?)? {
            return Ok(UploadDispatch::Complete(body));
        }
        if let Some(body) =
            super::super::dispatch::object::lookup_finish_receipt(account, &command.request)?
        {
            if let Some(key) = intent.key {
                if let Some(replayed) = intent.reserve(account.client.account_db()?)? {
                    return Ok(UploadDispatch::Complete(replayed));
                }
                account.client.account_db()?.complete_operation(key, &body)?;
            }
            super::super::dispatch::object::discard_finish_job_spool(account, &command.request);
            return Ok(UploadDispatch::Complete(body));
        }
        // Reserve before either generic Pending or the durable object Pending.
        let permit = match self.transfers.slots.reserve() {
            Ok(permit) => permit,
            Err(error) => {
                super::super::dispatch::object::discard_finish_job_spool(account, &command.request);
                return Err(error);
            }
        };
        if let Some(body) = intent.reserve(account.client.account_db()?)? {
            return Ok(UploadDispatch::Complete(body));
        }
        if let Some(key) = intent.key {
            account.client.account_db()?.bind_operation_objects(key, &command.request.body)?;
        }
        let (prepared, spool) =
            super::super::dispatch::object::prepare_finish_job(account, &command.request).await?;
        let binding = match prepared {
            PreparedPut::Complete(result) => {
                let body = result.response_body;
                if let Some(key) = intent.key {
                    account.client.account_db()?.complete_operation(key, &body)?;
                }
                return Ok(UploadDispatch::Complete(body));
            }
            PreparedPut::Ready(binding) => Arc::new(binding),
        };
        if binding.options.is_none() {
            let body = account.client.account_db()?.write_transaction(|| {
                let body =
                    super::super::dispatch::object::apply_put_job(account, &binding, None, None)?;
                super::super::read_model::capture(account, &command.request, &body)?;
                if let Some(key) = intent.key {
                    account.client.account_db()?.complete_operation(key, &body)?;
                }
                Ok::<_, SdkError>(body)
            })?;
            return Ok(UploadDispatch::Complete(body));
        }
        let UploadTransport { input, pool } =
            prepare_upload_transport(account, &binding, &self.timeouts)?;
        let connection = account.connection.clone();
        let generation = connection
            .as_ref()
            .map_or(0, super::super::connection_manager::ConnectionHandle::generation);
        let metadata = connection
            .as_ref()
            .and_then(super::super::connection_manager::ConnectionHandle::metadata);
        let deadline = command.admission.as_ref().map_or_else(
            || Instant::now() + self.timeouts.command,
            |admission| admission.command_deadline,
        );
        self.transfers.next = self
            .transfers
            .next
            .checked_add(1)
            .ok_or_else(|| SdkError::LocalBus("transfer job sequence exhausted".into()))?;
        let job_id = self.transfers.next;
        let context = UploadJob {
            job_id,
            generation,
            binding: Arc::clone(&binding),
            input: input.clone(),
            connection,
            metadata,
            pool,
            deadline,
            spool,
            checkpoints: self.transfers.checkpoints.clone(),
        };
        let record = UploadRecord { binding, request: command.request };
        Ok(UploadDispatch::Queued(Box::new(PreparedUpload { context, record, permit })))
    }

    pub(super) fn apply_transfer_checkpoint(&mut self, checkpoint: Checkpoint) {
        match checkpoint {
            Checkpoint::Fetch(checkpoint) => self.apply_fetch_checkpoint(checkpoint),
            Checkpoint::Progress { job_id, generation, binding, input, progress, ack } => {
                tracing::trace!(job_id, generation, "upload progress checkpoint");
                let result = self.upload_checkpoint(generation, &binding, &input, &progress);
                let _ = ack.send(result);
            }
            Checkpoint::Complete { job_id, generation, error, ack } => {
                let result = self.upload_complete(job_id, generation, error);
                let _ = ack.send(result);
            }
            Checkpoint::Release { job_id, generation, reply } => {
                let Some(mut upload) = self.transfers.jobs.remove(&job_id) else {
                    let _ = reply.send(Err(aborted()));
                    return;
                };
                if upload.handle.generation() != generation
                    || self
                        .state
                        .accounts
                        .get(&self.id)
                        .and_then(|account| account.connection.as_ref())
                        .is_none_or(|connection| connection.generation() != generation)
                {
                    let _ = reply.send(Err(aborted()));
                    return;
                }
                let result = upload.outcome.take().unwrap_or_else(|| Err(aborted()));
                let _ = reply.send(result);
            }
        }
    }

    fn upload_checkpoint(
        &self,
        generation: u64,
        binding: &PutBinding,
        input: &UploadInput,
        progress: &UploadProgress,
    ) -> Result<(), SdkError> {
        let account = self.state.accounts.get(&self.id).ok_or_else(aborted)?;
        if account
            .connection
            .as_ref()
            .is_none_or(|connection| connection.generation() != generation)
        {
            return Err(aborted());
        }
        account
            .client
            .account_db()?
            .check_object_identity(&binding.object.object_id, &binding.object.manifest_hash)?;
        let operation =
            account.client.object_operation(&binding.object.object_id)?.ok_or_else(aborted)?;
        if operation.operation_id != binding.operation_id
            || operation.request_hash != binding.request_hash
            || operation.state != OBJECT_OPERATION_LOCAL_COMMITTED
        {
            return Err(aborted());
        }
        account.client.persist_upload_progress(input, progress)?;
        Ok(())
    }

    fn upload_complete(
        &mut self,
        job_id: u64,
        generation: u64,
        error: Option<SdkError>,
    ) -> Result<(), SdkError> {
        let (account, upload) = self.valid_upload(job_id, generation)?;
        let db = account.client.account_db()?;
        let transfer = db
            .object_transfer(&upload.binding.object.object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .map(object_transfer_status);
        let result = db.write_transaction(|| {
            let body = super::super::dispatch::object::apply_put_job(
                account,
                &upload.binding,
                transfer.as_ref(),
                error.as_ref(),
            )?;
            if error.is_none() {
                super::super::read_model::capture(account, &upload.request, &body)?;
                if let Some(key) = MutationIntent::new(&upload.request)?.key {
                    db.complete_operation(key, &body)?;
                }
            }
            Ok::<_, SdkError>(body)
        });
        let body = result?;
        let outcome =
            error.map_or_else(|| Ok(ActorResponse { body, events: Vec::new(), nodes: None }), Err);
        self.transfers.jobs.get_mut(&job_id).ok_or_else(aborted)?.outcome = Some(outcome);
        Ok(())
    }

    fn valid_upload(
        &self,
        job_id: u64,
        generation: u64,
    ) -> Result<(&LocalBusAccountState, &Upload), SdkError> {
        let upload = self.transfers.jobs.get(&job_id).ok_or_else(aborted)?;
        let account = self.state.accounts.get(&self.id).ok_or_else(aborted)?;
        if upload.handle.generation() != generation
            || account
                .connection
                .as_ref()
                .is_none_or(|connection| connection.generation() != generation)
        {
            return Err(aborted());
        }
        account.client.account_db()?.check_object_identity(
            &upload.binding.object.object_id,
            &upload.binding.object.manifest_hash,
        )?;
        let operation = account
            .client
            .object_operation(&upload.binding.object.object_id)?
            .ok_or_else(aborted)?;
        if operation.operation_id != upload.binding.operation_id
            || operation.request_hash != upload.binding.request_hash
            || operation.state != OBJECT_OPERATION_LOCAL_COMMITTED
        {
            return Err(aborted());
        }
        Ok((account, upload))
    }
}

async fn upload_job(context: UploadJob, mut reply: Reply) -> Result<(), SdkError> {
    let UploadJob {
        job_id,
        generation,
        binding,
        input,
        connection,
        metadata,
        pool,
        deadline,
        spool,
        checkpoints,
    } = context;
    let _spool = spool;
    let network = async {
        #[cfg(feature = "itest-rfd-fault")]
        crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::PutAfterLocalCommitted)
            .await?;
        if let Some(input) = input {
            let connection = connection.ok_or(SdkError::NetworkingPending)?;
            let metadata = metadata.ok_or(SdkError::NetworkingPending)?;
            let mut engine = super::super::connection_manager::SessionClient::new(
                connection, metadata, deadline,
            );
            let pool = pool.ok_or_else(aborted)?;
            crate::client::object::upload_job::run(&mut engine, &pool, &input, |progress| {
                let checkpoints = checkpoints.clone();
                let binding = Arc::clone(&binding);
                let input = Arc::clone(&input);
                async move {
                    let (ack, response) = oneshot::channel();
                    checkpoints
                        .send(Checkpoint::Progress {
                            job_id,
                            generation,
                            binding,
                            input,
                            progress,
                            ack,
                        })
                        .await
                        .map_err(|_| aborted())?;
                    response.await.map_err(|_| aborted())?
                }
            })
            .await?;
        }
        #[cfg(feature = "itest-rfd-fault")]
        crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::PutBeforeCommitted).await?;
        Ok(())
    };
    let result = tokio::select! {biased;()=reply.closed()=>return Err(aborted()),result=timeout_at(deadline,network)=>result.map_err(|_|super::super::command_admission::unavailable("upload job deadline expired")).and_then(std::convert::identity)};
    let succeeded = result.is_ok();
    let (ack, response) = oneshot::channel();
    checkpoints
        .send(Checkpoint::Complete { job_id, generation, error: result.err(), ack })
        .await
        .map_err(|_| aborted())?;
    if let Err(error) = response.await.map_err(|_| aborted()).and_then(std::convert::identity) {
        let _ = reply.send(Err(error));
        return Ok(());
    }
    #[cfg(feature = "itest-rfd-fault")]
    if succeeded {
        crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::PutAfterCommitted).await?;
    }
    #[cfg(not(feature = "itest-rfd-fault"))]
    let _ = succeeded;
    checkpoints.send(Checkpoint::Release { job_id, generation, reply }).await.map_err(|_| aborted())
}
fn aborted() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}

struct UploadTransport {
    input: Option<Arc<UploadInput>>,
    pool: Option<Arc<ramflux_transport::RelayQuicPool>>,
}
fn prepare_upload_transport(
    account: &mut LocalBusAccountState,
    binding: &PutBinding,
    limits: &crate::bus::runtime_limits::RuntimeTimeouts,
) -> Result<UploadTransport, SdkError> {
    let network = (|| {
        let input = binding
            .options
            .as_ref()
            .map(|options| {
                account
                    .client
                    .prepare_upload_input(
                        Arc::clone(&binding.object),
                        binding.chunk_size,
                        options.clone(),
                    )
                    .map(|input| {
                        let _ = limits;
                        Arc::new(input)
                    })
            })
            .transpose()?;
        let pool = Some(account.relay_quic_pool()?);
        Ok::<_, SdkError>((input, pool))
    })();
    match network {
        Ok((input, pool)) => Ok(UploadTransport { input, pool }),
        Err(error) => {
            super::super::dispatch::object::apply_put_job(account, binding, None, Some(&error))?;
            Err(error)
        }
    }
}
