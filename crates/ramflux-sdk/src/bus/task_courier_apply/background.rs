// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded independent task sends after manifest preparation; every commit returns to the writer.

use super::{Failure, Item, JobRow, Preparation, charge, manifest_request_keys, queue, stop_class};
use crate::bus::dispatch::task_transport::prepared::Draft;
use crate::bus::{
    connection_manager::{AccountWork, SessionContext},
    couriers::{federation, writer::Writer},
    dispatch::{task_approval, task_approval_transport, task_transport},
};
use crate::prelude::*;
use serde_json::json;
use std::sync::{Arc, Mutex};

const QUEUED: usize = 8;
const RUNNING: usize = 4;
type Pending = Arc<Mutex<BTreeSet<String>>>;
struct Ticket {
    key: String,
    pending: Pending,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&self.key);
    }
}
pub(crate) struct Work {
    item: Item,
    preparation: Preparation,
    generation: u64,
    ticket: Ticket,
}
#[derive(Clone)]
pub(crate) struct Queue {
    sender: mpsc::Sender<Work>,
    pending: Pending,
}
impl Queue {
    pub(crate) fn new() -> (Self, mpsc::Receiver<Work>) {
        let (sender, receive) = mpsc::channel(QUEUED);
        (Self { sender, pending: Arc::default() }, receive)
    }
    pub(in crate::bus) fn enqueue(&self, item: Item, preparation: Preparation, generation: u64) {
        if !self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(item.key.clone())
        {
            return;
        }
        let ticket = Ticket { key: item.key.clone(), pending: Arc::clone(&self.pending) };
        let _ = self.sender.try_send(Work { item, preparation, generation, ticket });
    }
}
struct Plan {
    item: Item,
    routing: serde_json::Value,
    conversation: String,
    drafts: Vec<Draft>,
    config: GatewaySessionConfig,
    approval: bool,
}

pub(crate) async fn run(
    context: SessionContext,
    writer: mpsc::Sender<AccountWork>,
    queue: Arc<tokio::sync::Mutex<mpsc::Receiver<Work>>>,
) {
    let mut cancel = context.cancel.clone();
    let writer = Writer::new(writer, context.generation);
    let mut jobs = tokio::task::JoinSet::new();
    let mut tick = tokio::time::interval(context.network_wait());
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {biased;
            _=cancel.changed()=>break,
            _=tick.tick()=>{let _=writer.apply(|account|{account.signal_task_courier();Ok(())}).await;},
            result=jobs.join_next(),if !jobs.is_empty()=>{if let Some(Err(error))=result {tracing::warn!(%error,"task delivery worker stopped");}},
            work=async {queue.lock().await.recv().await},if jobs.len()<RUNNING=>{
                let Some(work)=work else{break};let context=context.clone();let writer=writer.clone();
                jobs.spawn(async move {
                    let again=if work.generation==context.generation {
                        match pass(&context,&writer,work.item,work.preparation).await {
                            Ok(again)=>again,
                            Err(error)=>{tracing::warn!(%error,"task delivery deferred");if stop_class(&error){writer.fatal(error).await;}false},
                        }
                    }else{false};
                    drop(work.ticket);
                    if again {let _=writer.apply(|account|{account.signal_task_courier();Ok(())}).await;}
                });
            }
        }
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
}
async fn pass(
    context: &SessionContext,
    writer: &Writer,
    item: Item,
    preparation: Preparation,
) -> Result<bool, SdkError> {
    let failure_item = item.clone();
    let plan = match writer.apply(move |account| prepare(account, item, preparation)).await {
        Ok(Some(plan)) => plan,
        Ok(None) => return Ok(false),
        Err(error) if stop_class(&error) => return Err(error),
        Err(_) => {
            return writer
                .apply(move |account| charge(account, &failure_item, Failure::Application))
                .await
                .map(|()| false);
        }
    };
    let result = send(context, writer, plan).await;
    match result {
        Ok(()) => Ok(true),
        Err(error) if stop_class(&error) => Err(error),
        Err(_) => writer
            .apply(move |account| charge(account, &failure_item, Failure::Application))
            .await
            .map(|()| false),
    }
}
fn valid(
    account: &LocalBusAccountState,
    item: &Item,
    conversation: &str,
    routing: &serde_json::Value,
) -> Result<bool, SdkError> {
    let Some(live) = queue::item(account, &item.key, now_unix_timestamp())? else {
        return Ok(false);
    };
    Ok(live.revision == item.revision
        && manifest_request_keys(&live.requests) == manifest_request_keys(&item.requests)
        && routing_fingerprint(account, conversation)? == *routing)
}
fn routing_fingerprint(
    account: &LocalBusAccountState,
    conversation: &str,
) -> Result<serde_json::Value, SdkError> {
    let db = account.client.account_db()?;
    let thread = db.client_record("conversation", conversation)?;
    let group = thread.as_ref().and_then(|row| row["group_id"].as_str());
    let state = group.map(|group| account.client.group_state(group)).transpose()?;
    let shared = group.map(|group| db.shared_group_state(group)).transpose()?.flatten();
    Ok(json!({"thread":thread,"group":state,"shared":shared.map(|state|state.snapshot().clone())}))
}
fn prepare(
    account: &mut LocalBusAccountState,
    item: Item,
    preparation: Preparation,
) -> Result<Option<Plan>, SdkError> {
    let Some(live) = queue::item(account, &item.key, now_unix_timestamp())? else {
        return Ok(None);
    };
    if live.revision != item.revision
        || manifest_request_keys(&live.requests) != manifest_request_keys(&item.requests)
    {
        account.signal_task_courier();
        return Ok(None);
    }
    let (manifests, fetched_after) = match preparation {
        Preparation::Deferred => return Ok(None),
        Preparation::Charged(reason) => {
            charge(account, &item, reason)?;
            return Ok(None);
        }
        Preparation::Ready { manifests, fetched_after } => (manifests, fetched_after),
    };
    account.task_prepared_only = true;
    let result = (|| {
        for manifest in manifests {
            account.client.persist_fetched_identity_directory_at(&manifest, fetched_after)?;
            account.task_prepared_manifests.insert(manifest.principal_commitment.clone(), manifest);
        }
        let Some((job, _)) = queue::load(account, &item.key)? else { return Ok(None) };
        let (conversation, drafts, approval) = match job {
            JobRow::Approval(job) => {
                let conversation = job.packet.request().binding.conversation_id.clone();
                let drafts = task_approval_transport::prepared_drafts(
                    account,
                    &conversation,
                    job.packet.recipient(),
                    &job.packet.bytes()?,
                )?;
                (conversation, drafts, true)
            }
            JobRow::Ack(job) => {
                let carrier = job.ack.original()?;
                let thread = account
                    .client
                    .account_db()?
                    .client_record("conversation", &carrier.conversation_id)?
                    .ok_or_else(|| SdkError::InboundRejected("task conversation missing".into()))?;
                let drafts = task_transport::prepared::controls(
                    account,
                    &carrier,
                    &thread,
                    task_transport::Mode::Ack(&job.ack),
                )?;
                (carrier.conversation_id, drafts, false)
            }
            JobRow::Forward(job) => {
                let history = account.client.task_history(&job.conversation_id, &job.task_id)?;
                let Some(last) = history.events.last() else {
                    account.client.account_db()?.delete_task_state(&item.key)?;
                    return Ok(None);
                };
                let thread = account
                    .client
                    .account_db()?
                    .client_record("conversation", &job.conversation_id)?
                    .ok_or_else(|| SdkError::InboundRejected("task conversation missing".into()))?;
                let drafts = task_transport::prepared::controls(
                    account,
                    &last.carrier,
                    &thread,
                    task_transport::Mode::Own,
                )?;
                (job.conversation_id, drafts, false)
            }
        };
        Ok(Some(Plan {
            routing: routing_fingerprint(account, &conversation)?,
            conversation,
            item,
            config: account.gateway_config.clone(),
            drafts,
            approval,
        }))
    })();
    account.task_prepared_manifests.clear();
    account.task_prepared_only = false;
    result
}
async fn send(context: &SessionContext, writer: &Writer, mut plan: Plan) -> Result<(), SdkError> {
    let preparation_deadline = tokio::time::Instant::now() + context.network_wait();
    let material = async {
        let mut sealed = Vec::new();
        for mut draft in std::mem::take(&mut plan.drafts) {
            let request = std::mem::replace(
                &mut draft.request,
                crate::client::routed::SendMaterialRequest { root: None, prekey: None },
            );
            let route = draft.target.federation.clone();
            let material =
                federation::material(context, &plan.config, request, route.as_ref()).await?;
            let item = plan.item.clone();
            let conversation = plan.conversation.clone();
            let routing = plan.routing.clone();
            let envelope = writer
                .apply(move |account| {
                    if !valid(account, &item, &conversation, &routing)? {
                        return Ok(None);
                    }
                    draft.seal(account, material).map(Some)
                })
                .await?;
            let Some(envelope) = envelope else { return Ok::<_, SdkError>(None) };
            sealed.push((envelope, route));
        }
        Ok(Some(sealed))
    };
    let Some(sealed) = tokio::time::timeout_at(preparation_deadline, material)
        .await
        .map_err(|_| SdkError::InboundPending("task courier preparation deferred".into()))??
    else {
        return Ok(());
    };
    let deadline = context.task_deadline(plan.approval);
    for (envelope, route) in sealed {
        federation::submit_until(context, envelope, route, deadline, false).await?;
    }
    writer.apply(move |account| complete(account, &plan)).await
}
fn complete(account: &LocalBusAccountState, plan: &Plan) -> Result<(), SdkError> {
    if !valid(account, &plan.item, &plan.conversation, &plan.routing)? {
        return Ok(());
    }
    let Some((mut job, _)) = queue::load(account, &plan.item.key)? else { return Ok(()) };
    let now = now_unix_timestamp();
    let db = account.client.account_db()?;
    match &mut job {
        JobRow::Approval(job) => {
            task_approval::record_delivery(account, &plan.item.key, job, true, now)
        }
        JobRow::Ack(job) => {
            let hash = crate::client::task::certificate::carrier_hash(&job.ack.original()?)?;
            db.write_transaction(|| {
                db.persist_actor_state(
                    &crate::client::task::key("ack_sent", &hash),
                    &json!({"start":now}),
                )?;
                db.prune_task_diagnostics("task/ack_sent/", 1024)?;
                db.delete_task_state(&plan.item.key)?;
                Ok::<_, SdkError>(())
            })
        }
        JobRow::Forward(_) => {
            db.delete_task_state(&plan.item.key)?;
            Ok(())
        }
    }
}
