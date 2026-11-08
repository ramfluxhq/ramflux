// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordered own-copy network work with local ratchet and unchanged-row checkpoints.

use super::{
    Target, Work, copy_id, finish_attempt, message_owner, pending_ordered, persist_work, state,
};
use crate::bus::connection_manager::{AccountWork, SessionContext};
use crate::client::{
    own_device_copy::{OwnCopyDraft, OwnDeviceMessage, OwnMessageInput},
    routed::{SendMaterial, SendMaterialRequest},
};
use crate::prelude::{LocalBusAccountState, gateway_direct_message_envelope, now_unix_timestamp};
use crate::{GatewayDirectMessage, GatewaySessionConfig, SdkDeviceManifestResponse, SdkError};
use ramflux_protocol::Envelope;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroize;

pub(crate) struct Plan {
    key: String,
    work: Work,
    fingerprint: serde_json::Value,
    config: GatewaySessionConfig,
    root: String,
    manifest: Option<SdkDeviceManifestResponse>,
}
pub(crate) struct DraftPlan {
    plan: Plan,
    draft: OwnCopyDraft,
    requests: Vec<SendMaterialRequest>,
}
pub(crate) struct SendPlan {
    plan: Plan,
    packet: OwnDeviceMessage,
    envelope: Envelope,
}
pub(crate) enum Prepared {
    Draft(Box<DraftPlan>),
    Send(Box<SendPlan>),
}
pub(crate) enum OwnCopyWork {
    Prepare {
        generation: u64,
        reply: oneshot::Sender<Result<Option<Plan>, SdkError>>,
    },
    Draft {
        generation: u64,
        plan: Box<Plan>,
        manifest: Box<Result<Option<SdkDeviceManifestResponse>, SdkError>>,
        reply: oneshot::Sender<Result<Option<Prepared>, SdkError>>,
    },
    Seal {
        generation: u64,
        draft: Box<DraftPlan>,
        materials: Result<Vec<SendMaterial>, SdkError>,
        reply: oneshot::Sender<Result<Option<SendPlan>, SdkError>>,
    },
    Complete {
        generation: u64,
        plan: Box<SendPlan>,
        outcome: Result<Vec<String>, SdkError>,
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
}
impl OwnCopyWork {
    pub(crate) fn generation(&self) -> u64 {
        match self {
            Self::Prepare { generation, .. }
            | Self::Draft { generation, .. }
            | Self::Seal { generation, .. }
            | Self::Complete { generation, .. } => *generation,
        }
    }
}
pub(crate) async fn run(context: SessionContext, writer: mpsc::Sender<AccountWork>) {
    let mut cancel = context.cancel.clone();
    loop {
        let result = tokio::select! {biased; _=cancel.changed()=>break, result=pass(&context,&writer)=>result};
        let failed = result.is_err();
        let active = match result {
            Ok(active) => active,
            Err(error) => {
                tracing::warn!(%error,"own-device message copy deferred");
                false
            }
        };
        let delay =
            if active { std::time::Duration::from_millis(10) } else { context.network_wait() };
        tokio::select! {biased; _=cancel.changed()=>break, ()=tokio::time::sleep(delay)=>{}, ()=context.courier_wake("own-device-copy"), if !failed=>{}}
    }
}
async fn pass(
    context: &SessionContext,
    writer: &mpsc::Sender<AccountWork>,
) -> Result<bool, SdkError> {
    let generation = context.generation;
    let (reply, response) = oneshot::channel();
    send(writer, OwnCopyWork::Prepare { generation, reply }).await?;
    let Some(plan) = response.await.map_err(|_| stopped())?? else { return Ok(false) };
    deliver_plan(context, writer, plan).await
}
async fn deliver_plan(
    context: &SessionContext,
    writer: &mpsc::Sender<AccountWork>,
    mut plan: Plan,
) -> Result<bool, SdkError> {
    let generation = context.generation;
    let manifest = if plan.work.packet.is_some() {
        Ok(None)
    } else if let Some(manifest) = plan.manifest.take() {
        Ok(Some(manifest))
    } else {
        let path = format!("/mvp1/device-manifest/{}", plan.root);
        let fetch = crate::prekey::sdk_gateway_get_json::<Option<SdkDeviceManifestResponse>>(
            &plan.config,
            &path,
        );
        tokio::time::timeout(context.network_wait(), fetch)
            .await
            .map_err(|_| stopped())?
            .and_then(|manifest| {
                manifest.ok_or_else(|| {
                    SdkError::InboundPending("own-device manifest unavailable".into())
                })
            })
            .map(Some)
    };
    // A retained packet needs no manifest refresh; the actor still rechecks its row.
    let (reply, response) = oneshot::channel();
    send(
        writer,
        OwnCopyWork::Draft {
            generation,
            plan: Box::new(plan),
            manifest: Box::new(manifest),
            reply,
        },
    )
    .await?;
    let Some(prepared) = response.await.map_err(|_| stopped())?? else { return Ok(true) };
    let plan = match prepared {
        Prepared::Send(plan) => *plan,
        Prepared::Draft(mut draft) => {
            let mut materials = Vec::new();
            let mut failure = None;
            for request in std::mem::take(&mut draft.requests) {
                match tokio::time::timeout(
                    context.network_wait(),
                    crate::bus::couriers::pair_material::fetch(
                        context,
                        &draft.plan.config,
                        request,
                        crate::bus::connection_manager::CallClass::Bulk,
                    ),
                )
                .await
                .unwrap_or_else(|_| Err(stopped()))
                {
                    Ok(material) => materials.push(material),
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
            let materials = failure.map_or(Ok(materials), Err);
            let (reply, response) = oneshot::channel();
            send(writer, OwnCopyWork::Seal { generation, draft, materials, reply }).await?;
            let Some(plan) = response.await.map_err(|_| stopped())?? else { return Ok(true) };
            plan
        }
    };
    let outcome = fanout(context, &plan).await;
    let (reply, response) = oneshot::channel();
    send(writer, OwnCopyWork::Complete { generation, plan: Box::new(plan), outcome, reply })
        .await?;
    response.await.map_err(|_| stopped())??;
    Ok(true)
}
async fn send(writer: &mpsc::Sender<AccountWork>, work: OwnCopyWork) -> Result<(), SdkError> {
    writer.send(AccountWork::OwnCopy(Box::new(work))).await.map_err(|_| stopped())
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}

pub(crate) fn apply(account: &LocalBusAccountState, work: OwnCopyWork) {
    match work {
        OwnCopyWork::Prepare { reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(prepare(account));
            }
        }
        OwnCopyWork::Draft { plan, manifest, reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(draft(account, *plan, *manifest));
            }
        }
        OwnCopyWork::Seal { draft, materials, reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(seal(account, *draft, materials));
            }
        }
        OwnCopyWork::Complete { plan, outcome, reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(complete(account, &plan, outcome));
            }
        }
    }
}
fn finish(
    account: &LocalBusAccountState,
    key: &str,
    work: &Work,
    status: &str,
) -> Result<(), SdkError> {
    let db = account.client.account_db()?;
    db.write_transaction(|| {
        db.remove_actor_state(key)?;
        state(&account.client, work, status, false)
    })
}
fn prepare(account: &LocalBusAccountState) -> Result<Option<Plan>, SdkError> {
    let now = now_unix_timestamp();
    for (key, mut work) in pending_ordered(&account.client, now)? {
        if (!work.local_manifest && message_owner(&work).is_some())
            || work.intent.expiry() <= now
            || (work.packet.is_none() && work.attempts >= 10)
            || copy_id(&account.client, &work.intent.id)? != work.intent.copy_id
        {
            finish(account, &key, &work, "failed")?;
            continue;
        }
        if work.held {
            continue;
        }
        if let Some(message) = message_owner(&work)
            && account.client.account_db()?.message_is_deleted(message)?
        {
            finish(account, &key, &work, "failed")?;
            continue;
        }
        if !work.targets.is_empty() {
            if work.targets.iter().all(Target::finished) {
                let status = if work.targets.iter().all(Target::acknowledged) {
                    "submitted"
                } else {
                    "failed"
                };
                finish(account, &key, &work, status)?;
                continue;
            }
            if work.next_at > now || !work.targets.iter().any(|target| target.due(now)) {
                continue;
            }
        }
        if work.next_at > now {
            continue;
        }
        if work.packet.is_none() {
            work.attempts += 1;
            work.next_at = now.saturating_add((1_i64 << work.attempts.min(6)).min(60));
        } else {
            work.next_at = now.saturating_add(2);
        }
        account.client.account_db()?.persist_actor_state(&key, &work)?;
        if work.packet.is_none()
            && work.local_manifest
            && !account.client.own_sent_has_siblings()?
        {
            finish(account, &key, &work, "not_needed")?;
            continue;
        }
        let manifest = if work.packet.is_none() && work.local_manifest {
            account.client.prepare_own_copy_manifest_refresh()?
        } else {
            None
        };
        return Ok(Some(Plan {
            fingerprint: serde_json::to_value(&work)?,
            work,
            key,
            root: account.client.surface_local_root_commitment()?,
            config: account.gateway_config.clone(),
            manifest,
        }));
    }
    Ok(None)
}
fn current(account: &LocalBusAccountState, plan: &Plan) -> Result<bool, SdkError> {
    let db = account.client.account_db()?;
    Ok(db.load_actor_state::<serde_json::Value>(&plan.key)?.as_ref() == Some(&plan.fingerprint)
        && !message_owner(&plan.work)
            .map(|id| db.message_is_deleted(id))
            .transpose()?
            .unwrap_or(false))
}
fn draft(
    account: &LocalBusAccountState,
    plan: Plan,
    manifest: Result<Option<SdkDeviceManifestResponse>, SdkError>,
) -> Result<Option<Prepared>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    if let Some(packet) = &plan.work.packet {
        let Ok(packet) = serde_json::from_value::<OwnDeviceMessage>(packet.clone()) else {
            finish(account, &plan.key, &plan.work, "failed")?;
            return Ok(None);
        };
        let mut plan = plan;
        let now = now_unix_timestamp();
        if plan.work.targets.is_empty() {
            plan.work.targets = packet
                .slots
                .iter()
                .map(|slot| Target::new(slot.recipient_device_id.clone(), plan.work.attempts, 0))
                .collect();
        }
        if plan.work.targets.iter().all(Target::finished) {
            let status = if plan.work.targets.iter().all(Target::acknowledged) {
                "submitted"
            } else {
                "failed"
            };
            finish(account, &plan.key, &plan.work, status)?;
            return Ok(None);
        }
        if !plan.work.targets.iter().any(|target| target.due(now)) {
            return Ok(None);
        }
        return envelope(account, plan, packet).map(|plan| Some(Prepared::Send(Box::new(plan))));
    }
    let manifest = account.client.accept_fetched_device_manifest(
        manifest?
            .ok_or_else(|| SdkError::InboundPending("own-device manifest unavailable".into()))?,
        &plan.root,
        "own_device_message",
    )?;
    let body = zeroize::Zeroizing::new(
        ramflux_protocol::decode_base64url(&plan.work.intent.body)
            .map_err(|_| SdkError::LocalBus("own-device intent encoding".into()))?,
    );
    let intent = &plan.work.intent;
    let prepared = account.client.prepare_own_copy_draft_until(
        &plan.config,
        OwnMessageInput {
            id: &intent.id,
            created_at: intent.created_at,
            conversation: &intent.conversation,
            group: intent.group.as_deref(),
            body: &body,
        },
        manifest,
        intent.expiry(),
    );
    let prepared = match prepared {
        Err(SdkError::InboundRejected(reason))
            if reason == crate::client::own_device_copy::TOO_LARGE =>
        {
            finish(account, &plan.key, &plan.work, "failed")?;
            return Ok(None);
        }
        result => result?,
    };
    let Some(draft) = prepared else {
        finish(account, &plan.key, &plan.work, "not_needed")?;
        return Ok(None);
    };
    let requests = account.client.own_copy_material_requests(&plan.config, &draft)?;
    Ok(Some(Prepared::Draft(Box::new(DraftPlan { plan, draft, requests }))))
}
fn seal(
    account: &LocalBusAccountState,
    draft: DraftPlan,
    materials: Result<Vec<SendMaterial>, SdkError>,
) -> Result<Option<SendPlan>, SdkError> {
    let DraftPlan { mut plan, draft, .. } = draft;
    if !current(account, &plan)? {
        return Ok(None);
    }
    let result = account.client.seal_own_copy_prepared(&plan.config, draft, materials?);
    let packet = match result {
        Err(SdkError::InboundRejected(reason))
            if reason == crate::client::own_device_copy::TOO_LARGE =>
        {
            finish(account, &plan.key, &plan.work, "failed")?;
            return Ok(None);
        }
        result => result?,
    };
    plan.work.context_delivery.clone_from(&packet.context_delivery);
    plan.work.targets = packet
        .slots
        .iter()
        .map(|slot| Target::new(slot.recipient_device_id.clone(), 0, now_unix_timestamp()))
        .collect();
    plan.work.packet = Some(serde_json::to_value(&packet)?);
    plan.work.intent.body.zeroize();
    if !persist_work(&account.client, &plan.key, &plan.work)? {
        finish(account, &plan.key, &plan.work, "failed")?;
        return Ok(None);
    }
    plan.fingerprint = serde_json::to_value(&plan.work)?;
    envelope(account, plan, packet).map(Some)
}
fn envelope(
    account: &LocalBusAccountState,
    mut plan: Plan,
    packet: OwnDeviceMessage,
) -> Result<SendPlan, SdkError> {
    let message = GatewayDirectMessage {
        conversation_id: packet.id.clone(),
        message_id: packet.id.clone(),
        envelope_id: crate::new_surface_message_id()?,
        source_principal_id: plan.config.principal_id.clone(),
        sender_id: plan.config.device_id.clone(),
        recipient_device_id: None,
        recipient_principal_commitment: None,
        target_delivery_id: plan.config.target_delivery_id.clone(),
        encrypted_body: packet.bytes()?,
        created_at: now_unix_timestamp(),
        ttl: account.client.content_ttl()?.min(
            u32::try_from(plan.work.intent.expiry().saturating_sub(now_unix_timestamp()).max(1))
                .map_err(|_| SdkError::LocalBus("own-copy TTL overflow".into()))?,
        ),
    };
    let mut envelope = gateway_direct_message_envelope(&plan.config, &message, None)?;
    envelope.delivery_class = ramflux_protocol::DeliveryClass::SelfDeviceControl;
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &envelope,
    )?;
    let now = now_unix_timestamp();
    for target in &mut plan.work.targets {
        target.charge(now);
    }
    if !persist_work(&account.client, &plan.key, &plan.work)? {
        return Err(SdkError::LocalBus("own-device retry capacity exceeded".into()));
    }
    plan.fingerprint = serde_json::to_value(&plan.work)?;
    Ok(SendPlan { plan, packet, envelope })
}
fn complete(
    account: &LocalBusAccountState,
    plan: &SendPlan,
    outcome: Result<Vec<String>, SdkError>,
) -> Result<(), SdkError> {
    if !current(account, &plan.plan)? {
        return Ok(());
    }
    let mut work = plan.plan.work.clone();
    finish_attempt(
        &account.client,
        &plan.plan.key,
        &mut work,
        outcome.as_ref().ok().map(Vec::as_slice),
        now_unix_timestamp(),
    )?;
    outcome.map(|_| ())
}

#[cfg(test)]
pub(crate) async fn drive_once(account: &mut LocalBusAccountState) -> Result<bool, SdkError> {
    let Some(plan) = prepare(account)? else {
        return Ok(false);
    };
    let client = account.session_client().await?;
    account.apply_session_metadata(client);
    let context =
        account.connection.as_ref().ok_or(SdkError::GatewaySessionNotEstablished)?.test_context();
    let (writer, mut work) = mpsc::channel(2);
    let pass = deliver_plan(&context, &writer, plan);
    tokio::pin!(pass);
    loop {
        tokio::select! {
            result=&mut pass=>return result,
            work=work.recv()=>{let Some(AccountWork::OwnCopy(work))=work else {return Err(stopped())};
                if work.generation()==context.generation {apply(account,*work)}
            }
        }
    }
}

async fn fanout(context: &SessionContext, plan: &SendPlan) -> Result<Vec<String>, SdkError> {
    let principal = plan.plan.config.principal_id.clone();
    let source = plan.plan.config.device_id.clone();
    let packet = plan.packet.clone();
    let envelope = plan.envelope.clone();
    context
        .call(
            move |engine| {
                Box::pin(async move {
                    let response = engine
                        .own_device_fanout(principal.clone(), source.clone(), envelope)
                        .await?;
                    if response.principal_id != principal || response.source_device_id != source {
                        return Err(SdkError::LocalBus(
                            "own-device fanout acknowledgement mismatch".into(),
                        ));
                    }
                    Ok(response
                        .delivered
                        .into_iter()
                        .filter(|delivery| {
                            packet
                                .slots
                                .iter()
                                .any(|slot| slot.recipient_device_id == delivery.device_id)
                                && matches!(delivery.outcome.as_str(), "online" | "offline_queued")
                        })
                        .map(|delivery| delivery.device_id)
                        .collect())
                })
            },
            context.call_deadline(),
        )
        .await
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn own_copy_prepare_does_not_double_charge_target_budget() -> Result<(), SdkError> {
        let root = crate::bus::runtime_tests::root("own-copy-single-charge");
        let account = crate::bus::runtime_tests::account(
            &root,
            "sender",
            None,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        super::super::stage(
            &account.client,
            OwnMessageInput {
                id: "copy",
                created_at: now_unix_timestamp(),
                conversation: "thread",
                group: None,
                body: b"body",
            },
            None,
        )?;
        let plan =
            prepare(&account)?.ok_or_else(|| SdkError::LocalBus("missing own-copy plan".into()))?;
        assert_eq!(plan.work.attempts, 1, "preparation has its own budget");
        let mut target = Target::new("sibling".into(), 0, 0);
        for attempt in 0..10 {
            assert!(!target.finished());
            target.charge(attempt * 60);
        }
        assert!(target.finished());
        assert_eq!(serde_json::to_value(&target)?["attempts"], 10);
        let key = plan.key;
        for attempts in 2..=10 {
            let mut work: Work =
                account.client.account_db()?.load_actor_state(&key)?.ok_or_else(stopped)?;
            work.next_at = 0;
            account.client.account_db()?.persist_actor_state(&key, &work)?;
            let plan = prepare(&account)?.ok_or_else(stopped)?;
            assert_eq!(plan.work.attempts, attempts);
            assert!(
                plan.work.next_at
                    >= now_unix_timestamp().saturating_add((1_i64 << attempts.min(6)).min(60) - 1)
            );
        }
        assert!(prepare(&account)?.is_none());
        assert!(!account.client.account_db()?.actor_state_exists(&key)?);
        drop(account);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
