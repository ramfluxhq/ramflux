// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact-control network steps with conditional actor-owned consent and pair commits.

use super::{
    Decision, ENVELOPE_SCHEMA, Intent, TTL, conversation, invalid, key, material_hash, queue,
};
use crate::bus::connection_manager::{AccountWork, SessionContext};
use crate::client::contact_requests::{
    Metadata,
    native_delivery::{self, ApprovalPlan, Approved},
};
use crate::client::routed::{SendMaterial, SendMaterialRequest};
use crate::gateway::session_push::SubmitRefusal;
use crate::prelude::*;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct Plan {
    intent: Intent,
    fingerprint: serde_json::Value,
    own_root: String,
    config: GatewaySessionConfig,
}
pub(crate) struct BodyPlan {
    plan: Plan,
    own: crate::SdkDeviceManifestResponse,
    devices: Vec<crate::prekey::SdkDeviceManifestEntry>,
    approval: Option<ApprovalPlan>,
    body: Zeroizing<Vec<u8>>,
}
#[derive(Clone)]
pub(crate) struct RecipientPlan {
    plan: Plan,
    message: GatewayDirectMessage,
    body: Zeroizing<Vec<u8>>,
    material_hash: String,
}
pub(crate) enum ContactWork {
    Prepare {
        generation: u64,
        reply: oneshot::Sender<Result<Option<Plan>, SdkError>>,
    },
    Body {
        generation: u64,
        plan: Box<Plan>,
        manifests: Box<(crate::SdkDeviceManifestResponse, crate::SdkDeviceManifestResponse)>,
        reply: oneshot::Sender<Result<Option<BodyPlan>, SdkError>>,
    },
    Approved {
        generation: u64,
        plan: Box<BodyPlan>,
        approved: Box<Approved>,
        reply: oneshot::Sender<Result<Option<BodyPlan>, SdkError>>,
    },
    Recipient {
        generation: u64,
        plan: Box<Plan>,
        device: Box<crate::prekey::SdkDeviceManifestEntry>,
        body: Zeroizing<Vec<u8>>,
        reply: oneshot::Sender<Result<Option<(RecipientPlan, SendMaterialRequest)>, SdkError>>,
    },
    Seal {
        generation: u64,
        plan: Box<RecipientPlan>,
        material: Box<SendMaterial>,
        reply: oneshot::Sender<Result<Option<ramflux_protocol::Envelope>, SdkError>>,
    },
    Complete {
        generation: u64,
        plan: Box<RecipientPlan>,
        reply: oneshot::Sender<Result<Option<Plan>, SdkError>>,
    },
    Finish {
        generation: u64,
        plan: Box<Plan>,
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
    Refused {
        generation: u64,
        plan: Box<Plan>,
        refusal: SubmitRefusal,
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
}
impl ContactWork {
    pub(crate) fn generation(&self) -> u64 {
        match self {
            Self::Prepare { generation, .. }
            | Self::Body { generation, .. }
            | Self::Approved { generation, .. }
            | Self::Recipient { generation, .. }
            | Self::Seal { generation, .. }
            | Self::Complete { generation, .. }
            | Self::Finish { generation, .. }
            | Self::Refused { generation, .. } => *generation,
        }
    }
}
pub(crate) async fn run(context: SessionContext, writer: mpsc::Sender<AccountWork>) {
    let mut cancel = context.cancel.clone();
    loop {
        let result =
            tokio::select! {biased;_=cancel.changed()=>break,result=pass(&context,&writer)=>result};
        let failed = result.is_err();
        let active = match result {
            Ok(active) => active,
            Err(error) => {
                tracing::debug!(%error,"contact control delivery deferred");
                false
            }
        };
        let delay = if active { Duration::from_millis(10) } else { context.network_wait() };
        tokio::select! {biased;_=cancel.changed()=>break,()=tokio::time::sleep(delay)=>{},()=context.courier_wake("contact-control"),if !failed=>{}}
    }
}
async fn send(writer: &mpsc::Sender<AccountWork>, work: ContactWork) -> Result<(), SdkError> {
    writer.send(AccountWork::Contacts(Box::new(work))).await.map_err(|_| stopped())
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}
async fn pass(
    context: &SessionContext,
    writer: &mpsc::Sender<AccountWork>,
) -> Result<bool, SdkError> {
    let generation = context.generation;
    let (reply, response) = oneshot::channel();
    send(writer, ContactWork::Prepare { generation, reply }).await?;
    let Some(plan) = response.await.map_err(|_| stopped())?? else { return Ok(false) };
    let fetch = async {
        let own =
            crate::client::contact::fetch_verified_device_manifest(&plan.config, &plan.own_root)
                .await?;
        let peer = crate::client::contact::fetch_verified_device_manifest(
            &plan.config,
            &plan.intent.peer_root,
        )
        .await?;
        Ok::<_, SdkError>((own, peer))
    };
    let manifests =
        tokio::time::timeout(context.network_wait(), fetch).await.map_err(|_| stopped())??;
    let (reply, response) = oneshot::channel();
    send(
        writer,
        ContactWork::Body {
            generation,
            plan: Box::new(plan),
            manifests: Box::new(manifests),
            reply,
        },
    )
    .await?;
    let Some(mut body) = response.await.map_err(|_| stopped())?? else { return Ok(true) };
    if let Some(approval) = body.approval.take() {
        let approved = tokio::time::timeout(context.network_wait(), approval.execute())
            .await
            .map_err(|_| stopped())??;
        let (reply, response) = oneshot::channel();
        send(
            writer,
            ContactWork::Approved {
                generation,
                plan: Box::new(body),
                approved: Box::new(approved),
                reply,
            },
        )
        .await?;
        let Some(result) = response.await.map_err(|_| stopped())?? else { return Ok(true) };
        body = result;
    }
    let mut complete = !body.devices.is_empty();
    for device in std::mem::take(&mut body.devices) {
        let (reply, response) = oneshot::channel();
        send(
            writer,
            ContactWork::Recipient {
                generation,
                plan: Box::new(body.plan.clone()),
                device: Box::new(device),
                body: body.body.clone(),
                reply,
            },
        )
        .await?;
        let Some((recipient, request)) = response.await.map_err(|_| stopped())?? else { continue };
        let result = deliver(context, writer, &recipient, request).await;
        match result {
            Ok(Some(plan)) => body.plan = plan,
            Ok(None) => return Ok(true),
            Err(error) => {
                complete = false;
                tracing::debug!(%error,"contact control recipient deferred");
            }
        }
    }
    if complete {
        let (reply, response) = oneshot::channel();
        send(writer, ContactWork::Finish { generation, plan: Box::new(body.plan), reply }).await?;
        response.await.map_err(|_| stopped())??;
    }
    Ok(true)
}
async fn deliver(
    context: &SessionContext,
    writer: &mpsc::Sender<AccountWork>,
    plan: &RecipientPlan,
    request: SendMaterialRequest,
) -> Result<Option<Plan>, SdkError> {
    let material = tokio::time::timeout(
        context.network_wait(),
        crate::bus::couriers::pair_material::fetch(
            context,
            &plan.plan.config,
            request,
            crate::bus::connection_manager::CallClass::Bulk,
        ),
    )
    .await
    .map_err(|_| stopped())??;
    let generation = context.generation;
    let (reply, response) = oneshot::channel();
    send(
        writer,
        ContactWork::Seal {
            generation,
            plan: Box::new(plan.clone()),
            material: Box::new(material),
            reply,
        },
    )
    .await?;
    let Some(envelope) = response.await.map_err(|_| stopped())?? else { return Ok(None) };
    match submit(context, envelope).await? {
        Ok(()) => {}
        Err(refusal) => {
            let (reply, response) = oneshot::channel();
            send(
                writer,
                ContactWork::Refused {
                    generation,
                    plan: Box::new(plan.plan.clone()),
                    refusal,
                    reply,
                },
            )
            .await?;
            response.await.map_err(|_| stopped())??;
            // A conflict ends this intent's delivery; any other refusal is an ordinary deferral.
            return if refusal == SubmitRefusal::Conflict {
                Ok(None)
            } else {
                Err(SdkError::GatewaySessionRejected(refusal.reason().to_owned()))
            };
        }
    }
    let (reply, response) = oneshot::channel();
    send(writer, ContactWork::Complete { generation, plan: Box::new(plan.clone()), reply }).await?;
    response.await.map_err(|_| stopped())?
}
/// One classified submit: a certain gateway refusal is the inner `Err`; every uncertain failure
/// is the outer `Err`.
async fn submit(
    context: &SessionContext,
    envelope: ramflux_protocol::Envelope,
) -> Result<Result<(), SubmitRefusal>, SdkError> {
    context
        .call(
            move |engine| {
                Box::pin(async move {
                    engine.submit_envelope_classified(envelope).await.map(|sent| sent.map(|_| ()))
                })
            },
            context.call_deadline(),
        )
        .await
}
/// The actor step for a certain refusal. A conflict takes the existing exhaustion branch
/// (`attempts = 8`: never picked again, a request reads `failed`, a response is dropped by the
/// queue); a capacity refusal raises the next attempt to the gateway's floor.
fn refused(
    account: &LocalBusAccountState,
    plan: &Plan,
    refusal: SubmitRefusal,
) -> Result<(), SdkError> {
    if !current(account, plan)? {
        return Ok(());
    }
    let mut intent = plan.intent.clone();
    match refusal {
        SubmitRefusal::Conflict => {
            tracing::warn!(reason = "submit_conflict", "contact control delivery retired");
            intent.attempts = 8;
        }
        SubmitRefusal::CapacityRetryAfter { retry_after_ms } => {
            let floor = i64::try_from(retry_after_ms.div_ceil(1000)).unwrap_or(i64::MAX);
            intent.next_at = intent.next_at.max(now_unix_timestamp().saturating_add(floor));
        }
        SubmitRefusal::RetrySafe => return Ok(()),
    }
    account.client.account_db()?.persist_actor_state(&key(&intent), &intent)?;
    Ok(())
}
pub(crate) fn apply(account: &LocalBusAccountState, work: ContactWork) {
    match work {
        ContactWork::Prepare { reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(prepare(account));
            }
        }
        ContactWork::Body { plan, manifests, reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(body(account, *plan, *manifests));
            }
        }
        ContactWork::Approved { plan, approved, reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(approved_body(account, *plan, *approved));
            }
        }
        ContactWork::Recipient { plan, device, body, reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(recipient(account, *plan, *device, body));
            }
        }
        ContactWork::Seal { plan, material, reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(seal(account, &plan, *material));
            }
        }
        ContactWork::Complete { plan, reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(complete(account, *plan));
            }
        }
        ContactWork::Refused { plan, refusal, reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(refused(account, &plan, refusal));
            }
        }
        ContactWork::Finish { plan, reply, .. } => {
            if !reply.is_closed() {
                let result = current(account, &plan).and_then(|current| {
                    if current {
                        account.client.account_db()?.remove_actor_state(&key(&plan.intent))?;
                    }
                    Ok(())
                });
                let _ = reply.send(result);
            }
        }
    }
}
fn prepare(account: &LocalBusAccountState) -> Result<Option<Plan>, SdkError> {
    let client = &account.client;
    client.maintain_contact_requests()?;
    let db = client.account_db()?;
    for request in db.deferred_contact_replies(now_unix_timestamp())? {
        if let Some(kind) = Metadata::read(&request)?.needs_reply {
            client.stage_contact_response(&request, kind)?;
        }
    }
    db.expire_contact_requests(now_unix_timestamp())?;
    for mut intent in queue(client)? {
        let now = now_unix_timestamp();
        if intent.attempts >= 8 || intent.next_at > now {
            continue;
        }
        intent.attempts += 1;
        intent.next_at = now.saturating_add((1_i64 << intent.attempts).min(60));
        db.persist_actor_state(&key(&intent), &intent)?;
        return Ok(Some(Plan {
            fingerprint: serde_json::to_value(&intent)?,
            intent,
            own_root: client.owned_device_identity()?.root_commitment().into(),
            config: account.gateway_config.clone(),
        }));
    }
    Ok(None)
}
fn current(account: &LocalBusAccountState, plan: &Plan) -> Result<bool, SdkError> {
    let db = account.client.account_db()?;
    if db.load_actor_state::<serde_json::Value>(&key(&plan.intent))?.as_ref()
        != Some(&plan.fingerprint)
        || plan.intent.expires_at <= now_unix_timestamp()
    {
        return Ok(false);
    }
    let direction = if plan.intent.kind == Decision::Request { "outbound" } else { "inbound" };
    let expected = match plan.intent.kind {
        Decision::Request => "pending",
        Decision::Accept => "accepted",
        Decision::Decline => "declined",
    };
    Ok(db
        .contact_request(&plan.intent.peer_root, direction)?
        .is_some_and(|row| row.request_id == plan.intent.request_id && row.state == expected))
}
fn body(
    account: &LocalBusAccountState,
    plan: Plan,
    manifests: (crate::SdkDeviceManifestResponse, crate::SdkDeviceManifestResponse),
) -> Result<Option<BodyPlan>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    let (own, peer) = manifests;
    if own.principal_commitment != plan.own_root
        || peer.principal_commitment != plan.intent.peer_root
    {
        return Err(invalid("contact manifest scope mismatch"));
    }
    account.client.persist_fetched_identity_directory(&own)?;
    account.client.persist_fetched_identity_directory(&peer)?;
    if peer.devices.len() > 64 {
        return Err(invalid("contact request device fanout exceeds budget"));
    }
    let (approval, body) = if own.custody.is_some() {
        (
            Some(native_delivery::prepare_approval(
                &account.client,
                &plan.config,
                &plan.intent,
                &own,
            )?),
            Zeroizing::new(Vec::new()),
        )
    } else {
        let intent = &plan.intent;
        let control = super::super::wire::sign(
            account.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            super::super::wire::Body {
                schema: super::super::wire::DOMAIN.into(),
                kind: intent.kind,
                request_id: intent.request_id.clone(),
                requester_root: intent.requester_root.clone(),
                target_root: intent.target_root.clone(),
                actor_root: plan.own_root.clone(),
                issued_at: intent.issued_at,
                expires_at: intent.expires_at,
                nonce: intent.nonce.clone(),
                note: intent.note.clone(),
                manifest: own.clone(),
            },
        )?;
        (None, Zeroizing::new(serde_json::to_vec(&control)?))
    };
    Ok(Some(BodyPlan { plan, own, devices: peer.devices, approval, body }))
}
fn approved_body(
    account: &LocalBusAccountState,
    mut plan: BodyPlan,
    approved: Approved,
) -> Result<Option<BodyPlan>, SdkError> {
    if !current(account, &plan.plan)? {
        return Ok(None);
    }
    let mut candidate = plan.plan.intent.clone();
    candidate.native_approval = Some(approved.clone());
    // Revalidation must accept this exact signed consent against the current authority.
    if !matches!(
        native_delivery::prepare_approval(
            &account.client,
            &plan.plan.config,
            &candidate,
            &plan.own
        )?,
        ApprovalPlan::Ready(_)
    ) {
        return Err(invalid("native consent authority changed"));
    }
    plan.body = native_delivery::save_approval(&account.client, &mut plan.plan.intent, approved)?;
    plan.plan.fingerprint = serde_json::to_value(&plan.plan.intent)?;
    Ok(Some(plan))
}
fn recipient(
    account: &LocalBusAccountState,
    plan: Plan,
    device: crate::prekey::SdkDeviceManifestEntry,
    body: Zeroizing<Vec<u8>>,
) -> Result<Option<(RecipientPlan, SendMaterialRequest)>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    let identity =
        account.client.device_identity_for_root(&plan.intent.peer_root, &device.device_id)?;
    let material = material_hash(&account.client, &identity)?;
    if plan.intent.delivered.contains(&(plan.intent.peer_root.clone(), device.device_id.clone()))
        && (plan.intent.kind != Decision::Request
            || account.client.account_db()?.contact_request_delivered(
                &plan.intent.request_id,
                &identity,
                &material,
            )?)
    {
        return Ok(None);
    }
    let id =
        format!("contact_{}", ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?));
    let message = GatewayDirectMessage {
        conversation_id: conversation(&plan.intent.requester_root, &plan.intent.target_root)?,
        message_id: id.clone(),
        envelope_id: id,
        source_principal_id: plan.config.principal_id.clone(),
        sender_id: plan.config.device_id.clone(),
        recipient_device_id: Some(device.device_id),
        recipient_principal_commitment: Some(plan.intent.peer_root.clone()),
        target_delivery_id: device.target_delivery_id,
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: account.client.content_ttl()?.min(
            u32::try_from(
                plan.intent.expires_at.saturating_sub(now_unix_timestamp()).clamp(1, TTL),
            )
            .map_err(|_| invalid("contact carrier lifetime is invalid"))?,
        ),
    };
    let request = account.client.routed_send_material_request(&plan.config, &message)?;
    Ok(Some((RecipientPlan { plan, message, body, material_hash: material }, request)))
}
fn seal(
    account: &LocalBusAccountState,
    plan: &RecipientPlan,
    material: SendMaterial,
) -> Result<Option<ramflux_protocol::Envelope>, SdkError> {
    if !current(account, &plan.plan)? {
        return Ok(None);
    }
    let mut message = plan.message.clone();
    let mut sealed = account.client.seal_routed_prepared(
        &plan.plan.config,
        &message,
        &plan.body,
        crate::client::routed::Route::control(),
        material,
    )?;
    if plan.plan.intent.kind == Decision::Request {
        sealed.packet.schema = ENVELOPE_SCHEMA.into();
    }
    // Control carrier; no Direct report payload.
    crate::dm::gateway_envelope_from_sealed(&plan.plan.config, &mut message, sealed, None).map(Some)
}
fn complete(
    account: &LocalBusAccountState,
    mut plan: RecipientPlan,
) -> Result<Option<Plan>, SdkError> {
    if !current(account, &plan.plan)? {
        return Ok(None);
    }
    let device = plan
        .message
        .recipient_device_id
        .as_deref()
        .ok_or_else(|| invalid("contact recipient absent"))?;
    let identity = account.client.device_identity_for_root(&plan.plan.intent.peer_root, device)?;
    if material_hash(&account.client, &identity)? != plan.material_hash {
        return Err(invalid("contact recipient material changed"));
    }
    let db = account.client.account_db()?;
    db.write_transaction(|| -> Result<(), SdkError> {
        if plan.plan.intent.kind == Decision::Request {
            db.mark_contact_request_delivered(
                &plan.plan.intent.request_id,
                &identity,
                &plan.material_hash,
                now_unix_timestamp(),
            )?;
        }
        plan.plan.intent.delivered.insert((plan.plan.intent.peer_root.clone(), device.into()));
        db.persist_actor_state(&key(&plan.plan.intent), &plan.plan.intent)?;
        Ok(())
    })?;
    plan.plan.fingerprint = serde_json::to_value(&plan.plan.intent)?;
    Ok(Some(plan.plan))
}

#[cfg(test)]
mod refusal_tests;
#[cfg(test)]
pub(crate) use refusal_tests::cells as refusal_cells;
