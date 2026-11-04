// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receipt outbox reads, network-only steps, and unchanged-row actor checkpoints.

use super::{
    ATTEMPTS, Duration, GATEWAY_RETRY_AT, GatewayDirectMessage, GatewaySessionConfig, LIFETIME,
    LocalBusAccountState, PREFIX, SCAN, SCAN_CURSOR, SdkError, Work, discard, finish,
    gateway_direct_message_envelope, mpsc, now_unix_timestamp, postpone, receipt_message,
};
use crate::bus::connection_manager::{AccountWork, SessionContext};
use crate::client::routed::{SendMaterial, SendMaterialRequest};
use tokio::sync::oneshot;

pub(crate) struct Plan {
    key: String,
    fingerprint: serde_json::Value,
    work: Work,
    message: GatewayDirectMessage,
    body: Vec<u8>,
    config: GatewaySessionConfig,
    request: Option<SendMaterialRequest>,
}

type SealedPlan = (Box<Plan>, ramflux_protocol::Envelope);

pub(crate) enum ReceiptWork {
    Prepare {
        generation: u64,
        reply: oneshot::Sender<Result<Option<Plan>, SdkError>>,
    },
    Seal {
        generation: u64,
        plan: Box<Plan>,
        material: Box<Result<SendMaterial, SdkError>>,
        reply: oneshot::Sender<Result<Option<SealedPlan>, SdkError>>,
    },
    Complete {
        generation: u64,
        plan: Box<Plan>,
        outcome: Result<(), SdkError>,
        reply: oneshot::Sender<Result<(), SdkError>>,
    },
}

impl ReceiptWork {
    pub(crate) fn generation(&self) -> u64 {
        match self {
            Self::Prepare { generation, .. }
            | Self::Seal { generation, .. }
            | Self::Complete { generation, .. } => *generation,
        }
    }
}

pub(crate) async fn run(context: SessionContext, writer: mpsc::Sender<AccountWork>) {
    let mut cancel = context.cancel.clone();
    loop {
        let result = tokio::select! {
            biased;
            _ = cancel.changed() => break,
            result = pass(&context, &writer) => result,
        };
        let failed = result.is_err();
        let active = match result {
            Ok(active) => active,
            Err(error) => {
                tracing::warn!(%error, "delivery receipt courier deferred");
                false
            }
        };
        // A successful batch drains promptly; a failure has this courier's own backoff.
        let delay = if active { Duration::from_millis(10) } else { context.network_wait() };
        tokio::select! {biased; _=cancel.changed()=>break,
            ()=tokio::time::sleep(delay)=>{},
            ()=context.courier_wake("delivery-receipts"), if !failed=>{},
        }
    }
}

async fn pass(
    context: &SessionContext,
    writer: &mpsc::Sender<AccountWork>,
) -> Result<bool, SdkError> {
    let generation = context.generation;
    let (reply, response) = oneshot::channel();
    writer
        .send(AccountWork::Receipts(Box::new(ReceiptWork::Prepare { generation, reply })))
        .await
        .map_err(|_| stopped())?;
    let Some(mut plan) = response.await.map_err(|_| stopped())?? else { return Ok(false) };
    let material = fetch_material(context, &mut plan).await;
    let (reply, response) = oneshot::channel();
    writer
        .send(AccountWork::Receipts(Box::new(ReceiptWork::Seal {
            generation,
            plan: Box::new(plan),
            material: Box::new(material),
            reply,
        })))
        .await
        .map_err(|_| stopped())?;
    let Some((plan, packet)) = response.await.map_err(|_| stopped())?? else { return Ok(true) };
    let outcome = context
        .priority_call(
            move |engine| Box::pin(async move { engine.submit_envelope(packet).await.map(|_| ()) }),
            context.receipt_timeout(),
        )
        .await;
    let (reply, response) = oneshot::channel();
    writer
        .send(AccountWork::Receipts(Box::new(ReceiptWork::Complete {
            generation,
            plan,
            outcome,
            reply,
        })))
        .await
        .map_err(|_| stopped())?;
    response.await.map_err(|_| stopped())??;
    Ok(true)
}

async fn fetch_material(
    context: &SessionContext,
    plan: &mut Plan,
) -> Result<SendMaterial, SdkError> {
    #[cfg(test)]
    if let Some(outcome) = test_hooks::network(plan.work.wire_message.as_deref()).await {
        return outcome;
    }
    if let Some(request) = plan.request.take() {
        tokio::time::timeout(
            context.network_wait(),
            crate::bus::couriers::pair_material::fetch(
                context,
                &plan.config,
                request,
                crate::bus::connection_manager::CallClass::Priority,
            ),
        )
        .await
        .unwrap_or_else(|_| Err(stopped()))
    } else {
        Ok(SendMaterial { manifest: None, bundle: None })
    }
}

pub(crate) fn apply(account: &mut LocalBusAccountState, work: ReceiptWork) {
    match work {
        ReceiptWork::Prepare { reply, .. } => {
            if !reply.is_closed() {
                let _ = reply.send(prepare(account));
            }
        }
        ReceiptWork::Seal { mut plan, material, reply, .. } => {
            if reply.is_closed() {
                return;
            }
            let result = seal(account, &mut plan, *material);
            #[cfg(test)]
            test_hooks::applied(plan.work.wire_message.as_deref());
            let result = result.map(|packet| packet.map(|packet| (plan, packet)));
            let _ = reply.send(result);
        }
        ReceiptWork::Complete { plan, outcome, reply, .. } => {
            if reply.is_closed() {
                return;
            }
            let result = complete(account, &plan, outcome);
            let _ = reply.send(result);
        }
    }
}

fn prepare(account: &LocalBusAccountState) -> Result<Option<Plan>, SdkError> {
    let db = account.client.account_db()?;
    let now = now_unix_timestamp();
    db.retain_delivery_receipts(now, 128)?;
    if db
        .load_actor_state::<i64>(GATEWAY_RETRY_AT)?
        .is_some_and(|at| now < at && at <= now.saturating_add(30))
    {
        return Ok(None);
    }
    let after = db.load_actor_state::<String>(SCAN_CURSOR)?.unwrap_or_default();
    let mut keys = db.actor_state_key_page_after(PREFIX, &after, SCAN)?;
    if keys.is_empty() && !after.is_empty() {
        keys = db.actor_state_key_page_after(PREFIX, "", SCAN)?;
    }
    let scan_end = keys.last().cloned();
    let mut rows = Vec::new();
    for key in keys {
        if let Some(work) = db.load_actor_state::<Work>(&key)?
            && (work.next_at <= now
                || work.at.saturating_add(LIFETIME) <= now
                || work.attempts >= ATTEMPTS)
        {
            rows.push((key, work));
        }
    }
    rows.sort_by_key(|(_, work)| work.at);
    let mut selected = None;
    for (key, work) in rows {
        if db.message_is_deleted(&work.message)? {
            discard(&account.client, &key, &work)?;
        } else if work.at.saturating_add(LIFETIME) <= now || work.attempts >= ATTEMPTS {
            finish(&account.client, &key, &work, "failed")?;
        } else {
            selected = Some((key, work));
            break;
        }
    }
    let Some((key, work)) = selected else {
        if let Some(scan_end) = scan_end {
            db.persist_actor_state(SCAN_CURSOR, &scan_end)?;
        }
        return Ok(None);
    };
    let (message, body) = receipt_message(account, &account.gateway_config, &work)?;
    let request = if work.packet.is_none() {
        Some(account.client.routed_send_material_request(&account.gateway_config, &message)?)
    } else {
        None
    };
    let Some(fingerprint) = db.load_actor_state::<serde_json::Value>(&key)? else {
        return Ok(None);
    };
    Ok(Some(Plan {
        key,
        fingerprint,
        work,
        message,
        body,
        config: account.gateway_config.clone(),
        request,
    }))
}

fn current(account: &LocalBusAccountState, plan: &Plan) -> Result<bool, SdkError> {
    Ok(account.client.account_db()?.load_actor_state::<serde_json::Value>(&plan.key)?.as_ref()
        == Some(&plan.fingerprint))
}

fn seal(
    account: &LocalBusAccountState,
    plan: &mut Plan,
    material: Result<SendMaterial, SdkError>,
) -> Result<Option<ramflux_protocol::Envelope>, SdkError> {
    if !current(account, plan)? {
        return Ok(None);
    }
    if account.client.account_db()?.message_is_deleted(&plan.work.message)? {
        discard(&account.client, &plan.key, &plan.work)?;
        return Ok(None);
    }
    let now = now_unix_timestamp();
    if plan.work.at.saturating_add(LIFETIME) <= now || plan.work.attempts >= ATTEMPTS {
        finish(&account.client, &plan.key, &plan.work, "failed")?;
        return Ok(None);
    }
    plan.work.attempts += 1;
    let backoff = (1_i64 << plan.work.attempts.min(6)).min(60);
    plan.work.next_at = now.saturating_add(30).saturating_add(backoff);
    account.client.account_db()?.persist_actor_state(&plan.key, &plan.work)?;
    let prepared = material.and_then(|material| {
        if let Some(packet) = &plan.work.packet {
            return Ok(packet.clone());
        }
        let sealed = account.client.seal_routed_prepared(
            &account.gateway_config,
            &plan.message,
            &plan.body,
            crate::client::routed::Route::receipt(),
            material,
        )?;
        plan.message.encrypted_body = serde_json::to_vec(&sealed)?;
        gateway_direct_message_envelope(&account.gateway_config, &plan.message, None)
    });
    let packet = match prepared {
        Ok(packet) => packet,
        Err(error) => {
            if matches!(error, SdkError::InboundRejected(_)) {
                finish(&account.client, &plan.key, &plan.work, "failed")?;
            } else {
                postpone(&account.client, &plan.key, &mut plan.work, backoff)?;
            }
            return Err(error);
        }
    };
    plan.work.packet = Some(packet.clone());
    account.client.account_db()?.persist_actor_state(&plan.key, &plan.work)?;
    account.client.account_db()?.persist_actor_state(SCAN_CURSOR, &plan.key)?;
    plan.fingerprint = serde_json::to_value(&plan.work)?;
    Ok(Some(packet))
}

fn complete(
    account: &LocalBusAccountState,
    plan: &Plan,
    outcome: Result<(), SdkError>,
) -> Result<(), SdkError> {
    if !current(account, plan)? {
        return Ok(());
    }
    if account.client.account_db()?.message_is_deleted(&plan.work.message)? {
        return discard(&account.client, &plan.key, &plan.work);
    }
    match outcome {
        Ok(()) => finish(&account.client, &plan.key, &plan.work, "sent"),
        Err(error) => {
            let mut work = plan.work.clone();
            let backoff = (1_i64 << work.attempts.min(6)).min(60);
            postpone(&account.client, &plan.key, &mut work, backoff)?;
            Err(error)
        }
    }
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};
    #[test]
    fn legacy_receipt_defaults_do_not_change_the_stored_row_fence() -> Result<(), SdkError> {
        let root = crate::bus::runtime_tests::root("receipt-legacy-row-fence");
        let account = crate::bus::runtime_tests::account(
            &root,
            "alice",
            None,
            Arc::new(AtomicBool::new(false)),
        )?;
        let manifest =
            crate::client::identity_authority::test_support::public_manifest(&account.client)?;
        account.client.persist_identity_directory(&manifest)?;
        let identity = account.client.owned_device_identity()?;
        let message = GatewayDirectMessage {
            conversation_id: "thread".into(),
            message_id: "receipt".into(),
            envelope_id: "retained-receipt".into(),
            source_principal_id: account.gateway_config.principal_id.clone(),
            sender_id: identity.device_id().into(),
            recipient_device_id: Some(identity.device_id().into()),
            recipient_principal_commitment: Some(identity.root_commitment().into()),
            target_delivery_id: account.gateway_config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 600,
        };
        let packet = gateway_direct_message_envelope(&account.gateway_config, &message, None)?;
        let work = Work {
            status_id: String::new(),
            conversation: "thread".into(),
            message: "stored-message".into(),
            wire_message: None,
            receiver: identity.storage_key().into(),
            sender: identity.storage_key().into(),
            root: Some(identity.root_commitment().into()),
            at: now_unix_timestamp(),
            attempts: 0,
            next_at: 0,
            packet: Some(packet),
        };
        let mut legacy = serde_json::to_value(&work)?;
        let object = legacy
            .as_object_mut()
            .ok_or_else(|| SdkError::LocalBus("expected receipt object".into()))?;
        object.remove("status_id");
        object.remove("wire_message");
        let key = format!("{PREFIX}legacy");
        let db = account.client.account_db()?;
        db.persist_actor_state(&key, &legacy)?;
        let mut plan = prepare(&account)?
            .ok_or_else(|| SdkError::LocalBus("legacy receipt was not selected".into()))?;
        let mut changed = legacy.clone();
        changed["next_at"] = serde_json::json!(123);
        db.persist_actor_state(&key, &changed)?;
        let empty = || Ok(SendMaterial { manifest: None, bundle: None });
        assert!(seal(&account, &mut plan, empty())?.is_none());
        assert_eq!(db.load_actor_state::<serde_json::Value>(&key)?, Some(changed));
        db.persist_actor_state(&key, &legacy)?;
        assert!(seal(&account, &mut plan, empty())?.is_some());
        assert_eq!(plan.work.attempts, 1);
        drop(account);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_hooks;

#[cfg(test)]
mod retention_tests {
    use super::*;
    #[test]
    fn receipt_prepare_applies_retention() -> Result<(), SdkError> {
        let root = crate::bus::runtime_tests::root("receipt-prepare-retention");
        let account = crate::bus::runtime_tests::account(
            &root,
            "sender",
            None,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        let db = account.client.account_db()?;
        let key = "delivery-receipt/status/expired";
        db.persist_receipt_state(key, &serde_json::json!({"state":"sent","delivered_at":1}), 1)?;
        assert!(db.actor_state_exists(key)?);
        assert!(prepare(&account)?.is_none());
        assert!(!db.actor_state_exists(key)?);
        drop(account);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) async fn test_fetch_material(
    context: &SessionContext,
    config: GatewaySessionConfig,
) -> Result<SendMaterial, SdkError> {
    let work = Work {
        status_id: String::new(),
        conversation: String::new(),
        message: String::new(),
        wire_message: None,
        receiver: String::new(),
        sender: "receipt-peer".into(),
        root: None,
        at: 0,
        attempts: 0,
        next_at: 0,
        packet: None,
    };
    let message = GatewayDirectMessage {
        conversation_id: String::new(),
        message_id: String::new(),
        envelope_id: String::new(),
        source_principal_id: String::new(),
        sender_id: String::new(),
        recipient_device_id: None,
        recipient_principal_commitment: None,
        target_delivery_id: String::new(),
        encrypted_body: Vec::new(),
        created_at: 0,
        ttl: 600,
    };
    let mut plan = Plan {
        key: String::new(),
        fingerprint: serde_json::Value::Null,
        work,
        message,
        body: Vec::new(),
        config,
        request: Some(SendMaterialRequest { root: None, prekey: Some("receipt-peer".into()) }),
    };
    fetch_material(context, &mut plan).await
}
