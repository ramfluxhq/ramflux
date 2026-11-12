// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded group-delivery round split into network steps and local row-fenced commits.

use super::{
    DEVICES_PER_DRAIN, DRIVER_PROGRESS, Delivered, GatewayDirectMessage, GatewaySessionConfig,
    Intent, LocalBusAccountState, LocalBusFederationRoute, MAX_DEVICES, ROOTS_PER_DRAIN,
    RecipientCursor, SdkError, StagedEnvelope, VerifiedGroupState, defer_round, delivered_key, key,
    now_unix_timestamp, persist_intent, prepare_intent, recipient_snapshot, recipients,
};
use crate::bus::{
    connection_manager::SessionContext,
    couriers::{federation, writer::Writer},
};
use crate::client::routed::{SendMaterial, SendMaterialRequest};
use crate::gateway::session_push::SubmitRefusal;
use recipients::{complete_root, journal_failure, selected_devices};

#[derive(Clone)]
struct Plan {
    intent: Intent,
    state: VerifiedGroupState,
    fingerprint: serde_json::Value,
    config: GatewaySessionConfig,
}
struct Target {
    plan: Plan,
    root: String,
    device: String,
    message: GatewayDirectMessage,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    route: Option<LocalBusFederationRoute>,
    request: SendMaterialRequest,
}
#[derive(Clone)]
struct Attempt {
    plan: Plan,
    root: String,
    device: String,
    envelope: ramflux_protocol::Envelope,
    route: Option<LocalBusFederationRoute>,
}
pub(crate) async fn pass(context: SessionContext, writer: Writer) -> Result<bool, SdkError> {
    let Some(mut plan) = writer.apply(prepare).await? else { return Ok(false) };
    let mut roots = 0;
    let mut attempts = 0;
    let mut continuing = false;
    for (root, excluded) in plan.intent.eligible.clone() {
        if plan
            .intent
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.root > root || (cursor.root == root && cursor.complete))
        {
            continue;
        }
        if roots >= ROOTS_PER_DRAIN {
            continuing = true;
            break;
        }
        roots += 1;
        let group = plan.intent.snapshot.group_id.clone();
        let root_for_route = root.clone();
        let route = writer
            .apply(move |account| {
                account.client.shared_group_federation_route(&group, &root_for_route)
            })
            .await?;
        let manifest = federation::manifest(&context, &plan.config, &root, route.as_ref()).await;
        let captured = plan.clone();
        let owned_root = root.clone();
        let Some((changed, devices)) = writer
            .apply(move |account| root_devices(account, captured, &owned_root, manifest))
            .await?
        else {
            return Ok(true);
        };
        plan = changed;
        for device in devices {
            if excluded.contains(&device.device_id)
                || plan.intent.cursor.as_ref().is_some_and(|cursor| {
                    cursor.root == root
                        && cursor
                            .after_device
                            .as_ref()
                            .is_some_and(|after| device.device_id <= *after)
                })
            {
                continue;
            }
            if plan.intent.round_devices >= MAX_DEVICES {
                plan.intent.round_devices = 0;
                continuing = true;
                break;
            }
            if attempts >= DEVICES_PER_DRAIN {
                continuing = true;
                break;
            }
            let captured = plan.clone();
            let owned_root = root.clone();
            let Some(target) = writer
                .apply(move |account| prepare_target(account, captured, &owned_root, device))
                .await?
            else {
                continue;
            };
            attempts += 1;
            let Some(changed) = Box::pin(deliver_target(&context, &writer, target)).await? else {
                return Ok(true);
            };
            plan = changed;
        }
        if continuing {
            break;
        }
        let owned_root = root.clone();
        let captured = plan;
        let Some(changed) =
            writer.apply(move |account| finish_root(account, captured, &owned_root)).await?
        else {
            return Ok(true);
        };
        plan = changed;
    }
    writer.apply(move |account| finish_round(account, plan, continuing)).await?;
    Ok(true)
}
/// The terminal branch of a delivery intent: journal why, then either keep a terminal boundary
/// alive for a later round or drop the intent.
fn exhaust(
    client: &crate::RamfluxClient,
    intent: &mut Intent,
    id: &str,
    now: i64,
    reason: &str,
) -> Result<(), SdkError> {
    let db = client.account_db()?;
    db.append_group_journal(&format!("{id}/{now}"),"group.state.delivery_failed",&serde_json::json!({"group_id":intent.snapshot.group_id,"epoch":intent.snapshot.epoch,"reason":reason}),now,id)?;
    if intent.terminal.iter().any(|boundary| boundary.expires_at > now) {
        intent.attempt = 0;
        intent.round_active = false;
        intent.next_at = now.saturating_add(300);
        intent.expires_at =
            intent.terminal.iter().map(|boundary| boundary.expires_at).max().unwrap_or(now);
        persist_intent(client, intent)?;
    } else {
        db.remove_actor_state(id)?;
    }
    Ok(())
}
fn prepare(account: &mut LocalBusAccountState) -> Result<Option<Plan>, SdkError> {
    let client = &account.client;
    let db = client.account_db()?;
    let after = db.load_actor_state::<String>(DRIVER_PROGRESS)?.unwrap_or_default();
    let now = now_unix_timestamp();
    let Some(mut intent) = db.next_shared_group_intent::<Intent>(&after, now)? else {
        return Ok(None);
    };
    let id = key(&intent.snapshot.group_id);
    db.persist_actor_state(DRIVER_PROGRESS, &id)?;
    if now < intent.next_at {
        return Ok(None);
    }
    if now >= intent.expires_at || (!intent.round_active && intent.attempt >= 8) {
        exhaust(client, &mut intent, &id, now, "retry_budget_exhausted")?;
        return Ok(None);
    }
    if !intent.round_active {
        intent.attempt += 1;
        intent.round_active = true;
        intent.round_failed = false;
        intent.round_devices = 0;
        intent.cursor = None;
    }
    persist_intent(client, &intent)?;
    let state = match prepare_intent(client, &mut intent, &account.target_delivery_id) {
        Ok(Some(state)) => state,
        Ok(None) => return Ok(None),
        Err(error) => {
            defer_round(client, &mut intent)?;
            return Err(error);
        }
    };
    Ok(Some(Plan {
        fingerprint: serde_json::to_value(&intent)?,
        intent,
        state,
        config: account.gateway_config.clone(),
    }))
}
fn current(account: &LocalBusAccountState, plan: &Plan) -> Result<bool, SdkError> {
    let db = account.client.account_db()?;
    Ok(db.load_actor_state::<serde_json::Value>(&key(&plan.intent.snapshot.group_id))?.as_ref()
        == Some(&plan.fingerprint)
        && db
            .shared_group_state(&plan.intent.snapshot.group_id)?
            .is_some_and(|state| state.snapshot().state_hash == plan.state.snapshot().state_hash))
}
fn persisted(account: &LocalBusAccountState, mut plan: Plan) -> Result<Plan, SdkError> {
    persist_intent(&account.client, &plan.intent)?;
    plan.fingerprint = serde_json::to_value(&plan.intent)?;
    Ok(plan)
}
fn root_devices(
    account: &LocalBusAccountState,
    mut plan: Plan,
    root: &str,
    manifest: Result<crate::SdkDeviceManifestResponse, SdkError>,
) -> Result<Option<(Plan, Vec<crate::prekey::SdkDeviceManifestEntry>)>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    let manifest = match manifest {
        Ok(manifest) => manifest,
        Err(error) => {
            tracing::debug!(%error,%root,"group member manifest refresh deferred");
            plan.intent.round_failed = true;
            complete_root(&account.client, &mut plan.intent, root)?;
            return persisted(account, plan).map(|plan| Some((plan, Vec::new())));
        }
    };
    account.client.persist_fetched_identity_directory(&manifest)?;
    if !plan.intent.cursor.as_ref().is_some_and(|cursor| cursor.root == root && !cursor.complete) {
        plan.intent.cursor =
            Some(RecipientCursor { root: root.into(), after_device: None, complete: false });
    }
    let devices = selected_devices(&account.client, &plan.intent, &plan.state, root, manifest)?;
    if devices.is_empty() {
        plan.intent.round_failed = true;
    }
    persisted(account, plan).map(|plan| Some((plan, devices)))
}
fn prepare_target(
    account: &LocalBusAccountState,
    mut plan: Plan,
    root: &str,
    device: crate::prekey::SdkDeviceManifestEntry,
) -> Result<Option<Target>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    let client = &account.client;
    let local = client.owned_device_identity()?;
    if (device.device_id == local.device_id() && root == local.root_commitment())
        || plan.intent.delivered.contains(&(root.into(), device.device_id.clone()))
    {
        return Ok(None);
    }
    let Some(snapshot) =
        recipient_snapshot(client, &plan.intent, &plan.state, root, &device.device_id)?
    else {
        return Ok(None);
    };
    let selected = if snapshot.state_hash == plan.state.snapshot().state_hash {
        plan.state.clone()
    } else {
        ramflux_crypto::resign_group_state_snapshot(
            client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &client.owned_group_actor(&plan.config.target_delivery_id)?,
            &ramflux_crypto::verify_group_state_snapshot(snapshot)?,
        )?
    };
    plan.intent.round_devices += 1;
    let bytes = zeroize::Zeroizing::new(client.shared_group_packet_for_recipient(
        &selected,
        &client.device_identity_for_root(root, &device.device_id)?,
    )?);
    let state = selected.snapshot();
    let envelope = format!(
        "group_state_{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.group_state.delivery.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &state.state_hash,
                &root,
                &device.device_id
            ))?
        )
    );
    let message = GatewayDirectMessage {
        conversation_id: state.state.conversation_id.clone(),
        message_id: crate::RamfluxClient::shared_group_packet_message_id(&bytes, &envelope)?,
        envelope_id: format!("group_state_{}", crate::new_surface_message_id()?),
        source_principal_id: plan.config.principal_id.clone(),
        sender_id: plan.config.device_id.clone(),
        recipient_device_id: Some(device.device_id.clone()),
        recipient_principal_commitment: Some(root.into()),
        target_delivery_id: device.target_delivery_id,
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: account.client.content_ttl()?,
    };
    let route = client.shared_group_federation_route(&state.group_id, root)?;
    let request = client.routed_send_material_request(&plan.config, &message)?;
    let plan = persisted(account, plan)?;
    Ok(Some(Target {
        plan,
        root: root.into(),
        device: device.device_id,
        message,
        bytes,
        route,
        request,
    }))
}
fn seal(
    account: &LocalBusAccountState,
    target: Target,
    material: Result<SendMaterial, SdkError>,
) -> Result<Option<Attempt>, SdkError> {
    let Target { mut plan, root, device, mut message, bytes, route, .. } = target;
    if !current(account, &plan)? {
        return Ok(None);
    }
    let current_route =
        account.client.shared_group_federation_route(&plan.intent.snapshot.group_id, &root)?;
    if serde_json::to_value(&current_route)? != serde_json::to_value(&route)? {
        return Ok(None);
    }
    let sealed = account.client.seal_routed_prepared(
        &plan.config,
        &message,
        &bytes,
        crate::client::routed::Route::group_control(&plan.intent.snapshot.group_id),
        material?,
    )?;
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    let envelope = crate::dm::gateway_direct_message_envelope(&plan.config, &message, None)?;
    plan.intent.active = Some(StagedEnvelope {
        federation: route.clone(),
        root: root.clone(),
        device: device.clone(),
        envelope: envelope.clone(),
    });
    plan = persisted(account, plan)?;
    Ok(Some(Attempt { plan, root, device, envelope, route }))
}
fn failed_target(
    account: &LocalBusAccountState,
    mut plan: Plan,
    root: &str,
    device: &str,
) -> Result<Option<Plan>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    plan.intent.round_failed = true;
    journal_failure(&account.client, &plan.state, root, device)?;
    plan.intent.cursor = Some(RecipientCursor {
        root: root.into(),
        after_device: Some(device.into()),
        complete: false,
    });
    persisted(account, plan).map(Some)
}
fn complete(
    account: &LocalBusAccountState,
    attempt: Attempt,
    outcome: Result<Result<(), SubmitRefusal>, SdkError>,
) -> Result<Option<Plan>, SdkError> {
    let Attempt { mut plan, root, device, route, .. } = attempt;
    if !current(account, &plan)? {
        return Ok(None);
    }
    if serde_json::to_value(
        account.client.shared_group_federation_route(&plan.intent.snapshot.group_id, &root)?,
    )? != serde_json::to_value(&route)?
    {
        return Ok(None);
    }
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(SubmitRefusal::Conflict)) => {
            // The gateway already holds this envelope id with different content: the staged
            // envelope is never resubmitted and the intent takes its terminal branch now.
            tracing::debug!("group state submission conflicted; entering the terminal branch");
            plan.intent.active = None;
            let id = key(&plan.intent.snapshot.group_id);
            exhaust(
                &account.client,
                &mut plan.intent,
                &id,
                now_unix_timestamp(),
                "submit_conflict",
            )?;
            return Ok(None);
        }
        Ok(Err(refusal)) => {
            if let SubmitRefusal::CapacityRetryAfter { retry_after_ms } = refusal {
                plan.intent.min_defer_secs =
                    i64::try_from(retry_after_ms.div_ceil(1000)).unwrap_or(i64::MAX);
            }
            tracing::debug!(reason = refusal.reason(), "group state submission deferred");
            return failed_target(account, plan, &root, &device);
        }
        Err(error) => {
            tracing::debug!(%error,"group state submission deferred");
            return failed_target(account, plan, &root, &device);
        }
    }
    plan.intent.delivered.insert((root.clone(), device.clone()));
    account.client.account_db()?.persist_actor_state(
        &delivered_key(&plan.intent.snapshot.group_id),
        &Delivered {
            state_hash: plan.intent.snapshot.state_hash.clone(),
            devices: plan.intent.delivered.clone(),
        },
    )?;
    plan.intent.active = None;
    plan.intent.cursor =
        Some(RecipientCursor { root, after_device: Some(device), complete: false });
    persisted(account, plan).map(Some)
}
fn finish_root(
    account: &LocalBusAccountState,
    mut plan: Plan,
    root: &str,
) -> Result<Option<Plan>, SdkError> {
    if !current(account, &plan)? {
        return Ok(None);
    }
    complete_root(&account.client, &mut plan.intent, root)?;
    persisted(account, plan).map(Some)
}
fn finish_round(
    account: &LocalBusAccountState,
    mut plan: Plan,
    continuing: bool,
) -> Result<(), SdkError> {
    if !current(account, &plan)? {
        return Ok(());
    }
    if continuing {
        persist_intent(&account.client, &plan.intent)
    } else if plan.intent.round_failed {
        defer_round(&account.client, &mut plan.intent)
    } else {
        account.client.account_db()?.remove_actor_state(&key(&plan.intent.snapshot.group_id))?;
        Ok(())
    }
}

async fn deliver_target(
    context: &SessionContext,
    writer: &Writer,
    mut target: Target,
) -> Result<Option<Plan>, SdkError> {
    let request =
        std::mem::replace(&mut target.request, SendMaterialRequest { root: None, prekey: None });
    let material = federation::material(
        context,
        &target.plan.config,
        request,
        crate::bus::connection_manager::CallClass::Bulk,
        target.route.as_ref(),
    )
    .await;
    let captured = target.plan.clone();
    let owned_root = target.root.clone();
    let owned_device = target.device.clone();
    let sealed = writer.apply(move |account| seal(account, target, material)).await;

    match sealed {
        Ok(Some(attempt)) => {
            let outcome = federation::submit_classified(
                context,
                attempt.envelope.clone(),
                attempt.route.clone(),
            )
            .await;
            writer.apply(move |account| complete(account, attempt, outcome)).await
        }
        Ok(None) => Ok(None),
        Err(error) => {
            tracing::debug!(%error,"group state sealing deferred");
            writer
                .apply(move |account| failed_target(account, captured, &owned_root, &owned_device))
                .await
        }
    }
}
