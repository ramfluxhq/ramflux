// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded resumable recipient rounds through authenticated pair and federation transports.
use super::submit_staged;
use super::{
    DEVICES_PER_DRAIN, DeliveryProgress, Duration, GatewayDirectMessage, GatewaySessionEngine,
    Intent, MAX_DEVICES, ROOTS_PER_DRAIN, RamfluxClient, RecipientCursor, SdkError, StagedEnvelope,
    VerifiedGroupState, now_unix_timestamp, persist_intent, recipient_snapshot,
};
pub(super) async fn deliver(
    client: &RamfluxClient,
    engine: &mut GatewaySessionEngine,
    intent: &mut Intent,
    state: &VerifiedGroupState,
) -> Result<(usize, DeliveryProgress), SdkError> {
    let mut delivered = 0;
    let mut roots = 0;
    let mut attempts = 0;
    let eligible = intent.eligible.clone();
    for (root, excluded) in eligible {
        if intent
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.root > root || (cursor.root == root && cursor.complete))
        {
            continue;
        }
        if roots >= ROOTS_PER_DRAIN {
            return Ok((delivered, DeliveryProgress::Continue));
        }
        roots += 1;
        let Some(manifest) = refresh_root(client, engine, intent, state, &root).await? else {
            continue;
        };
        if !intent.cursor.as_ref().is_some_and(|cursor| cursor.root == root && !cursor.complete) {
            intent.cursor =
                Some(RecipientCursor { root: root.clone(), after_device: None, complete: false });
            persist_intent(client, intent)?;
        }
        let devices = selected_devices(client, intent, state, &root, manifest)?;
        if devices.is_empty() {
            intent.round_failed = true;
        }
        for device in devices {
            if excluded.contains(&device.device_id)
                || intent.cursor.as_ref().is_some_and(|cursor| {
                    cursor.root == root
                        && cursor
                            .after_device
                            .as_ref()
                            .is_some_and(|after| device.device_id <= *after)
                })
            {
                continue;
            }
            let local = client.owned_device_identity()?;
            if (device.device_id == local.device_id() && root == local.root_commitment())
                || intent.delivered.contains(&(root.clone(), device.device_id.clone()))
            {
                continue;
            }
            if intent.round_devices >= MAX_DEVICES {
                intent.round_devices = 0;
                persist_intent(client, intent)?;
                return Ok((delivered, DeliveryProgress::Continue));
            }
            if attempts >= DEVICES_PER_DRAIN {
                return Ok((delivered, DeliveryProgress::Continue));
            }
            let Some(snapshot) =
                recipient_snapshot(client, intent, state, &root, &device.device_id)?
            else {
                continue;
            };
            let selected = if snapshot.state_hash == state.snapshot().state_hash {
                state.clone()
            } else {
                ramflux_crypto::resign_group_state_snapshot(
                    client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                    &client.owned_group_actor(&engine.config.target_delivery_id)?,
                    &ramflux_crypto::verify_group_state_snapshot(snapshot.clone())?,
                )?
            };
            attempts += 1;
            intent.round_devices += 1;
            let name = device.device_id.clone();
            if let Ok(Ok(())) = tokio::time::timeout(
                Duration::from_secs(3),
                deliver_one(client, engine, intent, &selected, &root, device),
            )
            .await
            {
                delivered += 1;
            } else {
                intent.round_failed = true;
                journal_failure(client, state, &root, &name)?;
            }
            intent.cursor = Some(RecipientCursor {
                root: root.clone(),
                after_device: Some(name),
                complete: false,
            });
            persist_intent(client, intent)?;
        }
        complete_root(client, intent, &root)?;
    }
    Ok((
        delivered,
        if intent.round_failed { DeliveryProgress::Retry } else { DeliveryProgress::Complete },
    ))
}
async fn refresh_root(
    client: &RamfluxClient,
    engine: &GatewaySessionEngine,
    intent: &mut Intent,
    state: &VerifiedGroupState,
    root: &str,
) -> Result<Option<crate::prekey::SdkDeviceManifestResponse>, SdkError> {
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        client.shared_group_manifest(&engine.config, &state.view().group_id, root),
    )
    .await
    .map_err(|error| SdkError::InboundPending(format!("group manifest deadline: {error}")))
    .and_then(std::convert::identity);
    match result {
        Ok(manifest) => Ok(Some(manifest)),
        Err(error) => {
            intent.round_failed = true;
            tracing::debug!(%error, %root, "group member manifest refresh deferred");
            complete_root(client, intent, root)?;
            Ok(None)
        }
    }
}
fn complete_root(client: &RamfluxClient, intent: &mut Intent, root: &str) -> Result<(), SdkError> {
    intent.cursor = Some(RecipientCursor { root: root.into(), after_device: None, complete: true });
    persist_intent(client, intent)
}
async fn deliver_one(
    client: &RamfluxClient,
    engine: &mut GatewaySessionEngine,
    intent: &mut Intent,
    selected: &VerifiedGroupState,
    root: &str,
    device: crate::prekey::SdkDeviceManifestEntry,
) -> Result<(), SdkError> {
    let bytes = zeroize::Zeroizing::new(client.shared_group_packet(
        selected,
        selected.view().effective_role(root, &device.device_id).is_some(),
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
    let mut message = GatewayDirectMessage {
        conversation_id: state.state.conversation_id.clone(),
        message_id: envelope.clone(),
        envelope_id: format!("group_state_{}", crate::new_surface_message_id()?),
        source_principal_id: engine.config.principal_id.clone(),
        sender_id: engine.config.device_id.clone(),
        recipient_device_id: Some(device.device_id.clone()),
        recipient_principal_commitment: Some(root.into()),
        target_delivery_id: device.target_delivery_id,
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: if selected.view().effective_role(root, &device.device_id).is_some() {
            3600
        } else {
            u32::try_from(super::BOUNDARY_SECONDS)
                .map_err(|_| SdkError::LocalBus("removal boundary TTL overflow".into()))?
        },
    };
    let federation = client.shared_group_federation_route(&state.group_id, root)?;
    let route = crate::client::routed::Route::group_control(&state.group_id);
    let sealed = if let Some(federation) = &federation {
        client.seal_routed_federated_as(
            engine,
            &message,
            &bytes,
            federation.recipient_prekey_url.as_deref(),
            route,
        )?
    } else {
        client.seal_routed_as(engine, &message, &bytes, route).await?
    };
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    intent.active = Some(StagedEnvelope {
        federation,
        root: root.into(),
        device: device.device_id.clone(),
        envelope: crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?,
    });
    // Persist each sealed attempt before submit; application-level state replay is harmless.
    persist_intent(client, intent)?;
    submit_staged(client, engine, intent).await?;
    Ok(())
}

fn selected_boundary(intent: &Intent, root: &str, device: &str) -> bool {
    intent
        .terminal
        .iter()
        .any(|boundary| boundary.root == root && boundary.devices.contains(device))
}

fn journal_failure(
    client: &RamfluxClient,
    state: &VerifiedGroupState,
    root: &str,
    name: &str,
) -> Result<(), SdkError> {
    let subject = ramflux_protocol::hash_base64url(
        "ramflux.group.delivery.subject.v1",
        &ramflux_protocol::canonical_json_bytes(&(&state.view().group_id, &root, &name))?,
    );
    let now = now_unix_timestamp();
    client.account_db()?.append_group_journal(&format!("group-device/{subject}/{}",now/300),"group.state.delivery_failed",&serde_json::json!({"group_id":state.view().group_id,"root_commitment":root,"device_id":name,"epoch":state.view().epoch,"reason":"submit_failed"}),now,&subject)?;
    Ok(())
}

fn selected_devices(
    client: &RamfluxClient,
    intent: &Intent,
    state: &VerifiedGroupState,
    root: &str,
    manifest: crate::prekey::SdkDeviceManifestResponse,
) -> Result<Vec<crate::prekey::SdkDeviceManifestEntry>, SdkError> {
    let allowed = client.shared_group_selected_devices(state)?.remove(root).unwrap_or_default();
    let mut devices = manifest
        .devices
        .into_iter()
        .filter(|device| {
            allowed.contains(&device.device_id)
                || selected_boundary(intent, root, &device.device_id)
        })
        .collect::<Vec<_>>();
    devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    Ok(devices)
}
