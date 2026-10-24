// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Inline account-history copies through the existing encrypted own-device sync protocol.
use crate::prelude::*;
pub(crate) async fn push(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let revision = account
        .client
        .account_db()?
        .load_actor_state::<u64>("own-device/history_revision")?
        .unwrap_or(0);
    let copied = account
        .client
        .account_db()?
        .load_actor_state::<u64>("own-device/history_copied")?
        .unwrap_or(0);
    if revision == copied {
        return Ok(0);
    }
    let mut engine = account.take_live_engine().await?;
    let result = async {
        let manifest = account
            .client
            .cache_verified_device_manifest(
                &engine.config,
                &account.principal_commitment,
                "own_device_history",
            )
            .await?;
        let local = engine.config.device_id.clone();
        if !manifest.devices.iter().any(|device| device.device_id == local) {
            return Err(SdkError::InboundRejected(
                "own-device history source is not active".into(),
            ));
        }
        let targets = manifest
            .devices
            .into_iter()
            .filter(|device| device.device_id != local)
            .collect::<Vec<_>>();
        let mut sent = 0;
        if !targets.is_empty() {
            let endpoint = std::env::var("RAMFLUX_SDK_RELAY_ENDPOINT").ok().or_else(|| {
                std::env::var("RAMFLUX_SDK_RELAY_QUIC_ADDR")
                    .ok()
                    .map(|addr| format!("quic://{addr}"))
            });
            let options =
                account.client.relay_transfer_options(endpoint, None, None)?.ok_or_else(|| {
                    SdkError::LocalBus("own-device history requires a configured relay".into())
                })?;
            let pool = account.relay_quic_pool()?;
            for target in targets {
                let exported = account
                    .client
                    .export_own_device_sync(
                        &mut engine,
                        &pool,
                        &account.principal_commitment,
                        &target.device_id,
                        &options.relay_endpoint,
                        None,
                        64 * 1024,
                    )
                    .await?;
                let message = GatewayDirectMessage {
                    conversation_id: format!("own-device.history:{}", account.principal_commitment),
                    message_id: exported.snapshot_id.clone(),
                    envelope_id: crate::new_surface_message_id()?,
                    source_principal_id: engine.config.principal_id.clone(),
                    sender_id: local.clone(),
                    recipient_device_id: Some(target.device_id),
                    target_delivery_id: target.target_delivery_id,
                    encrypted_body: Vec::new(),
                    created_at: now_unix_timestamp(),
                    ttl: 3600,
                };
                account
                    .client
                    .send_plaintext_direct_message_without_franking(
                        &mut engine,
                        message,
                        &serde_json::to_vec(&exported.envelope)?,
                        crate::client::routed::Route {
                            kind: crate::client::routed::Kind::Control,
                            group_id: None,
                            attachments: false,
                        },
                    )
                    .await?;
                sent += 1;
            }
        }
        account.client.account_db()?.persist_actor_state("own-device/history_copied", &revision)?;
        Ok::<_, SdkError>(sent)
    }
    .await;
    account.put_engine(engine);
    result
}
