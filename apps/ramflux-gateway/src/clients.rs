use std::sync::{Arc, Mutex};

use crate::{NotifyHttpClient, RouterMeshClient};

pub(crate) fn router_mesh_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<RouterMeshClient> {
    let endpoint = config.mesh.endpoints.get("router").cloned().unwrap_or_default();
    if endpoint.is_empty() {
        return Err(anyhow::anyhow!("missing router mesh endpoint"));
    }
    Ok(RouterMeshClient {
        endpoint,
        server_name: "ramflux-router".to_owned(),
        tls: ramflux_transport::MeshTlsConfig {
            ca_cert: config.mesh.ca_cert.clone().into(),
            service_cert: config.mesh.service_cert.clone().into(),
            service_key: config.mesh.service_key.clone().into(),
        },
        client: ramflux_transport::MeshHttpClient::new(),
    })
}

pub(crate) fn notify_http_client(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<NotifyHttpClient> {
    Ok(NotifyHttpClient {
        endpoint: std::env::var("RAMFLUX_NOTIFY_HTTP_URL")
            .unwrap_or_else(|_| "http://ramflux-notify:18083".to_owned()),
        signer: ramflux_node_core::require_node_service_signing_key(config)?,
    })
}

#[cfg(feature = "itest-http")]
pub(crate) fn pre_auth_gate(
    request: &ramflux_node_core::ItestHttpRequest,
    state: &Arc<Mutex<ramflux_node_core::GatewayState>>,
    store: &ramflux_node_core::GatewayRedbStore,
) -> anyhow::Result<Option<ramflux_node_core::GatewayPreAuthChallengeResponse>> {
    let source_ip_hash =
        request.source_ip_hash.as_deref().unwrap_or("unknown-source-ip").to_owned();
    let now = request.pre_auth_now.unwrap_or_else(ramflux_node_core::now_unix_seconds);
    let mut gateway = gateway_state(state)?;
    let decision =
        match gateway.check_pre_auth(&source_ip_hash, request.pre_auth_cookie.as_deref(), now) {
            Ok(decision) => decision,
            Err(error) => {
                store.save_pre_auth_hot(&gateway)?;
                return Err(error.into());
            }
        };
    Ok(match decision {
        ramflux_node_core::GatewayPreAuthDecision::Accepted => {
            store.save_pre_auth_hot(&gateway)?;
            None
        }
        ramflux_node_core::GatewayPreAuthDecision::Challenge(challenge) => {
            store.save_pre_auth_with_challenges(&gateway)?;
            Some(challenge)
        }
    })
}

pub(crate) fn gateway_state(
    state: &Arc<Mutex<ramflux_node_core::GatewayState>>,
) -> anyhow::Result<std::sync::MutexGuard<'_, ramflux_node_core::GatewayState>> {
    state.lock().map_err(|error| anyhow::anyhow!("gateway state lock poisoned: {error}"))
}

#[cfg(feature = "itest-http")]
pub(crate) fn is_timeout_error(error: &ramflux_node_core::NodeCoreError) -> bool {
    matches!(error, ramflux_node_core::NodeCoreError::ItestHttp(message) if message.contains("timed out") || message.contains("WouldBlock"))
}

pub(crate) fn router_post_json<T, R>(
    router: &RouterMeshClient,
    path: &str,
    value: &T,
) -> Result<R, ramflux_transport::TransportError>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    router.client.post_json(&router.endpoint, path, &router.tls, &router.server_name, value)
}

pub(crate) fn router_get_json<R>(
    router: &RouterMeshClient,
    path: &str,
) -> Result<R, ramflux_transport::TransportError>
where
    R: serde::de::DeserializeOwned,
{
    router.client.get_json(&router.endpoint, path, &router.tls, &router.server_name)
}

pub(crate) fn router_cursor(
    router: &RouterMeshClient,
    target_delivery_id: &str,
) -> Result<Option<ramflux_node_core::ItestMvp0CursorResponse>, ramflux_transport::TransportError> {
    router_get_json(router, &format!("/mvp0/cursor/{target_delivery_id}"))
}

pub(crate) fn router_inbox(
    router: &RouterMeshClient,
    target_delivery_id: &str,
    after_inbox_seq: u64,
    limit: usize,
) -> Result<ramflux_node_core::ItestMvp1InboxResponse, ramflux_transport::TransportError> {
    router_get_json(
        router,
        &format!("/mvp1/inbox/{target_delivery_id}?after={after_inbox_seq}&limit={limit}"),
    )
}

pub(crate) fn notify_offline_wake(
    notify: &NotifyHttpClient,
    target_delivery_id: &str,
    envelope: &ramflux_protocol::Envelope,
) -> anyhow::Result<()> {
    let encrypted_hint = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::NOTIFICATION_WAKE,
        envelope.encrypted_payload.as_bytes(),
    );
    let mut wake = ramflux_protocol::NotificationWake {
        schema: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: notify.signer.signing_key_id().to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        wake_id: format!("wake_{}", envelope.envelope_id),
        push_alias: target_delivery_id.to_owned(),
        delivery_class: notification_class_for_envelope(envelope),
        priority: ramflux_protocol::PushPriority::Normal,
        ttl: 86_400,
        collapse_key: Some(format!(
            "target:{}:content",
            ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::PUSH_ALIAS,
                target_delivery_id.as_bytes(),
            )
        )),
        encrypted_hint: Some(encrypted_hint),
    };
    notify.signer.sign_notification_wake(&mut wake)?;
    let _: serde_json::Value = ramflux_node_core::itest_http_post_json(
        &format!("{}/s13/notify/wake", notify.endpoint),
        &serde_json::json!({
            "device_delivery_id": target_delivery_id,
            "wake": wake,
            "queued_at": ramflux_node_core::now_unix_seconds()
        }),
    )?;
    Ok(())
}

pub(crate) fn notification_class_for_envelope(
    envelope: &ramflux_protocol::Envelope,
) -> ramflux_protocol::NotificationDeliveryClass {
    match envelope.delivery_class {
        ramflux_protocol::DeliveryClass::SelfDeviceControl => {
            ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification
        }
        ramflux_protocol::DeliveryClass::NotificationWake => {
            ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
        }
        _ => ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
    }
}
