// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Router owner coordination uses the notify service's exact authenticated mesh identity.

use ramflux_node_core::{
    NodeCoreError,
    send_authority::{AuthorityReadRequest, AuthorityRpc, SendAuthorityError},
};
use std::{sync::Arc, time::Instant};

static ADMISSION: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();

struct NotifyRpc(ramflux_transport::MeshAuthorityClient);
impl AuthorityRpc for NotifyRpc {
    fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
        deadline: Instant,
    ) -> Result<serde_json::Value, NodeCoreError> {
        self.0.post(path, body, deadline).map_err(|error| match error {
            ramflux_transport::TransportError::BackpressureRejected { .. } => {
                SendAuthorityError::Busy.into()
            }
            error => NodeCoreError::ItestHttp(error.to_string()),
        })
    }
}

pub(crate) fn configure(
    config: &ramflux_node_core::NodeServiceConfig,
    store: &ramflux_node_core::RouterRedbStore,
) -> anyhow::Result<()> {
    let Some(endpoint) = config.mesh.endpoints.get("notify-authority") else { return Ok(()) };
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    };
    store.configure_owner_send_authority(Arc::new(NotifyRpc(
        ramflux_transport::MeshAuthorityClient::new(
            endpoint.clone(),
            format!("spiffe://{}/ramflux-notify", config.node_id),
            "ramflux-notify".into(),
            tls,
            Arc::new(tokio::sync::Semaphore::new(64)),
        ),
    )))?;
    Ok(())
}

pub(crate) async fn read(
    bytes: &[u8],
    router: &crate::router_runtime::RouterHandle,
    peer: &ramflux_node_core::MeshPeerIdentity,
) -> anyhow::Result<ramflux_transport::GatewayQuicResponse> {
    if peer.node_id != router.node_id()
        || peer.service_id != "ramflux-notify"
        || peer.instance_id.is_some()
    {
        anyhow::bail!("same-node notify role required");
    }
    if bytes.len() > 8192 {
        anyhow::bail!("authority request too large");
    }
    let admission = Arc::clone(ADMISSION.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(64))))
        .try_acquire_owned()?;
    let request: AuthorityReadRequest = ramflux_protocol::parse_i_json(bytes)?;
    request.validate()?;
    let router = router.clone();
    let reply = tokio::task::spawn_blocking(move || {
        let _admission = admission;
        router.store().notify_owner_read(&request)
    })
    .await??;
    let bytes = ramflux_protocol::canonical_json_bytes(&reply)?;
    if bytes.len() > 65536 {
        anyhow::bail!("authority reply too large");
    }
    Ok(ramflux_transport::GatewayQuicResponse { status: 200, body: serde_json::to_value(reply)? })
}
