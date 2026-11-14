// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The gateway origin uses notify's coordinator and answers only authenticated notify reads.

use ramflux_node_core::{
    NodeCoreError,
    send_authority::{AuthorityReadRequest, AuthorityRpc, SendAuthorityError},
};
use std::{sync::Arc, time::Instant};

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
    store: &ramflux_node_core::GatewayRedbStore,
) -> anyhow::Result<()> {
    let Some(endpoint) = config.mesh.endpoints.get("notify-authority") else { return Ok(()) };
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: config.mesh.ca_cert.clone().into(),
        service_cert: config.mesh.service_cert.clone().into(),
        service_key: config.mesh.service_key.clone().into(),
    };
    store.configure_call_send_authority(Arc::new(NotifyRpc(
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

pub(crate) struct Reads {
    pub(crate) node_id: String,
    pub(crate) store: Arc<ramflux_node_core::GatewayRedbStore>,
    pub(crate) admission: Arc<tokio::sync::Semaphore>,
}

pub(crate) async fn read(
    accepted: ramflux_transport::MeshQuicAcceptedRequest,
    identity: Option<String>,
    reads: Arc<Reads>,
) -> anyhow::Result<()> {
    let peer = identity
        .as_deref()
        .and_then(|identity| ramflux_node_core::parse_mesh_spiffe_uri(identity).ok());
    if !peer.is_some_and(|peer| {
        peer.node_id == reads.node_id
            && peer.service_id == "ramflux-notify"
            && peer.instance_id.is_none()
    }) {
        accepted.write_text_response(403, "notify role required").await?;
        return Ok(());
    }
    let admission = Arc::clone(&reads.admission).try_acquire_owned();
    let result = if let (Ok(admission), Some(bytes)) = (admission, accepted.raw_body.as_ref()) {
        if bytes.len() > 8192 {
            Err(NodeCoreError::PayloadTooLarge)
        } else {
            let request: AuthorityReadRequest = ramflux_protocol::parse_i_json(bytes)?;
            request.validate()?;
            tokio::task::spawn_blocking(move || {
                let _admission = admission;
                reads.store.call_authority_read(&request)
            })
            .await
            .map_err(|e| NodeCoreError::ItestHttp(e.to_string()))
            .and_then(|result| result)
        }
    } else {
        Err(SendAuthorityError::Busy.into())
    };
    match result {
        Ok(reply) => {
            let bytes = ramflux_protocol::canonical_json_bytes(&reply)?;
            if bytes.len() > 65536 {
                accepted.write_text_response(413, "authority reply too large").await?;
            } else {
                accepted.write_json_response(200, &reply).await?;
            }
        }
        Err(error) => {
            accepted.write_text_response(503, &error.to_string()).await?;
        }
    }
    Ok(())
}
