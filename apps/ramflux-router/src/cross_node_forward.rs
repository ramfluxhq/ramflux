// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-node mTLS handoff to the federation's ordinary outbound envelope flow.
use ramflux_node_core::{FederatedEnvelopeForwardResponse, HomeSubmitForward, NodeCoreError};
use ramflux_transport::{MeshHttpClient, MeshTlsConfig, RawMeshPost};
use std::time::{Duration, Instant};

const FORWARD_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REPLY_BYTES: usize = 1024 * 1024;

pub(crate) struct Client {
    endpoint: String,
    tls: MeshTlsConfig,
    http: MeshHttpClient,
}

pub(crate) fn configure(
    config: &ramflux_node_core::NodeServiceConfig,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<()> {
    let Some(endpoint) = config.mesh.endpoints.get("federation").filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    router.install_cross_node_forward(Client {
        endpoint: endpoint.clone(),
        tls: MeshTlsConfig {
            ca_cert: config.mesh.ca_cert.clone().into(),
            service_cert: config.mesh.service_cert.clone().into(),
            service_key: config.mesh.service_key.clone().into(),
        },
        http: MeshHttpClient::new(),
    })
}

impl Client {
    pub(crate) fn forward(
        &self,
        request: &HomeSubmitForward,
    ) -> Result<FederatedEnvelopeForwardResponse, NodeCoreError> {
        let deadline = Instant::now() + FORWARD_TIMEOUT;
        let body = serde_json::to_vec(request).map_err(forward_error)?;
        let response = self
            .http
            .post_raw(&RawMeshPost {
                endpoint: &self.endpoint,
                path: ramflux_node_core::HOME_SUBMIT_FORWARD_PATH,
                tls: &self.tls,
                server_name: "ramflux-federation",
                headers: &[],
                body: &body,
                max_response_bytes: MAX_REPLY_BYTES,
                deadline,
            })
            .map_err(forward_error)?;
        if !(200..300).contains(&response.status) {
            return Err(NodeCoreError::ItestHttp(format!(
                "federation mesh refused (HTTP {})",
                response.status
            )));
        }
        ramflux_protocol::parse_i_json(&response.body).map_err(forward_error)
    }
}

fn forward_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::ItestHttp(error.to_string())
}
