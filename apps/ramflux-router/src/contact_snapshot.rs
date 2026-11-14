// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original discovery documents come from this node's configured mutual-TLS federation service.
use ramflux_node_core::{
    NodeCoreError, NodeServiceConfig,
    contact_reach::{ReachError, ReachSourceDocuments},
};
use ramflux_protocol::contact_reach::{self as wire, Discovery};
use ramflux_transport::{BoundedHttpGet, BoundedHttpTls};
use std::time::Instant;
pub(crate) fn configure(
    service: ramflux_node_core::CustodyService,
    config: &NodeServiceConfig,
) -> anyhow::Result<ramflux_node_core::CustodyService> {
    if !wire::enabled() {
        return Ok(service);
    }
    let documents = std::sync::Arc::new(SourceDocuments::configured(config)?);
    Ok(service
        .with_reach_source_documents(documents.clone())?
        .with_reach_peer_resolver(documents.clone())?
        .with_reach_source_submitter(documents)?)
}
pub(crate) struct SourceDocuments {
    node: String,
    endpoint: String,
    tls: BoundedHttpTls,
}
fn storage(error: impl std::fmt::Display) -> ReachError {
    ReachError::Storage(NodeCoreError::ItestHttp(error.to_string()))
}
impl SourceDocuments {
    pub(crate) fn configured(config: &NodeServiceConfig) -> anyhow::Result<Self> {
        let endpoint = config
            .mesh
            .endpoints
            .get("federation")
            .ok_or_else(|| anyhow::anyhow!("reach requires its own federation mesh endpoint"))?
            .clone();
        anyhow::ensure!(!endpoint.starts_with("http://"), "reach discovery requires mutual TLS");
        let tls = BoundedHttpTls::new(
            &crate::serve::mesh_tls_config(config),
            "ramflux-federation",
            None,
        )?
        .with_mesh_peer(&config.node_id, "ramflux-federation")?;
        Ok(Self { node: config.node_id.clone(), endpoint, tls })
    }
    fn read_document(&self, path: &str, deadline: Instant) -> Result<Vec<u8>, ReachError> {
        ramflux_transport::bounded_http_get(BoundedHttpGet {
            endpoint: &self.endpoint,
            path,
            tls: Some(&self.tls),
            deadline,
            max_bytes: 1024 * 1024,
        })
        .map_err(storage)
    }
}
impl ReachSourceDocuments for SourceDocuments {
    fn continuity(&self, deadline: Instant) -> Result<Vec<serde_json::Value>, ReachError> {
        let bytes = self.read_document("/.well-known/ramflux/continuity", deadline)?;
        let document: wire::NodeContinuityDocument = wire::decode(&bytes, 1024 * 1024)?;
        document.validate()?;
        if document.node_id != self.node {
            return Err(ReachError::Refused(wire::Reason::ForeignSnapshotInvalid));
        }
        document
            .rotations
            .into_iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)
    }
    fn read(&self, deadline: Instant) -> Result<Discovery, ReachError> {
        let client = self.read_document("/.well-known/ramflux/client", deadline)?;
        let server = self.read_document("/.well-known/ramflux/server", deadline)?;
        let client: ramflux_protocol::WellKnownClientRecord =
            ramflux_protocol::custody::decode(&client, 1024 * 1024)?;
        let server = ramflux_protocol::parse_i_json(&server)?;
        wire::original_document(&client, 1024 * 1024)?;
        wire::original_document(&server, 1024 * 1024)?;
        Ok(Discovery { client, server })
    }
}

impl ramflux_node_core::contact_reach::ReachPeerResolver for SourceDocuments {
    fn query(
        &self,
        request: &wire::PeerQueryRequest,
        deadline: Instant,
    ) -> Result<wire::PeerQueryResponse, ReachError> {
        request.validate()?;
        let body = ramflux_protocol::canonical_json_bytes(request)?;
        let bytes = ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
            endpoint: &self.endpoint,
            path: wire::FOREIGN_PATH,
            body: &body,
            tls: Some(&self.tls),
            deadline,
            max_bytes: wire::MAX_FRAME_BYTES,
        })
        .map_err(storage)?;
        let response = wire::decode(&bytes, wire::MAX_FRAME_BYTES)?;
        request.validate_response(&response)?;
        Ok(response)
    }
}

impl ramflux_node_core::contact_reach::ReachSourceSubmitter for SourceDocuments {
    fn submit(
        &self,
        request: &wire::SourceSubmitRequest,
        deadline: Instant,
    ) -> Result<wire::SourceSubmitResponse, ReachError> {
        request.validate()?;
        let mut next = request.clone();
        next.remaining_ms = deadline
            .checked_duration_since(Instant::now())
            .and_then(|left| u64::try_from(left.as_millis()).ok())
            .filter(|ms| (1..=10_000).contains(ms))
            .ok_or(ReachError::Refused(wire::Reason::ForeignUnavailable))?;
        let body = ramflux_protocol::canonical_json_bytes(&next)?;
        let bytes = ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
            endpoint: &self.endpoint,
            path: wire::FOREIGN_PATH,
            body: &body,
            tls: Some(&self.tls),
            deadline,
            max_bytes: wire::MAX_SUBMIT_RESPONSE_BYTES,
        })
        .map_err(storage)?;
        let response = wire::decode(&bytes, wire::MAX_SUBMIT_RESPONSE_BYTES)?;
        request.validate_response(&response)?;
        Ok(response)
    }
}
