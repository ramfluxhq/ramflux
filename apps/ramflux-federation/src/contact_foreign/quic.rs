// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bound queued plus running QUIC contact work before copying request or service handles.
use super::{Context, PeerContext, Response};
use crate::RouterMeshClient;
use ramflux_node_core::{FederationRedbStore, NodeCoreError};
use ramflux_transport::GatewayQuicRequest;
use std::{sync::Arc, time::Instant};
use tokio::sync::{Semaphore, SemaphorePermit};

pub(crate) struct Job {
    _slot: SemaphorePermit<'static>,
    request: GatewayQuicRequest,
    node: crate::FederationDiscoverySurface,
    router: Arc<RouterMeshClient>,
    store: Arc<FederationRedbStore>,
    peer_uri: Option<String>,
    peer_ip: Option<std::net::IpAddr>,
    received: Instant,
}
impl Job {
    pub(crate) fn prepare(
        request: &GatewayQuicRequest,
        node: &crate::FederationDiscoverySurface,
        router: &Arc<RouterMeshClient>,
        store: &Arc<FederationRedbStore>,
        peer: PeerContext<'_>,
        received: Instant,
    ) -> Result<Self, Response> {
        static WORKERS: Semaphore = Semaphore::const_new(4);
        let slot = WORKERS.try_acquire().map_err(|_| super::failure(503, "foreign_capacity"))?;
        // The shared frame decoder already checked I-JSON; the worker strictly dispatches
        // Query at 8192 bytes and Submit at the existing aggregate frame ceiling.
        let bytes = ramflux_protocol::canonical_json_bytes(&request.body)
            .map_err(|_| super::failure(400, "foreign_invalid_frame"))?;
        if bytes.len() > ramflux_protocol::contact_reach::MAX_FRAME_BYTES {
            return Err(super::failure(413, "foreign_payload_too_large"));
        }
        Ok(Self {
            _slot: slot,
            request: request.clone(),
            node: node.clone(),
            router: Arc::clone(router),
            store: Arc::clone(store),
            peer_uri: peer.uri.map(str::to_owned),
            peer_ip: peer.ip,
            received,
        })
    }
    pub(crate) fn run(self) -> Result<Option<Response>, NodeCoreError> {
        let body = ramflux_protocol::canonical_json_bytes(&self.request.body)
            .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
        super::route(
            &self.request.method,
            &self.request.path,
            &body,
            Context {
                node: &self.node,
                router: &self.router,
                store: &self.store,
                peer: PeerContext { uri: self.peer_uri.as_deref(), ip: self.peer_ip },
                received: self.received,
            },
        )
    }
}
