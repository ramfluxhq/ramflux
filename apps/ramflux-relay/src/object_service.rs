// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reusable authenticated object data plane; the process listener uses the same route owner.
use ramflux_node_core::{RelayCacheState, RelayRedbStore, RelayTrustSnapshotCache};
use ramflux_transport::{GatewayQuicRequest, GatewayQuicResponse};
use std::sync::{Arc, Mutex};

/// Object operations verify the relay's pinned trust, requester proof and exact object binding.
/// Supplying a request never supplies or replaces the pinned authority used by this owner.
#[derive(Clone)]
pub struct RelayObjectService {
    node: Arc<str>,
    trust: Arc<Mutex<RelayTrustSnapshotCache>>,
    store: Arc<RelayRedbStore>,
    state: Arc<Mutex<RelayCacheState>>,
}
impl RelayObjectService {
    #[must_use]
    pub fn new(
        node: Arc<str>,
        trust: Arc<Mutex<RelayTrustSnapshotCache>>,
        store: Arc<RelayRedbStore>,
        state: Arc<Mutex<RelayCacheState>>,
    ) -> Self {
        Self { node, trust, store, state }
    }
    /// Execute the ordinary signed v3 request against the actual durable relay store.
    #[must_use]
    pub fn handle(&self, request: &GatewayQuicRequest, now: u64) -> GatewayQuicResponse {
        let Ok(trust) = self.trust.lock() else {
            return crate::client_quic::relay_client_quic_response(
                503,
                serde_json::json!({"error":"relay trust unavailable"}),
            );
        };
        crate::client_quic::relay_client_quic_route(
            request,
            &trust,
            &self.store,
            &self.state,
            &self.node,
            now,
        )
    }
}
