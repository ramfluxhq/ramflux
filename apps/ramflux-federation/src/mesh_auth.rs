// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One default-deny policy for all federation mesh transports.
use ramflux_node_core::{MeshPeerIdentity, NodeCoreError};
use std::sync::OnceLock;

pub(crate) const ENVELOPE_PATH: &str = "/s8/federation/envelope";
pub(crate) const ENVELOPE_BODY_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub(crate) enum AuthLevel {
    Anonymous,
    Peer(MeshPeerIdentity),
}
impl AuthLevel {
    pub(crate) fn from_uri(uri: Option<&str>) -> Self {
        uri.and_then(|uri| ramflux_node_core::parse_mesh_spiffe_uri(uri).ok())
            .map_or(Self::Anonymous, Self::Peer)
    }
    pub(crate) fn service(&self) -> Option<&str> {
        match self {
            Self::Anonymous => None,
            Self::Peer(peer) => Some(&peer.service_id),
        }
    }
    pub(crate) fn anonymous(&self) -> bool {
        matches!(self, Self::Anonymous)
    }
}

enum RoutePolicy {
    AnonymousSigned,
    LocalPeer(&'static [&'static str]),
    RemoteFederation,
    SameNodeRouter,
}
const SERVICES: &[&str] = &[
    "ramflux-federation",
    "ramflux-router",
    "ramflux-gateway",
    "ramflux-relay",
    "ramflux-notify",
    "ramflux-signaling",
];
fn policy(method: &str, path: &str) -> RoutePolicy {
    match (method, path) {
        ("POST", ENVELOPE_PATH) => RoutePolicy::AnonymousSigned,
        ("GET", "/healthz" | "/mvp9/federation/trust-snapshot") => RoutePolicy::LocalPeer(SERVICES),
        ("POST", ramflux_node_core::MIGRATION_PEER_PATH | crate::attachment_renewal::PEER_PATH) => {
            RoutePolicy::RemoteFederation
        }
        ("POST", ramflux_node_core::HOME_SUBMIT_FORWARD_PATH) => RoutePolicy::SameNodeRouter,
        ("POST", "/internal/retention/gc_sweep") => RoutePolicy::LocalPeer(&["ramflux-retention"]),
        _ => RoutePolicy::LocalPeer(&[]),
    }
}
pub(crate) fn admit(auth: &AuthLevel, method: &str, path: &str, local: &str) -> bool {
    match policy(method, path) {
        RoutePolicy::AnonymousSigned => true, // Certificate never supplies envelope authority.
        RoutePolicy::LocalPeer(services) => {
            matches!(auth, AuthLevel::Peer(peer) if peer.node_id == local && services.contains(&peer.service_id.as_str()))
        }
        RoutePolicy::RemoteFederation => {
            matches!(auth, AuthLevel::Peer(peer) if peer.node_id != local && peer.service_id == "ramflux-federation")
        }
        RoutePolicy::SameNodeRouter => {
            matches!(auth, AuthLevel::Peer(peer) if peer.node_id == local && peer.service_id == "ramflux-router")
        }
    }
}

pub(crate) use crate::ingress_limits::{AnonymousPermit, HandshakePermit};

fn worker_slot(
    pool: &'static OnceLock<std::sync::Arc<tokio::sync::Semaphore>>,
    capacity: usize,
) -> Result<tokio::sync::OwnedSemaphorePermit, NodeCoreError> {
    pool.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(capacity)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| NodeCoreError::Capacity { resource: "federation workers" })
}
pub(crate) fn discovery_worker() -> Result<tokio::sync::OwnedSemaphorePermit, NodeCoreError> {
    static POOL: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();
    worker_slot(&POOL, 4)
}
pub(crate) fn request_worker() -> Result<tokio::sync::OwnedSemaphorePermit, NodeCoreError> {
    static POOL: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();
    worker_slot(&POOL, 64)
}
