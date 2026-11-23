// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One default-deny policy for all federation mesh transports.
use ramflux_node_core::{MeshPeerIdentity, NodeCoreError};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Mutex, OnceLock},
};

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
    VerifiedPeer(&'static [&'static str]),
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
        ("GET", "/healthz" | "/mvp9/federation/trust-snapshot") => {
            RoutePolicy::VerifiedPeer(SERVICES)
        }
        ("POST", ramflux_node_core::MIGRATION_PEER_PATH | crate::attachment_renewal::PEER_PATH) => {
            RoutePolicy::VerifiedPeer(&["ramflux-federation"])
        }
        ("POST", ramflux_node_core::HOME_SUBMIT_FORWARD_PATH) => RoutePolicy::SameNodeRouter,
        ("POST", "/internal/retention/gc_sweep") => {
            RoutePolicy::VerifiedPeer(&["ramflux-retention"])
        }
        _ => RoutePolicy::VerifiedPeer(&[]),
    }
}
pub(crate) fn admit(auth: &AuthLevel, method: &str, path: &str, local: &str) -> bool {
    match policy(method, path) {
        RoutePolicy::AnonymousSigned => true, // Certificate never supplies envelope authority.
        RoutePolicy::VerifiedPeer(services) => {
            auth.service().is_some_and(|service| services.contains(&service))
        }
        RoutePolicy::SameNodeRouter => {
            matches!(auth, AuthLevel::Peer(peer) if peer.node_id == local && peer.service_id == "ramflux-router")
        }
    }
}

#[derive(Default)]
struct Limits {
    connections: BTreeMap<IpAddr, usize>,
    requests: BTreeMap<IpAddr, usize>,
}
static LIMITS: OnceLock<Mutex<Limits>> = OnceLock::new();
pub(crate) struct AnonymousPermit {
    ip: IpAddr,
    connection: bool,
}
impl AnonymousPermit {
    pub(crate) fn acquire(
        auth: &AuthLevel,
        ip: IpAddr,
        connection: bool,
    ) -> Result<Option<Self>, NodeCoreError> {
        if !auth.anonymous() {
            return Ok(None);
        }
        let mut limits = LIMITS
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| crate::inbound_trust::refused())?;
        let (rows, total, per_ip) = if connection {
            (&mut limits.connections, 16, 2)
        } else {
            (&mut limits.requests, 8, 2)
        };
        if rows.values().sum::<usize>() >= total || rows.get(&ip).copied().unwrap_or(0) >= per_ip {
            return Err(NodeCoreError::Capacity { resource: "anonymous federation ingress" });
        }
        *rows.entry(ip).or_default() += 1;
        Ok(Some(Self { ip, connection }))
    }
}
impl Drop for AnonymousPermit {
    fn drop(&mut self) {
        if let Ok(mut limits) = LIMITS.get_or_init(Mutex::default).lock() {
            let rows = if self.connection { &mut limits.connections } else { &mut limits.requests };
            if let Some(count) = rows.get_mut(&self.ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    rows.remove(&self.ip);
                }
            }
        }
    }
}

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
pub(crate) fn handshake_worker() -> Result<tokio::sync::OwnedSemaphorePermit, NodeCoreError> {
    static POOL: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();
    worker_slot(&POOL, 16)
}
