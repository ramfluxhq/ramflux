// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared bounded admission and worker lifetime for federation HTTP listeners.
use ramflux_node_core::NodeCoreError;
use std::{net::TcpStream, sync::Arc, time::Instant};

pub(crate) fn connection_limit(public: bool, value: Option<&str>) -> Result<usize, NodeCoreError> {
    let name = if public { "PUBLIC" } else { "ADMIN" };
    value.unwrap_or("64").parse::<usize>().ok().filter(|v| (1..=4096).contains(v)).ok_or_else(
        || {
            NodeCoreError::ItestHttp(format!(
                "RAMFLUX_FEDERATION_{name}_MAX_CONNECTIONS must be 1..4096"
            ))
        },
    )
}
pub(crate) fn spawn_connection<T: Send + 'static>(
    stream: TcpStream,
    connections: &Arc<ramflux_node_core::ConnectionSet>,
    context: T,
    accepted_at: Instant,
    handler: impl FnOnce(&mut TcpStream, &mut T, Instant, &ramflux_node_core::ConnectionGuard)
    + Send
    + 'static,
) -> std::io::Result<bool> {
    connections.spawn(stream, context, move |mut stream, context, connection| {
        handler(&mut stream, context, accepted_at, connection);
    })
}

// Completion observes resource release in the registry; it owns no thread handle.
#[cfg(test)]
pub(crate) struct TestWorker(Arc<ramflux_node_core::ConnectionSet>);
#[cfg(test)]
impl TestWorker {
    pub(crate) fn from_connections(connections: Arc<ramflux_node_core::ConnectionSet>) -> Self {
        Self(connections)
    }
    pub(crate) fn join(self) -> std::io::Result<()> {
        let deadline = Instant::now() + std::time::Duration::from_secs(8);
        while !self.0.is_empty() {
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connections did not drain",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(())
    }
}
#[cfg(test)]
pub(crate) fn spawn_public_test_connection(
    stream: TcpStream,
    context: crate::public_http::FederationPublicHttpContext,
    connections: Arc<ramflux_node_core::ConnectionSet>,
    limits: ramflux_node_core::HttpRequestLimits,
    source_limits: &Arc<crate::public_source_limits::PublicSourceLimits>,
) -> Option<TestWorker> {
    crate::public_http::spawn_public_connection(
        stream,
        context,
        &connections,
        limits,
        source_limits,
    )
    .ok()?
    .then_some(TestWorker(connections))
}
#[cfg(test)]
pub(crate) fn spawn_admin_test_connection(
    stream: TcpStream,
    context: crate::admin_http::FederationAdminHttpContext,
    connections: Arc<ramflux_node_core::ConnectionSet>,
    limits: ramflux_node_core::HttpRequestLimits,
) -> Option<TestWorker> {
    crate::admin_http::spawn_admin_connection(stream, context, &connections, limits)
        .ok()?
        .then_some(TestWorker(connections))
}
#[cfg(test)]
pub(crate) fn spawn_test_connection(
    stream: TcpStream,
    connections: Arc<ramflux_node_core::ConnectionSet>,
    accepted_at: Instant,
    handler: impl FnOnce(&mut TcpStream, Instant) + Send + 'static,
) -> Option<TestWorker> {
    spawn_connection(
        stream,
        &connections,
        Some(handler),
        accepted_at,
        |stream, handler, at, connection| {
            let Some(_request) = connection.begin_request() else {
                return;
            };
            if let Some(handler) = handler.take() {
                handler(stream, at);
            }
        },
    )
    .ok()?
    .then_some(TestWorker(connections))
}
