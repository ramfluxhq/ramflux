// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared bounded admission and worker lifetime for federation HTTP listeners.
use ramflux_node_core::NodeCoreError;
use std::{
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

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
struct ConnectionPermit(Arc<AtomicUsize>);
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(crate) fn spawn_connection(
    mut stream: TcpStream,
    active: Arc<AtomicUsize>,
    limit: usize,
    handler: impl FnOnce(&mut TcpStream, Instant) + Send + 'static,
) -> Option<std::thread::JoinHandle<()>> {
    let accepted_at = Instant::now();
    if active
        .try_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |n| {
                if n < limit { Some(n + 1) } else { None }
            },
        )
        .is_err()
    {
        // Refuse before spawning; the accept loop never waits for a drain or request body.
        let _ = ramflux_node_core::write_http_response_with_deadline(
            &mut stream,
            "503 Service Unavailable",
            "text/plain; charset=utf-8",
            b"service unavailable",
            accepted_at + Duration::from_secs(1),
        );
        return None;
    }
    let permit = ConnectionPermit(active);
    match std::thread::Builder::new().spawn(move || {
        let _permit = permit;
        handler(&mut stream, accepted_at);
    }) {
        Ok(worker) => Some(worker),
        Err(error) => {
            tracing::warn!(%error, "federation HTTP worker unavailable");
            None
        }
    }
}
