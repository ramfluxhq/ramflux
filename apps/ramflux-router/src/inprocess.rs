// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-process access to the production mesh dispatcher for integration tests.
use std::sync::Arc;

/// A real router runtime backed by its durable store.
pub struct Router(crate::router_runtime::RouterHandle);
impl Router {
    /// Opens or restarts a router from its durable database.
    /// # Errors
    /// Returns database or recovery errors.
    pub fn open(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(path)?);
        let state = Arc::new(store.load_router()?.unwrap_or_default());
        Ok(Self(crate::router_runtime::RouterHandle::tokio(state, store, None)))
    }

    /// Dispatches a mesh request through the production router handler.
    /// # Errors
    /// Returns validation or durable storage errors.
    pub fn dispatch(
        &self,
        request: ramflux_transport::MeshHttpRequest,
        peer: &str,
    ) -> anyhow::Result<(u16, serde_json::Value)> {
        let response = crate::handlers::handle_mesh_request_value(request, &self.0, peer)?;
        let status = response
            .status
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing status"))?
            .parse()?;
        Ok((status, serde_json::from_slice(&response.body)?))
    }
}
