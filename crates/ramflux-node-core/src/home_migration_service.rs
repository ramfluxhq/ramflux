// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Operation-scoped custody migration execution over independently admitted node peers.
use crate::{MigrationNode, NodeCoreError};
use ramflux_protocol::home_migration::{Request, Response};
use std::sync::Arc;

/// Server configuration supplies peers and transport; request JSON never supplies a trusted pin.
pub trait HomeMigrationMesh: Send + Sync {
    /// Obtain an independently admitted peer's node signing key.
    /// # Errors
    /// Rejects unknown, removed or unavailable peers.
    fn peer_key(&self, node: &str) -> Result<String, NodeCoreError>;
}
pub struct HomeMigrationService {
    pub(crate) node: Arc<MigrationNode>,
    pub(crate) mesh: Arc<dyn HomeMigrationMesh>,
}
impl HomeMigrationService {
    #[must_use]
    pub fn new(node: Arc<MigrationNode>, mesh: Arc<dyn HomeMigrationMesh>) -> Self {
        Self { node, mesh }
    }
    pub(crate) fn execute(
        &self,
        _router: &crate::RouterCore,
        _store: &crate::RouterRedbStore,
        _request: Request,
        _now: u64,
    ) -> Result<Response, ramflux_protocol::custody::CustodyRefusal> {
        let _ = &self.mesh;
        Err(ramflux_protocol::custody::CustodyRefusal::Unsupported)
    }
}
