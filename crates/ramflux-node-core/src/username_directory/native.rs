// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native custody admission reuses the shared account/root and home-genesis authority.
use crate::{MigrationNode, NodeCoreError, RouterCore, RouterRedbStore};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::{home_migration as home, username_directory as wire};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameHomeCall {
    pub request: wire::NativeUsernameRequest,
    pub history: home::ResolveResult,
}

pub const USERNAME_LOCAL_PATH: &str = "/internal/username-directory";
pub const USERNAME_HISTORY_PATH: &str = "/mvp1/username/home-history";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalUsernameCall {
    pub admin_token: String,
    pub budget_ms: u64,
    pub call: UsernameHomeCall,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameHistoryRequest {
    pub root: String,
}

/// Receives only a current native root and the shared store's real home history.
pub trait UsernameHomeBackend: Send + Sync {
    /// # Errors
    /// Returns unavailable/uncertain transport failures; never manufactures a committed reply.
    fn execute(
        &self,
        call: UsernameHomeCall,
        deadline: Instant,
    ) -> Result<wire::NativeUsernameReply, NodeCoreError>;
}

pub struct NativeUsernameService {
    node: Arc<MigrationNode>,
    backend: Arc<dyn UsernameHomeBackend>,
    center: super::CenterPin,
}

impl NativeUsernameService {
    #[must_use]
    pub fn from_home_authority(
        service: &crate::HomeMigrationService,
        backend: Arc<dyn UsernameHomeBackend>,
        center: super::CenterPin,
    ) -> Self {
        Self::new(Arc::clone(&service.node), backend, center)
    }
    pub(crate) fn matches_node(&self, node: &str, key: &str) -> bool {
        self.node.node_id() == node && self.node.public_key() == key
    }
    #[must_use]
    pub fn new(
        node: Arc<MigrationNode>,
        backend: Arc<dyn UsernameHomeBackend>,
        center: super::CenterPin,
    ) -> Self {
        Self { node, backend, center }
    }

    /// # Errors
    /// Refuses unbound sessions, wrong roots/homes, missing current native authority and genesis.
    pub fn execute(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        source: &RootQualifiedDeviceRef,
        request: wire::NativeUsernameRequest,
        now: u64,
    ) -> Result<wire::NativeUsernameReply, NodeCoreError> {
        request.validate().map_err(|e| NodeCoreError::InvalidConfiguration(e.to_string()))?;
        if !wire::enabled()
            || request.center != self.center.public_identity()
        {
            return Ok(wire::NativeUsernameReply::Refused {
                failure: super::failure(wire::DirectoryCode::OwnershipMismatch),
            });
        }
        if let Some(declaration) = &request.declaration {
            if declaration.body.account_anchor != source.root_commitment() || declaration.body.home_node != self.node.node_id() {
                return Err(NodeCoreError::Unauthorized("username declaration owner mismatch".into()));
            }
            router.ensure_home_genesis(store, &self.node, declaration, now)?;
        }
        if let wire::NativeUsernameAction::Mutate { operation, .. } = &request.action
            && operation.body.principal_commitment != source.root_commitment() {
            return Err(NodeCoreError::Unauthorized("username operation owner mismatch".into()));
        }
        let _lease = store.acquire_home_operation(source.root_commitment())?;
        let history = self.history(router, store, source.root_commitment(), now)?;
        self.backend.execute(
            UsernameHomeCall { request, history },
            Instant::now() + Duration::from_secs(10),
        )
    }

    /// Internal federation read never creates a missing genesis or imports client history.
    /// # Errors
    /// Refuses inactive roots, stale native authority, unknown history and nonterminal homes.
    pub fn history(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        root: &str,
        now: u64,
    ) -> Result<home::ResolveResult, NodeCoreError> {
        let _lease = store.acquire_home_operation(root)?;
        let publication = router.custody_record(root, now)?.ok_or_else(|| {
            NodeCoreError::Unauthorized("native username root unavailable".into())
        })?;
        router.verify_custody_possession_authority(&publication, now, true)?;
        let history = store.resolve_migration_home(root, None, home::MAX_CHAIN_RECORDS)?;
        let first = history.predecessors.first().unwrap_or(&history.home);
        let verified = ramflux_crypto::home_migration::verify_home_chain(&history, first, now)
            .map_err(|e| NodeCoreError::Unauthorized(e.to_string()))?;
        if verified.home() != (self.node.node_id(), self.node.public_key()) {
            return Err(NodeCoreError::Unauthorized(
                "username reporter is not terminal home".into(),
            ));
        }
        Ok(history)
    }
}
