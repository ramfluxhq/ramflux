// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Operation-scoped custody migration execution over independently admitted node peers.
use crate::{MigrationNode, NodeCoreError};
use ramflux_protocol::home_migration::{Request, Response};
use std::sync::{Arc, Mutex};

/// Server configuration supplies peers and transport; request JSON never supplies a trusted pin.
pub trait HomeMigrationMesh: Send + Sync {
    /// Obtain an independently admitted peer's node signing key.
    /// # Errors
    /// Rejects unknown, removed or unavailable peers.
    fn peer_key(&self, node: &str) -> Result<String, NodeCoreError>;
    /// Exchange a typed request over the admitted peer's pinned-CA mesh channel.
    /// # Errors
    /// Returns a retryable peer failure without inferring commit or noncommit.
    fn exchange(
        &self,
        _node: &str,
        _request: &crate::MigrationPeerCall,
    ) -> Result<crate::MigrationPeerReply, NodeCoreError> {
        Err(NodeCoreError::HomeMigration(
            ramflux_protocol::home_migration::Refusal::PeeringUnavailable,
        ))
    }
}
pub(crate) struct MigrationCaller {
    pub purpose: ramflux_protocol::custody::MigrationPurpose,
    pub publication: crate::CustodyPublication,
    pub source: std::net::IpAddr,
}
pub(crate) struct MigrationExecution<'a> {
    pub router: &'a crate::RouterCore,
    pub store: &'a crate::RouterRedbStore,
    pub caller: &'a MigrationCaller,
    pub authority: &'a ramflux_crypto::custody::VerifiedRecord,
    pub now: u64,
}
pub struct HomeMigrationService {
    pub(crate) node: Arc<MigrationNode>,
    pub(crate) mesh: Arc<dyn HomeMigrationMesh>,
    pub(crate) preflight: Mutex<crate::home_migration_preflight::PreflightCache>,
}
impl HomeMigrationService {
    #[must_use]
    pub fn new(node: Arc<MigrationNode>, mesh: Arc<dyn HomeMigrationMesh>) -> Self {
        Self { node, mesh, preflight: Mutex::default() }
    }
    pub(crate) fn execute(
        &self,
        router: &crate::RouterCore,
        store: &crate::RouterRedbStore,
        request: Request,
        caller: MigrationCaller,
        now: u64,
    ) -> Result<Response, ramflux_protocol::custody::CustodyRefusal> {
        use ramflux_protocol::{
            custody::CustodyRefusal,
            home_migration::{Action, ActionPayload, AttestRequest, Refusal},
        };
        let result = (|| {
            let _verification = self.node.acquire_migration_verification()?;
            let now = store.migration_clock_floor(now)?;
            request
                .validate_payload_binding()
                .map_err(|_| NodeCoreError::HomeMigration(Refusal::EvidenceRequired))?;
            if !caller.purpose.allows(request.control.body.action)
                || (request.control.body.action != Action::Attest
                    && request.control.body.audience_node != self.node.node_id())
            {
                return Err(NodeCoreError::HomeMigration(Refusal::PinMismatch));
            }
            let authority = match caller.purpose {
                ramflux_protocol::custody::MigrationPurpose::Manage => {
                    router.verify_migration_possession_authority(&caller.publication, now)?
                }
                ramflux_protocol::custody::MigrationPurpose::Read => {
                    router.verify_custody_possession_authority(&caller.publication, now, false)?
                }
            };
            ramflux_crypto::home_migration::verify_actor(&request.control, &authority, now)
                .map_err(|_| NodeCoreError::HomeMigration(Refusal::AuthorityUpdateRequired))?;
            let scope =
                MigrationExecution { router, store, caller: &caller, authority: &authority, now };
            match &request.payload {
                ActionPayload::Attest(payload) => self.attest_owner(
                    &scope,
                    &request,
                    &AttestRequest { control: request.control.clone(), payload: payload.clone() },
                ),
                ActionPayload::Prepare(prepare) => self.prepare_owner(&scope, &request, prepare),
                _ => {
                    return match self.execute_operation(&scope, &request)? {
                        Some(response) => Ok(Some(response)),
                        None => self.execute_read(&scope, &request),
                    };
                }
            }
            .map(Some)
        })();
        drop((request, caller));
        match result {
            Ok(Some(response)) => Ok(response),
            Ok(None) => Err(CustodyRefusal::Unsupported),
            Err(NodeCoreError::HomeMigration(reason)) => {
                Err(CustodyRefusal::HomeMigration { reason, nack: None })
            }
            Err(_) => Err(CustodyRefusal::PersistenceUnavailable),
        }
    }
}
