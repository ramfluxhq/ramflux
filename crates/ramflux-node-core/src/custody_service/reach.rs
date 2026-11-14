// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source snapshots enter only from the node's own authenticated federation proxy.
use super::{CustodyRefusal, CustodyService, RouterCore, RouterRedbStore};
use crate::{NodeCoreError, contact_reach::ReachSourceDocuments};
use ramflux_protocol::contact_reach::{
    self as wire, PeerQueryRequest, PeerQueryResponse, PeerQueryResult, PeerQueryResultKind, Reason,
};
use std::sync::Arc;
impl CustodyService {
    /// Attach the locally configured discovery reader without accepting an owner-selected origin.
    /// # Errors
    /// Refuses activation without the matching home service and its verified node signer.
    pub fn with_reach_source_documents(
        mut self,
        documents: Arc<dyn ReachSourceDocuments>,
    ) -> Result<Self, CustodyRefusal> {
        if wire::enabled() && self.reach.is_none() {
            return Err(CustodyRefusal::BindingRefused);
        }
        if let Some(service) = self.reach.take() {
            self.reach = Some(service.with_source_documents(documents));
        }
        Ok(self)
    }
    /// Attach only the configured node's authenticated federation query adapter.
    /// # Errors
    /// Refuses reach activation without its verified home signer.
    pub fn with_reach_peer_resolver(
        mut self,
        resolver: Arc<dyn crate::contact_reach::ReachPeerResolver>,
    ) -> Result<Self, CustodyRefusal> {
        if wire::enabled() && self.reach.is_none() {
            return Err(CustodyRefusal::BindingRefused);
        }
        if let Some(service) = self.reach.take() {
            self.reach = Some(service.with_peer_resolver(resolver));
        }
        Ok(self)
    }
    /// Attach this node's configured mutual-TLS source Submit transport.
    /// # Errors
    /// Refuses reach activation without its verified home service.
    pub fn with_reach_source_submitter(
        mut self,
        submitter: Arc<dyn crate::contact_reach::ReachSourceSubmitter>,
    ) -> Result<Self, CustodyRefusal> {
        if wire::enabled() && self.reach.is_none() {
            return Err(CustodyRefusal::BindingRefused);
        }
        if let Some(service) = self.reach.take() {
            self.reach = Some(service.with_source_submitter(submitter));
        }
        Ok(self)
    }
    /// Configure the own-node cost transport; account/session authentication remains in the home.
    /// # Errors
    /// Refuses activation without a verified receiving-home signer.
    pub fn with_reach_cost_transport(
        mut self,
        transport: Arc<dyn crate::contact_reach::ReachCostTransport>,
    ) -> Result<Self, CustodyRefusal> {
        if wire::enabled() && self.reach.is_none() {
            return Err(CustodyRefusal::BindingRefused);
        }
        if let Some(service) = self.reach.take() {
            self.reach = Some(service.with_cost_transport(transport));
        }
        Ok(self)
    }

    /// Issue after the listener verifies the own-federation role and its peer budget admission.
    /// # Errors
    /// Refuses malformed input; executor failures retain the pinned uncertain/definite error arms.
    pub fn contact_cost(
        &self,
        store: &RouterRedbStore,
        request: &wire::CostRequest,
        now: u64,
    ) -> Result<wire::CostResponse, NodeCoreError> {
        request.validate().map_err(|error| NodeCoreError::Unauthorized(error.to_string()))?;
        let result = self.reach.as_ref().map_or_else(wire::unavailable, |service| {
            service
                .issue_cost_from_proxy(store, request, now)
                .unwrap_or_else(|error| crate::contact_reach::owner_error(&error))
        });
        Ok(wire::CostResponse { request_id: request.request_id.clone(), result })
    }

    /// Dispatch a public read after the mesh listener checks the exact local node/service identity.
    /// # Errors
    /// Refuses malformed carrier input; valid requests retain typed correlated results.
    pub fn contact_snapshot(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        request: &PeerQueryRequest,
        now: u64,
    ) -> Result<PeerQueryResponse, NodeCoreError> {
        request.validate().map_err(|error| NodeCoreError::Unauthorized(error.to_string()))?;
        if let Some(service) = &self.reach {
            return service
                .public_query_from_proxy(router, store, request, now)
                .map_err(|error| NodeCoreError::Unauthorized(error.to_string()));
        }
        Ok(PeerQueryResponse {
            kind: PeerQueryResultKind::QueryResult,
            request_id: request.request_id.clone(),
            result: PeerQueryResult::Error {
                reason: Reason::FeatureDisabled,
                retry_after_ms: None,
                current_revision: None,
            },
        })
    }
}
