// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private migration transport reuses admitted routes and pinned peer CAs without client tokens.
use crate::{
    FederationAdminHttpContext, FederationDiscoverySurface, RouterMeshClient,
    SharedFederationTrustState,
};
use ramflux_node_core::{
    HOME_MIGRATION_CAPABILITY, LocalMigrationAction, LocalMigrationReply, LocalMigrationRequest,
    MIGRATION_PEER_PATH, MigrationPeerReply, MigrationPeerRequest, NodeCoreError,
    migration_hop_budget, migration_hop_deadline,
};
use ramflux_protocol::home_migration::{MAX_FRAME_BYTES, Refusal};
use std::time::Instant;
fn failure(reason: Refusal) -> NodeCoreError {
    NodeCoreError::HomeMigration(reason)
}
fn transport(_: impl std::fmt::Display) -> NodeCoreError {
    failure(Refusal::PeeringUnavailable)
}
fn enabled(discovery: &FederationDiscoverySurface) -> Result<(), NodeCoreError> {
    if discovery.node_capabilities.iter().any(|cap| cap == HOME_MIGRATION_CAPABILITY) {
        Ok(())
    } else {
        Err(failure(Refusal::PeeringUnavailable))
    }
}
struct Peer {
    key: String,
    endpoint: String,
    ca: String,
}
fn admitted(state: &SharedFederationTrustState, node: &str) -> Result<Peer, NodeCoreError> {
    let state = state.snapshot()?;
    let now = crate::now_unix_seconds()?;
    if !state.can_deliver_to(node, now)
        || !state
            .negotiated_capabilities(node)
            .is_some_and(|caps| caps.contains(HOME_MIGRATION_CAPABILITY))
    {
        return Err(failure(Refusal::PeeringUnavailable));
    }
    Ok(Peer {
        key: state.pinned_node_public_key(node).ok_or_else(|| failure(Refusal::PinMismatch))?,
        endpoint: state
            .route(node)
            .ok_or_else(|| failure(Refusal::PeeringUnavailable))?
            .endpoint
            .clone(),
        ca: state.pinned_peer_ca_cert_pem(node).ok_or_else(|| failure(Refusal::PinMismatch))?,
    })
}
pub(crate) fn local(
    request: LocalMigrationRequest,
    context: &FederationAdminHttpContext,
    received: Instant,
) -> Result<LocalMigrationReply, NodeCoreError> {
    crate::admin_http::require_admin_token(context.admin_token.as_deref(), &request.admin_token)?;
    let result = (|| {
        enabled(&context.discovery)?;
        let deadline = migration_hop_deadline(request.budget_ms, received)?;
        match request.action {
            LocalMigrationAction::PeerKey { node_id } => {
                let peer = admitted(&context.state, &node_id)?;
                migration_hop_budget(deadline)?;
                Ok(LocalMigrationReply::PeerKey { node_id, public_key: peer.key })
            }
            LocalMigrationAction::Exchange { call } => {
                if call.claimed_peer() != context.discovery.node_id
                    || call.audience() == context.discovery.node_id
                {
                    return Err(failure(Refusal::PeeringUnavailable));
                }
                let peer = admitted(&context.state, call.audience())?;
                let tls = ramflux_transport::BoundedHttpTls::new(
                    &context.router.tls,
                    "ramflux-federation",
                    Some(&[peer.ca]),
                )
                .map_err(transport)?;
                let body = serde_json::to_vec(&MigrationPeerRequest {
                    budget_ms: migration_hop_budget(deadline)?,
                    call: *call,
                })
                .map_err(transport)?;
                let bytes =
                    ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
                        endpoint: &peer.endpoint,
                        path: MIGRATION_PEER_PATH,
                        body: &body,
                        tls: Some(&tls),
                        deadline,
                        max_bytes: MAX_FRAME_BYTES,
                    })
                    .map_err(transport)?;
                let reply = ramflux_protocol::home_migration::decode(&bytes, MAX_FRAME_BYTES)
                    .map_err(transport)?;
                Ok(LocalMigrationReply::Peer { reply: Box::new(reply) })
            }
        }
    })();
    match result {
        Err(NodeCoreError::HomeMigration(reason)) => Ok(LocalMigrationReply::Refused { reason }),
        other => other,
    }
}
pub(crate) fn inbound(
    request: MigrationPeerRequest,
    state: &SharedFederationTrustState,
    router: &RouterMeshClient,
    discovery: &FederationDiscoverySurface,
    received: Instant,
) -> Result<MigrationPeerReply, NodeCoreError> {
    let result = (|| {
        enabled(discovery)?;
        if request.call.audience() != discovery.node_id
            || request.call.claimed_peer() == discovery.node_id
        {
            return Err(failure(Refusal::PeeringUnavailable));
        }
        // Admission is rechecked on this hop. The local router independently reloads the
        // signing pin and verifies the node/owner signatures under its shared job ceiling.
        admitted(state, request.call.claimed_peer())?;
        let deadline = migration_hop_deadline(request.budget_ms, received)?;
        let request =
            MigrationPeerRequest { budget_ms: migration_hop_budget(deadline)?, call: request.call };
        let tls = ramflux_transport::BoundedHttpTls::new(&router.tls, &router.server_name, None)
            .map_err(transport)?;
        let body = serde_json::to_vec(&request).map_err(transport)?;
        let bytes = ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
            endpoint: &router.endpoint,
            path: MIGRATION_PEER_PATH,
            body: &body,
            tls: Some(&tls),
            deadline,
            max_bytes: MAX_FRAME_BYTES,
        })
        .map_err(transport)?;
        ramflux_protocol::home_migration::decode(&bytes, MAX_FRAME_BYTES).map_err(transport)
    })();
    match result {
        Err(NodeCoreError::HomeMigration(reason)) => Ok(MigrationPeerReply::Refused(reason)),
        other => other,
    }
}
