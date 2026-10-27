// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Migration runtime configuration and the router's private local-federation adapter.
use ramflux_node_core::{
    HomeMigrationMesh, HomeMigrationService, LocalMigrationAction, LocalMigrationReply,
    LocalMigrationRequest, MigrationEndpoints, MigrationPeerCall, MigrationPeerReply,
    NodeCoreError, NodeServiceConfig, migration_hop_budget,
};
use ramflux_protocol::{
    custody::{Envelope, NodeIdentityRecord, object_hash},
    home_migration::{MAX_FRAME_BYTES, Refusal},
};
use std::{sync::Arc, time::Instant};
struct LocalFederation {
    url: String,
    token: String,
}
fn failure() -> NodeCoreError {
    NodeCoreError::HomeMigration(Refusal::PeeringUnavailable)
}
impl LocalFederation {
    fn call(
        &self,
        action: LocalMigrationAction,
        deadline: Instant,
    ) -> Result<LocalMigrationReply, NodeCoreError> {
        let body = serde_json::to_vec(&LocalMigrationRequest {
            admin_token: self.token.clone(),
            budget_ms: migration_hop_budget(deadline)?,
            action,
        })
        .map_err(|_| failure())?;
        let response = ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
            endpoint: &self.url,
            path: ramflux_node_core::MIGRATION_LOCAL_PATH,
            body: &body,
            tls: None,
            deadline,
            max_bytes: MAX_FRAME_BYTES,
        })
        .map_err(|_| failure())?;
        ramflux_protocol::home_migration::decode(&response, MAX_FRAME_BYTES).map_err(|_| failure())
    }
}
impl HomeMigrationMesh for LocalFederation {
    fn peer_key(&self, node: &str, deadline: Instant) -> Result<String, NodeCoreError> {
        match self.call(LocalMigrationAction::PeerKey { node_id: node.into() }, deadline)? {
            LocalMigrationReply::PeerKey { node_id, public_key } if node_id == node => {
                Ok(public_key)
            }
            LocalMigrationReply::Refused { reason } => Err(NodeCoreError::HomeMigration(reason)),
            _ => Err(failure()),
        }
    }
    fn exchange(
        &self,
        node: &str,
        call: &MigrationPeerCall,
        deadline: Instant,
    ) -> Result<MigrationPeerReply, NodeCoreError> {
        if node != call.audience() {
            return Err(failure());
        }
        match self
            .call(LocalMigrationAction::Exchange { call: Box::new(call.clone()) }, deadline)?
        {
            LocalMigrationReply::Peer { reply } => Ok(*reply),
            LocalMigrationReply::Refused { reason } => Err(NodeCoreError::HomeMigration(reason)),
            LocalMigrationReply::PeerKey { .. } => Err(failure()),
        }
    }
}
pub(crate) fn enabled() -> anyhow::Result<bool> {
    match ramflux_node_core::environment::var("RAMFLUX_HOME_MIGRATION_ENABLED").ok().as_deref() {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => anyhow::bail!("RAMFLUX_HOME_MIGRATION_ENABLED must be 0 or 1"),
    }
}
fn required(name: &str) -> anyhow::Result<String> {
    ramflux_node_core::environment::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty() && !v.contains("${"))
        .ok_or_else(|| anyhow::anyhow!("missing {name}"))
}
pub(crate) fn configured(
    config: &NodeServiceConfig,
    record: &Envelope<NodeIdentityRecord>,
    now: u64,
) -> anyhow::Result<Option<HomeMigrationService>> {
    if !enabled()? {
        return Ok(None);
    }
    let signer = ramflux_node_core::require_node_service_signing_key(config)?;
    let ca = std::fs::read_to_string(&config.mesh.ca_cert)?;
    let url = required("RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_ORIGIN")?
        .trim_end_matches('/')
        .to_owned();
    if !url.starts_with("http://") || url.trim_end_matches('/').split('/').count() != 3 {
        anyhow::bail!(
            "RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_ORIGIN must be an internal HTTP origin"
        );
    }
    let token = required("RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_TOKEN")?;
    if token.len() > 256 {
        anyhow::bail!("RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_TOKEN exceeds its budget");
    }
    let endpoints = MigrationEndpoints {
        gateway_tcp_addr: required("RAMFLUX_CLIENT_GATEWAY_TCP_ADDR")?,
        federation_endpoint: required("RAMFLUX_FEDERATION_PUBLIC_ENDPOINT")?,
        discovery_hash: ramflux_protocol::encode_base64url([0; 32]),
        server_record_hash: object_hash(record)?,
    };
    let node =
        signer.home_migration_node(record.clone(), endpoints, now)?.require_client_discovery(ca)?;
    Ok(Some(HomeMigrationService::new(Arc::new(node), Arc::new(LocalFederation { url, token }))))
}
