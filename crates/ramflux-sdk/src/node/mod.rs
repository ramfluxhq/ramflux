// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Daemon-level client node discovery and endpoint selection.
use crate::prelude::*;
use ramflux_protocol::{WellKnownClientRecord, verify_client_discovery_record};
use serde::{Deserialize, Serialize};
mod discovery;
pub(crate) mod probe;
pub use probe::{GatewayProbe, probe_gateway_pre_account};
mod profile;
mod store;
pub(crate) use discovery::{discovery_origin, fetch_client_record};
pub use profile::{NodeGateway, NodePinSource, NodeProfile, NodeRelay};
pub(crate) use store::{NodeStore, PendingNode};
pub(crate) async fn resolve_node_addr(addr: &str) -> Result<SocketAddr, SdkError> {
    tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(addr))
        .await
        .map_err(|_| node_error("node DNS lookup timed out"))??
        .next()
        .ok_or_else(|| node_error("node address has no resolved addresses"))
}

pub(crate) fn node_error(message: &str) -> SdkError {
    SdkError::LocalBus(message.to_owned())
}

pub(crate) async fn profile_relay_options(
    id: &str,
    relay: &NodeRelay,
    ca: &Path,
    principal: &str,
) -> Result<RelayTransferOptions, SdkError> {
    Ok(RelayTransferOptions {
        relay_endpoint: format!("quic://{}", relay.quic_addr),
        token_provider: crate::object::RelayTokenProvider::GatewayIssued,
        interrupt_after_chunks: None,
        relay_quic_peer_addr: Some(resolve_node_addr(&relay.quic_addr).await?.to_string()),
        relay_quic_server_name: Some(relay.server_name.clone()),
        relay_quic_ca_cert: Some(ca.to_path_buf()),
        relay_owner_home_node_id: Some(id.to_owned()),
        relay_owner_principal_id: Some(principal.to_owned()),
        relay_audience_node_id: Some(id.to_owned()),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use tests::DISCOVERY_CLIENT;
