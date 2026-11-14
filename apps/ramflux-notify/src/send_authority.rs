// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated notify coordination surface; all blocking work stays off runtime workers.

use ramflux_node_core::{
    NodeCoreError, NotifyRedbStore,
    send_authority::{
        AuthorityConfiguration, AuthorityControlRequest, AuthorityScope, NOTIFY_CALL_READ_PATH,
        NOTIFY_OWNER_READ_PATH, SEND_AUTHORITY_BOOT_PATH, SEND_AUTHORITY_PATH,
        SEND_AUTHORITY_STATE_PATH, SendAuthorityError, reservation,
    },
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) struct Surface {
    clients: BTreeMap<String, ramflux_transport::MeshAuthorityClient>,
    budget: Arc<tokio::sync::Semaphore>,
    default_router: Option<String>,
}

fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::ItestHttp(error.to_string())
}

impl Surface {
    pub(crate) fn new(
        config: &ramflux_node_core::NodeServiceConfig,
        store: &NotifyRedbStore,
    ) -> Result<Self, NodeCoreError> {
        let authority = AuthorityConfiguration::for_service(config)?;
        let local = format!("spiffe://{}/ramflux-notify", config.node_id);
        store.send_authority().configure_local_writer(local.clone())?;
        let mut identities = authority.origins.keys().cloned().collect::<Vec<_>>();
        identities.push(local);
        store.send_authority().configure_origins(authority.root_budget, &identities)?;
        store.restore_notification_authority()?;
        let budget = Arc::new(tokio::sync::Semaphore::new(64));
        let routers = authority
            .origins
            .iter()
            .filter(|(identity, _)| {
                ramflux_node_core::parse_mesh_spiffe_uri(identity)
                    .is_ok_and(|peer| peer.service_id == "ramflux-router")
            })
            .collect::<Vec<_>>();
        let configured = config
            .mesh
            .endpoints
            .get("router-async")
            .or_else(|| config.mesh.endpoints.get("router"))
            .or_else(|| config.mesh.endpoints.get("ramflux-router"));
        let default_router = routers
            .iter()
            .find(|(_, endpoint)| configured.is_some_and(|configured| configured == *endpoint))
            .map(|(identity, _)| (*identity).clone())
            .or_else(|| {
                if routers.len() == 1 {
                    routers.first().map(|(identity, _)| (*identity).clone())
                } else {
                    None
                }
            });
        let tls = super::notify_mesh_tls_config(config);
        let mut clients = BTreeMap::new();
        for (identity, endpoint) in authority.origins {
            let peer = ramflux_node_core::parse_mesh_spiffe_uri(&identity)?;
            clients.insert(
                identity.clone(),
                ramflux_transport::MeshAuthorityClient::new(
                    endpoint,
                    identity,
                    peer.service_id,
                    tls.clone(),
                    Arc::clone(&budget),
                ),
            );
        }
        Ok(Self { clients, budget, default_router })
    }

    pub(crate) fn configure_reader(&self, store: &mut NotifyRedbStore) {
        let clients = self.clients.clone();
        let authority = store.send_authority_handle();
        let default_router = self.default_router.clone();
        store.set_send_authority_reader(move |request, deadline| {
            let role = request.scope.origin_service().ok_or(SendAuthorityError::Invalid)?;
            let identity = authority
                .origin_for_scope(&request.scope)?
                .or_else(|| (role == "ramflux-router").then(|| default_router.clone()).flatten())
                .ok_or(SendAuthorityError::Closed)?;
            let client = clients.get(&identity).ok_or(SendAuthorityError::Closed)?;
            let path = if role == "ramflux-router" {
                NOTIFY_OWNER_READ_PATH
            } else {
                NOTIFY_CALL_READ_PATH
            };
            let value = client
                .post(
                    path,
                    &serde_json::to_value(request).map_err(error)?,
                    deadline.min(Instant::now() + Duration::from_secs(5)),
                )
                .map_err(error)?;
            let bytes = ramflux_protocol::canonical_json_bytes(&value).map_err(error)?;
            if bytes.len() > 65536 {
                return Err(NodeCoreError::PayloadTooLarge);
            }
            decode(&bytes)
        });
    }

    pub(crate) fn admit(
        &self,
        identity: &str,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, NodeCoreError> {
        if !self.clients.contains_key(identity) {
            return Err(NodeCoreError::Unauthorized("unconfigured notification origin".into()));
        }
        Arc::clone(&self.budget).try_acquire_owned().map_err(|_| SendAuthorityError::Busy.into())
    }

    #[cfg(test)]
    pub(crate) fn without_origins_for_test() -> Self {
        Self {
            clients: BTreeMap::new(),
            budget: Arc::new(tokio::sync::Semaphore::new(64)),
            default_router: None,
        }
    }

    pub(crate) fn handle(
        &self,
        store: &NotifyRedbStore,
        identity: &str,
        path: &str,
        bytes: &[u8],
        _admission: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<serde_json::Value, NodeCoreError> {
        let client = self.clients.get(identity).ok_or_else(|| {
            NodeCoreError::Unauthorized("unconfigured notification origin".into())
        })?;
        if bytes.len() > 8192 {
            return Err(NodeCoreError::PayloadTooLarge);
        }
        let gate = store.send_authority();
        let value = match path {
            SEND_AUTHORITY_BOOT_PATH => {
                serde_json::to_value(gate.boot_reply(identity, &decode(bytes)?)?)
            }
            SEND_AUTHORITY_STATE_PATH => {
                serde_json::to_value(gate.state_reply(identity, &decode(bytes)?)?)
            }
            reservation::RESERVATION_PATH => {
                serde_json::to_value(store.authority_reservation_reply(
                    identity,
                    &decode(bytes)?,
                    ramflux_node_core::now_unix_seconds(),
                )?)
            }
            reservation::RESERVATIONS_PATH => {
                serde_json::to_value(gate.reservations_reply(identity, &decode(bytes)?)?)
            }
            SEND_AUTHORITY_PATH => {
                let request: AuthorityControlRequest = decode(bytes)?;
                let deadline = Instant::now() + Duration::from_secs(5);
                let reply = gate.control_reply(
                    identity,
                    &request,
                    |query| {
                        let path = match &query.scope {
                            AuthorityScope::Owner { .. } => NOTIFY_OWNER_READ_PATH,
                            AuthorityScope::Call { .. } => NOTIFY_CALL_READ_PATH,
                            _ => return Err(SendAuthorityError::Invalid.into()),
                        };
                        let value = client
                            .post(path, &serde_json::to_value(query).map_err(error)?, deadline)
                            .map_err(error)?;
                        let bytes =
                            ramflux_protocol::canonical_json_bytes(&value).map_err(error)?;
                        if bytes.len() > 65536 {
                            return Err(NodeCoreError::PayloadTooLarge);
                        }
                        decode(&bytes)
                    },
                    ramflux_node_core::now_unix_seconds(),
                )?;
                serde_json::to_value(reply)
            }
            _ => return Err(NodeCoreError::Unauthorized("unknown authority RPC".into())),
        }
        .map_err(error)?;
        Ok(value)
    }
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, NodeCoreError> {
    ramflux_protocol::parse_i_json(bytes).map_err(error)
}

pub(crate) fn is_path(path: &str) -> bool {
    path.as_bytes().starts_with(b"/internal/notify/send-authority")
}
