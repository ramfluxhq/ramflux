// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Operator configuration for the single notify coordinator and its exact origin identities.

use super::{SendAuthorityError, reservation::DEFAULT_RECIPIENT_ROOT_BUDGET};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfiguration {
    #[serde(default = "default_root_budget")]
    pub root_budget: u64,
    pub origins: BTreeMap<String, String>,
}

fn default_root_budget() -> u64 {
    DEFAULT_RECIPIENT_ROOT_BUDGET
}

impl AuthorityConfiguration {
    /// # Errors
    /// Rejects foreign node/service identities, empty endpoints and unfunded quotas.
    pub fn validate(&self, node_id: &str) -> Result<(), SendAuthorityError> {
        if self.origins.is_empty()
            || self.origins.len() > 1024
            || self.root_budget < u64::try_from(self.origins.len() + 1).map_err(super::storage)?
        {
            return Err(SendAuthorityError::Invalid);
        }
        for (identity, endpoint) in &self.origins {
            let peer = crate::parse_mesh_spiffe_uri(identity).map_err(super::storage)?;
            if peer.node_id != node_id
                || !matches!(peer.service_id.as_str(), "ramflux-router" | "ramflux-gateway")
                || endpoint.is_empty()
                || endpoint.len() > 512
            {
                return Err(SendAuthorityError::Invalid);
            }
        }
        Ok(())
    }

    /// Existing deployments can name the gateway's exact instance in `[send_authority.origins]`.
    /// # Errors
    /// Refuses invalid configuration rather than substituting a weaker service identity.
    pub fn for_service(config: &crate::NodeServiceConfig) -> Result<Self, SendAuthorityError> {
        if let Some(authority) = &config.send_authority {
            authority.validate(&config.node_id)?;
            return Ok(authority.clone());
        }
        let mut origins = BTreeMap::new();
        if let Some(endpoint) = config
            .mesh
            .endpoints
            .get("router-async")
            .or_else(|| config.mesh.endpoints.get("router"))
        {
            origins.insert(format!("spiffe://{}/ramflux-router", config.node_id), endpoint.clone());
        }
        if let Some(endpoint) = config.mesh.endpoints.get("gateway") {
            origins.insert(
                format!("spiffe://{}/ramflux-gateway/ramflux-gateway", config.node_id),
                endpoint.clone(),
            );
        }
        let authority = Self { root_budget: DEFAULT_RECIPIENT_ROOT_BUDGET, origins };
        authority.validate(&config.node_id)?;
        Ok(authority)
    }
}
