// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Existing native custody sessions dispatch username work to the local authenticated home.
use ramflux_node_core::{HomeMigrationService, NodeCoreError, username_directory as directory};
use std::{sync::Arc, time::Instant};

struct Backend {
    origin: String,
    token: String,
}

impl directory::UsernameHomeBackend for Backend {
    fn execute(
        &self,
        call: directory::UsernameHomeCall,
        deadline: Instant,
    ) -> Result<ramflux_protocol::username_directory::NativeUsernameReply, NodeCoreError> {
        let local = directory::LocalUsernameCall {
            admin_token: self.token.clone(),
            budget_ms: ramflux_node_core::migration_hop_budget(deadline)?,
            call,
        };
        let body = ramflux_protocol::canonical_json_bytes(&local).map_err(|_| unavailable())?;
        if body.len() > directory::MAX_REPORT_BYTES + 16384 {
            return Err(unavailable());
        }
        let bytes = ramflux_transport::bounded_http_post(ramflux_transport::BoundedHttpPost {
            endpoint: &self.origin,
            path: directory::USERNAME_LOCAL_PATH,
            body: &body,
            tls: None,
            deadline,
            max_bytes: directory::MAX_REPORT_BYTES + 16384,
        })
        .map_err(|_| unavailable())?;
        ramflux_protocol::home_migration::decode(&bytes, directory::MAX_REPORT_BYTES + 16384)
            .map_err(|_| unavailable())
    }
}

fn unavailable() -> NodeCoreError {
    NodeCoreError::Unauthorized("username home unavailable".into())
}

pub(crate) fn configured(
    migration: Option<&HomeMigrationService>,
) -> anyhow::Result<Option<directory::NativeUsernameService>> {
    let Some(config) = directory::DirectoryConfig::from_env()? else {
        return Ok(None);
    };
    anyhow::ensure!(
        matches!(config.role, directory::DirectoryRole::Home { .. }),
        "router username role must be home"
    );
    anyhow::ensure!(
        ramflux_protocol::username_directory::enabled(),
        "complete username path is not released"
    );
    let authority = migration.ok_or_else(|| {
        anyhow::anyhow!("username home requires configured native home authority")
    })?;
    let required = |name| ramflux_node_core::environment::var(name).map_err(anyhow::Error::from);
    let origin = required("RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_ORIGIN")?;
    anyhow::ensure!(
        origin.starts_with("http://")
            && origin.split('/').count() == 3
            && !origin.contains('@')
            && !origin.contains('?')
            && !origin.contains('#'),
        "local username origin must be explicit internal HTTP"
    );
    let token = required("RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_TOKEN")?;
    anyhow::ensure!(!token.is_empty() && token.len() <= 256, "local username token required");
    Ok(Some(directory::NativeUsernameService::from_home_authority(
        authority,
        Arc::new(Backend { origin, token }),
        config.center,
    )))
}
