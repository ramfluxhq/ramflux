// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Home-owned client: actual native history, signed discovery and a fresh pinned TLS channel.
use super::{Result, directory, error, rpc};
use crate::{FederationDiscoverySurface, RouterMeshClient};
use ramflux_protocol::home_migration::ResolveResult;
use std::sync::Arc;

#[derive(Clone)]
pub struct CenterClient {
    pub node: Arc<ramflux_node_core::NodeServiceConfig>,
    pub pin: directory::CenterPin,
    pub directory: Arc<directory::HomeDirectory>,
    pub service: directory::HomeServiceConfig,
    pub router: Arc<RouterMeshClient>,
    pub discovery: FederationDiscoverySurface,
    pub secret: Arc<ramflux_node_core::NodeSecret>,
    pub slots: Arc<tokio::sync::Semaphore>,
}

impl CenterClient {
    pub fn history(&self, root: &str) -> Result<ResolveResult> {
        let history: ResolveResult = crate::router_post_json(
            &self.router,
            directory::USERNAME_HISTORY_PATH,
            &directory::UsernameHistoryRequest { root: root.into() },
        )?;
        self.verify_history(root, &history)?;
        Ok(history)
    }

    pub fn verify_history(&self, root: &str, history: &ResolveResult) -> Result<()> {
        let first = history.predecessors.first().unwrap_or(&history.home);
        if !matches!(first.record, ramflux_protocol::home_migration::HomeRecord::Genesis { .. }) {
            return Err(error("username requires real genesis history"));
        }
        let verified = ramflux_crypto::home_migration::verify_home_chain(
            history,
            first,
            crate::now_unix_seconds()?,
        )?;
        if verified.evidence().record.account_anchor() != root
            || verified.home() != (&self.discovery.node_id, &self.discovery.node_public_key)
        {
            return Err(error("username native home mismatch"));
        }
        Ok(())
    }

    pub fn exchange_blocking(
        &self,
        root: &str,
        request: &directory::DirectoryRequest,
    ) -> Result<directory::AuthorityResponse> {
        let _slot = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| error("username exchange capacity"))?;
        self.exchange_admitted(root, request)
    }

    fn exchange_admitted(
        &self,
        root: &str,
        request: &directory::DirectoryRequest,
    ) -> Result<directory::AuthorityResponse> {
        let history = self.history(root)?;
        let now = crate::now_unix_seconds()?;
        let signer = self.secret.with_bytes(directory::DirectorySigner::from_seed);
        let service = signer.home_service(directory::HomeServiceAddress {
            version: 1,
            node: self.discovery.node_id.clone(),
            public_key: self.discovery.node_public_key.clone(),
            origin: self.service.origin.clone(),
            tls_server_name: self.service.tls_server_name.clone(),
            ca_cert_pem: self.discovery.node_ca_cert_pem.clone(),
            issued_at: now,
            expires_at: now.checked_add(86400).ok_or_else(|| error("username clock"))?,
        })?;
        let evidence = directory::ReportingEvidence {
            reach: self.directory.reach_commit(root)?,
            discovery: self.discovery.well_known_record()?,
            history,
            service,
        };
        rpc::center(&self.node, &self.pin, &signer, evidence, root, request)
    }

    pub fn revalidate(
        &self,
        home: &directory::HomeDirectory,
        root: &str,
        operation: Option<String>,
    ) -> Result<directory::LiveHomeRevalidation> {
        let request = ramflux_protocol::username_directory::HomeRevalidateRequest {
            root: root.into(),
            known_directory_epoch: home.directory_epoch(root)?,
            operation_id: operation,
            nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        };
        match self.exchange_blocking(
            root,
            &directory::DirectoryRequest::Revalidate { request: request.clone() },
        )? {
            directory::AuthorityResponse::Revalidated { result } => {
                Ok(directory::LiveHomeRevalidation::from_authenticated_reply(
                    &self.pin,
                    &request,
                    *result,
                    crate::now_unix_seconds()?,
                )?)
            }
            directory::AuthorityResponse::Refused { failure } => {
                Err(directory::CheckpointError::Directory(failure.code).into())
            }
            _ => Err(error("username revalidation response mismatch")),
        }
    }
}

impl directory::UsernameCenterClient for CenterClient {
    fn exchange<'a>(
        &'a self,
        root: &'a str,
        request: directory::DirectoryRequest,
    ) -> directory::UsernameExchange<'a> {
        let owner = self.clone();
        let root = root.to_owned();
        Box::pin(async move {
            let permit = Arc::clone(&owner.slots)
                .acquire_owned()
                .await
                .map_err(|_| directory::CheckpointError::Refused("home_exchange_stopped"))?;
            tokio::task::spawn_blocking(move || {
                // Keep cancellation from releasing the concurrency charge before IO actually ends.
                let _permit = permit;
                let mutation = matches!(request, directory::DirectoryRequest::Mutate { .. });
                let result = owner.exchange_admitted(&root, &request).map_err(|error| {
                    tracing::warn!(%error, "username centre exchange failed");
                    directory::CheckpointError::Directory(
                        ramflux_protocol::username_directory::DirectoryCode::DirectoryUnavailable,
                    )
                })?;
                if mutation && let directory::AuthorityResponse::Refused { failure } = &result {
                    tracing::info!(code = failure.code.as_str(), "username mutation refused");
                }
                Ok(result)
            })
            .await
            .map_err(|_| directory::CheckpointError::Refused("home_exchange_stopped"))?
        })
    }
}
