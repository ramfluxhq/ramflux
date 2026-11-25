// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary home storage, autonomous reconciliation and authenticated local native dispatch.
use super::{Result, client::CenterClient, directory, error, flag, refuse, warn_drop, wire};
use crate::{FederationDiscoverySurface, RouterMeshClient};
use ramflux_protocol::username_directory as w;
use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

static HOME: OnceLock<Arc<HomeService>> = OnceLock::new();

pub(super) struct HomeService {
    pub directory: Arc<directory::HomeDirectory>,
    pub client: Arc<CenterClient>,
    pub coordinator: Arc<directory::HomeCoordinator>,
    pub private: Vec<directory::PrivateHomePin>,
    pub budgets: Arc<super::home_profile::HandlerBudgets>,
}

pub(crate) fn start(
    node: &ramflux_node_core::NodeServiceConfig,
    router: Arc<RouterMeshClient>,
    discovery: &FederationDiscoverySurface,
) -> Result<()> {
    let Some(config) = directory::DirectoryConfig::from_env()? else {
        return Ok(());
    };
    let directory::DirectoryRole::Home { database, service } = config.role else {
        return refuse("federation home role");
    };
    if !w::enabled() {
        return refuse("complete username path is not released");
    }
    let secret = Arc::new(ramflux_node_core::NodeSecret::required_env(
        "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE",
    )?);
    let public = secret.with_bytes(ramflux_crypto::public_key_base64url_from_seed);
    if public != discovery.node_public_key || node.node_id != discovery.node_id {
        return refuse("username home signer mismatch");
    }
    let private = if let Some(path) = &service.private_peers_file {
        let bytes = super::tls::read_file(path, 32768)?;
        let pins: Vec<directory::PrivateHomePin> = wire::decode(&bytes)?;
        if pins.len() > 64 {
            return refuse("private username pins bound");
        }
        let mut seen = std::collections::BTreeSet::new();
        for pin in &pins {
            pin.validate()?;
            if !seen.insert((&pin.node, &pin.public_key, &pin.origin)) {
                return refuse("duplicate private username pin");
            }
        }
        pins
    } else {
        Vec::new()
    };
    let home = if flag("--username-home-initialize") {
        directory::HomeDirectory::initialize(&database, &node.node_id, config.center.clone())?
    } else {
        directory::HomeDirectory::open(&database, &node.node_id, config.center.clone())?
    };
    let home = Arc::new(home);
    let client = Arc::new(CenterClient {
        node: Arc::new(node.clone()),
        pin: config.center,
        directory: Arc::clone(&home),
        service,
        router,
        discovery: discovery.clone(),
        secret,
        slots: Arc::new(tokio::sync::Semaphore::new(16)),
    });
    let port: Arc<dyn directory::UsernameCenterClient> = client.clone();
    let coordinator = Arc::new(directory::HomeCoordinator::new(Arc::clone(&home), port));
    let owner = Arc::new(HomeService {
        directory: home,
        client,
        coordinator,
        private,
        budgets: Arc::new(super::home_profile::HandlerBudgets::default()),
    });
    super::home_profile::listen(Arc::clone(&owner))?;
    HOME.set(Arc::clone(&owner)).map_err(|_| error("username home already configured"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(16)
        .enable_all()
        .build()?;
    ramflux_node_core::spawn_service_worker("username-home-coordinator", move |shutdown| {
        runtime.block_on(async move {
            let renew = Arc::clone(&owner);
            let cancel = shutdown.clone();
            let heartbeat = tokio::spawn(async move {
                renew.renew_locator(cancel).await;
            });
            if let Err(error) = owner.coordinator.clone().run(shutdown).await {
                tracing::error!(%error, "username home reconciliation stopped");
            }
            heartbeat.abort();
            let _ = heartbeat.await;
        });
    })?;
    Ok(())
}

pub(crate) fn local(
    bytes: &[u8],
    context: &crate::FederationAdminHttpContext,
    received: Instant,
) -> Result<w::NativeUsernameReply> {
    if bytes.len() > directory::MAX_REPORT_BYTES + 16384 {
        return refuse("local username frame bound");
    }
    let local: directory::LocalUsernameCall = wire::decode(bytes)?;
    crate::admin_http::require_admin_token(context.admin_token.as_deref(), &local.admin_token)?;
    let deadline = ramflux_node_core::migration_hop_deadline(local.budget_ms, received)?;
    let home = HOME.get().ok_or_else(|| error("username home unavailable"))?;
    let reply = home.execute(local.call, deadline);
    if Instant::now() >= deadline {
        return refuse("local username deadline");
    }
    match reply {
        Ok(reply) => Ok(reply),
        Err(error) => {
            if let Some(directory::CheckpointError::Directory(code)) =
                error.downcast_ref::<directory::CheckpointError>()
            {
                return Ok(w::NativeUsernameReply::Refused { failure: directory::failure(*code) });
            }
            tracing::warn!(%error, "username home operation unavailable");
            warn_drop("centre_exchange", home.client.pin.url.as_str(), "exchange", &error);
            Ok(w::NativeUsernameReply::Refused {
                failure: directory::failure(w::DirectoryCode::DirectoryUnavailable),
            })
        }
    }
}

impl HomeService {
    fn execute(
        &self,
        call: directory::UsernameHomeCall,
        deadline: Instant,
    ) -> Result<w::NativeUsernameReply> {
        call.request.validate()?;
        if call.request.center != self.client.pin.public_identity() {
            return refuse("independent username centre pins disagree");
        }
        let root = call.history.home.record.account_anchor();
        let _permit = self.budgets.acquire(root)?;
        self.client.verify_history(root, &call.history)?;
        let master = ramflux_crypto::verifying_key_from_base64url(
            &call.history.home.authority.record.body.master_certificate.body.master_public_key,
        )?;
        if ramflux_crypto::identity_root_commitment(&master) != *root {
            return refuse("username master/root mismatch");
        }
        self.directory.enrol(root)?;
        match call.request.action {
            action @ (w::NativeUsernameAction::ReplyAuthorize { .. }
            | w::NativeUsernameAction::ReachGet
            | w::NativeUsernameAction::ReachSet { .. }) => {
                self.execute_reach(root, &call.authority, &call.history, action)
            }
            w::NativeUsernameAction::Recover { operation, profile } => {
                let native = &call.history.home.authority.record.body;
                if profile.body.principal_id != native.principal_id
                    || profile.body.display_name != native.profile.display_name
                    || profile.body.kind
                        != w::ProfileKind::from_principal_kind(native.principal_kind)
                {
                    return Err(directory::CheckpointError::Directory(
                        w::DirectoryCode::InvalidProfile,
                    )
                    .into());
                }
                let live = self.client.revalidate(&self.directory, root, None)?;
                self.directory.recover_committed(
                    &master,
                    directory::HomeIntent {
                        operation: *operation,
                        profile: *profile,
                        reservation: None,
                    },
                    live,
                    crate::now_unix_seconds()?,
                )?;
                self.status(root, None, &native.master_certificate.body.master_public_key)
            }
            w::NativeUsernameAction::Mutate { operation, profile } => self.mutate(
                root,
                &call.history.home.authority.record.body,
                *operation,
                *profile,
                deadline,
            ),
            w::NativeUsernameAction::Status { operation_id } => self.status(
                root,
                operation_id,
                &call.history.home.authority.record.body.master_certificate.body.master_public_key,
            ),
            w::NativeUsernameAction::Resolve { name, nonce } => self.resolve(root, &name, &nonce),
        }
    }

    fn mutate(
        &self,
        root: &str,
        native: &ramflux_protocol::custody::DeviceSet,
        operation: w::UsernameOperation,
        profile: w::SignedIdentityProfileV2,
        deadline: Instant,
    ) -> Result<w::NativeUsernameReply> {
        if profile.body.principal_id != native.principal_id
            || profile.body.display_name != native.profile.display_name
            || profile.body.kind != w::ProfileKind::from_principal_kind(native.principal_kind)
        {
            return Err(
                directory::CheckpointError::Directory(w::DirectoryCode::InvalidProfile).into()
            );
        }
        let master = ramflux_crypto::verifying_key_from_base64url(
            &native.master_certificate.body.master_public_key,
        )?;
        let operation_id = operation.body.operation_id.clone();
        let attempt = self.coordinator.watch_attempt(root, &operation_id)?;
        self.directory.begin(&master, operation, Some(profile), crate::now_unix_seconds()?)?;
        self.coordinator.wake();
        match attempt.wait(deadline.saturating_duration_since(Instant::now())) {
            directory::HomeAttemptOutcome::Refused(code) => {
                return Ok(w::NativeUsernameReply::Refused { failure: directory::failure(code) });
            }
            directory::HomeAttemptOutcome::Complete => {
                return self.status(
                    root,
                    Some(operation_id),
                    &native.master_certificate.body.master_public_key,
                );
            }
            directory::HomeAttemptOutcome::Pending => {}
        }
        Ok(w::NativeUsernameReply::Status {
            status: Box::new(w::NativeUsernameStatus {
                operation_id: Some(operation_id),
                state: w::NativeUsernameState::Pending,
                binding: None,
                profile: None,
                receipt: None,
                operation_receipt: None,
                current_operation: None,
            }),
        })
    }

    async fn renew_locator(self: Arc<Self>, shutdown: tokio_util::sync::CancellationToken) {
        let mut cursor = None;
        loop {
            let page = self.directory.reporting_roots(cursor.as_deref(), 128);
            let mut renewed = false;
            if let Ok((roots, next)) = page {
                cursor = next;
                for root in roots {
                    tokio::select! {
                        () = shutdown.cancelled() => return,
                        result = directory::UsernameCenterClient::exchange(self.client.as_ref(), &root, directory::DirectoryRequest::Status { operation_id: None }) => {
                            // Even a valid NotFound reports the live home locator for this native root.
                            if result.is_ok() { renewed = true; cursor = None; break; }
                        }
                    }
                }
            }
            let delay = if renewed { Duration::from_secs(3600) } else { Duration::from_secs(60) };
            tokio::select! { () = shutdown.cancelled() => return, () = tokio::time::sleep(delay) => {} }
        }
    }
}
