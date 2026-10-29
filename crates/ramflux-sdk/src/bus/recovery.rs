// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit connection-local phrase recovery never enters replay journals or network prompts.
use super::{custody_response, supervisor::Supervisor};
use crate::{
    LocalBusFrame, SdkError,
    custody::{CommitGate, RecoveryCeremony},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::watch;
use zeroize::Zeroizing;

const WARNING: &str = "Confirm this account fingerprint. A directory may withhold newer authority. Recovery revokes all other devices. Enter your phrase only for recovery you started yourself.";
struct CancelOnDrop(Arc<CommitGate>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Serialize)]
struct Prepared {
    ceremony_id: String,
    account_anchor: String,
    expires_in_ms: u64,
    warning: &'static str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    account_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirm {
    phrase: Zeroizing<String>,
    passphrase: Zeroizing<String>,
    confirmed_anchor: String,
}

pub(super) async fn respond(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
    ceremony: &mut Option<RecoveryCeremony>,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    let result = apply(request, supervisor, ceremony, disconnected).await;
    match result {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            *ceremony = None;
            custody_response::error(request, &error)
        }
    }
}
async fn apply(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
    ceremony: &mut Option<RecoveryCeremony>,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    super::custody_setup::validate_headers(request, &mut None)?;
    super::requests::deadline(request)?;
    if request.kind != crate::LocalBusFrameKind::Request || request.operation_id.is_some() {
        return Err(SdkError::CustodySetupInvalid);
    }
    match request.method.as_str() {
        "account.recover.begin" => {
            *ceremony = None;
            let input: Begin = serde_json::from_value(std::mem::take(&mut request.body))
                .map_err(|_| SdkError::CustodySetupInvalid)?;
            super::custody_setup::primary_provider(&supervisor.config).preflight()?;
            // Reconcile an earlier intent through ordinary unlock before starting another recovery.
            RecoveryCeremony::begin(
                &supervisor.config.data_root,
                &input.account_id,
                crate::custody::network_now()?,
            )?;
            tokio::select! { biased;
                _ = disconnected.changed() => return Err(SdkError::CustodySetupInvalid),
                result = refresh_checkpoints(&supervisor.config, &input.account_id) => result?,
            }
            let pending = RecoveryCeremony::begin(
                &supervisor.config.data_root,
                &input.account_id,
                crate::custody::network_now()?,
            )?;
            let response = Prepared {
                ceremony_id: pending.ceremony_id().into(),
                account_anchor: pending.account_anchor().into(),
                expires_in_ms: pending.expires_in_ms(),
                warning: WARNING,
            };
            *ceremony = Some(pending);
            custody_response::success(request, response)
        }
        "account.recover.confirm" => {
            let pending = ceremony.take().ok_or(SdkError::CustodySetupInvalid)?;
            // Deserialize from an erasing byte buffer, never clone or journal phrase values.
            let bytes = crate::custody::serialize_secret(&request.body, 8192)?;
            super::secrets::wipe(&mut request.body);
            let input: Confirm =
                serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
            drop(bytes);
            let result = confirm(request, supervisor, pending, input, disconnected).await?;
            custody_response::success(request, result)
        }
        "account.recover.cancel" => {
            if request.body.as_object().is_none_or(|map| !map.is_empty()) {
                return Err(SdkError::CustodySetupInvalid);
            }
            *ceremony = None;
            custody_response::success(
                request,
                super::custody_response::Cancelled { cancelled: true },
            )
        }
        _ => Err(SdkError::CustodySetupInvalid),
    }
}
async fn confirm(
    request: &LocalBusFrame,
    supervisor: &Supervisor,
    pending: RecoveryCeremony,
    input: Confirm,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<crate::LocalBusCreatedAccount, SdkError> {
    pending.verify_phrase(
        &input.phrase,
        &input.confirmed_anchor,
        crate::custody::network_now()?,
    )?;
    let id = pending.account_id().to_owned();
    let root = supervisor.config.data_root.clone();
    let secret = input.passphrase;
    let verification_id = id.clone();
    let secret = tokio::task::spawn_blocking(move || {
        crate::client::account::verify_stored_data_secret(
            &root,
            &verification_id,
            secret.as_bytes(),
        )?;
        Ok::<_, SdkError>(secret)
    })
    .await
    .map_err(|_| SdkError::CustodySetupInvalid)??;
    if !supervisor.installing.borrow_mut().insert(id.clone()) {
        return Err(SdkError::NetworkingPending);
    }
    let result = promote(
        request,
        supervisor,
        Promotion {
            pending,
            phrase: input.phrase,
            confirmed_anchor: input.confirmed_anchor,
            passphrase: secret,
        },
        disconnected,
    )
    .await;
    supervisor.installing.borrow_mut().remove(&id);
    result
}
struct Promotion {
    pending: RecoveryCeremony,
    phrase: Zeroizing<String>,
    confirmed_anchor: String,
    passphrase: Zeroizing<String>,
}
async fn promote(
    request: &LocalBusFrame,
    supervisor: &Supervisor,
    promotion: Promotion,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<crate::LocalBusCreatedAccount, SdkError> {
    let Promotion { mut pending, phrase, confirmed_anchor, passphrase } = promotion;
    let id = pending.account_id().to_owned();
    let deadline = super::requests::deadline(request)?
        .map_or(pending.deadline(), |limit| pending.deadline().min(limit.into_std()));
    let gate = Arc::new(CommitGate::new(deadline));
    let _cancel = CancelOnDrop(gate.clone());
    pending.guard_commit(gate);
    if let Some(actor) = supervisor.account_actor(&id) {
        actor.stop().await?;
    }
    supervisor.remove_backup_actor(&id);
    let vault = super::custody_setup::primary_provider(&supervisor.config);
    let worker = tokio::task::spawn_blocking(move || {
        pending.confirm(
            &phrase,
            &confirmed_anchor,
            vault.as_ref(),
            crate::custody::network_now()?,
        )?;
        Ok::<_, SdkError>(passphrase)
    });
    let secret = tokio::select! { biased;
        _ = disconnected.changed() => return Err(SdkError::CustodySetupInvalid),
        result = worker => result.map_err(|_| SdkError::CustodySetupInvalid)??,
    };
    if *disconnected.borrow() {
        return Err(SdkError::CustodySetupInvalid);
    }
    supervisor.activate_native(&id, secret).await
}

async fn refresh_checkpoints(config: &crate::LocalBusConfig, id: &str) -> Result<(), SdkError> {
    let own =
        crate::custody::load_data_account(&config.data_root, id, crate::custody::network_now()?)?;
    let anchor = &own.record().body.account_anchor;
    let nodes = crate::node::NodeStore::load(&config.data_root, &config.builtin_nodes)?;
    let mut checkpoints = Vec::new();
    for profile in nodes.profiles.values().filter(|profile| {
        profile.enabled
            && profile.expires_at > crate::time::now_unix_timestamp().unsigned_abs()
            && !profile.safety_warnings.contains("key_changed")
    }) {
        let endpoint = crate::GatewayQuicEndpointConfig {
            bind_addr: ([0, 0, 0, 0], 0).into(),
            gateway_addr: ([0, 0, 0, 0], 0).into(),
            server_name: String::new(),
            ca_cert: std::path::PathBuf::new(),
            principal_id: own.record().body.principal_id.clone(),
            device_id: own.local_device_id()?.into(),
            target_delivery_id: String::new(),
            prekey_http_url: None,
        };
        let gateway = crate::GatewaySessionConfig::auto(
            profile.gateway_config(&config.data_root, endpoint).await?,
        );
        let result = crate::prekey::sdk_gateway_get_json::<
            Option<crate::prekey::SdkDeviceManifestResponse>,
        >(&gateway, &format!("/mvp1/device-manifest/{anchor}"))
        .await;
        match result {
            Ok(Some(manifest)) => {
                if manifest.principal_commitment != *anchor {
                    return Err(SdkError::CustodySetupInvalid);
                }
                let native = manifest.custody.ok_or(SdkError::CustodyModeDowngrade)?;
                let authority = ramflux_protocol::custody::CustodyAuthority {
                    publication: native.publication,
                    custodian_publication: native.custodian_publication,
                };
                let verified = ramflux_crypto::custody::verify_publication(
                    &authority,
                    crate::custody::network_now()?,
                )?;
                if verified.envelope().body.principal_id != own.record().body.principal_id
                    || verified.envelope().body.principal_kind != own.record().body.principal_kind
                {
                    return Err(SdkError::CustodySetupInvalid);
                }
                checkpoints.push(authority);
            }
            Ok(None)
            | Err(SdkError::Transport(_) | SdkError::Io(_) | SdkError::GatewaySessionRejected(_)) =>
                {}
            Err(error) => return Err(error),
        }
    }
    checkpoints.sort_by_key(|authority| authority.publication.record.body.device_set_epoch);
    for authority in checkpoints {
        let current = crate::custody::load_data_account(
            &config.data_root,
            id,
            crate::custody::network_now()?,
        )?;
        if authority.publication.record.body.device_set_epoch
            >= current.record().body.device_set_epoch
        {
            crate::custody::accept_publication(
                &config.data_root,
                id,
                &authority,
                crate::custody::network_now()?,
            )?;
        }
    }
    Ok(())
}
