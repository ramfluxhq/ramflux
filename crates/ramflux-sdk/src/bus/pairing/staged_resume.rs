// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private ordinary data unlock for a new recipient; never an account/session admission.
use super::{
    Arc, FreshPairingNative, GatewayCustodyConfig, GatewayQuicEndpointConfig, GatewaySessionConfig,
    HttpRelay, LocalPairingParticipant, Mutex, NativePairingPublication, NativePairingQuery,
    PairingActor, PairingIdentity, PairingNative, PairingWire, SdkError, install_actor_with_writer,
    provider_for_account,
};
use crate::custody::pairing::{
    local_credential::{load_reservation, scoped},
    private_credential::PrivateCredentialScope,
};
use ramflux_crypto::custody::pairing::PairingRole;
use ramflux_protocol::custody::pairing::{
    context_v3::TranscriptV3,
    local_dto::{CredentialRequest, StatusRequest},
};

pub(super) fn has_pending(
    root: &std::path::Path,
    account: &str,
    request: &StatusRequest,
) -> Result<bool, SdkError> {
    request.validate().map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    if crate::custody::authority_exists(root, account)? {
        return Ok(false);
    }
    Ok(crate::custody::pairing::install_store::list_pending(root, account)?.iter().any(|row| {
        row.operation_id == request.operation_id
            && row.recipient_mode == "new"
            && row.install_purpose == "transfer_destination"
            && row.state == "vault_durable"
            && row.record_hash.is_none()
            && row.prior_record_hash.is_none()
    }) && load_reservation(root, account)?.is_some())
}

pub(super) struct Owner {
    provider: Arc<dyn crate::custody::pairing::LocalCredentialProvider>,
    jobs: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
impl Owner {
    pub(super) fn new(root: &std::path::Path, account: &str) -> Result<Self, SdkError> {
        Ok(Self {
            provider: provider_for_account(root, account.into())?,
            jobs: Mutex::new(Vec::new()),
        })
    }
    pub(super) async fn drain(&self, cancel: bool) {
        if cancel {
            self.provider.cancel();
        }
        let jobs = std::mem::take(
            &mut *self.jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for job in jobs {
            let _ = job.await;
        }
    }
}
struct Unlocked {
    db: ramflux_storage::AccountDb,
    record: ramflux_crypto::custody::pairing::FullResumeRecord,
    master_key: String,
    base_epoch: u64,
}
fn unlock(
    root: &std::path::Path,
    account: &str,
    request: &StatusRequest,
    provider: &dyn crate::custody::pairing::LocalCredentialProvider,
) -> Result<Unlocked, SdkError> {
    if !has_pending(root, account, request)? {
        return Err(SdkError::PairingCode("NotFound"));
    }
    let stored = load_reservation(root, account)?.ok_or(SdkError::PairingCode("NotFound"))?;
    let expected = CredentialRequest {
        local_account_id: account.into(),
        reservation_id: stored.reservation_id,
        frontend_generation: stored.frontend_generation,
        action: "unlock".into(),
    };
    let provider = scoped(
        provider,
        PrivateCredentialScope::data(expected.clone(), Some(request.operation_id.clone()))?,
    );
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root)?;
    crate::custody::pairing::recipient::unlock_with_provider(
        &mut client,
        account,
        &expected,
        &provider,
    )?;
    let db = client.active_account_db.take().ok_or(SdkError::AccountDbNotUnlocked)?;
    let live = db
        .pairing_live_rows()?
        .into_iter()
        .find(|row| row.operation_id == request.operation_id)
        .ok_or(SdkError::PairingCode("NotFound"))?;
    if live.generation != request.generation
        || live.role != "responder"
        || live.phase != "mutually_confirmed"
        || db.pairing_head()?.is_some()
    {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let stage = db.open_full_transfer_stage(
        &request.operation_id,
        PairingRole::Responder,
        crate::custody::network_now()?,
    )?;
    let record = stage.resume_record()?;
    let context = TranscriptV3::from_wire_bytes(&record.transcript)
        .map_err(|_| SdkError::PairingCode("WrongContext"))?;
    if context.initiator.common.recipient_mode != "new" {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let base_epoch = context.initiator.common.device_set_epoch;
    let master_key = context.initiator.common.master_public_key;
    drop(stage);
    Ok(Unlocked { db, record, master_key, base_epoch })
}

pub(super) async fn install(
    config: Arc<crate::LocalBusConfig>,
    nodes: Arc<crate::node::NodeStore>,
    account: &str,
    request: &StatusRequest,
    owner: &Owner,
) -> Result<(), SdkError> {
    let pairing = config
        .pairing
        .clone()
        .filter(|config| config.enabled)
        .ok_or(SdkError::PairingCode("NotFound"))?;
    let root = config.data_root.clone();
    let provider = owner.provider.clone();
    let owned_root = root.clone();
    let owned_account = account.to_owned();
    let owned_request = request.clone();
    let private = provider.clone();
    let (send, receive) = tokio::sync::oneshot::channel();
    {
        let mut jobs = owner.jobs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !jobs.is_empty() {
            return Err(SdkError::PairingCode("Busy"));
        }
        jobs.push(tokio::task::spawn_blocking(move || {
            let result = unlock(&owned_root, &owned_account, &owned_request, private.as_ref());
            let _ = send.send(result);
        }));
    }
    let unlocked = receive.await.map_err(|_| SdkError::PairingCode("Retired"))??;
    let profile = nodes
        .selected(Some(&unlocked.record.grant.node_id), true)?
        .ok_or(SdkError::NoNodeSelected)?;
    if profile.node_id != unlocked.record.grant.node_id {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let vault = super::super::custody_setup::primary_provider(&config);
    let gateway =
        gateway(&config, account, &profile, &unlocked.record.grant, vault.clone()).await?;
    let mut network = crate::gateway::proof_network_config(&gateway)?;
    network.gateway_address = crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?;
    let node = crate::custody::CustodyConnection::discover_pairing_node(network.clone()).await?;
    let proof: Arc<dyn PairingNative> = Arc::new(FreshPairingNative::new(network, vault.clone()));
    let runtime = tokio::runtime::Handle::current();
    let participant = Arc::new(LocalPairingParticipant {
        root: root.clone(),
        account_id: account.into(),
        vault,
        provider,
        db: Mutex::new(Some(unlocked.db)),
        persist: Arc::new(NativePairingPublication {
            native: proof.clone(),
            runtime: runtime.clone(),
        }),
        query: Arc::new(NativePairingQuery { config: gateway, runtime }),
    });
    let mut actor = PairingActor::new(
        PairingIdentity {
            account_id: account.into(),
            local_ref: unlocked.record.grant.destination_ref,
            master_public_key: Some(unlocked.master_key),
            base_record_hash: unlocked.record.base_record_hash,
            base_epoch: unlocked.base_epoch,
            is_primary: false,
        },
        Some(proof),
        Arc::new(HttpRelay::from_config(&pairing)?),
        pairing,
    );
    actor.set_full_node(node);
    actor.set_participant(participant);
    install_actor_with_writer(&root, account.into(), actor, None)
}
async fn gateway(
    config: &crate::LocalBusConfig,
    account: &str,
    profile: &crate::node::NodeProfile,
    grant: &ramflux_protocol::custody::pairing::full_transfer::lease::DataGrant,
    vault: Arc<dyn crate::custody::PrimaryVault>,
) -> Result<GatewaySessionConfig, SdkError> {
    let endpoint = profile
        .gateway_config(
            &config.data_root,
            GatewayQuicEndpointConfig {
                bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                gateway_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                server_name: String::new(),
                ca_cert: std::path::PathBuf::new(),
                principal_id: grant.source_ref.account_anchor.clone(),
                device_id: grant.destination_ref.device_id.clone(),
                target_delivery_id: String::new(),
                prekey_http_url: None,
            },
        )
        .await?;
    let tcp = crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?;
    Ok(GatewaySessionConfig::auto(endpoint).with_tcp_gateway_addr(tcp).with_native_custody(
        GatewayCustodyConfig {
            account_root: config.data_root.clone(),
            account_id: account.into(),
            node_id: profile.node_id.clone(),
            node_public_key: profile.node_public_key.clone(),
            vault,
        },
    ))
}

#[cfg(test)]
pub(crate) fn unlock_for_test(
    root: &std::path::Path,
    account: &str,
    request: &StatusRequest,
    provider: &dyn crate::custody::pairing::LocalCredentialProvider,
) -> Result<ramflux_storage::AccountDb, SdkError> {
    Ok(unlock(root, account, request, provider)?.db)
}
