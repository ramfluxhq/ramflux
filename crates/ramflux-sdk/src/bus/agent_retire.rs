// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node proof for `agent.retire` (the current primary) and the node half of `agent.delete`
//! (the agent device, while the host fence still passes). One connect attempt. Local state
//! changes only after the node accepts.

use super::actor::AccountActor;
use super::supervisor::Supervisor;
use crate::SdkError;
use crate::custody::agent_creation::{AgentCreationStore, agent_account_id};
use crate::custody::{CustodyConnection, CustodyNetworkConfig};
use crate::gateway::GatewayQuicEndpointConfig;
use crate::node::NodeProfile;
use ramflux_protocol::custody::BindingMode;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) async fn prove_primary_retire(
    supervisor: &Supervisor,
    actor: &AccountActor,
    human: &str,
    agent_anchor: &str,
) -> Result<(), SdkError> {
    let root = supervisor.config.data_root.clone();
    let now = super::custody_setup::now()?;
    require_record(&root, human, agent_anchor)?;
    require_local_primary(&root, human, now)?;
    let node = home_node(actor).await?;
    let profile = supervisor.node_profile(&node)?;
    let device = local_device_id(&root, human, now)?;
    let admission = actor.pairing_admission().await?;
    let config =
        proof_config(&root, &profile, human, &device, binding_mode(supervisor), admission).await?;
    let vault = super::custody_setup::primary_provider(&supervisor.config);
    Box::pin(CustodyConnection::prove_agent_retirement(config, vault, agent_anchor.to_owned()))
        .await
}

pub(super) async fn prove_agent_delete(
    supervisor: &Supervisor,
    actor: &AccountActor,
    human: &str,
    agent_anchor: &str,
) -> Result<(), SdkError> {
    let root = supervisor.config.data_root.clone();
    require_active_record(&root, human, agent_anchor)?;
    let agent_account = agent_account(&root, human, agent_anchor)?
        .ok_or(SdkError::AgentCreationRefused("agent_not_found"))?;
    let now = super::custody_setup::now()?;
    let device = local_device_id(&root, &agent_account, now)?;
    let node = home_node(actor).await?;
    let profile = supervisor.node_profile(&node)?;
    let config =
        proof_config(&root, &profile, &agent_account, &device, binding_mode(supervisor), None)
            .await?;
    let vault = super::custody_setup::primary_provider(&supervisor.config);
    Box::pin(CustodyConnection::prove_agent_retirement(config, vault, agent_anchor.to_owned()))
        .await
}

fn binding_mode(supervisor: &Supervisor) -> BindingMode {
    #[cfg(test)]
    {
        supervisor.config.rebind_binding_mode.unwrap_or(BindingMode::HomeRelayReceipt)
    }
    #[cfg(not(test))]
    {
        let _ = supervisor;
        BindingMode::HomeRelayReceipt
    }
}

async fn home_node(actor: &AccountActor) -> Result<String, SdkError> {
    actor.agent_home_node().await?.ok_or(SdkError::NetworkingPending)
}

fn require_record(root: &Path, human: &str, agent: &str) -> Result<(), SdkError> {
    let Some(record) = load_record(root, human, agent)? else {
        return Err(SdkError::AgentCreationRefused("agent_not_found"));
    };
    let _ = record;
    Ok(())
}

fn require_active_record(root: &Path, human: &str, agent: &str) -> Result<(), SdkError> {
    let Some(record) = load_record(root, human, agent)? else {
        return Err(SdkError::AgentCreationRefused("agent_not_found"));
    };
    if record.lifecycle != crate::agent_record::LIFECYCLE_ACTIVE {
        return Err(SdkError::AgentCreationRefused("unsupported"));
    }
    Ok(())
}

fn load_record(
    root: &Path,
    human: &str,
    agent: &str,
) -> Result<Option<crate::agent_record::StoredAgentRecord>, SdkError> {
    let directory = root.join("custody_accounts").join(human).join("agent_creation");
    if !directory.is_dir() {
        return Ok(None);
    }
    let store = AgentCreationStore::open(root.to_path_buf(), human)?;
    crate::agent_record::AgentRecordStore::at(store.agent_record_dir()).load(agent)
}

fn agent_account(root: &Path, human: &str, agent: &str) -> Result<Option<String>, SdkError> {
    let directory = root.join("custody_accounts").join(human).join("agent_creation");
    if !directory.is_dir() {
        return Ok(None);
    }
    let store = AgentCreationStore::open(root.to_path_buf(), human)?;
    agent_account_id(&store, agent)
}

fn require_local_primary(root: &Path, human: &str, now: u64) -> Result<(), SdkError> {
    let account = crate::custody::load_account(root, human, now)?;
    let own = account.local_device_id()?;
    let body = &account.record().body;
    let primary = &body.master_certificate.body.primary_device_ref;
    if primary.device_id != own || primary.account_anchor != body.account_anchor {
        return Err(SdkError::AgentCreationRefused("creation_not_primary"));
    }
    Ok(())
}

fn local_device_id(root: &Path, account_id: &str, now: u64) -> Result<String, SdkError> {
    let account = crate::custody::load_account(root, account_id, now)?;
    Ok(account.local_device_id()?.to_owned())
}

async fn proof_config(
    root: &Path,
    profile: &NodeProfile,
    account_id: &str,
    device_id: &str,
    binding_mode: BindingMode,
    pairing_admission: Option<std::sync::Arc<ramflux_storage::PairingAdmissionReader>>,
) -> Result<CustodyNetworkConfig, SdkError> {
    let unset = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
    let endpoint = profile
        .gateway_config(
            root,
            GatewayQuicEndpointConfig {
                bind_addr: unset,
                gateway_addr: unset,
                server_name: String::new(),
                ca_cert: PathBuf::new(),
                principal_id: String::new(),
                device_id: device_id.to_owned(),
                target_delivery_id: String::new(),
                prekey_http_url: None,
            },
        )
        .await?;
    Ok(CustodyNetworkConfig {
        pairing_admission,
        account_root: root.to_path_buf(),
        account_id: account_id.to_owned(),
        device_id: device_id.to_owned(),
        gateway_address: crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?,
        server_name: endpoint.server_name,
        ca_certificate: endpoint.ca_cert,
        node_id: profile.node_id.clone(),
        node_public_key: profile.node_public_key.clone(),
        audience: profile.node_id.clone(),
        binding_mode,
        allow_no_channel_binding: false,
        timeout: Duration::from_secs(10),
    })
}
