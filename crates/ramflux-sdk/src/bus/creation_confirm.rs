// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Secret confirmation persists off the bus thread, then opens the ordinary account actor.
use super::{custody_response, supervisor::Supervisor};
use crate::{
    LocalBusFrame, SdkError,
    custody::{CommitGate, CreationCeremony},
};
use std::sync::Arc;
use tokio::sync::watch;
use zeroize::Zeroizing;

struct CancelOnDrop(Arc<CommitGate>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) async fn respond(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
    ceremony: &mut Option<CreationCeremony>,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<Zeroizing<Vec<u8>>, SdkError> {
    super::custody_setup::validate_headers(request, ceremony)?;
    let result = confirm(request, supervisor, ceremony, disconnected).await;
    *ceremony = None;
    match result {
        Ok(account) => custody_response::success(request, account),
        Err(error) => custody_response::error(request, &error),
    }
}

async fn confirm(
    request: &mut LocalBusFrame,
    supervisor: &Supervisor,
    ceremony: &mut Option<CreationCeremony>,
    disconnected: &mut watch::Receiver<bool>,
) -> Result<crate::LocalBusCreatedAccount, SdkError> {
    super::requests::deadline(request)?;
    if request.kind != crate::LocalBusFrameKind::Request || request.operation_id.is_some() {
        return Err(SdkError::CustodySetupInvalid);
    }
    let mut pending = ceremony.take().ok_or(SdkError::CustodySetupInvalid)?;
    let home_node_id = pending.home_node_id().map(str::to_owned);
    let data_root = supervisor.config.data_root.clone();
    let builtin_nodes = supervisor.config.builtin_nodes.clone();
    let agent = pending.principal_kind() == ramflux_protocol::PrincipalKind::HeadlessAi;
    let (words, passphrase) = take_secrets(request, agent)?;
    let gate = Arc::new(CommitGate::new(pending.deadline()));
    let _cancel = CancelOnDrop(Arc::clone(&gate));
    pending.guard_commit(gate);
    let vault = super::custody_setup::primary_provider(&supervisor.config);
    let worker = tokio::task::spawn_blocking(move || {
        let home_node_id = revalidate_home_node(&data_root, &builtin_nodes, home_node_id)?;
        let account = pending.confirm_with_passphrase(
            &words,
            vault.as_ref(),
            super::custody_setup::now()?,
            passphrase.as_bytes(),
        )?;
        Ok::<_, SdkError>((account.local_account_id().to_owned(), passphrase, home_node_id))
    });
    let (id, passphrase, home_node_id) = tokio::select! {
        biased;
        _ = disconnected.changed() => return Err(SdkError::CustodySetupInvalid),
        result = worker => result.map_err(|_| SdkError::CustodySetupInvalid)??,
    };
    if *disconnected.borrow() {
        return Err(SdkError::CustodySetupInvalid);
    }
    tokio::select! {
        biased;
        _ = disconnected.changed() => Err(SdkError::CustodySetupInvalid),
        result = supervisor.activate_native(&id, passphrase, home_node_id) => result,
    }
}

fn revalidate_home_node(
    data_root: &std::path::Path,
    builtin_nodes: &[crate::NodeProfile],
    home_node_id: Option<String>,
) -> Result<Option<String>, SdkError> {
    if let Some(node_id) = home_node_id.as_deref() {
        crate::node::NodeStore::load(data_root, builtin_nodes)?
            .confirmed_for_new_account(node_id)?;
    }
    Ok(home_node_id)
}

fn take_secrets(
    request: &mut LocalBusFrame,
    agent: bool,
) -> Result<([Zeroizing<String>; 3], Zeroizing<String>), SdkError> {
    let map = request
        .body
        .as_object_mut()
        .filter(|map| map.len() == if agent { 1 } else { 2 })
        .ok_or(SdkError::CustodySetupInvalid)?;
    let passphrase = if agent {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *bytes).map_err(|_| SdkError::CustodyRandomUnavailable)?;
        Zeroizing::new(ramflux_protocol::encode_base64url(*bytes))
    } else {
        let Some(serde_json::Value::String(passphrase)) = map.remove("passphrase") else {
            return Err(SdkError::CustodySetupInvalid);
        };
        Zeroizing::new(passphrase)
    };
    let values = map
        .get_mut("words")
        .and_then(serde_json::Value::as_array_mut)
        .filter(|words| words.len() == 3)
        .ok_or(SdkError::CustodySetupInvalid)?;
    let mut words = std::array::from_fn(|_| Zeroizing::new(String::new()));
    for (target, value) in words.iter_mut().zip(values) {
        let serde_json::Value::String(word) = std::mem::take(value) else {
            return Err(SdkError::CustodySetupInvalid);
        };
        *target = Zeroizing::new(word);
    }
    Ok((words, passphrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(id: &str) -> crate::NodeProfile {
        crate::NodeProfile {
            discovery_url: format!("https://{id}"),
            node_id: id.into(),
            node_public_key: ramflux_protocol::encode_base64url([41; 32]),
            pin_source: crate::NodePinSource::Operator,
            ca_cert_pem: "test CA".into(),
            gateway: crate::NodeGateway {
                quic_addr: "127.0.0.1:1".into(),
                tcp_addr: "127.0.0.1:1".into(),
                server_name: id.into(),
            },
            relay: crate::NodeRelay { quic_addr: "127.0.0.1:1".into(), server_name: id.into() },
            prekey_http_url: format!("https://{id}"),
            signaling_turn_addr: String::new(),
            protocol_versions: Vec::new(),
            client_capabilities: Vec::new(),
            discovered_at: 1,
            expires_at: u64::MAX,
            enabled: true,
            builtin: false,
            safety_warnings: std::collections::BTreeSet::new(),
        }
    }

    #[test]
    fn confirm_revalidation_rejects_a_removed_or_disabled_node_before_account_persistence()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let removed = profile("removed.example");
        let disabled = profile("disabled.example");
        let mut nodes = crate::node::NodeStore::default();
        nodes.profiles.insert(removed.node_id.clone(), removed.clone());
        nodes.profiles.insert(disabled.node_id.clone(), disabled.clone());
        nodes.save(root.path())?;

        let mut changed = crate::node::NodeStore::load(root.path(), &[])?;
        changed.profiles.remove(&removed.node_id);
        changed.profiles.get_mut(&disabled.node_id).ok_or("disabled profile")?.enabled = false;
        changed.save(root.path())?;

        for node_id in [removed.node_id, disabled.node_id] {
            assert!(matches!(
                revalidate_home_node(root.path(), &[], Some(node_id)),
                Err(SdkError::NoNodeSelected)
            ));
        }
        assert!(!root.path().join("custody_accounts").exists());
        Ok(())
    }
}
