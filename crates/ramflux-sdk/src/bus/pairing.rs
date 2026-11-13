// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-bound ceremony construction; ordinary session setup never owns this connection.
use super::state::LocalBusDaemonState;
use crate::custody::pairing::{
    FreshPairingNative, HttpRelay, LocalPairingParticipant, NativePairingPublication,
    NativePairingQuery, PairingActor, PairingIdentity, PairingNative, install_actor_with_writer,
    private_credential::provider_for_account, work_signal,
};
use crate::{
    GatewayCustodyConfig, GatewayQuicEndpointConfig, GatewaySessionConfig, LocalBusFrame, SdkError,
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    local_dto::{Begin, FullTransferBegin, Join},
};
use ramflux_protocol::custody::{DeviceRef, object_hash};
use std::sync::{Arc, Mutex};

pub(super) async fn ensure_actor(
    state: &LocalBusDaemonState,
    account_id: &str,
    request: &LocalBusFrame,
) -> Result<(), SdkError> {
    if work_signal(&state.config.data_root, account_id).is_some() {
        return Ok(());
    }
    match request.method.as_str() {
        "device.pair.begin" => {
            let begin: Begin = serde_json::from_value(request.body.clone())?;
            begin.validate().map_err(|_| SdkError::PairingCode("InvalidInput"))?;
        }
        "device.transfer.begin" => {
            let begin: FullTransferBegin = serde_json::from_value(request.body.clone())?;
            begin.validate().map_err(|_| SdkError::PairingCode("InvalidInput"))?;
        }
        "device.pair.join" | "device.transfer.join" => {
            let join = validated_join(request)?;
            return if join.token.invitation.body.recipient_mode == "existing" {
                install_source(state, account_id, Some(&join)).await
            } else {
                install_new_recipient(state, account_id, join).await
            };
        }
        _ => return Ok(()),
    }
    install_source(state, account_id, None).await
}

async fn install_source(
    state: &LocalBusDaemonState,
    account_id: &str,
    recipient: Option<&Join>,
) -> Result<(), SdkError> {
    let config = state.config.pairing.clone().ok_or(SdkError::PairingCode("NotFound"))?;
    if !config.enabled {
        return Err(SdkError::PairingCode("NotFound"));
    }
    let account = state
        .accounts
        .get(account_id)
        .ok_or_else(|| SdkError::AccountNotOpen(account_id.into()))?;
    let root = &state.config.data_root;
    let native = crate::custody::load_account(root, account_id, crate::custody::network_now()?)?;
    let record = native.record();
    let device_id = native.local_device_id()?;
    let device = record
        .body
        .devices
        .iter()
        .find(|device| device.device_id == device_id)
        .ok_or(SdkError::CustodySetupInvalid)?;
    let reference = DeviceRef {
        account_anchor: record.body.account_anchor.clone(),
        device_id: device_id.into(),
        device_epoch: device.device_epoch,
    };
    let primary = source_or_linked_role(recipient, &reference, record)?;
    let saved = account.client.account_db()?.load_actor_state::<String>("account/node-id")?;
    let profile =
        state.nodes.selected(saved.as_deref(), saved.is_some())?.ok_or(SdkError::NoNodeSelected)?;
    let old = &account.gateway_config;
    let endpoint = profile
        .gateway_config(
            root,
            GatewayQuicEndpointConfig {
                bind_addr: old.bind_addr,
                gateway_addr: old.gateway_addr,
                server_name: old.server_name.clone(),
                ca_cert: old.ca_cert.clone(),
                principal_id: record.body.principal_id.clone(),
                device_id: device_id.into(),
                target_delivery_id: old.target_delivery_id.clone(),
                prekey_http_url: None,
            },
        )
        .await?;
    let tcp = crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?;
    let vault = super::custody_setup::primary_provider(&state.config);
    let gateway = GatewaySessionConfig::auto(endpoint)
        .with_tcp_gateway_addr(tcp)
        .with_native_custody(GatewayCustodyConfig {
            account_root: root.clone(),
            account_id: account_id.into(),
            node_id: profile.node_id,
            node_public_key: profile.node_public_key,
            vault: vault.clone(),
        })
        .with_account_identity(&account.client)?;
    let mut network = crate::gateway::proof_network_config(&gateway)?;
    // FreshPairingNative uses TCP, while the ordinary config's default address is QUIC.
    network.gateway_address = tcp;
    let recipient_node = verified_recipient_node(recipient, network.clone()).await?;
    let proof: Arc<dyn PairingNative> = Arc::new(FreshPairingNative::new(network, vault.clone()));
    let runtime = tokio::runtime::Handle::current();
    let participant = Arc::new(LocalPairingParticipant {
        root: root.clone(),
        account_id: account_id.into(),
        vault,
        provider: provider_for_account(root, account_id.into())?,
        db: Mutex::new(None),
        persist: Arc::new(NativePairingPublication {
            native: proof.clone(),
            runtime: runtime.clone(),
        }),
        query: Arc::new(NativePairingQuery { config: gateway, runtime }),
    });
    let mut actor = PairingActor::new(
        PairingIdentity {
            account_id: account_id.into(),
            local_ref: reference,
            master_public_key: Some(record.body.master_certificate.body.master_public_key.clone()),
            base_record_hash: object_hash(record)?,
            base_epoch: record.body.device_set_epoch,
            is_primary: primary,
        },
        Some(proof),
        Arc::new(HttpRelay::from_config(&config)?),
        config,
    );
    if let Some(node) = recipient_node {
        actor.set_full_node(node);
    }
    actor.set_participant(participant);
    let writer = actor.bind_frontend_writer(account.client.account_db()?)?;
    install_actor_with_writer(root, account_id.into(), actor, Some(writer))
}

async fn verified_recipient_node(
    recipient: Option<&Join>,
    network: crate::custody::CustodyNetworkConfig,
) -> Result<Option<ramflux_crypto::custody::VerifiedNodeRecord>, SdkError> {
    let Some(join) = recipient else {
        return Ok(None);
    };
    let node = crate::custody::CustodyConnection::discover_pairing_node(network).await?;
    if node.envelope().body.node_signing_public_key != join.token.invitation.body.node_key {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    Ok(Some(node))
}

fn source_or_linked_role(
    recipient: Option<&Join>,
    reference: &DeviceRef,
    record: &ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
) -> Result<bool, SdkError> {
    let primary = reference == &record.body.master_certificate.body.primary_device_ref;
    if let Some(join) = recipient {
        let invitation = &join.token.invitation.body;
        if invitation.destination_ref.as_ref() != Some(reference)
            || invitation.account_anchor != record.body.account_anchor
            || invitation.base_record_hash != object_hash(record)?
            || invitation.base_epoch != record.body.device_set_epoch
            || primary
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
    } else if !primary {
        return Err(SdkError::PairingCode("PrimaryRequired"));
    }
    Ok(primary)
}

fn validated_join(request: &LocalBusFrame) -> Result<Join, SdkError> {
    let join: Join = serde_json::from_value(request.body.clone())?;
    join.validate().map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    let invitation = &join.token.invitation;
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::custody::pairing::native::invitation_signing_bytes(&invitation.body)
            .map_err(|_| SdkError::PairingCode("InvalidInput"))?,
        &invitation.signature,
        &invitation.body.node_key,
    )
    .map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    Ok(join)
}

/// Only a new-recipient invitation may create an account actor without unlocking an account.
/// This grants neither an ordinary account nor session admission.
pub(super) fn creates_recipient(
    config: &crate::LocalBusConfig,
    request: &LocalBusFrame,
) -> Result<bool, SdkError> {
    if !matches!(request.method.as_str(), "device.pair.join" | "device.transfer.join") {
        return Ok(false);
    }
    if !config.pairing.as_ref().is_some_and(|config| config.enabled) {
        return Err(SdkError::PairingCode("NotFound"));
    }
    Ok(validated_join(request)?.token.invitation.body.recipient_mode == "new")
}

async fn install_new_recipient(
    state: &LocalBusDaemonState,
    account_id: &str,
    join: Join,
) -> Result<(), SdkError> {
    let config = state.config.pairing.clone().ok_or(SdkError::PairingCode("NotFound"))?;
    if !config.enabled {
        return Err(SdkError::PairingCode("NotFound"));
    }
    if join.token.invitation.body.recipient_mode != "new" {
        return Err(SdkError::AccountDbNotUnlocked);
    }
    if state.accounts.contains_key(account_id) {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let root = &state.config.data_root;
    // Account IDs are local choices; a token cannot select an existing account's vault.
    let provider = provider_for_account(root, account_id.into())?;
    if crate::custody::account_exists(root, account_id)? {
        return Err(SdkError::PairingCode("Busy"));
    }
    let profile = state.nodes.selected(None, false)?.ok_or(SdkError::NoNodeSelected)?;
    let invitation = &join.token.invitation.body;
    let tcp = crate::node::resolve_node_addr(&profile.gateway.tcp_addr).await?;
    let vault = super::custody_setup::primary_provider(&state.config);
    let endpoint = profile
        .gateway_config(
            root,
            GatewayQuicEndpointConfig {
                bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                gateway_addr: tcp,
                server_name: String::new(),
                ca_cert: std::path::PathBuf::new(),
                principal_id: invitation.account_anchor.clone(),
                device_id: "unreserved".into(),
                target_delivery_id: String::new(),
                prekey_http_url: None,
            },
        )
        .await?;
    let gateway = GatewaySessionConfig::auto(endpoint)
        .with_tcp_gateway_addr(tcp)
        .with_native_custody(GatewayCustodyConfig {
            account_root: root.clone(),
            account_id: account_id.into(),
            node_id: profile.node_id,
            node_public_key: profile.node_public_key,
            vault: vault.clone(),
        });
    let mut network = crate::gateway::proof_network_config(&gateway)?;
    network.gateway_address = tcp;
    let node = crate::custody::CustodyConnection::discover_pairing_node(network.clone()).await?;
    if node.envelope().body.node_signing_public_key != invitation.node_key {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let proof: Arc<dyn PairingNative> = Arc::new(FreshPairingNative::new(network, vault.clone()));
    let runtime = tokio::runtime::Handle::current();
    let participant = Arc::new(LocalPairingParticipant {
        root: root.clone(),
        account_id: account_id.into(),
        vault,
        provider,
        db: Mutex::new(None),
        persist: Arc::new(NativePairingPublication {
            native: proof.clone(),
            runtime: runtime.clone(),
        }),
        query: Arc::new(NativePairingQuery { config: gateway, runtime }),
    });
    let mut actor = PairingActor::new(
        PairingIdentity {
            account_id: account_id.into(),
            local_ref: DeviceRef {
                account_anchor: invitation.account_anchor.clone(),
                device_id: "unreserved".into(),
                device_epoch: 1,
            },
            master_public_key: None,
            base_record_hash: invitation.base_record_hash.clone(),
            base_epoch: invitation.base_epoch,
            is_primary: false,
        },
        Some(proof),
        Arc::new(HttpRelay::from_config(&config)?),
        config,
    );
    actor.set_full_node(node);
    actor.set_participant(participant);
    install_actor_with_writer(root, account_id.into(), actor, None)
}

/// G3 is the only path from a new recipient staging actor to an ordinary unlocked account.
pub(super) fn adopt_installed(
    state: &mut LocalBusDaemonState,
    account_id: &str,
) -> Result<bool, SdkError> {
    if state.accounts.contains_key(account_id) {
        return Ok(false);
    }
    let Some(client) =
        crate::custody::pairing::take_installed_recipient(&state.config.data_root, account_id)?
    else {
        return Ok(false);
    };
    let native = client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
    let anchor = native.record().body.account_anchor.clone();
    let device_id = native.local_device_id()?.to_owned();
    let endpoint = GatewayQuicEndpointConfig {
        bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        gateway_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        server_name: String::new(),
        ca_cert: std::path::PathBuf::new(),
        principal_id: native.record().body.principal_id.clone(),
        device_id,
        target_delivery_id: client.owned_device_identity()?.storage_key().into(),
        prekey_http_url: None,
    };
    let gateway = GatewaySessionConfig::auto(endpoint).with_born_v3_account(native);
    let mut account = super::state::LocalBusAccountState::disconnected(client, gateway, anchor);
    account.activation_pending = true;
    account.native_setup = Some(state.config.clone());
    let index = account.client.account_index()?;
    index.set_account_unlocked(account_id, true)?;
    index.set_active_account(account_id)?;
    state.accounts.insert(account_id.into(), account);
    state.active_account_id = Some(account_id.into());
    Ok(true)
}

pub(super) fn refresh_source_role(
    account: &mut super::state::LocalBusAccountState,
) -> Result<(), SdkError> {
    if account.client.born_v3_account.is_none() {
        return Ok(());
    }
    let id = account.client.account_db()?.local_account_id.clone();
    let root = account.client.account_index()?.root();
    let current = crate::custody::load_data_account(root, &id, crate::custody::network_now()?)?;
    if account
        .client
        .born_v3_account
        .as_ref()
        .is_some_and(|cached| cached.record() != current.record())
    {
        account.gateway_config = account.gateway_config.clone().with_born_v3_account(&current);
        account.client.born_v3_account = Some(Box::new(current));
    }
    Ok(())
}
