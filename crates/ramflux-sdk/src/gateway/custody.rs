// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native possession proof on the same transport used by the ordinary session engine.
use super::GatewaySessionConfig;
use crate::{
    SdkError,
    custody::{
        BornAccount, BranchCredentials, CustodyConnection, CustodyNetworkConfig, PrimaryVault,
    },
};
use ramflux_protocol::custody::{BindingMode, DeviceRef};
use std::{path::PathBuf, sync::Arc};

type SessionStream = Box<dyn ramflux_transport::GatewaySessionTransport + Send>;

/// Independent receiving-node trust and the selected account's branch vault provider.
#[derive(Clone)]
pub struct GatewayCustodyConfig {
    pub account_root: PathBuf,
    pub account_id: String,
    pub node_id: String,
    pub node_public_key: String,
    pub vault: Arc<dyn PrimaryVault>,
}
impl std::fmt::Debug for GatewayCustodyConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayCustodyConfig")
            .field("account_id", &self.account_id)
            .field("node_id", &self.node_id)
            .field("vault", &"<redacted>")
            .finish_non_exhaustive()
    }
}
pub(super) struct Prepared {
    network: CustodyNetworkConfig,
    credentials: (BornAccount, DeviceRef, BranchCredentials),
}
pub(super) async fn prepare(
    config: &GatewaySessionConfig,
) -> Result<Option<Box<Prepared>>, SdkError> {
    let Some(custody) = &config.custody else { return Ok(None) };
    refresh_local_publication(config, custody).await?;
    let network = CustodyNetworkConfig {
        account_root: custody.account_root.clone(),
        account_id: custody.account_id.clone(),
        device_id: config.device_id.clone(),
        gateway_address: config.gateway_addr,
        server_name: config.server_name.clone(),
        ca_certificate: config.ca_cert.clone(),
        node_id: custody.node_id.clone(),
        node_public_key: custody.node_public_key.clone(),
        audience: custody.node_id.clone(),
        binding_mode: BindingMode::HomeRelayReceipt,
        allow_no_channel_binding: false,
        timeout: config.timeout,
    };
    let credentials =
        CustodyConnection::<SessionStream>::prepare(&network, Arc::clone(&custody.vault)).await?;
    Ok(Some(Box::new(Prepared { network, credentials })))
}
async fn refresh_local_publication(
    config: &GatewaySessionConfig,
    custody: &GatewayCustodyConfig,
) -> Result<(), SdkError> {
    let root = custody.account_root.clone();
    let id = custody.account_id.clone();
    let (anchor, state) = tokio::task::spawn_blocking(move || {
        let account = crate::custody::load_account(&root, &id, crate::custody::network_now()?)?;
        Ok::<_, SdkError>((account.record().body.account_anchor.clone(), account.state()))
    })
    .await
    .map_err(|_| SdkError::CustodySetupInvalid)??;
    // This is a public directory read over the configured TLS/QUIC peer. It does not
    // enter either identity-proof mode and remains possible before initial registration.
    let manifest = crate::prekey::sdk_gateway_get_json::<
        Option<crate::prekey::SdkDeviceManifestResponse>,
    >(config, &format!("/mvp1/device-manifest/{anchor}"))
    .await?;
    let Some(manifest) = manifest else {
        return if state == crate::custody::CreationState::NetworkingPending {
            Ok(())
        } else {
            Err(SdkError::InboundPending("native current head unavailable".into()))
        };
    };
    if manifest.principal_commitment != anchor {
        return Err(SdkError::CustodySetupInvalid);
    }
    let native = manifest.custody.ok_or(SdkError::CustodyModeDowngrade)?;
    let root = custody.account_root.clone();
    let id = custody.account_id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let now = crate::custody::network_now()?;
        let authority = ramflux_protocol::custody::CustodyAuthority {
            publication: native.publication,
            custodian_publication: native.custodian_publication,
        };
        let verified = ramflux_crypto::custody::verify_publication(&authority, now)?;
        let local = crate::custody::load_account(&root, &id, now)?;
        if verified.envelope().body.account_anchor != local.record().body.account_anchor {
            return Err(SdkError::CustodySetupInvalid);
        }
        // An explicit recovery must publish its journaled successor before the directory
        // can serve it. Authenticate the predecessor without adopting it or lowering pins.
        if local.recovery_publication_pending(&root)?
            && verified.envelope().body.device_set_epoch < local.record().body.device_set_epoch
        {
            return Ok(ramflux_crypto::custody::PinOutcome::Unchanged);
        }
        crate::custody::accept_publication(&root, &id, &authority, now)
    })
    .await
    .map_err(|_| SdkError::CustodySetupInvalid)??;
    if outcome == ramflux_crypto::custody::PinOutcome::Fenced {
        return Err(SdkError::InboundRejected("native current head is fenced".into()));
    }
    Ok(())
}

pub(super) async fn authenticate(
    prepared: Option<Box<Prepared>>,
    stream: SessionStream,
    config: &mut GatewaySessionConfig,
) -> Result<SessionStream, SdkError> {
    let Some(prepared) = prepared else { return Ok(stream) };
    let Prepared { network, credentials } = *prepared;
    let connection =
        Box::pin(CustodyConnection::authenticate_stream(network, stream, credentials)).await?;
    let (stream, account, reference, credentials) = connection.into_gateway_parts().await?;
    let source = ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(
        account.verified(),
        &reference.device_id,
    )?;
    account.verified().authorize(&reference, "register", crate::custody::network_now()?)?;
    let certificate = account
        .record()
        .body
        .devices
        .iter()
        .find(|entry| entry.device_id == reference.device_id)
        .and_then(|entry| entry.branch_certificate.as_ref())
        .ok_or(SdkError::CustodySetupInvalid)?;
    config.principal_id.clone_from(&account.record().body.principal_id);
    config.device_id.clone_from(&reference.device_id);
    config.device_epoch = reference.device_epoch;
    source.storage_key().clone_into(&mut config.target_delivery_id);
    config.branch_proof_hash = ramflux_protocol::custody::object_hash(certificate)?;
    config.device_branch = Some(Arc::new(credentials.signing));
    config.source_identity = Some(source);
    config.custody_networking_pending = false;
    Ok(Box::new(NativeSessionStream(stream)))
}

// The native directory can carry checkpoint evidence beyond the ordinary frame budget.
// Select the larger bounded reader only after the channel-bound native handoff.
struct NativeSessionStream(SessionStream);
impl ramflux_transport::GatewaySessionFrameSink for NativeSessionStream {
    fn send_frame<'a>(
        &'a mut self,
        bytes: &'a [u8],
    ) -> ramflux_transport::GatewaySessionFrameFuture<'a, ()> {
        self.0.send_frame(bytes)
    }
    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        self.0.finish()
    }
}
impl ramflux_transport::GatewaySessionFrameSource for NativeSessionStream {
    fn recv_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        self.0.recv_custody_frame()
    }
}

#[cfg(test)]
#[path = "custody_publication_tests.rs"]
mod publication_tests;
