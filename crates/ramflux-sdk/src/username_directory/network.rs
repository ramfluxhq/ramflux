// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Separate native proof connections carry only signed username documents and public state.
use crate::{SdkError, custody::PrimaryVault, gateway::GatewaySessionConfig};
use ramflux_protocol::{
    custody::{CustodyServerFrame, CustodySessionAction, DeviceSet, Envelope},
    username_directory as w,
};
use std::sync::Arc;

pub(crate) struct UsernameNetworkReply {
    pub reply: w::NativeUsernameReply,
    pub own_record: Envelope<DeviceSet>,
    pub own_home: String,
}

pub(crate) async fn exchange_username(
    config: &GatewaySessionConfig,
    transport: &super::UsernameConnection,
    center: w::NativeDirectoryPin,
    action: w::NativeUsernameAction,
) -> Result<UsernameNetworkReply, SdkError> {
    if !w::enabled() {
        return Err(w::DirectoryCode::DirectoryUnavailable.into());
    }
    center.validate().map_err(|_| w::DirectoryCode::DirectoryUnavailable)?;
    let custody = config.custody.as_ref().ok_or_else(|| {
        tracing::debug!(stage = "configuration", "username native custody unavailable");
        SdkError::NetworkingPending
    })?;
    let vault: Arc<dyn PrimaryVault> = Arc::clone(&custody.vault);
    let network = crate::gateway::proof_network_config(config)?;
    let home = network.node_id.clone();
    let mut connection = transport
        .open(network.clone(), Arc::clone(&vault))
        .await
        .inspect_err(|error| trace_failure("connect", error))?;
    let account = connection.account();
    let now = crate::custody::network_now()?;
    let declaration = if account.local_device_id()?
        == account.record().body.master_certificate.body.primary_device_ref.device_id
    {
        Some(
            account
                .group_primary(vault.as_ref())
                .inspect_err(|error| trace_failure("primary", error))?
                .sign_home_declaration(
                    ramflux_protocol::home_migration::HomeDeclarationV1 {
                        version: 1,
                        principal_id: account.record().body.principal_id.clone(),
                        account_anchor: account.record().body.account_anchor.clone(),
                        home_node: home.clone(),
                        created_at: now,
                        nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                    },
                    account.verified(),
                    now,
                )?,
        )
    } else {
        None
    };
    let own_record = account.record().clone();
    let request = w::NativeUsernameRequest { center, declaration, action };
    request.validate().map_err(|_| w::DirectoryCode::InvalidProfile)?;
    let result = connection
        .request(CustodySessionAction::UsernameDirectory { request: Box::new(request) })
        .await
        .inspect_err(|error| trace_failure("request", error))?;
    let CustodyServerFrame::UsernameDirectory { response } = result else {
        return Err(w::DirectoryCode::DirectoryUnavailable.into());
    };
    transport.retain(&network, connection)?;
    if let w::NativeUsernameReply::Refused { failure } = *response {
        return Err(failure.code.into());
    }
    Ok(UsernameNetworkReply { reply: *response, own_record, own_home: home })
}

fn trace_failure(stage: &str, error: &SdkError) {
    tracing::debug!(
        stage,
        error_code = crate::prelude::local_bus_error_code(error),
        "username native exchange deferred"
    );
}
