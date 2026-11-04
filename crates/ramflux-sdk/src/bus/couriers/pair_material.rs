// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Network-only pair-material acquisition; validation and ratchet changes stay on the actor.

use crate::bus::connection_manager::SessionContext;
use crate::client::routed::{SendMaterial, SendMaterialRequest};
use crate::{GatewaySessionConfig, SdkDeviceManifestResponse, SdkError};

pub(crate) async fn fetch(
    context: &SessionContext,
    config: &GatewaySessionConfig,
    request: SendMaterialRequest,
) -> Result<SendMaterial, SdkError> {
    let manifest = if let Some(root) = request.root {
        let response = crate::prekey::sdk_gateway_get_json::<Option<SdkDeviceManifestResponse>>(
            config,
            &format!("/mvp1/device-manifest/{root}"),
        )
        .await?
        .ok_or_else(|| SdkError::InboundPending("recipient authority unavailable".into()))?;
        Some((root, response))
    } else {
        None
    };
    let bundle = if let Some(lookup) = request.prekey {
        Some(
            context
                .call(
                    move |engine| {
                        Box::pin(async move { engine.fetch_prekey_bundle(&lookup).await })
                    },
                    context.call_deadline(),
                )
                .await?
                .bundle
                .ok_or_else(|| SdkError::InboundPending("recipient prekey unavailable".into()))?,
        )
    } else {
        None
    };
    Ok(SendMaterial { manifest, bundle })
}
