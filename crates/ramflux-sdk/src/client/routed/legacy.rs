// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy routing accepts only an existing exact device-pair and ratchet-session binding.
use super::{GatewayInboxEntry, RamfluxClient, SdkError};
impl RamfluxClient {
    #[cfg(test)]
    pub(crate) async fn authorize_bound_legacy(
        &self,
        gateway: &crate::GatewaySessionConfig,
        entry: &GatewayInboxEntry,
        conversation: &str,
    ) -> Result<(), SdkError> {
        crate::RamfluxClient::require_legacy_routing_binding(
            &gateway.device_id,
            entry,
            conversation,
        )?;
        self.ensure_inbound_device(gateway, entry).await
    }

    /// Sync half of `authorize_bound_legacy`: the exact device/session/conversation binding,
    /// including the v2-blocks-legacy guard. Shared by the live DM path and the W1 DM paths.
    /// It does not run `ensure_inbound_device`; async callers must do that separately.
    #[cfg(test)]
    pub(crate) fn require_legacy_routing_binding(
        local: &str,
        entry: &GatewayInboxEntry,
        conversation: &str,
    ) -> Result<(), SdkError> {
        if crate::RamfluxClient::legacy_routing_binding(local, entry)?.as_deref()
            != Some(conversation)
        {
            return Err(SdkError::InboundRejected(
                "legacy delivery has no matching device/session/conversation binding".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn legacy_routing_binding(
        local: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<String>, SdkError> {
        let _ = (local, entry);
        Err(SdkError::GeneratedRefused {
            code: crate::GeneratedRefusalCode::Content,
            reason: "retired application codec".into(),
        })
    }
}
