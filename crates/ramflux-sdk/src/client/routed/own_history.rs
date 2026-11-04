// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed transport binding for routed own-history imports and prepared completion.

use super::{Kind, Routing, invalid};
use crate::own_device_sync::SdkOwnDeviceSyncEnvelope;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};

impl RamfluxClient {
    pub(crate) fn routed_own_history_envelope(
        entry: &GatewayInboxEntry,
        route: &Routing,
        body: &[u8],
        local: &str,
    ) -> Result<Option<SdkOwnDeviceSyncEnvelope>, SdkError> {
        if route.kind != Kind::Control
            || !serde_json::from_slice::<serde_json::Value>(body)
                .is_ok_and(|value| value["schema"] == "ramflux.sdk.own_device_sync.v1")
        {
            return Ok(None);
        }
        let envelope: SdkOwnDeviceSyncEnvelope = ramflux_protocol::parse_i_json(body)?;
        if envelope.source_device_id != entry.envelope.source_device_id
            || envelope.target_device_id != local
        {
            return Err(invalid("own-device history transport scope mismatch"));
        }
        Ok(Some(envelope))
    }
}
