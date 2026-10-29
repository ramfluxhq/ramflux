// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated transport provenance retained across deferred group decryption.
use super::{SurfaceSender, key};
use crate::{RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub(super) struct Origin {
    pub principal: String,
    pub device: String,
    pub envelope_id: String,
    pub expires_at: i64,
    #[serde(default)]
    pub group_epoch: Option<u64>,
}
impl Origin {
    pub fn sender(&self) -> SurfaceSender<'_> {
        SurfaceSender {
            principal: &self.principal,
            device: &self.device,
            envelope_id: &self.envelope_id,
            expires_at: Some(self.expires_at),
            group_epoch: self.group_epoch,
        }
    }
}
impl RamfluxClient {
    pub(crate) fn record_surface_origin(
        &self,
        message: &str,
        entry: &crate::GatewayInboxEntry,
        group_epoch: Option<u64>,
    ) -> Result<(), SdkError> {
        self.account_db()?.persist_message_actor_state(
            message,
            &key("origin", message),
            &Origin {
                group_epoch,
                principal: entry.envelope.source_principal_id.clone(),
                device: entry.envelope.source_device_id.clone(),
                envelope_id: entry.envelope.envelope_id.clone(),
                expires_at: entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl)),
            },
        )?;
        Ok(())
    }
}
