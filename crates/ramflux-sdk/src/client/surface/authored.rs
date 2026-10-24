// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retained signed outgoing requests keep retry identity stable after projection advances.
use super::{Carrier, invalid, key};
use crate::{RamfluxClient, SdkError};
pub(super) fn authored_key(carrier: &Carrier) -> Result<(String, String), SdkError> {
    let prefix = key("authored", &carrier.surface_reference()?) + "/";
    let suffix = ramflux_protocol::hash_base64url(
        "ramflux.surface.authored.v1",
        &ramflux_protocol::canonical_json_bytes(&(
            &carrier.sender_principal_id,
            &carrier.message_id,
        ))?,
    );
    Ok((format!("{prefix}{suffix}"), prefix))
}
impl RamfluxClient {
    pub(crate) fn retain_authored_surface(&self, carrier: &Carrier) -> Result<(), SdkError> {
        let (key, prefix) = authored_key(carrier)?;
        let previous = self.account_db()?.load_actor_state::<serde_json::Value>(&key)?;
        let delivery =
            previous.as_ref().and_then(|row| row["delivery_state"].as_str()).unwrap_or("failed");
        self.account_db()?.persist_actor_state(
            &key,
            &serde_json::json!({"carrier":carrier,"delivery_state":delivery}),
        )?;
        self.account_db()?.prune_surface_records(&prefix, 256, 4 * 1024 * 1024, &key)?;
        Ok(())
    }
    pub(crate) fn reuse_authored_surface(
        &self,
        carrier: &Carrier,
    ) -> Result<Option<Carrier>, SdkError> {
        let (key, _) = authored_key(carrier)?;
        let previous = self
            .account_db()?
            .load_actor_state::<serde_json::Value>(&key)?
            .map(|row| {
                serde_json::from_value::<Carrier>(row.get("carrier").cloned().unwrap_or(row))
            })
            .transpose()?;
        if let Some(previous) = &previous
            && (previous.wire_base64 != carrier.wire_base64
                || previous.payload_kind != carrier.payload_kind
                || previous.sender_device_id != carrier.sender_device_id)
        {
            return Err(invalid("surface logical message id already used"));
        }
        Ok(previous)
    }
    pub(crate) fn surface_outgoing_submitted(&self, carrier: &Carrier) -> Result<bool, SdkError> {
        let (key, _) = authored_key(carrier)?;
        Ok(self
            .account_db()?
            .load_actor_state::<serde_json::Value>(&key)?
            .is_some_and(|row| row["delivery_state"] == "submitted" || row.get("schema").is_some()))
    }
    pub(crate) fn set_surface_outgoing_state(
        &self,
        carrier: &Carrier,
        state: &str,
    ) -> Result<(), SdkError> {
        let (key, prefix) = authored_key(carrier)?;
        self.account_db()?.persist_actor_state(
            &key,
            &serde_json::json!({"carrier":carrier,"delivery_state":state}),
        )?;
        self.account_db()?.prune_surface_records(&prefix, 256, 4 * 1024 * 1024, &key)?;
        if let Some(mut view) =
            self.account_db()?.client_record("surface", &carrier.surface_reference()?)?
        {
            view["delivery_state"] = serde_json::json!(state);
            self.account_db()?.persist_client_record(
                "surface",
                &carrier.surface_reference()?,
                &view,
            )?;
        }
        Ok(())
    }
}
