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

impl RamfluxClient {
    pub(crate) fn set_surface_delivery_devices(
        &self,
        carrier: &Carrier,
        devices: &[serde_json::Value],
    ) -> Result<(), SdkError> {
        let (id, _) = authored_key(carrier)?;
        if let Some(mut row) = self.account_db()?.load_actor_state::<serde_json::Value>(&id)? {
            row["delivery_devices"] = serde_json::json!(devices);
            self.account_db()?.persist_actor_state(&id, &row)?;
        }
        self.set_surface_delivery_field(carrier, "delivery_devices", serde_json::json!(devices))
    }
    pub(crate) fn set_surface_own_copy_state(
        &self,
        carrier: &Carrier,
        state: &str,
    ) -> Result<(), SdkError> {
        self.set_surface_delivery_field(carrier, "own_device_copy_state", serde_json::json!(state))
    }
    fn set_surface_delivery_field(
        &self,
        carrier: &Carrier,
        field: &str,
        value: serde_json::Value,
    ) -> Result<(), SdkError> {
        let reference = carrier.surface_reference()?;
        if let Some(mut view) = self.account_db()?.client_record("surface", &reference)? {
            view[field] = value;
            self.account_db()?.persist_client_record("surface", &reference, &view)?;
        }
        Ok(())
    }
}

impl RamfluxClient {
    pub(crate) fn queue_surface_own_copy(
        &self,
        carrier: &Carrier,
        epoch: Option<u64>,
    ) -> Result<bool, SdkError> {
        let result = (|| {
            let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            if carrier.sender_principal_id != local.principal_id
                || carrier.sender_device_id != local.device_id
            {
                return Err(invalid("own copy source differs from the local author"));
            }
            let control = self.surface_control_packet(carrier, super::ControlKind::Own, epoch)?;
            let bytes = control.bytes()?;
            let message = Self::surface_timeline_id(carrier)?;
            let reference = carrier.surface_reference()?;
            let thread = self
                .account_db()?
                .client_record("conversation", &carrier.conversation_id)?
                .ok_or_else(|| invalid("own surface conversation missing"))?;
            crate::bus::own_device_copy::stage(
                self,
                crate::client::own_device_copy::OwnMessageInput {
                    id: &message,
                    created_at: crate::prelude::now_unix_timestamp(),
                    conversation: &carrier.conversation_id,
                    group: thread["group_id"].as_str(),
                    body: &bytes,
                },
                Some(("surface", &reference)),
            )
        })();
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                tracing::warn!(%error,"surface own-device copy staging failed");
                self.set_surface_own_copy_state(carrier, "failed")?;
                Ok(false)
            }
        }
    }
}
