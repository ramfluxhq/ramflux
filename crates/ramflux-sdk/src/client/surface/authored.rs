// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retained signed outgoing requests keep retry identity stable after projection advances.
use super::{Carrier, invalid, key};
use crate::{RamfluxClient, SdkError};
fn authored_key(carrier: &Carrier) -> Result<(String, String), SdkError> {
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
        self.account_db()?.persist_actor_state(&key, carrier)?;
        self.account_db()?.prune_surface_records(&prefix, 256, 4 * 1024 * 1024, &key)?;
        Ok(())
    }
    pub(crate) fn reuse_authored_surface(
        &self,
        carrier: &Carrier,
    ) -> Result<Option<Carrier>, SdkError> {
        let (key, _) = authored_key(carrier)?;
        let previous = self.account_db()?.load_actor_state::<Carrier>(&key)?;
        if let Some(previous) = &previous
            && (previous.wire_base64 != carrier.wire_base64
                || previous.payload_kind != carrier.payload_kind
                || previous.sender_device_id != carrier.sender_device_id)
        {
            return Err(invalid("surface logical message id already used"));
        }
        Ok(previous)
    }
}
