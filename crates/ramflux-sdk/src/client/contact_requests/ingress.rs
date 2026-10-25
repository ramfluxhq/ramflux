// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Limited stranger authentication for the request-only encrypted envelope.
use super::{ENVELOPE_SCHEMA, invalid};
use crate::prelude::*;
impl RamfluxClient {
    pub(crate) async fn contact_request_candidate(
        &self,
        gateway: &GatewaySessionConfig,
        entry: &GatewayInboxEntry,
    ) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
        self.maintain_contact_requests()?;
        if entry.envelope.encrypted_payload.len() > 262_144 {
            return Err(invalid("contact envelope exceeds its byte budget"));
        }
        let packet = crate::client::routed::decode(&entry.envelope)?;
        if packet.schema != ENVELOPE_SCHEMA {
            return Err(invalid("contact request envelope required"));
        }
        let root = packet
            .source_principal_commitment
            .ok_or_else(|| invalid("contact requester root is missing"))?;
        if ramflux_protocol::decode_base64url(&root).map_or(true, |bytes| {
            bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != root
        }) {
            return Err(invalid("contact requester root is malformed"));
        }
        let db = self.account_db()?;
        if db.contact_request_fence(&root, now_unix_timestamp())?.is_some()
            || db.contact_request(&root, "inbound")?.is_some_and(|record| {
                record.state == "blocked"
                    || (record.state == "declined"
                        && now_unix_timestamp()
                            < record.updated_at.saturating_add(super::DECLINE_COOLDOWN_SECONDS))
            })
        {
            return Err(invalid("contact requests from this root are closed"));
        }
        let manifest =
            crate::client::contact::fetch_verified_device_manifest(gateway, &root).await?;
        let sender = manifest
            .devices
            .iter()
            .find(|device| device.device_id == entry.envelope.source_device_id)
            .ok_or_else(|| invalid("contact requester device is not current"))?;
        crate::client::routed::verify_sender_record(
            entry,
            &serde_json::json!({
            "principal_id":manifest.principal_id,"signing_public_key":sender.branch_public_key}),
        )?;
        let now = now_unix_timestamp();
        if !db.charge_contact_request(&format!("bootstrap:{root}"), 32, 3600, now)?
            || !db.charge_contact_request("bootstrap-attempts", 120, 3600, now)?
        {
            return Err(SdkError::InboundPending("contact authentication budget exhausted".into()));
        }
        let own = self.owned_device_identity()?;
        self.cache_verified_device_manifest(gateway, own.root_commitment(), "contact-request-self")
            .await?;
        Ok(manifest)
    }
    pub(crate) fn contact_route_gate(
        &self,
        entry: &GatewayInboxEntry,
        route: &crate::client::routed::Routing,
        body: &[u8],
    ) -> Result<(), SdkError> {
        use crate::client::routed::Kind;
        if !matches!(route.kind, Kind::Direct | Kind::Control) {
            return Ok(());
        }
        self.contact_request_admission(entry)?;
        let source = self.authenticated_device_identity(entry)?;
        if self.pending_contact_root(source.root_commitment())?
            && !self.friend_link_peer_is_accepted(source.root_commitment())?
            && route.kind != Kind::Direct
        {
            self.verify_contact_control(entry, route, body)?;
        }

        Ok(())
    }
}
