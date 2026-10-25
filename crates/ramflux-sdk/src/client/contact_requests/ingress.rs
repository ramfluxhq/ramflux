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
        let now = now_unix_timestamp();
        for (bucket, limit) in [(format!("bootstrap:{root}"), 32), (format!("inbound:{root}"), 4)] {
            if !db.contact_request_budget_available(&bucket, limit, now)? {
                return Err(invalid("contact requester rate limit exceeded"));
            }
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
        // Global and account pressure defer before any charge, so redriving a held request never
        // spends the requester's own quota.
        if !self.contact_admission_capacity(Some(&root), now)? {
            return Err(SdkError::ContactRequestCapacity(
                "contact admission capacity exhausted".into(),
            ));
        }
        if !db.charge_contact_request(&format!("bootstrap:{root}"), 32, 3600, now)? {
            if db.contact_request_budget_available(&format!("bootstrap:{root}"), 32, now)? {
                return Err(SdkError::ContactRequestCapacity(
                    "contact rate bucket capacity exhausted".into(),
                ));
            }
            return Err(invalid("contact requester rate limit exceeded"));
        }
        if !db.charge_contact_request("bootstrap-attempts", 120, 3600, now)? {
            return Err(SdkError::ContactRequestCapacity(
                "contact authentication budget exhausted".into(),
            ));
        }
        let own = self.owned_device_identity()?;
        self.cache_verified_device_manifest(gateway, own.root_commitment(), "contact-request-self")
            .await?;
        Ok(manifest)
    }
    /// Read-only global and account-wide admission capacity. `root` adds the requester's own
    /// bucket and floor rows to the table-capacity estimate once it is authenticated.
    pub(crate) fn contact_admission_capacity(
        &self,
        root: Option<&str>,
        now: i64,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        if !db.contact_request_budget_available("bootstrap-attempts", 120, now)?
            || !db.contact_request_budget_available("inbound-account", 64, now)?
        {
            return Ok(false);
        }
        let mut buckets = vec!["bootstrap-attempts".to_owned(), "inbound-account".to_owned()];
        if let Some(root) = root {
            buckets.extend([format!("bootstrap:{root}"), format!("inbound:{root}")]);
        }
        Ok(db.contact_request_inbound_capacity(&buckets, root, now)?)
    }
    pub(crate) fn contact_route_gate(
        &self,
        entry: &GatewayInboxEntry,
        route: &crate::client::routed::Routing,
        body: &[u8],
    ) -> Result<(), SdkError> {
        use crate::client::routed::Kind;
        if matches!(route.kind, Kind::GroupControl | Kind::GroupMessage) {
            let source = self.authenticated_device_identity(entry)?;
            if self.friend_rejection_reason(source.root_commitment())?.as_deref()
                == Some("friend.blocked")
                || self.friend_rejection_reason(&entry.envelope.source_principal_id)?.as_deref()
                    == Some("friend.blocked")
            {
                return Err(invalid("group sender is blocked"));
            }
            if route.kind == Kind::GroupMessage {
                let group = route.group_id.as_deref().ok_or_else(|| invalid("group id missing"))?;
                if !self
                    .local_is_group_member(group)
                    .map_err(|error| SdkError::InboundPending(error.to_string()))?
                {
                    if self.account_db()?.shared_group_state(group)?.is_some() {
                        return Err(invalid("group membership has ended"));
                    }
                    return Err(SdkError::InboundPending(
                        "group consent or membership is pending".into(),
                    ));
                }
            }
            return Ok(());
        }
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
