// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Consent before conversation projection; request-only device authority cannot admit other controls.
use crate::prelude::*;
use ramflux_storage::ContactRequestRecord;
use serde_json::{Value, json};
mod delivery;
mod ingress;
mod messages;
mod wire;
pub(crate) use delivery::{flush, status as delivery_status};
pub(crate) use wire::{Control, Decision, ENVELOPE_SCHEMA, conversation};
use wire::{TTL, invalid};
pub(super) const DECLINE_COOLDOWN_SECONDS: i64 = 60;

impl RamfluxClient {
    pub(crate) fn contact_request_policy(&self) -> Result<String, SdkError> {
        Ok(self
            .account_db()?
            .client_record("settings", "contact_requests")?
            .and_then(|value| value["contact_requests"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "manual".into()))
    }
    pub(crate) fn set_contact_request_policy(&self, policy: &str) -> Result<(), SdkError> {
        if !matches!(policy, "manual" | "auto_accept") {
            return Err(invalid("contact_requests must be manual or auto_accept"));
        }
        self.account_db()?.persist_client_record(
            "settings",
            "contact_requests",
            &json!({"contact_requests":policy}),
        )?;
        Ok(())
    }
    pub(crate) fn contact_request_retryable(&self, selector: &str) -> Result<bool, SdkError> {
        self.account_db()?.expire_contact_requests(now_unix_timestamp())?;
        let root = self
            .account_db()?
            .client_record("identity", selector)?
            .and_then(|row| row["contact_identity_commitment"].as_str().map(str::to_owned))
            .unwrap_or_else(|| selector.into());
        Ok(self.account_db()?.contact_request(&root, "outbound")?.is_some_and(|row| {
            row.state == "expired"
                || (row.state == "declined"
                    && now_unix_timestamp()
                        >= row.updated_at.saturating_add(DECLINE_COOLDOWN_SECONDS))
        }))
    }
    pub(crate) fn pending_contact_root(&self, root: &str) -> Result<bool, SdkError> {
        Ok(self
            .account_db()?
            .contact_request(root, "inbound")?
            .is_some_and(|row| row.state == "pending" && row.expires_at > now_unix_timestamp()))
    }
    pub(crate) fn contact_request_admission(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let reference = self.inbound_device_reference(entry)?;
        let Some((root, _)) = ramflux_protocol::parse_qualified_device_id(&reference)? else {
            return Ok(());
        };
        let db = self.account_db()?;
        if let Some(request) = db.contact_request(&root, "inbound")?
            && !self.friend_link_peer_is_accepted(&root)?
            && (request.state != "pending" || request.expires_at <= now_unix_timestamp())
        {
            return Err(invalid("contact request is declined, blocked or expired"));
        }
        Ok(())
    }
    pub(crate) fn receive_contact_control(
        &self,
        entry: &GatewayInboxEntry,
        route: &crate::client::routed::Routing,
        bytes: &[u8],
    ) -> Result<bool, SdkError> {
        #[derive(serde::Deserialize)]
        struct Header {
            body: HeaderBody,
        }
        #[derive(serde::Deserialize)]
        struct HeaderBody {
            schema: String,
        }
        if !serde_json::from_slice::<Header>(bytes)
            .is_ok_and(|header| header.body.schema == wire::DOMAIN)
        {
            return Ok(false);
        }
        let control = self.verify_contact_control(entry, route, bytes)?;
        self.apply_contact_control(&control)?;
        Ok(true)
    }
    pub(crate) fn apply_contact_control(&self, control: &Control) -> Result<(), SdkError> {
        let body = &control.body;
        let db = self.account_db()?;
        let now = now_unix_timestamp();
        db.expire_contact_requests(now)?;
        if body.kind != Decision::Request {
            return self.apply_contact_response(control);
        }
        let root = &body.requester_root;
        if self.friend_rejection_reason(&body.manifest.principal_id)?.is_some() {
            return Ok(());
        }
        if let Some(old) = db.contact_request(root, "inbound")? {
            if old.state == "blocked"
                || (old.state == "declined"
                    && (now < old.updated_at.saturating_add(DECLINE_COOLDOWN_SECONDS)
                        || body.issued_at <= old.updated_at))
            {
                return Ok(());
            }
            if old.request_id == body.request_id {
                if old.state == "accepted" {
                    self.stage_contact_response(&old, Decision::Accept)?;
                }
                return Ok(());
            }
            if !matches!(old.state.as_str(), "expired" | "declined" | "accepted") {
                return Err(invalid("another contact request is already pending"));
            }
        }
        if !db.charge_contact_request(&format!("inbound:{root}"), 4, 3600, now)?
            || !db.charge_contact_request("inbound-account", 64, 3600, now)?
        {
            return Err(invalid("contact request rate limit exceeded"));
        }
        let prior = db
            .friend_link_for_peer(root)?
            .or(db.friend_link_for_peer(&body.manifest.principal_id)?);
        let reciprocal = self.friend_link_peer_is_accepted(root)?
            || self.friend_link_peer_is_accepted(&body.manifest.principal_id)?;
        let request = ContactRequestRecord {
            contact_identity_commitment: root.clone(),
            direction: "inbound".into(),
            request_id: body.request_id.clone(),
            principal_id: body.manifest.principal_id.clone(),
            link_id: prior.map_or_else(
                || super::contact_roots::contact_link_id(root, &body.target_root),
                |link| Ok(link.link_id),
            )?,
            state: "pending".into(),
            request_json: serde_json::to_vec(control)?,
            expires_at: body.expires_at,
            updated_at: now,
        };
        if !db.persist_contact_request(&request)? {
            return Ok(());
        }
        self.record_pending_friend_link(&request.link_id, root, &body.target_root)?;
        if reciprocal || self.contact_request_policy()? == "auto_accept" {
            self.decide_inbound_contact(&request, "accepted")?;
        }
        Ok(())
    }
    fn apply_contact_response(&self, control: &Control) -> Result<(), SdkError> {
        let body = &control.body;
        let db = self.account_db()?;
        let request = db
            .contact_request(&body.target_root, "outbound")?
            .filter(|request| request.request_id == body.request_id)
            .ok_or_else(|| invalid("contact response has no matching outbound request"))?;
        let state = if body.kind == Decision::Accept { "accepted" } else { "declined" };
        if request.state == state {
            return Ok(());
        }
        if request.state != state && request.state != "pending" {
            return Err(invalid("contact response cannot reactivate a terminal request"));
        }
        if self.friend_rejection_reason(&body.manifest.principal_id)?.is_some() {
            return Ok(());
        }
        db.decide_contact_request(
            &body.target_root,
            "outbound",
            &body.request_id,
            state,
            now_unix_timestamp(),
        )?;
        if body.kind == Decision::Accept {
            self.establish_friend_link(&request.link_id, &body.requester_root, &body.target_root)?;
            self.replicate_contact_acceptance(&request)?;
        }
        Ok(())
    }
    pub(crate) fn decide_inbound_contact(
        &self,
        request: &ContactRequestRecord,
        state: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if request.state == state {
            return Ok(());
        }
        db.write_transaction(|| -> Result<(), SdkError> {
            if !db.decide_contact_request(
                &request.contact_identity_commitment,
                "inbound",
                &request.request_id,
                state,
                now_unix_timestamp(),
            )? {
                return Err(crate::ContactReason::RequestClosed.into());
            }
            let own = self.owned_device_identity()?;
            if state == "accepted" {
                if !self.friend_link_peer_is_accepted(&request.contact_identity_commitment)? {
                    self.establish_friend_link(
                        &request.link_id,
                        &request.contact_identity_commitment,
                        own.root_commitment(),
                    )?;
                }
                db.confirm_reciprocal_contact(
                    &request.contact_identity_commitment,
                    now_unix_timestamp(),
                )?;
                self.replicate_contact_acceptance(request)?;
                self.stage_contact_response(request, Decision::Accept)?;
                self.release_contact_messages(&request.contact_identity_commitment)?;
            } else {
                if state == "blocked" {
                    self.block_friend_link(&request.link_id)?;
                } else if db.friend_link(&request.link_id)?.state == "pending" {
                    self.reject_friend_link(&request.link_id)?;
                }
                db.discard_contact_messages(&request.contact_identity_commitment)?;
                if state == "declined" {
                    self.stage_contact_response(request, Decision::Decline)?;
                }
            }
            Ok(())
        })
    }
    fn replicate_contact_acceptance(&self, request: &ContactRequestRecord) -> Result<(), SdkError> {
        let manifest: crate::prekey::SdkDeviceManifestResponse = self
            .account_db()?
            .load_actor_state(&format!(
                "identity/manifest-root/{}",
                request.contact_identity_commitment
            ))?
            .ok_or_else(|| invalid("verified accepted contact manifest is unavailable"))?;
        self.stage_own_contact(&manifest, &request.link_id)
    }
    pub(crate) fn contact_requests_list(&self) -> Result<Value, SdkError> {
        self.account_db()?.expire_contact_requests(now_unix_timestamp())?;
        let db = self.account_db()?;
        let mut records = db.pending_contact_requests()?;
        records.extend(db.outgoing_contact_requests()?);
        let requests = records
            .iter()
            .map(|record| self.contact_request_preview(record))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({"requests":requests,"contact_requests":self.contact_request_policy()?}))
    }
    pub(crate) fn contact_request_preview(
        &self,
        record: &ContactRequestRecord,
    ) -> Result<Value, SdkError> {
        let wire: Value = serde_json::from_slice(&record.request_json)?;
        let raw_note =
            if record.direction == "inbound" { &wire["body"]["note"] } else { &wire["note"] };
        let note = raw_note.as_str().map(ramflux_protocol::text_safety::quote_fallback_field);
        let held = if record.direction == "inbound" {
            self.account_db()?.held_contact_messages(&record.contact_identity_commitment)?
        } else {
            Vec::new()
        };
        let own = self.read_device_identity()?.ok_or(SdkError::IdentityRootMissing)?;
        let material = |root: &str| -> Result<_, SdkError> {
            let manifest = self
                .account_db()?
                .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
                    "identity/manifest-root/{root}"
                ))?
                .ok_or_else(|| invalid("request safety material unavailable"))?;
            super::contact::contact_safety_material_from_manifest(&manifest)
        };
        let safety = material(own.root_commitment())
            .and_then(|own| {
                material(&record.contact_identity_commitment)
                    .map(|peer| ramflux_crypto::safety_number(&own, &peer))
            })
            .ok();
        Ok(
            json!({"request_id":record.request_id,"link_id":record.link_id,"principal_id":record.principal_id,
            "root_commitment":record.contact_identity_commitment,"direction":record.direction,"state":record.state,
            "expires_at":record.expires_at,"note":note,"message_count":held.len(),
            "preview":Self::contact_message_preview(held.first().map(Vec::as_slice))?,
            "safety_number":safety}),
        )
    }
}
