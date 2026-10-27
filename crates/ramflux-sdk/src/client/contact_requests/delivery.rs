// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded contact-control delivery through the ordinary authenticated device-pair transport.
use super::{ContactRequestRecord, Decision, ENVELOPE_SCHEMA, TTL, conversation, invalid};
use crate::prelude::*;
use serde::{Deserialize, Serialize};
const PREFIX: &str = "contact-request/send/";
#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Intent {
    pub(super) kind: Decision,
    pub(super) request_id: String,
    pub(super) requester_root: String,
    pub(super) target_root: String,
    pub(super) peer_root: String,
    pub(super) note: Option<String>,
    pub(super) expires_at: i64,
    #[serde(default)]
    pub(super) issued_at: i64,
    #[serde(default)]
    pub(super) nonce: String,
    pub(super) attempts: u8,
    pub(super) next_at: i64,
    pub(super) delivered: BTreeSet<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native_approval: Option<super::native_delivery::Approved>,
}
pub(super) fn key(intent: &Intent) -> String {
    format!(
        "{PREFIX}{}",
        ramflux_protocol::hash_base64url(
            "ramflux.contact_request.delivery.v1",
            format!("{}:{}:{:?}", intent.peer_root, intent.request_id, intent.kind).as_bytes()
        )
    )
}
fn queue(client: &RamfluxClient) -> Result<Vec<Intent>, SdkError> {
    let db = client.account_db()?;
    let now = now_unix_timestamp();
    let mut retained = Vec::new();
    for intent in db.list_actor_states::<Intent>(PREFIX)? {
        let closed = if intent.kind == Decision::Request {
            db.contact_request(&intent.peer_root, "outbound")?
                .is_none_or(|row| row.request_id != intent.request_id || row.state != "pending")
        } else {
            db.contact_request(&intent.peer_root, "inbound")?.is_none_or(|row| {
                row.request_id != intent.request_id
                    || row.state
                        != if intent.kind == Decision::Accept { "accepted" } else { "declined" }
            })
        };
        if intent.expires_at <= now
            || closed
            || (intent.kind != Decision::Request && intent.attempts >= 8)
        {
            db.remove_actor_state(&key(&intent))?;
        } else {
            retained.push(intent);
        }
    }
    Ok(retained)
}
fn enqueue(client: &RamfluxClient, intent: &Intent) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let pending = queue(client)?;
    let id = key(intent);
    if db.actor_state_exists(&id)? {
        return Ok(());
    }
    if pending.iter().filter(|row| row.attempts < 8).count() >= 128
        || pending.iter().filter(|row| row.peer_root == intent.peer_root).count() >= 4
    {
        return Err(SdkError::InboundPending("contact delivery capacity exhausted".into()));
    }
    db.persist_actor_state(&id, intent)?;
    Ok(())
}
fn material_hash(
    client: &RamfluxClient,
    recipient: &ramflux_crypto::RootQualifiedDeviceRef,
) -> Result<String, SdkError> {
    let record = client.trusted_device(recipient)?;
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.contact_request.recipient_material.v1",
        &ramflux_protocol::canonical_json_bytes(&(
            &record["device_epoch"],
            &record["signing_public_key"],
            &record["x25519_identity_public"],
        ))?,
    ))
}
impl RamfluxClient {
    pub(crate) async fn ensure_contact_request_before_direct(
        &self,
        engine: &mut GatewaySessionEngine,
        message: &GatewayDirectMessage,
    ) -> Result<(), SdkError> {
        let reference = Self::qualified_recipient(message)?;
        let (root, raw) = ramflux_protocol::parse_qualified_device_id(&reference)?
            .ok_or_else(|| invalid("recipient root required"))?;
        let Some(request) = self.account_db()?.contact_request(&root, "outbound")? else {
            if self
                .account_db()?
                .client_record("contact_request_status", &root)?
                .is_some_and(|row| row["state"] != "accepted")
            {
                return Err(SdkError::InboundPending(
                    "contact request must be explicitly retried".into(),
                ));
            }
            return Ok(());
        };
        if request.state == "accepted" {
            return Ok(());
        }
        if request.state != "pending" || request.expires_at <= now_unix_timestamp() {
            return Err(SdkError::InboundPending("contact request is closed or expired".into()));
        }
        // Resolve current key material before loading the ordinary send ratchet. Sending the
        // request below advances that pair, so no caller may retain a stale pre-request session.
        self.cache_verified_device_manifest(
            &engine.config,
            &root,
            "contact-request-before-message",
        )
        .await?;
        let recipient = self.device_identity_for_root(&root, &raw)?;
        let material = material_hash(self, &recipient)?;
        if self.account_db()?.contact_request_delivered(
            &request.request_id,
            &recipient,
            &material,
        )? {
            return Ok(());
        }
        let metadata = super::Metadata::read(&request)?;
        let selector = Intent {
            kind: Decision::Request,
            request_id: request.request_id.clone(),
            requester_root: self.owned_device_identity()?.root_commitment().into(),
            target_root: root.clone(),
            peer_root: root,
            note: metadata.note,
            issued_at: metadata.issued_at,
            nonce: metadata.nonce,
            expires_at: request.expires_at,
            attempts: 0,
            next_at: now_unix_timestamp(),
            delivered: BTreeSet::new(),
            native_approval: None,
        };
        let id = key(&selector);
        let stored = self.account_db()?.load_actor_state::<Intent>(&id)?;
        if stored.is_none() {
            enqueue(self, &selector)?;
        }
        let mut intent = stored.unwrap_or(selector);
        let now = now_unix_timestamp();
        if intent.attempts >= 8 || now < intent.next_at {
            return Err(SdkError::InboundPending(
                "contact request submission is backed off".into(),
            ));
        }
        intent.attempts += 1;
        intent.next_at = now.saturating_add((1_i64 << intent.attempts).min(60));
        self.account_db()?.persist_actor_state(&id, &intent)?;
        match deliver(self, engine, &mut intent).await {
            Ok((_, true)) => {
                self.account_db()?.remove_actor_state(&id)?;
            }
            Ok(_) => {}
            Err(error) => tracing::debug!(%error,"first-message contact request deferred"),
        }
        if !self.account_db()?.contact_request_delivered(
            &request.request_id,
            &recipient,
            &material,
        )? {
            return Err(SdkError::InboundPending(
                "contact request must be submitted before its first message".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn stage_contact_request(
        &self,
        peer: &crate::prekey::SdkDeviceManifestResponse,
        link_id: &str,
        note: Option<&str>,
    ) -> Result<(), SdkError> {
        if note.is_some_and(|n| {
            n.chars().count() > 140 || !ramflux_protocol::text_safety::single_line_is_safe(n)
        }) {
            return Err(crate::ContactReason::InvalidRequestNote.into());
        }
        let db = self.account_db()?;
        db.expire_contact_request(&peer.principal_commitment, "outbound", now_unix_timestamp())?;
        let old = db.contact_request(&peer.principal_commitment, "outbound")?;
        if old.is_none() {
            self.check_retained_outbound_contact_cooldown(&peer.principal_commitment)?;
        }
        if let Some(old) = &old {
            if old.state == "accepted" {
                return Ok(());
            }
            if !(matches!(old.state.as_str(), "expired" | "pending")
                || (old.state == "declined"
                    && now_unix_timestamp()
                        >= old.updated_at.saturating_add(super::DECLINE_COOLDOWN_SECONDS)))
            {
                return Err(invalid("contact request is closed or cooling down"));
            }
        }
        let now = now_unix_timestamp();
        if !db.charge_contact_request("outbound-account", 64, 3600, now)?
            || !db.charge_contact_request(
                &format!("outbound:{}", peer.principal_commitment),
                4,
                3600,
                now,
            )?
        {
            return Err(crate::ContactReason::LookupRateLimited.into());
        }
        // A local re-add restores this side's consent; an explicit block still needs unblock.
        db.clear_contact_request_fence(&peer.principal_commitment, Some("declined"))?;
        let own = self.owned_device_identity()?;
        let previous = old
            .as_ref()
            .filter(|row| row.state == "pending")
            .map(super::Metadata::read)
            .transpose()?;
        let metadata = if let Some(previous) = previous.filter(|m| !m.nonce.is_empty()) {
            previous
        } else {
            super::Metadata {
                nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                issued_at: now,
                note: note.map(str::to_owned),
                needs_reply: None,
            }
        };
        let id = super::wire::request_id(own.root_commitment(), &metadata.nonce)?;
        if let Some(old) = &old
            && old.state == "pending"
            && old.request_id != id
        {
            db.decide_contact_request(
                &peer.principal_commitment,
                "outbound",
                &old.request_id,
                "expired",
                now,
            )?;
        }
        self.restart_contact_request_pair(peer, old.as_ref(), &id)?;
        let intent = Intent {
            kind: Decision::Request,
            request_id: id.clone(),
            requester_root: own.root_commitment().into(),
            target_root: peer.principal_commitment.clone(),
            peer_root: peer.principal_commitment.clone(),
            note: metadata.note.clone(),
            expires_at: metadata.issued_at.saturating_add(TTL),
            issued_at: metadata.issued_at,
            nonce: metadata.nonce.clone(),
            attempts: 0,
            next_at: now,
            delivered: BTreeSet::new(),
            native_approval: None,
        };
        let record = ContactRequestRecord {
            contact_identity_commitment: peer.principal_commitment.clone(),
            direction: "outbound".into(),
            request_id: id,
            principal_id: peer.principal_id.clone(),
            link_id: link_id.into(),
            state: "pending".into(),
            request_json: metadata.bytes()?,
            expires_at: intent.expires_at,
            updated_at: now,
        };
        db.persist_contact_request(&record).map_err(|error| match error {
            StorageError::AuthorizationRejected => {
                SdkError::InboundPending("pending contact capacity exhausted".into())
            }
            other => other.into(),
        })?;
        self.record_outbound_contact_state(&peer.principal_commitment, "pending", now)?;
        db.remove_actor_state(&key(&intent))?;
        enqueue(self, &intent)
    }
    fn restart_contact_request_pair(
        &self,
        peer: &crate::prekey::SdkDeviceManifestResponse,
        old: Option<&ContactRequestRecord>,
        id: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let retained_status =
            db.client_record("contact_request_status", &peer.principal_commitment)?;
        let fresh_pair = old.is_some_and(|row| row.request_id != id)
            || retained_status
                .as_ref()
                .is_some_and(|row| matches!(row["state"].as_str(), Some("expired" | "declined")));
        if fresh_pair {
            for device in &peer.devices {
                let identity =
                    self.device_identity_for_root(&peer.principal_commitment, &device.device_id)?;
                self.remove_device_pair(&identity, "contact_request_restarted")?;
            }
        }
        Ok(())
    }
    pub(super) fn stage_contact_response(
        &self,
        request: &ContactRequestRecord,
        kind: Decision,
    ) -> Result<(), SdkError> {
        let own = self.owned_device_identity()?;
        let metadata = super::Metadata::read(request)?;
        let issued_at = now_unix_timestamp();
        let mut deferred = super::Metadata::read(request)?;
        deferred.needs_reply = Some(kind);
        self.account_db()?.update_contact_request_metadata(
            &request.contact_identity_commitment,
            "inbound",
            &request.request_id,
            &deferred.bytes()?,
        )?;
        let queued = enqueue(
            self,
            &Intent {
                kind,
                request_id: request.request_id.clone(),
                requester_root: request.contact_identity_commitment.clone(),
                target_root: own.root_commitment().into(),
                peer_root: request.contact_identity_commitment.clone(),
                note: None,
                expires_at: issued_at.saturating_add(TTL),
                issued_at,
                nonce: metadata.nonce,
                attempts: 0,
                next_at: now_unix_timestamp(),
                delivered: BTreeSet::new(),
                native_approval: None,
            },
        );
        match queued {
            Ok(()) => {
                deferred.needs_reply = None;
                self.account_db()?.update_contact_request_metadata(
                    &request.contact_identity_commitment,
                    "inbound",
                    &request.request_id,
                    &deferred.bytes()?,
                )?;
                Ok(())
            }
            Err(SdkError::InboundPending(reason)) => {
                tracing::debug!(%reason,"contact reply waits for delivery capacity");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}
pub(crate) async fn flush(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    account.client.maintain_contact_requests()?;
    let db = account.client.account_db()?;
    for request in db.deferred_contact_replies(now_unix_timestamp())? {
        if let Some(kind) = super::Metadata::read(&request)?.needs_reply {
            account.client.stage_contact_response(&request, kind)?;
        }
    }
    db.expire_contact_requests(now_unix_timestamp())?;
    let pending = queue(&account.client)?;
    let mut sent = 0;
    let mut attempted = 0;
    for mut intent in pending {
        let now = now_unix_timestamp();
        let id = key(&intent);
        if intent.kind == Decision::Request
            && account
                .client
                .account_db()?
                .contact_request(&intent.peer_root, "outbound")?
                .is_none_or(|row| row.state != "pending" || row.request_id != intent.request_id)
        {
            account.client.account_db()?.remove_actor_state(&id)?;
            continue;
        }
        if intent.kind != Decision::Request
            && account
                .client
                .account_db()?
                .contact_request(&intent.peer_root, "inbound")?
                .is_none_or(|row| {
                    row.request_id != intent.request_id
                        || row.state
                            != if intent.kind == Decision::Accept { "accepted" } else { "declined" }
                })
        {
            account.client.account_db()?.remove_actor_state(&id)?;
            continue;
        }
        if intent.expires_at <= now {
            account.client.account_db()?.remove_actor_state(&id)?;
            continue;
        }
        if intent.attempts >= 8 {
            if intent.kind != Decision::Request {
                account.client.account_db()?.remove_actor_state(&id)?;
            }
            continue;
        }
        if intent.next_at > now {
            continue;
        }
        if attempted >= 4 {
            continue;
        }
        attempted += 1;
        intent.attempts += 1;
        intent.next_at = now.saturating_add((1_i64 << intent.attempts).min(60));
        account.client.account_db()?.persist_actor_state(&id, &intent)?;
        let mut engine = account.take_live_engine().await?;
        let outcome = deliver(&account.client, &mut engine, &mut intent).await;
        account.put_engine(engine);
        match outcome {
            Ok((count, complete)) => {
                sent += count;
                if complete {
                    account.client.account_db()?.remove_actor_state(&id)?;
                }
            }
            Err(error) => tracing::debug!(%error,"contact control delivery deferred"),
        }
    }
    Ok(sent)
}
async fn deliver(
    client: &RamfluxClient,
    engine: &mut GatewaySessionEngine,
    intent: &mut Intent,
) -> Result<(usize, bool), SdkError> {
    let own = client.owned_device_identity()?;
    let own_manifest = crate::client::contact::fetch_verified_device_manifest(
        &engine.config,
        own.root_commitment(),
    )
    .await?;
    let peer =
        crate::client::contact::fetch_verified_device_manifest(&engine.config, &intent.peer_root)
            .await?;
    client.persist_identity_directory(&own_manifest)?;
    client.persist_identity_directory(&peer)?;
    let bytes = if own_manifest.custody.is_some() {
        super::native_delivery::approve(client, &engine.config, intent, &own_manifest).await?
    } else {
        let control = super::wire::sign(
            client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            super::wire::Body {
                schema: super::wire::DOMAIN.into(),
                kind: intent.kind,
                request_id: intent.request_id.clone(),
                requester_root: intent.requester_root.clone(),
                target_root: intent.target_root.clone(),
                actor_root: own.root_commitment().into(),
                issued_at: intent.issued_at,
                expires_at: intent.expires_at,
                nonce: intent.nonce.clone(),
                note: intent.note.clone(),
                manifest: own_manifest,
            },
        )?;
        zeroize::Zeroizing::new(serde_json::to_vec(&control)?)
    };
    if peer.devices.len() > 64 {
        return Err(invalid("contact request device fanout exceeds budget"));
    }
    let mut sent = 0;
    let mut complete = !peer.devices.is_empty();
    for device in peer.devices {
        let recipient = (intent.peer_root.clone(), device.device_id.clone());
        if intent.delivered.contains(&recipient) {
            if intent.kind != Decision::Request {
                continue;
            }
            let identity = client.device_identity_for_root(&intent.peer_root, &device.device_id)?;
            if client.account_db()?.contact_request_delivered(
                &intent.request_id,
                &identity,
                &material_hash(client, &identity)?,
            )? {
                continue;
            }
            intent.delivered.remove(&recipient);
        }
        let result = send_one(client, engine, intent, &device, &bytes).await;
        if let Err(error) = result {
            complete = false;
            tracing::debug!(%error,"contact control recipient deferred");
        } else {
            if intent.kind == Decision::Request {
                let identity =
                    client.device_identity_for_root(&intent.peer_root, &device.device_id)?;
                client.account_db()?.mark_contact_request_delivered(
                    &intent.request_id,
                    &identity,
                    &material_hash(client, &identity)?,
                    now_unix_timestamp(),
                )?;
            }
            intent.delivered.insert(recipient);
            client.account_db()?.persist_actor_state(&key(intent), intent)?;
            sent += 1;
        }
    }
    Ok((sent, complete))
}
async fn send_one(
    client: &RamfluxClient,
    engine: &mut GatewaySessionEngine,
    intent: &Intent,
    device: &crate::prekey::SdkDeviceManifestEntry,
    body: &[u8],
) -> Result<(), SdkError> {
    let id =
        format!("contact_{}", ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?));
    let mut message = GatewayDirectMessage {
        conversation_id: conversation(&intent.requester_root, &intent.target_root)?,
        message_id: id.clone(),
        envelope_id: id,
        source_principal_id: engine.config.principal_id.clone(),
        sender_id: engine.config.device_id.clone(),
        recipient_device_id: Some(device.device_id.clone()),
        recipient_principal_commitment: Some(intent.peer_root.clone()),
        target_delivery_id: device.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: u32::try_from(intent.expires_at.saturating_sub(now_unix_timestamp()).clamp(1, TTL))
            .map_err(|_| invalid("contact carrier lifetime is invalid"))?,
    };
    let mut packet = client
        .seal_routed_as(engine, &message, body, crate::client::routed::Route::control())
        .await?;
    if intent.kind == Decision::Request {
        packet.schema = ENVELOPE_SCHEMA.into();
    }
    message.encrypted_body = serde_json::to_vec(&packet)?;
    engine
        .submit_envelope(crate::dm::gateway_direct_message_envelope(
            &engine.config,
            &message,
            None,
        )?)
        .await?;
    Ok(())
}

pub(crate) fn status(client: &RamfluxClient, root: &str) -> Result<&'static str, SdkError> {
    for intent in client.account_db()?.list_actor_states::<Intent>(PREFIX)? {
        if intent.peer_root == root {
            return Ok(if intent.attempts >= 8 { "failed" } else { "queued" });
        }
    }
    Ok("submitted")
}
