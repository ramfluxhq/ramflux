// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded contact-control delivery through the ordinary authenticated device-pair transport.
use super::{ContactRequestRecord, Decision, ENVELOPE_SCHEMA, TTL, conversation, invalid};
use crate::prelude::*;
use serde::{Deserialize, Serialize};
const PREFIX: &str = "contact-request/send/";
#[derive(Clone, Deserialize, Serialize)]
struct Intent {
    kind: Decision,
    request_id: String,
    requester_root: String,
    target_root: String,
    peer_root: String,
    note: Option<String>,
    expires_at: i64,
    attempts: u8,
    next_at: i64,
    delivered: BTreeSet<(String, String)>,
}
fn key(intent: &Intent) -> String {
    format!(
        "{PREFIX}{}",
        ramflux_protocol::hash_base64url(
            "ramflux.contact_request.delivery.v1",
            format!("{}:{}:{:?}", intent.peer_root, intent.request_id, intent.kind).as_bytes()
        )
    )
}
fn enqueue(client: &RamfluxClient, intent: &Intent) -> Result<(), SdkError> {
    let db = client.account_db()?;
    let id = key(intent);
    if db.actor_state_exists(&id)? {
        return Ok(());
    }
    if db.list_actor_states::<Intent>(PREFIX)?.len() >= 128 {
        return Err(invalid("contact request delivery queue is full"));
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
        let note: serde_json::Value = serde_json::from_slice(&request.request_json)?;
        let selector = Intent {
            kind: Decision::Request,
            request_id: request.request_id.clone(),
            requester_root: self.owned_device_identity()?.root_commitment().into(),
            target_root: root.clone(),
            peer_root: root,
            note: note["note"].as_str().map(str::to_owned),
            expires_at: request.expires_at,
            attempts: 0,
            next_at: now_unix_timestamp(),
            delivered: BTreeSet::new(),
        };
        let id = key(&selector);
        let mut intent = self.account_db()?.load_actor_state::<Intent>(&id)?.unwrap_or(selector);
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
        if let Some(old) = db.contact_request(&peer.principal_commitment, "outbound")? {
            if matches!(old.state.as_str(), "accepted" | "pending") {
                return Ok(());
            }
            if old.state != "expired"
                && !(old.state == "declined"
                    && now_unix_timestamp()
                        >= old.updated_at.saturating_add(super::DECLINE_COOLDOWN_SECONDS))
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
        let own = self.owned_device_identity()?;
        let id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        let intent = Intent {
            kind: Decision::Request,
            request_id: id.clone(),
            requester_root: own.root_commitment().into(),
            target_root: peer.principal_commitment.clone(),
            peer_root: peer.principal_commitment.clone(),
            note: note.map(str::to_owned),
            expires_at: now.saturating_add(TTL),
            attempts: 0,
            next_at: now,
            delivered: BTreeSet::new(),
        };
        let record = ContactRequestRecord {
            contact_identity_commitment: peer.principal_commitment.clone(),
            direction: "outbound".into(),
            request_id: id,
            principal_id: peer.principal_id.clone(),
            link_id: link_id.into(),
            state: "pending".into(),
            request_json: serde_json::to_vec(&serde_json::json!({"note":note}))?,
            expires_at: intent.expires_at,
            updated_at: now,
        };
        db.persist_contact_request(&record)?;
        enqueue(self, &intent)
    }
    pub(super) fn stage_contact_response(
        &self,
        request: &ContactRequestRecord,
        kind: Decision,
    ) -> Result<(), SdkError> {
        let own = self.owned_device_identity()?;
        enqueue(
            self,
            &Intent {
                kind,
                request_id: request.request_id.clone(),
                requester_root: request.contact_identity_commitment.clone(),
                target_root: own.root_commitment().into(),
                peer_root: request.contact_identity_commitment.clone(),
                note: None,
                expires_at: request.expires_at,
                attempts: 0,
                next_at: now_unix_timestamp(),
                delivered: BTreeSet::new(),
            },
        )
    }
}
pub(crate) async fn flush(account: &mut LocalBusAccountState) -> Result<usize, SdkError> {
    let db = account.client.account_db()?;
    db.expire_contact_requests(now_unix_timestamp())?;
    let pending = db.list_actor_states::<Intent>(PREFIX)?;
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
    let now = now_unix_timestamp();
    let control = super::wire::sign(
        client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        super::wire::Body {
            schema: super::wire::DOMAIN.into(),
            kind: intent.kind,
            request_id: intent.request_id.clone(),
            requester_root: intent.requester_root.clone(),
            target_root: intent.target_root.clone(),
            actor_root: own.root_commitment().into(),
            issued_at: now,
            expires_at: intent.expires_at,
            nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            note: intent.note.clone(),
            manifest: own_manifest,
        },
    )?;
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&control)?);
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
        ttl: 3600,
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
