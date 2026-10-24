// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Envelope v2: private authenticated routing and device-pair session selection.

use crate::prelude::*;
use serde::{Deserialize, Serialize};
mod archive;
mod auth;
pub(crate) mod bootstrap_sequence;
mod committed;
mod context;
pub(crate) mod control;
mod object_slot;
mod project;
pub(crate) use committed::{committed_key, conversation_watermark, object_watermark};
mod legacy;
mod receive;
pub(crate) use receive::Delivery;
mod pair_lifecycle;
mod recovery;
mod reset_policy;
mod reset_work;
mod send_candidate;
mod session;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Direct,
    GroupMessage,
    GroupControl,
    Receipt,
    Control,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Routing {
    pub kind: Kind,
    pub conversation_id: String,
    pub group_id: Option<String>,
    pub message_id: String,
    #[serde(default)]
    pub attachments: bool,
}
#[derive(Deserialize, Serialize)]
struct Plaintext {
    routing: Routing,
    body_base64: zeroize::Zeroizing<String>,
}

pub(crate) struct Opened {
    pub routing: Routing,
    pub body: zeroize::Zeroizing<Vec<u8>>,
    pub decrypted: zeroize::Zeroizing<ramflux_crypto::DmDecryptionOutput>,
    pub session: ramflux_crypto::DmSession,
    pub bundle_hash: [u8; 32],
    pub local_device: String,
    pub remote_device: String,
}

pub(crate) fn associated_data(
    envelope_id: &str,
    sender: &str,
    recipient: &str,
    bundle: &[u8; 32],
) -> Result<Vec<u8>, SdkError> {
    Ok(ramflux_protocol::canonical_json_bytes(&(
        "ramflux.sdk.envelope.aad.v2",
        envelope_id,
        dm_device_id_hash(sender),
        dm_device_id_hash(recipient),
        bundle,
        2_u32,
    ))?)
}

#[derive(Clone)]
pub(crate) struct Route {
    pub kind: Kind,
    pub group_id: Option<String>,
    pub attachments: bool,
}
impl Route {
    pub fn attachments() -> Self {
        Self { kind: Kind::Direct, group_id: None, attachments: true }
    }
    pub fn direct() -> Self {
        Self { kind: Kind::Direct, group_id: None, attachments: false }
    }
    pub fn control() -> Self {
        Self { kind: Kind::Control, group_id: None, attachments: false }
    }
    pub fn receipt() -> Self {
        Self { kind: Kind::Receipt, group_id: None, attachments: false }
    }
    pub fn group_message(id: &str) -> Self {
        Self { kind: Kind::GroupMessage, group_id: Some(id.to_owned()), attachments: false }
    }
    pub fn group_control(id: &str) -> Self {
        Self { kind: Kind::GroupControl, group_id: Some(id.to_owned()), attachments: false }
    }
}
fn routing(message: &GatewayDirectMessage, route: Route) -> Routing {
    Routing {
        kind: route.kind,
        attachments: route.attachments,
        group_id: route.group_id,
        conversation_id: message.conversation_id.clone(),
        message_id: message.envelope_id.clone(),
    }
}

struct SealPair<'a> {
    local: &'a str,
    remote: &'a str,
    session: &'a mut ramflux_crypto::DmSession,
    header: Option<SdkDmX3dhHeader>,
    bundle: [u8; 32],
}

impl RamfluxClient {
    pub(crate) async fn seal_routed_as(
        &self,
        engine: &mut GatewaySessionEngine,
        message: &GatewayDirectMessage,
        body: &[u8],
        route: Route,
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        let recipient = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("v2 requires recipient device id"))?;
        let (mut session, header, bundle) = self.send_pair_session(engine, message).await?;
        self.seal_routed_with_route(
            message,
            body,
            route,
            SealPair {
                local: &engine.config.device_id,
                remote: recipient,
                session: &mut session,
                header,
                bundle,
            },
        )
    }

    pub(crate) fn seal_routed_federated_as(
        &self,
        engine: &GatewaySessionEngine,
        message: &GatewayDirectMessage,
        body: &[u8],
        url: Option<&str>,
        route: Route,
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        let recipient = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("v2 requires recipient device id"))?;
        let (mut session, header, bundle) =
            self.send_pair_session_from_url(&engine.config.device_id, message, url)?;
        self.seal_routed_with_route(
            message,
            body,
            route,
            SealPair {
                local: &engine.config.device_id,
                remote: recipient,
                session: &mut session,
                header,
                bundle,
            },
        )
    }

    fn seal_routed_with_route(
        &self,
        message: &GatewayDirectMessage,
        body: &[u8],
        route: Route,
        pair: SealPair<'_>,
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        let SealPair { local, remote, session, header, bundle } = pair;
        let mut route = routing(message, route);
        if route.kind == Kind::GroupControl
            && let Some(group) = route.group_id.as_deref()
            && let Some(link) = self.account_db()?.client_record("group", group)?
            && let Some(conversation) =
                link.get("conversation_id").and_then(serde_json::Value::as_str)
        {
            conversation.clone_into(&mut route.conversation_id);
        }
        let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(&Plaintext {
            routing: route,
            body_base64: zeroize::Zeroizing::new(ramflux_protocol::encode_base64url(body)),
        })?);
        let aad = associated_data(&message.envelope_id, local, remote, &bundle)?;
        let ciphertext = session.encrypt(&plaintext, &aad)?;
        // Never reuse a send key after transport cancellation or a process crash.
        if header.is_some() {
            self.account_db()?
                .persist_actor_state(&format!("dm-pair/local/{}", session.session_id), &true)?;
        }
        self.persist_pair(local, remote, &bundle, session)?;
        self.finish_pair_retirement()?;

        Ok(SdkDmEncryptedEnvelope {
            source_principal_commitment: self.identity_root.as_ref().map(|root| {
                ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key())
            }),
            schema: "ramflux.sdk.dm_x3dh_envelope.v2".to_owned(),
            version: 2,
            x3dh: header,
            ciphertext,
        })
    }

    pub(crate) fn open_routed(
        &self,
        entry: &GatewayInboxEntry,
        local: &str,
    ) -> Result<Opened, SdkError> {
        self.authenticated_envelope_sender(entry)?;
        let envelope = decode(&entry.envelope)?;
        let remote = &entry.envelope.source_device_id;
        let (mut session, bundle) =
            self.recv_pair_session(local, remote, &entry.envelope.envelope_id, &envelope)?;
        let aad = associated_data(&entry.envelope.envelope_id, remote, local, &bundle)?;
        let decrypted = zeroize::Zeroizing::new(
            session.decrypt_with_franking_keys(&envelope.ciphertext, &aad)?,
        );
        let plaintext: Plaintext = serde_json::from_slice(&decrypted.plaintext)?;
        if plaintext.routing.attachments && plaintext.routing.kind != Kind::Direct {
            return Err(invalid("attachment flag requires a direct route"));
        }
        if plaintext.routing.conversation_id.is_empty()
            || plaintext.routing.message_id != entry.envelope.envelope_id
        {
            return Err(invalid("invalid authenticated routing header"));
        }
        if matches!(plaintext.routing.kind, Kind::GroupMessage | Kind::GroupControl)
            && plaintext.routing.group_id.as_deref().is_none_or(str::is_empty)
        {
            return Err(invalid("missing authenticated group id"));
        }
        let body = ramflux_protocol::decode_base64url(&plaintext.body_base64)
            .map_err(|_| invalid("invalid routed body"))?;
        Ok(Opened {
            routing: plaintext.routing,
            body: zeroize::Zeroizing::new(body),
            decrypted,
            session,
            bundle_hash: bundle,
            local_device: local.to_owned(),
            remote_device: remote.clone(),
        })
    }
}

pub(crate) fn decode(
    envelope: &ramflux_protocol::Envelope,
) -> Result<SdkDmEncryptedEnvelope, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
        .map_err(|_| invalid("invalid encrypted payload"))?;
    let decoded: SdkDmEncryptedEnvelope = serde_json::from_slice(&bytes)?;
    if decoded.version != 2 || decoded.schema != "ramflux.sdk.dm_x3dh_envelope.v2" {
        return Err(invalid("unrouted legacy envelope"));
    }
    Ok(decoded)
}
fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.to_owned())
}

#[cfg(test)]
mod tests;
