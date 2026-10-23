// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Envelope v2: private authenticated routing and device-pair session selection.

use crate::prelude::*;
use serde::{Deserialize, Serialize};
mod legacy;
mod receive;
pub(crate) use receive::Delivery;
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
}
#[derive(Deserialize, Serialize)]
struct Plaintext {
    routing: Routing,
    body_base64: String,
}

pub(crate) struct Opened {
    pub routing: Routing,
    pub body: Vec<u8>,
    pub decrypted: ramflux_crypto::DmDecryptionOutput,
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

fn routing(message: &GatewayDirectMessage, body: &[u8]) -> Result<Routing, SdkError> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok();
    let schema = value
        .as_ref()
        .and_then(|value| value.get("schema"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let (kind, group_id) = match schema {
        "ramflux.sdk.group_sender_key.message.v1" => (
            Kind::GroupMessage,
            value
                .as_ref()
                .and_then(|value| value.get("group_id"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        ),
        "ramflux.sdk.group_sender_key.distribution_envelope.v1" => {
            let encoded = value
                .as_ref()
                .and_then(|value| value.get("distribution_base64"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("missing group distribution"))?;
            let decoded = ramflux_protocol::decode_base64url(encoded)
                .map_err(|_| invalid("invalid group distribution"))?;
            let distribution: SdkGroupSenderKeyDistribution = serde_json::from_slice(&decoded)?;
            (Kind::GroupControl, Some(distribution.group_id))
        }
        "ramflux.sdk.group_control.v1" => (
            Kind::GroupControl,
            value
                .as_ref()
                .and_then(|value| value.pointer("/event/body/group_id"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        ),
        "ramflux.sdk.receipt_event.v1" => (Kind::Receipt, None),
        schema if schema.starts_with("ramflux.a2i") => (Kind::Control, None),
        _ if serde_json::from_slice::<A2iControlEvent>(body).is_ok() => (Kind::Control, None),
        _ => (Kind::Direct, None),
    };
    Ok(Routing {
        kind,
        conversation_id: message.conversation_id.clone(),
        group_id,
        message_id: message.envelope_id.clone(),
    })
}

struct SealPair<'a> {
    local: &'a str,
    remote: &'a str,
    session: &'a mut ramflux_crypto::DmSession,
    header: Option<SdkDmX3dhHeader>,
    bundle: [u8; 32],
}

impl RamfluxClient {
    pub(crate) async fn seal_routed(
        &self,
        engine: &mut GatewaySessionEngine,
        message: &GatewayDirectMessage,
        body: &[u8],
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        let recipient = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("v2 requires recipient device id"))?;
        let (mut session, header, bundle) = self.send_pair_session(engine, message).await?;
        self.seal_routed_with_session(
            message,
            body,
            SealPair {
                local: &engine.config.device_id,
                remote: recipient,
                session: &mut session,
                header,
                bundle,
            },
        )
    }

    pub(crate) fn seal_routed_federated(
        &self,
        engine: &GatewaySessionEngine,
        message: &GatewayDirectMessage,
        body: &[u8],
        url: Option<&str>,
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        let recipient = message
            .recipient_device_id
            .as_deref()
            .ok_or_else(|| invalid("v2 requires recipient device id"))?;
        let (mut session, header, bundle) =
            self.send_pair_session_from_url(&engine.config.device_id, message, url)?;
        self.seal_routed_with_session(
            message,
            body,
            SealPair {
                local: &engine.config.device_id,
                remote: recipient,
                session: &mut session,
                header,
                bundle,
            },
        )
    }

    fn seal_routed_with_session(
        &self,
        message: &GatewayDirectMessage,
        body: &[u8],
        pair: SealPair<'_>,
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        let SealPair { local, remote, session, header, bundle } = pair;
        let mut route = routing(message, body)?;
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
            body_base64: ramflux_protocol::encode_base64url(body),
        })?);
        let aad = associated_data(&message.envelope_id, local, remote, &bundle)?;
        let ciphertext = session.encrypt(&plaintext, &aad)?;
        // Never reuse a send key after transport cancellation or a process crash.
        self.persist_pair(local, remote, &bundle, session)?;
        self.persist_dm_session(&message.conversation_id, &message.envelope_id, "send", session)?;
        Ok(SdkDmEncryptedEnvelope {
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
        let envelope = decode(&entry.envelope)?;
        let remote = &entry.envelope.source_device_id;
        let (mut session, bundle) =
            self.recv_pair_session(local, remote, &entry.envelope.envelope_id, &envelope)?;
        let aad = associated_data(&entry.envelope.envelope_id, remote, local, &bundle)?;
        let decrypted = session.decrypt_with_franking_keys(&envelope.ciphertext, &aad)?;
        let plaintext: Plaintext = serde_json::from_slice(&decrypted.plaintext)?;
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
            body,
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
    SdkError::LocalBus(message.to_owned())
}

#[cfg(test)]
mod tests;
