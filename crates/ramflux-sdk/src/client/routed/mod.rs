// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Envelope v2: private authenticated routing and device-pair session selection.

use crate::client::identity_authority::HeadUse;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
mod federated_async;
pub(crate) use federated_async::SealForward;
mod archive;
mod auth;
pub(crate) use auth::{PreparedInbound, verify_sender_record};
pub(crate) mod bootstrap_sequence;
mod committed;
mod contact_preview;
mod context;
pub(crate) mod control;
#[cfg(test)]
mod native_contact_tests;
mod object_slot;
mod own_history;
pub(crate) use object_slot::PairObjectSlotRequest;
mod project;
pub(crate) use committed::{Committed, conversation_watermark, object_watermark};
pub(crate) mod group_directory;
mod legacy;
pub(crate) use group_directory::ReceiveGroupDirectory;
mod receive;
pub(crate) use receive::Delivery;
mod pair_lifecycle;
mod prepared;
mod recovery;
mod replay_migration;
mod reset_policy;
mod reset_prepare;
mod reset_work;
#[cfg(test)]
pub(crate) use reset_prepare::with_fixed_pair_control_id;
pub(crate) use reset_prepare::{PairControlDraft, PairControlKind};
mod send_candidate;
mod session;
pub(crate) use prepared::{SendMaterial, SendMaterialRequest};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_message_id: Option<String>,
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
    pub local_device: ramflux_crypto::RootQualifiedDeviceRef,
    pub remote_device: ramflux_crypto::RootQualifiedDeviceRef,
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
    let group_message_id =
        matches!(&route.kind, Kind::GroupMessage).then(|| message.message_id.clone());
    Routing {
        kind: route.kind,
        attachments: route.attachments,
        group_id: route.group_id,
        conversation_id: message.conversation_id.clone(),
        group_message_id,
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

struct SealedPairPersist<'a> {
    inner_len: usize,
    sealed: &'a ramflux_crypto::DmCiphertext,
    local: &'a str,
    remote: &'a str,
    bundle: &'a [u8; 32],
    session: &'a ramflux_crypto::DmSession,
    message: &'a GatewayDirectMessage,
    header: Option<&'a SdkDmX3dhHeader>,
}

fn persist_sealed_pair(
    client: &RamfluxClient,
    persist: &SealedPairPersist<'_>,
) -> Result<(), SdkError> {
    let local_ref = client.local_device_identity(persist.local)?;
    let remote_id = client.device_identity(persist.remote)?;
    if !crate::client::target_selection::schema_v1_selected() {
        mark_local_pair_origin(client, persist)?;
        return client.persist_pair(&local_ref, &remote_id, persist.bundle, persist.session);
    }
    let sizes = measure_wire_sealed_send(client, persist)?;
    let before = session::persisted_pair_snapshot(client, &local_ref, &remote_id)?;
    let mut ratchet = ramflux_protocol::message::outer::TemporaryRatchet::wrap_session(before);
    let advanced = serde_json::to_vec(&persist.session.snapshot())?;
    ramflux_protocol::message::outer::accept_after_size_preflight(sizes, &mut ratchet, advanced)
        .map_err(map_size_preflight)?;
    mark_local_pair_origin(client, persist)?;
    client.persist_pair(&local_ref, &remote_id, persist.bundle, persist.session)
}

fn mark_local_pair_origin(
    client: &RamfluxClient,
    persist: &SealedPairPersist<'_>,
) -> Result<(), SdkError> {
    if persist.header.is_none() {
        return Ok(());
    }
    client
        .account_db()?
        .persist_actor_state(&format!("dm-pair/local/{}", persist.session.session_id), &true)?;
    Ok(())
}

fn map_size_preflight(error: ramflux_protocol::message::outer::OuterProfileError) -> SdkError {
    match error {
        ramflux_protocol::message::outer::OuterProfileError::PayloadTooLarge => {
            SdkError::PayloadTooLarge
        }
        other => SdkError::InboundRejected(other.to_string()),
    }
}

fn measure_wire_sealed_send(
    client: &RamfluxClient,
    persist: &SealedPairPersist<'_>,
) -> Result<ramflux_protocol::message::outer::IngressSizes, SdkError> {
    let wire_local = crate::client::identity_authority::device_namespace::wire_device_id(
        &client.local_device_reference(persist.local)?,
    )?;
    let envelope = cryptobox_sender_envelope(client, persist, &wire_local)?;
    ramflux_protocol::message::outer::IngressSizes::measure_wire(
        &envelope,
        persist.inner_len,
        &persist.sealed.canonical_header_bytes,
        &[],
    )
    .map_err(map_size_preflight)
}

fn cryptobox_sender_envelope(
    client: &RamfluxClient,
    persist: &SealedPairPersist<'_>,
    wire_device_id: &str,
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let nested = SdkDmEncryptedEnvelope {
        source_principal_commitment: Some(client.own_account_anchor()?),
        schema: "ramflux.sdk.dm_x3dh_envelope.v2".to_owned(),
        version: 2,
        x3dh: persist.header.cloned(),
        ciphertext: persist.sealed.clone(),
    };
    let encrypted_payload =
        ramflux_protocol::message::outer::wire_encrypted_payload(&serde_json::to_vec(&nested)?)
            .map_err(map_size_preflight)?;
    let payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        encrypted_payload.as_bytes(),
    );
    let source_principal_id = client.device_branch.as_ref().map_or_else(
        || persist.message.source_principal_id.clone(),
        |branch| branch.principal_id.clone(),
    );
    let mut envelope = ramflux_protocol::Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: sdk_signed_fields(""),
        envelope_id: persist.message.envelope_id.clone(),
        source_principal_id,
        source_device_id: wire_device_id.to_owned(),
        target_delivery_id: persist.message.target_delivery_id.clone(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Normal,
        ttl: persist.message.ttl,
        created_at: persist.message.created_at,
        encrypted_payload,
        payload_hash,
    };
    if let Ok(anchor) = client.own_account_anchor() {
        envelope.ext.ext.insert("source_root_commitment".into(), serde_json::Value::String(anchor));
    }
    envelope.signed.signature = match client.device_branch.as_ref() {
        Some(branch) => ramflux_crypto::sign_protocol_object_with_device_branch(branch, &envelope)?,
        None => ramflux_crypto::sign_protocol_object(&envelope)?,
    };
    Ok(envelope)
}

impl RamfluxClient {
    pub(crate) async fn seal_routed_as(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        body: &[u8],
        route: Route,
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        if route.kind == Kind::Direct {
            Box::pin(self.ensure_contact_request_before_direct(engine, message)).await?;
        }
        let recipient = Self::qualified_recipient(message)?;
        let (mut session, header, bundle) = self.send_pair_session(engine, message).await?;
        self.bind_outgoing_delivery(
            &self.local_device_identity(&engine.config().device_id)?,
            message,
            &route.kind,
        )?;
        self.seal_routed_with_route(
            message,
            body,
            route,
            SealPair {
                local: &engine.config().device_id,
                remote: &recipient,
                session: &mut session,
                header,
                bundle,
            },
        )
    }

    pub(crate) fn seal_routed_federated_as(
        &self,
        engine: &impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        body: &[u8],
        url: Option<&str>,
        route: Route,
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        let recipient = Self::qualified_recipient(message)?;
        let (mut session, header, bundle) = self.send_pair_session_from_url(
            &self.local_device_identity(&engine.config().device_id)?,
            message,
            url,
        )?;
        self.bind_outgoing_delivery(
            &self.local_device_identity(&engine.config().device_id)?,
            message,
            &route.kind,
        )?;
        self.seal_routed_with_route(
            message,
            body,
            route,
            SealPair {
                local: &engine.config().device_id,
                remote: &recipient,
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
        self.require_backup_outbound_ready()?;
        let SealPair { local, remote, session, header, bundle } = pair;
        let remote = self.device_reference(remote)?;
        let wire_remote =
            crate::client::identity_authority::device_namespace::wire_device_id(&remote)?;
        let mut route = routing(message, route);
        if route.kind == Kind::GroupMessage {
            route.group_message_id = Some(
                self.outgoing_group_logical_id(&message.message_id)?
                    .unwrap_or_else(|| message.message_id.clone()),
            );
        }
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
        let aad = associated_data(&message.envelope_id, local, &wire_remote, &bundle)?;
        let ciphertext = session.encrypt(&plaintext, &aad)?;
        persist_sealed_pair(
            self,
            &SealedPairPersist {
                inner_len: plaintext.len(),
                sealed: &ciphertext,
                local,
                remote: &remote,
                bundle: &bundle,
                session,
                message,
                header: header.as_ref(),
            },
        )?;
        self.finish_pair_retirement()?;

        Ok(SdkDmEncryptedEnvelope {
            source_principal_commitment: Some(self.own_account_anchor()?),
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
        self.authenticated_envelope_sender(HeadUse::NewAuthorization, entry)?;
        let envelope = decode(&entry.envelope)?;
        let (mut session, bundle) = self.recv_pair_session(
            &self.local_device_identity(local)?,
            &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
            &entry.envelope.envelope_id,
            &envelope,
        )?;
        let aad = associated_data(
            &entry.envelope.envelope_id,
            &entry.envelope.source_device_id,
            local,
            &bundle,
        )?;
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
        if let Some(id) = &plaintext.routing.group_message_id
            && (plaintext.routing.kind != Kind::GroupMessage
                || id.is_empty()
                || id.len() > 256
                || !ramflux_protocol::text_safety::single_line_is_safe(id))
        {
            return Err(invalid("invalid authenticated group message id"));
        }
        let body = ramflux_protocol::decode_base64url(&plaintext.body_base64)
            .map_err(|_| invalid("invalid routed body"))?;
        Ok(Opened {
            routing: plaintext.routing,
            body: zeroize::Zeroizing::new(body),
            decrypted,
            session,
            bundle_hash: bundle,
            local_device: self.local_device_identity(local)?,
            remote_device: self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
        })
    }
    #[cfg(test)]
    pub(crate) fn is_call_control_entry(
        &self,
        entry: &GatewayInboxEntry,
        local: &str,
    ) -> Result<bool, SdkError> {
        let opened = self.open_routed(entry, local)?;
        Ok(opened.routing.kind == Kind::Control
            && opened.body.starts_with(crate::client::call::PREFIX))
    }
}

pub(crate) fn decode(
    envelope: &ramflux_protocol::Envelope,
) -> Result<SdkDmEncryptedEnvelope, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
        .map_err(|_| invalid("invalid encrypted payload"))?;
    let decoded =
        if let Ok(compact) = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes) {
            if !compact.sidecar.is_empty() {
                ramflux_protocol::message::outer::decode_candidate_sidecar(compact.sidecar)
                    .map_err(|error| invalid(&error.to_string()))?;
            }
            let mut decoded: SdkDmEncryptedEnvelope = serde_json::from_slice(compact.sidecar)?;
            decoded.ciphertext.ciphertext = compact.ciphertext.to_vec();
            decoded
        } else {
            serde_json::from_slice(&bytes)?
        };
    if decoded.version != 2
        || !matches!(
            decoded.schema.as_str(),
            "ramflux.sdk.dm_x3dh_envelope.v2" | crate::client::contact_requests::ENVELOPE_SCHEMA
        )
    {
        return Err(invalid("unrouted legacy envelope"));
    }
    Ok(decoded)
}
fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.to_owned())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(in crate::client) use tests::legacy_selector::import_entry as observe_legacy_import;

#[cfg(test)]
pub(in crate::client) use tests::legacy_selector::registered as observe_legacy_registration;
