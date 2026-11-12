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
pub(crate) mod generated_receive;
mod project;
pub(crate) use committed::{Committed, conversation_watermark, object_watermark};
pub(crate) mod group_directory;
mod legacy;
mod native_control;
pub(crate) use group_directory::ReceiveGroupDirectory;
mod receive;
mod refused_pair;
mod report;
pub(crate) use receive::{Delivery, JoinedW1};
pub(crate) use report::{SealedRouted, refuse_a0_mismatch};
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
mod ephemeral_content;
mod send_candidate;
mod session;
mod typing;
pub(crate) use ephemeral_content::EphemeralContent;
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

const AAD_V2_DOMAIN: &str = "ramflux.sdk.envelope.aad.v2";
const AAD_V3_DOMAIN: &str = "ramflux.sdk.envelope.aad.v3";

#[derive(Clone, Copy)]
struct CandidateAadBinding<'a> {
    delivery_mode: &'a str,
    collapse_tag: [u8; 32],
    report_commitment: Option<[u8; 32]>,
}

fn refuse_received_outer_fields(envelope: &ramflux_protocol::Envelope) -> Result<(), SdkError> {
    ramflux_protocol::message::outer::refuse_named_fields_while_gate_off(envelope)
        .map_err(map_size_preflight)?;
    if !crate::client::target_selection::schema_v1_selected() {
        return Ok(());
    }
    ramflux_protocol::message::outer::parse_live_named_delivery_mode(envelope)
        .map_err(map_size_preflight)?;
    ramflux_protocol::message::outer::require_live_collapse_tag(envelope)
        .map_err(map_size_preflight)?;
    Ok(())
}

pub(crate) fn associated_data(
    envelope_id: &str,
    sender: &str,
    recipient: &str,
    bundle: &[u8; 32],
) -> Result<Vec<u8>, SdkError> {
    if crate::client::target_selection::schema_v1_selected() {
        let (collapse_tag, delivery_mode) = crate::dm::derived_candidate_binding(envelope_id);
        return associated_data_bound(
            envelope_id,
            sender,
            recipient,
            bundle,
            CandidateAadBinding { delivery_mode, collapse_tag, report_commitment: None },
        );
    }
    associated_data_v2(envelope_id, sender, recipient, bundle)
}

pub(crate) fn associated_data_from_outer(
    envelope: &ramflux_protocol::Envelope,
    sender: &str,
    recipient: &str,
    bundle: &[u8; 32],
) -> Result<Vec<u8>, SdkError> {
    ramflux_protocol::message::outer::refuse_named_fields_while_gate_off(envelope)
        .map_err(map_size_preflight)?;
    if !crate::client::target_selection::schema_v1_selected() {
        return associated_data_v2(&envelope.envelope_id, sender, recipient, bundle);
    }
    let delivery_mode = ramflux_protocol::message::outer::parse_live_named_delivery_mode(envelope)
        .map_err(map_size_preflight)?;
    associated_data_bound(
        &envelope.envelope_id,
        sender,
        recipient,
        bundle,
        CandidateAadBinding {
            delivery_mode: delivery_mode.as_str(),
            collapse_tag: ramflux_protocol::message::outer::require_live_collapse_tag(envelope)
                .map_err(map_size_preflight)?,
            report_commitment: ramflux_protocol::message::outer::live_report_commitment_bytes(
                envelope,
            )
            .map_err(map_size_preflight)?,
        },
    )
}

fn associated_data_v2(
    envelope_id: &str,
    sender: &str,
    recipient: &str,
    bundle: &[u8; 32],
) -> Result<Vec<u8>, SdkError> {
    Ok(ramflux_protocol::canonical_json_bytes(&(
        AAD_V2_DOMAIN,
        envelope_id,
        dm_device_id_hash(sender),
        dm_device_id_hash(recipient),
        bundle,
        2_u32,
    ))?)
}

fn associated_data_bound(
    envelope_id: &str,
    sender: &str,
    recipient: &str,
    bundle: &[u8; 32],
    binding: CandidateAadBinding<'_>,
) -> Result<Vec<u8>, SdkError> {
    let generation = ramflux_protocol::schema_profile::MESSAGE_SCHEMA_V1_GENERATION;
    if let Some(commitment) = binding.report_commitment {
        return Ok(ramflux_protocol::canonical_json_bytes(&(
            AAD_V3_DOMAIN,
            envelope_id,
            dm_device_id_hash(sender),
            dm_device_id_hash(recipient),
            bundle,
            2_u32,
            generation,
            binding.delivery_mode,
            binding.collapse_tag,
            commitment,
        ))?);
    }
    Ok(ramflux_protocol::canonical_json_bytes(&(
        AAD_V3_DOMAIN,
        envelope_id,
        dm_device_id_hash(sender),
        dm_device_id_hash(recipient),
        bundle,
        2_u32,
        generation,
        binding.delivery_mode,
        binding.collapse_tag,
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
    collapse_tag: Option<String>,
    report_commitment: Option<String>,
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
        collapse_tag: persist.collapse_tag.clone(),
        report_commitment: persist.report_commitment.clone(),
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
        delivery_mode: None,
        collapse_tag: None,
        report_commitment: None,
    };
    crate::dm::apply_candidate_named_fields_with(
        &mut envelope,
        persist.collapse_tag.as_deref(),
        persist.report_commitment.as_deref(),
    );
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
    /// Prepare a durable same-root `SelfSync` delivery. Submit the returned envelope unchanged.
    /// Allocate once with `change_self_sync`, then pass that same value to every sibling.
    /// This transport preparation never increments the revision or consumes the message stream.
    /// # Errors
    /// Refuses a foreign or unauthorized device, invalid update, or persistence failure.
    pub async fn prepare_self_sync_delivery(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        value: ramflux_protocol::message::SelfSync,
    ) -> Result<ramflux_protocol::Envelope, SdkError> {
        use crate::client::identity_authority::NativeOperation;
        use ramflux_protocol::message as g;
        let recipient = Self::qualified_recipient(message)?;
        let remote = self.device_identity(&recipient)?;
        let local = self.owned_device_identity()?;
        if remote.root_commitment() != local.root_commitment() {
            return Err(SdkError::InboundRejected("self sync: foreign recipient root".into()));
        }
        self.require_native_operation(&remote, NativeOperation::Sync)?;
        let (mut session, header, bundle) = self.send_pair_session(engine, message).await?;
        self.account_db()?.write_transaction(|| {
            self.authorize_self_sync(&local, &message.conversation_id)?;
            g::self_sync::validate(&value).map_err(|_| invalid("invalid SelfSync body"))?;
            self.require_native_operation(&remote, NativeOperation::Sync)?;
            let inner = self.self_sync_publication_inner(&message.conversation_id, &value)?;
            let identity = <g::Inner as prost::Message>::decode(inner.as_slice())
                .map_err(|_| invalid("SelfSync publication identity missing"))?
                .identity
                .ok_or_else(|| invalid("SelfSync publication identity missing"))?;
            let mut message = message.clone();
            message.message_id = ramflux_protocol::encode_base64url(&identity.id);
            let sealed = self.seal_routed_with_route(
                &message,
                &inner,
                Route::control(),
                SealPair {
                    local: &engine.config().device_id,
                    remote: &recipient,
                    session: &mut session,
                    header,
                    bundle,
                },
            )?;
            let envelope = crate::dm::gateway_envelope_from_sealed(
                engine.config(),
                &mut message,
                sealed,
                None,
            )?;
            self.persist_self_sync_delivery(&message.conversation_id, &value, &envelope)?;
            Ok(envelope)
        })
    }

    pub(crate) async fn seal_routed_as(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        body: &[u8],
        route: Route,
    ) -> Result<SealedRouted, SdkError> {
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
    ) -> Result<SealedRouted, SdkError> {
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
    ) -> Result<SealedRouted, SdkError> {
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
        bind_generated_route_identity(&mut route, body);
        let inner = zeroize::Zeroizing::new(serde_json::to_vec(&Plaintext {
            routing: route.clone(),
            body_base64: zeroize::Zeroizing::new(ramflux_protocol::encode_base64url(body)),
        })?);
        let report = if crate::client::target_selection::schema_v1_selected()
            && !report::omit_direct_report()
        {
            let recipient = self.device_identity(&remote)?;
            Some(report::assemble_direct_report(self, message, session, &inner, local, &recipient)?)
        } else {
            None
        };
        let plaintext = if let Some(ref report) = report {
            zeroize::Zeroizing::new(report.framed.as_bytes().to_vec())
        } else {
            inner
        };
        let aad = if let Some(ref report) = report {
            associated_data_bound(
                &message.envelope_id,
                local,
                &wire_remote,
                &bundle,
                CandidateAadBinding {
                    delivery_mode: "durable",
                    collapse_tag: report.collapse_tag,
                    report_commitment: Some(report.report_commitment),
                },
            )?
        } else {
            associated_data(&message.envelope_id, local, &wire_remote, &bundle)?
        };
        let ciphertext = session.encrypt(&plaintext, &aad)?;
        let collapse_tag =
            report.as_ref().map(|r| ramflux_protocol::encode_base64url(r.collapse_tag));
        let report_commitment =
            report.as_ref().map(|r| ramflux_protocol::encode_base64url(r.report_commitment));
        persist_sealed_pair(
            self,
            &SealedPairPersist {
                inner_len: plaintext.len().saturating_sub(report.as_ref().map_or(0, |_| {
                    ramflux_protocol::message::outer::FRAME_PREFIX_BYTES
                        + ramflux_protocol::message::outer::REPORT_OPENING_BYTES
                })),
                sealed: &ciphertext,
                local,
                remote: &remote,
                bundle: &bundle,
                session,
                message,
                header: header.as_ref(),
                collapse_tag: collapse_tag.clone(),
                report_commitment: report_commitment.clone(),
            },
        )?;
        self.finish_pair_retirement()?;

        Ok(SealedRouted {
            packet: SdkDmEncryptedEnvelope {
                source_principal_commitment: Some(self.own_account_anchor()?),
                schema: "ramflux.sdk.dm_x3dh_envelope.v2".to_owned(),
                version: 2,
                x3dh: header,
                ciphertext,
                collapse_tag,
                report_commitment,
            },
            committed_a0: report.map(|sealed| sealed.a0_bytes),
            metadata_commitment: report::message_metadata_commitment(
                body,
                message.created_at,
                message.ttl,
            )?,
        })
    }

    pub(crate) fn open_routed(
        &self,
        entry: &GatewayInboxEntry,
        local: &str,
    ) -> Result<Opened, SdkError> {
        self.authenticated_envelope_sender(HeadUse::NewAuthorization, entry)?;
        refuse_received_outer_fields(&entry.envelope)?;
        let envelope = decode(&entry.envelope)?;
        report::refuse_payload_outer_mismatch(&entry.envelope, &envelope)?;
        let local_device = self.local_device_identity(local)?;
        let remote_device = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let (mut session, bundle) = self.recv_pair_session(
            &local_device,
            &remote_device,
            &entry.envelope.envelope_id,
            &envelope,
        )?;
        let aad = associated_data_from_outer(
            &entry.envelope,
            &entry.envelope.source_device_id,
            local,
            &bundle,
        )?;
        let decrypted = zeroize::Zeroizing::new(
            session.decrypt_with_franking_keys(&envelope.ciphertext, &aad)?,
        );
        let inner = report::opened_inner_plaintext(&entry.envelope, &decrypted.plaintext)?;
        let plaintext: Plaintext = serde_json::from_slice(&inner)?;
        report::refuse_direct_candidate_opening(
            &entry.envelope,
            &session,
            &plaintext.routing.kind,
        )?;
        if plaintext.routing.attachments && plaintext.routing.kind != Kind::Direct {
            return Err(invalid("attachment flag requires a direct route"));
        }
        let body = ramflux_protocol::decode_base64url(&plaintext.body_base64)
            .map_err(|_| invalid("invalid routed body"))?;
        let logical_id = if crate::client::target_selection::schema_v1_selected() {
            use prost::Message as _;
            ramflux_protocol::message::Inner::decode(body.as_slice())
                .ok()
                .and_then(|inner| inner.identity)
                .map(|identity| ramflux_protocol::encode_base64url(identity.id))
        } else {
            None
        };
        if plaintext.routing.conversation_id.is_empty()
            || plaintext.routing.message_id
                != logical_id.as_deref().unwrap_or(&entry.envelope.envelope_id)
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
        Ok(Opened {
            routing: plaintext.routing,
            body: zeroize::Zeroizing::new(body),
            decrypted,
            session,
            bundle_hash: bundle,
            local_device,
            remote_device,
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
                ramflux_protocol::message::outer::decode_compact_candidate_sidecar(compact.sidecar)
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
fn bind_generated_route_identity(route: &mut Routing, body: &[u8]) {
    if crate::client::target_selection::schema_v1_selected() {
        use prost::Message as _;
        if let Ok(inner) = ramflux_protocol::message::Inner::decode(body)
            && let Some(identity) = inner.identity
        {
            route.message_id = ramflux_protocol::encode_base64url(identity.id);
            if route.kind == Kind::GroupMessage {
                route.group_message_id = Some(route.message_id.clone());
            }
        }
    }
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

/// Validate ciphertext binding before any incoming v2 cache or replay shortcut.
pub(crate) fn validate_routed_ciphertext(entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    if entry.envelope.schema == "ramflux.envelope.v2"
        || ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION == 1
    {
        ramflux_protocol::sender_signed_transcript(
            &entry.envelope,
            ramflux_protocol::SenderTranscriptMode::WithCiphertext,
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) async fn native_typing_pair_fixture() -> crate::client::native_test_support::TestResult<
    (crate::client::native_test_support::Fixture, crate::client::native_test_support::Fixture),
> {
    Box::pin(tests::candidate_ephemeral::native_pair()).await
}

#[cfg(test)]
pub(crate) fn native_typing_delivery_fixture(
    a: &crate::client::native_test_support::Fixture,
    b: &crate::client::native_test_support::Fixture,
) -> crate::client::native_test_support::TestResult<(ramflux_protocol::Envelope, Vec<String>)> {
    tests::candidate_ephemeral::native_typing_delivery(a, b)
}
