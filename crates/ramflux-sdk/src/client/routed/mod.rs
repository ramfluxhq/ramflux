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
mod conversation;
pub(crate) use conversation::ConversationEvent;
pub(crate) mod control;
mod generated_applications;
pub(crate) mod generated_receive;
#[cfg(test)]
mod native_contact_tests;
mod object_slot;
#[cfg(test)]
mod session_fresh_tests;

mod project;
pub(crate) use committed::{Committed, conversation_watermark, object_watermark};
#[cfg(test)]
mod legacy;
mod mls_channel;
pub(super) mod native_control;
mod receive;
mod refused_pair;
mod report;
pub(crate) use receive::{Delivery, JoinedW1};
pub(crate) use report::{SealedRouted, refuse_a0_mismatch};
mod pair_lifecycle;
mod prepared;
mod recovery;
mod reset_policy;
mod reset_prepare;
mod reset_work;
mod send_cache;
#[cfg(test)]
pub(crate) use reset_prepare::with_fixed_pair_control_id;
pub(crate) use reset_prepare::{PairControlDraft, PairControlKind};
mod ephemeral_content;
mod generated_transport;
mod send_candidate;
mod session;
mod typing;
mod wake_stamp;
pub(crate) use ephemeral_content::EphemeralContent;
pub(crate) use prepared::{SendMaterial, SendMaterialRequest};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Direct,
    Receipt,
    Control,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct Routing {
    pub kind: Kind,
    pub conversation_id: String,
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
    /// The opened plaintext before the report frame is removed (the report opening's carrier).
    pub framed: zeroize::Zeroizing<Vec<u8>>,
    /// The MLS group the message was opened in (empty on the typing path until D4b moves it).
    pub group_id: Vec<u8>,
    pub local_device: ramflux_crypto::RootQualifiedDeviceRef,
    pub remote_device: ramflux_crypto::RootQualifiedDeviceRef,
}

const AAD_V3_DOMAIN: &str = "ramflux.sdk.envelope.aad.v3";

#[derive(Clone, Copy)]
struct CandidateAadBinding<'a> {
    delivery_mode: &'a str,
    collapse_tag: [u8; 32],
    report_commitment: Option<[u8; 32]>,
}

fn refuse_received_outer_fields(envelope: &ramflux_protocol::Envelope) -> Result<(), SdkError> {
    ramflux_protocol::message::outer::refuse_live_bridge(envelope).map_err(map_size_preflight)?;

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
    let (collapse_tag, delivery_mode) = crate::dm::derived_candidate_binding(envelope_id);
    associated_data_bound(
        envelope_id,
        sender,
        recipient,
        bundle,
        CandidateAadBinding { delivery_mode, collapse_tag, report_commitment: None },
    )
}

pub(crate) fn associated_data_from_outer(
    envelope: &ramflux_protocol::Envelope,
    sender: &str,
    recipient: &str,
    bundle: &[u8; 32],
) -> Result<Vec<u8>, SdkError> {
    ramflux_protocol::message::outer::refuse_live_bridge(envelope).map_err(map_size_preflight)?;

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
    pub attachments: bool,
}
impl Route {
    pub(crate) fn from_inner(body: &[u8]) -> Result<Self, SdkError> {
        let parsed = generated_transport::generated_plaintext(body)?;
        Ok(Self { kind: parsed.routing.kind, attachments: false })
    }

    #[cfg(test)]
    pub fn attachments() -> Self {
        Self { kind: Kind::Direct, attachments: true }
    }
    pub fn direct() -> Self {
        Self { kind: Kind::Direct, attachments: false }
    }
    pub fn control() -> Self {
        Self { kind: Kind::Control, attachments: false }
    }
    pub fn receipt() -> Self {
        Self { kind: Kind::Receipt, attachments: false }
    }
}
fn routing(message: &GatewayDirectMessage, route: Route) -> Routing {
    Routing {
        kind: route.kind,
        attachments: route.attachments,
        conversation_id: message.conversation_id.clone(),
        message_id: message.envelope_id.clone(),
    }
}

#[derive(Clone, Copy)]
struct SealPair<'a> {
    local: &'a str,
    remote: &'a str,
}

struct RoutedSeal<'a> {
    message: &'a GatewayDirectMessage,
    body: &'a [u8],
    kind: Kind,
    local: &'a str,
    recipient: &'a ramflux_crypto::RootQualifiedDeviceRef,
    shared: send_cache::SealedShared,
    inner: &'a [u8],
    outer_profile: Option<(&'static str, u32)>,
}

fn complete_routed_seal(
    client: &RamfluxClient,
    channel: &mls_channel::Channel,
    finish: RoutedSeal<'_>,
) -> Result<SealedRouted, SdkError> {
    let RoutedSeal { message, body, kind, local, recipient, shared, inner, outer_profile } = finish;
    let report = match &shared.opening {
        Some(opening) => {
            let kcollapse = channel.collapse_key()?;
            Some(report::assemble_target_report(
                client,
                message,
                &report::SharedReport { kcollapse: &kcollapse, inner, opening },
                recipient,
                &report::ReportPolicy {
                    local_device_id: local,
                    mode: "durable",
                    priority: ramflux_protocol::Priority::Normal,
                    outer_profile,
                },
            )?)
        }
        None => None,
    };
    let collapse_tag =
        report.as_ref().map(|assembled| ramflux_protocol::encode_base64url(assembled.collapse_tag));
    let report_commitment = report
        .as_ref()
        .map(|assembled| ramflux_protocol::encode_base64url(assembled.report_commitment));
    let packet = mls_channel::packet(client, &shared.message, collapse_tag, report_commitment)?;
    preflight_sealed_size(client, local, message, &packet, inner.len())?;
    let sealed = SealedRouted {
        packet,
        committed_a0: report.map(|assembled| assembled.a0_bytes),
        metadata_commitment: report::message_metadata_commitment(
            body,
            message.created_at,
            message.ttl,
        )?,
        suppress_wake: false,
    };
    Ok(wake_stamp::apply(sealed, &kind, body))
}

/// Refuse a sealed message whose real signed envelope is over the size caps.
fn preflight_sealed_size(
    client: &RamfluxClient,
    local: &str,
    message: &GatewayDirectMessage,
    packet: &SdkDmEncryptedEnvelope,
    inner_len: usize,
) -> Result<(), SdkError> {
    let wire_local = crate::client::identity_authority::device_namespace::wire_device_id(
        &client.local_device_reference(local)?,
    )?;
    let envelope = cryptobox_sender_envelope(client, message, packet, &wire_local)?;
    let sizes = ramflux_protocol::message::outer::IngressSizes::measure_wire(
        &envelope,
        inner_len,
        &packet.ciphertext.canonical_header_bytes,
        &[],
    )
    .map_err(map_size_preflight)?;
    ramflux_protocol::message::outer::check_ingress_caps(sizes).map_err(map_size_preflight)
}

fn map_size_preflight(error: ramflux_protocol::message::outer::OuterProfileError) -> SdkError {
    match error {
        ramflux_protocol::message::outer::OuterProfileError::PayloadTooLarge => {
            SdkError::PayloadTooLarge
        }
        other => SdkError::InboundRejected(other.to_string()),
    }
}

fn cryptobox_sender_envelope(
    client: &RamfluxClient,
    message: &GatewayDirectMessage,
    nested: &SdkDmEncryptedEnvelope,
    wire_device_id: &str,
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let encrypted_payload =
        ramflux_protocol::message::outer::wire_encrypted_payload(&serde_json::to_vec(nested)?)
            .map_err(map_size_preflight)?;
    let payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        encrypted_payload.as_bytes(),
    );
    let source_principal_id = client
        .device_branch
        .as_ref()
        .map_or_else(|| message.source_principal_id.clone(), |branch| branch.principal_id.clone());
    let mut envelope = ramflux_protocol::Envelope {
        schema: ramflux_protocol::message::outer::CANDIDATE_ENVELOPE_SCHEMA.to_owned(),
        version: 2,
        domain: ramflux_protocol::message::outer::CANDIDATE_ENVELOPE_SCHEMA.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: crate::gateway::helpers::sdk_device_signed_fields(wire_device_id, ""),
        envelope_id: message.envelope_id.clone(),
        source_principal_id,
        source_device_id: wire_device_id.to_owned(),
        target_delivery_id: message.target_delivery_id.clone(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::Message,
        priority: ramflux_protocol::Priority::Normal,
        ttl: message.ttl,
        created_at: message.created_at,
        encrypted_payload,
        payload_hash,
        delivery_mode: Some("durable".into()),
        collapse_tag: None,
        report_commitment: None,
    };
    crate::dm::apply_candidate_named_fields_with(
        &mut envelope,
        nested.collapse_tag.as_deref(),
        nested.report_commitment.as_deref(),
    );
    if let Ok(anchor) = client.own_account_anchor() {
        envelope.ext.ext.insert("source_root_commitment".into(), serde_json::Value::String(anchor));
    }
    let branch = client
        .device_branch
        .as_ref()
        .ok_or_else(|| SdkError::GatewaySessionRejected("sealing config incomplete".into()))?;
    envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(branch, &envelope)?;
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
        Self::require_self_sync_floor_bootstrap()?;
        let recipient = Self::qualified_recipient(message)?;
        let remote = self.device_identity(&recipient)?;
        let local = self.owned_device_identity()?;
        if remote.root_commitment() != local.root_commitment() {
            return Err(SdkError::InboundRejected("self sync: foreign recipient root".into()));
        }
        self.require_native_operation(&remote, NativeOperation::Sync)?;
        self.send_authority_gate(engine, message, false).await?;
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
                SealPair { local: &engine.config().device_id, remote: &recipient },
            )?;
            let envelope = crate::dm::gateway_envelope_from_sealed(
                &engine.sealing_config()?,
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
        // Only user content (a direct send) forces a fresh authority fetch; pair resets and
        // other control sends keep the cached-authority gate of their existing authorization.
        self.send_authority_gate(engine, message, route.kind == Kind::Direct).await?;
        self.account_db()?.write_transaction(|| {
            if route.kind == Kind::Direct {
                self.capture_own_authored_direct(message, body)?;
            }
            self.bind_outgoing_delivery(
                &self.local_device_identity(&engine.config().device_id)?,
                message,
                &route.kind,
            )?;
            self.seal_routed_with_route(
                message,
                body,
                route,
                SealPair { local: &engine.config().device_id, remote: &recipient },
            )
        })
    }

    pub(crate) fn seal_routed_federated_as(
        &self,
        engine: &impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        body: &[u8],
        _url: Option<&str>,
        route: Route,
    ) -> Result<SealedRouted, SdkError> {
        let recipient = Self::qualified_recipient(message)?;
        let local = self.local_device_identity(&engine.config().device_id)?;
        self.require_pair_device_active(&local)?;
        self.bind_outgoing_delivery(&local, message, &route.kind)?;
        self.seal_routed_with_route(
            message,
            body,
            route,
            SealPair { local: &engine.config().device_id, remote: &recipient },
        )
    }

    fn seal_routed_with_route(
        &self,
        message: &GatewayDirectMessage,
        body: &[u8],
        route: Route,
        pair: SealPair<'_>,
    ) -> Result<SealedRouted, SdkError> {
        self.account_db()?
            .write_transaction(|| self.seal_routed_with_route_in(message, body, route, pair, None))
    }

    fn require_generated_send_layer(
        &self,
        message: &GatewayDirectMessage,
        body: &[u8],
    ) -> Result<(), SdkError> {
        #[cfg(test)]
        if report::allows_invalid_header_fixture() {
            return Ok(());
        }
        if body.len() > ramflux_protocol::message::outer::MAX_INNER_BYTES {
            return Err(SdkError::PayloadTooLarge);
        }
        let inner = <ramflux_protocol::message::Inner as prost::Message>::decode(body)
            .map_err(|_| invalid("generated Inner required before sealing"))?;
        if inner.layer > ramflux_protocol::message::registry::PROFILE_FLOOR {
            let kind = ramflux_protocol::message::KindId::try_from(
                i32::try_from(inner.kind).map_err(|_| invalid("invalid generated kind"))?,
            )
            .map_err(|_| invalid("unsupported generated kind"))?;
            self.require_dm_layer(
                message,
                Self::candidate_target_plan(|| self.dm_selection_request(message, kind))?,
                inner.layer,
            )?;
        }
        Ok(())
    }

    fn seal_routed_with_route_in(
        &self,
        message: &GatewayDirectMessage,
        body: &[u8],
        route: Route,
        pair: SealPair<'_>,
        outer_profile: Option<(&'static str, u32)>,
    ) -> Result<SealedRouted, SdkError> {
        self.require_backup_outbound_ready()?;
        self.require_generated_send_layer(message, body)?;
        let SealPair { local, remote } = pair;
        let recipient = self.device_identity(remote)?;
        // The recipient must be a trusted device with a live incarnation (unchanged gate).
        self.trusted_device(HeadUse::NewAuthorization, &recipient)?
            .get("device_epoch")
            .and_then(serde_json::Value::as_u64)
            .filter(|epoch| *epoch != 0)
            .ok_or_else(|| invalid("recipient incarnation missing"))?;
        let route = Self::prepare_seal_routing(message, body, route);
        let inner = generated_transport::seal_plaintext(body, &route)?;
        let channel = self.send_channel(&recipient)?;
        let shared = self.seal_shared(&channel, body, &inner, !report::omit_direct_report())?;
        complete_routed_seal(
            self,
            &channel,
            RoutedSeal {
                message,
                body,
                kind: route.kind,
                local,
                recipient: &recipient,
                shared,
                inner: &inner,
                outer_profile,
            },
        )
    }

    fn prepare_seal_routing(message: &GatewayDirectMessage, body: &[u8], route: Route) -> Routing {
        let mut route = routing(message, route);
        bind_generated_route_identity(&mut route, body);
        route
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
        if envelope.x3dh.is_some() {
            return Err(invalid("a bootstrap header is not part of the MLS channel"));
        }
        let opened = self
            .open_shared(&remote_device, &envelope.ciphertext.ciphertext)
            .inspect_err(|error| {
                tracing::warn!(
                    decrypt_site = "routed_mls",
                    delivery_class = ?entry.envelope.delivery_class,
                    %error,
                    "routed envelope decryption failed"
                );
            })?;
        let framed = opened.plaintext;
        let inner = report::opened_inner_plaintext(&entry.envelope, &framed)?;
        let plaintext = generated_transport::generated_plaintext(&inner)?;
        report::require_report_commitment(&entry.envelope)?;
        if plaintext.routing.attachments && plaintext.routing.kind != Kind::Direct {
            return Err(invalid("attachment flag requires a direct route"));
        }
        let body = ramflux_protocol::decode_base64url(&plaintext.body_base64)
            .map_err(|_| invalid("invalid routed body"))?;
        if generated_transport::identified_inner(&body).is_some()
            && inner.as_slice() != body.as_slice()
        {
            return Err(invalid("generated Inner cannot use the routed JSON carrier"));
        }
        let logical_id = {
            use prost::Message as _;
            ramflux_protocol::message::Inner::decode(body.as_slice())
                .ok()
                .and_then(|inner| inner.identity)
                .map(|identity| ramflux_protocol::encode_base64url(identity.id))
        };
        if plaintext.routing.conversation_id.is_empty()
            || plaintext.routing.message_id
                != logical_id.as_deref().unwrap_or(&entry.envelope.envelope_id)
        {
            return Err(invalid("invalid authenticated routing header"));
        }
        Ok(Opened {
            routing: plaintext.routing,
            body: zeroize::Zeroizing::new(body),
            framed,
            group_id: opened.group_id,
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
        Ok(opened.routing.kind == Kind::Control && crate::client::call::is_call_body(&opened.body))
    }
}

pub(crate) fn decode(
    envelope: &ramflux_protocol::Envelope,
) -> Result<SdkDmEncryptedEnvelope, SdkError> {
    let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)
        .map_err(|_| invalid("invalid encrypted payload"))?;
    let compact = ramflux_protocol::message::outer::decode_compact_cryptobox(&bytes)
        .map_err(|_| invalid("compact cryptobox required"))?;
    ramflux_protocol::message::outer::decode_compact_candidate_sidecar(compact.sidecar)
        .map_err(|error| invalid(&error.to_string()))?;
    let mut decoded: SdkDmEncryptedEnvelope = serde_json::from_slice(compact.sidecar)?;
    decoded.ciphertext.ciphertext = compact.ciphertext.to_vec();
    if decoded.version != 2 || decoded.schema != "ramflux.sdk.dm_x3dh_envelope.v2" {
        return Err(invalid("unrouted legacy envelope"));
    }
    Ok(decoded)
}
fn bind_generated_route_identity(route: &mut Routing, body: &[u8]) {
    use prost::Message as _;
    if let Ok(inner) = ramflux_protocol::message::Inner::decode(body)
        && let Some(identity) = inner.identity
    {
        route.message_id = ramflux_protocol::encode_base64url(identity.id);
    }
}

fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.to_owned())
}

#[cfg(test)]
mod tests;

/// Validate ciphertext binding before any incoming v2 cache or replay shortcut.
pub(crate) fn validate_routed_ciphertext(entry: &GatewayInboxEntry) -> Result<(), SdkError> {
    ramflux_protocol::sender_signed_transcript(
        &entry.envelope,
        ramflux_protocol::SenderTranscriptMode::WithCiphertext,
    )?;
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
