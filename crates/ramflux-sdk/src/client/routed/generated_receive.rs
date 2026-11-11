// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated receive projection. Called only after source, AEAD and C verification, inside W1.
use super::{Kind, Opened, invalid};
use crate::client::identity_authority::{HeadUse, NativeOperation};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message::{
    self as g,
    validation::{self, ScanOutcome},
};
use ramflux_storage::{MessageMetadata, RawInnerCopyKind, RawInnerCopyWrite};
use serde::{Deserialize, Serialize};

pub(super) enum GeneratedProjection {
    Native,
    Handled(Option<Vec<u8>>),
}

struct GeneratedCommit<'a> {
    opened: &'a Opened,
    entry: &'a GatewayInboxEntry,
    bytes: &'a [u8],
    metadata: Option<&'a MessageMetadata>,
    identity: Option<g::EventIdentity>,
}

pub(super) fn mutation_erasure_targets(
    bytes: &[u8],
) -> (bool, Vec<super::committed::ErasureTarget>) {
    if !crate::client::target_selection::schema_v1_selected() {
        return (false, Vec::new());
    }
    let Ok((_, content)) = RamfluxClient::decode_generated_inner(bytes) else {
        return (false, Vec::new());
    };
    let references = match content.value {
        Some(g::content::Value::Edit(edit)) => edit.target.into_iter().collect::<Vec<_>>(),
        Some(g::content::Value::Reaction(reaction)) => reaction.target.into_iter().collect(),
        Some(g::content::Value::Delete(_)) => return (true, Vec::new()),
        _ => Vec::new(),
    };
    (
        false,
        references
            .into_iter()
            .map(|reference| ramflux_protocol::encode_base64url(reference.id))
            .map(|message_id| super::committed::ErasureTarget { message_id })
            .collect(),
    )
}

/// Only immutable authenticated receive provenance is retained, never a fresh authority grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Provenance {
    pub source: String,
    pub conversation: String,
    pub message: String,
    pub envelope_id: String,
    pub payload_hash: String,
    pub expires_at: i64,
    pub original_mode: String,
    pub source_epoch: u64,
    pub original_route: String,
    pub outer_receipt_key: String,
    pub received_erasure_generation: i64,
}

impl RamfluxClient {
    pub(super) fn project_generated_entry(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        bytes: &[u8],
        metadata: Option<&MessageMetadata>,
    ) -> Result<GeneratedProjection, SdkError> {
        self.project_generated_entry_in(opened, entry, bytes, metadata).map_err(|error| match error
        {
            SdkError::Storage(ramflux_storage::StorageError::UnsupportedRawQuotaExceeded {
                source_anchor,
                scope,
            }) => SdkError::StorageCapacity { source_anchor, scope },
            SdkError::LocalBus(reason) => SdkError::GeneratedRefused {
                code: crate::error::GeneratedRefusalCode::Content,
                reason,
            },
            SdkError::InboundRejected(reason) => SdkError::GeneratedRefused {
                code: crate::error::GeneratedRefusalCode::Authority,
                reason,
            },
            SdkError::Storage(ramflux_storage::StorageError::GroupPermissionDenied) => {
                SdkError::GeneratedRefused {
                    code: crate::error::GeneratedRefusalCode::Authority,
                    reason: "group sender lacks permission".into(),
                }
            }
            other => other,
        })
    }

    fn project_generated_entry_in(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        bytes: &[u8],
        metadata: Option<&MessageMetadata>,
    ) -> Result<GeneratedProjection, SdkError> {
        // Dormant integration retains the native callers until the final codec-removal commit.
        let scanned = match validation::scan_inner(bytes) {
            Ok(scanned) => scanned,
            Err(error) if g::Inner::decode(bytes).is_ok_and(|inner| inner.identity.is_some()) => {
                return Err(SdkError::GeneratedRefused {
                    code: crate::error::GeneratedRefusalCode::Content,
                    reason: error.to_string(),
                });
            }
            Err(_) => return Ok(GeneratedProjection::Native),
        };
        let inner = g::Inner::decode(bytes).ok();
        self.authorize_generated_origin(opened, entry, &scanned)?;
        Self::verify_generated_message_header(entry, bytes)?;
        if self.prepare_generated_identity(
            opened,
            entry,
            bytes,
            scanned.kind,
            inner.as_ref().and_then(|inner| inner.identity.as_ref()),
        )? {
            return Ok(GeneratedProjection::Handled(None));
        }
        self.capture_generated_original_header(entry, bytes)?;
        if opened.routing.kind == Kind::GroupMessage && scanned.kind == 1 {
            return self.project_generated_group(
                opened,
                entry,
                &scanned,
                metadata,
                inner.and_then(|inner| inner.identity),
            );
        }
        if scanned.outcome == ScanOutcome::Unsupported
            || inner.as_ref().is_none_or(|inner| inner.identity.is_none())
        {
            self.retain_generated_unsupported(opened, entry, &scanned)?;
            return Ok(GeneratedProjection::Handled(None));
        }
        let content = match g::registry::decode_body(scanned.kind, scanned.body, scanned.layer) {
            Ok(content) => content,
            Err(
                validation::ValidationError::Malformed | validation::ValidationError::Unsupported,
            ) => {
                self.retain_generated_unsupported(opened, entry, &scanned)?;
                return Ok(GeneratedProjection::Handled(None));
            }
            Err(error) => {
                return Err(SdkError::InboundRejected(format!(
                    "invalid generated content: {error}"
                )));
            }
        };
        self.project_known_generated(
            GeneratedCommit {
                opened,
                entry,
                bytes,
                metadata,
                identity: inner.and_then(|inner| inner.identity),
            },
            content,
        )
    }

    // True means the authenticated identity is already retired, deleted or projected.
    fn prepare_generated_identity(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        bytes: &[u8],
        kind: u32,
        identity: Option<&g::EventIdentity>,
    ) -> Result<bool, SdkError> {
        let Some(identity) = identity else {
            return Ok(false);
        };
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let source_epoch = self
            .account_db()?
            .client_device_record(&source)?
            .and_then(|record| record["device_epoch"].as_u64())
            .ok_or_else(|| invalid("source epoch missing"))?;
        if identity.conversation_id != opened.routing.conversation_id
            || identity.author.as_ref().is_none_or(|author| {
                author.account_anchor != source.root_commitment()
                    || author.device_id != source.device_id()
                    || author.device_epoch != source_epoch
            })
        {
            return Err(SdkError::GeneratedRefused {
                code: crate::error::GeneratedRefusalCode::Identity,
                reason: "identity differs from authenticated source or conversation".into(),
            });
        }

        g::identity::verify(identity).map_err(|_| SdkError::GeneratedRefused {
            code: crate::error::GeneratedRefusalCode::Identity,
            reason: "event id transcript mismatch".into(),
        })?;
        if self.apply_generated_delete_fence(identity)? {
            return Ok(true);
        }
        // An Edit retires the original payload, including fresh recipient copies.
        // Authenticate its outer and header before ignoring it without retention.
        if kind == 1
            && self
                .account_db()?
                .load_actor_state::<bool>(&format!(
                    "routed/report-opening-retired/{}",
                    opened.routing.message_id
                ))?
                .unwrap_or(false)
        {
            return Ok(true);
        }
        if kind == 1
            && let Some(stored) = self.account_db()?.message_content(&opened.routing.message_id)?
        {
            if stored != bytes {
                return Err(SdkError::ReplayMismatch);
            }
            return Ok(true);
        }
        let now_ms = crate::client::generated_identity::now_ms();
        self.merge_generated_clock(identity.hlc, now_ms)?;
        let order = crate::client::generated_identity::order_hlc(identity.hlc, now_ms);
        self.account_db()?.persist_message_actor_state(
            &opened.routing.message_id,
            &format!("routed/generated-order/{}", opened.routing.message_id),
            &identity.hlc,
        )?;
        self.account_db()?.persist_message_actor_state(
            &opened.routing.message_id,
            &format!("routed/generated-display-hlc/{}", opened.routing.message_id),
            &order,
        )?;
        Ok(false)
    }

    fn verify_generated_message_header(
        entry: &GatewayInboxEntry,
        bytes: &[u8],
    ) -> Result<(), SdkError> {
        use g::original_header::{self, EvidenceError};
        let issued =
            u64::try_from(entry.envelope.created_at).map_err(|_| invalid("negative issue time"))?;
        let expires = issued
            .checked_add(u64::from(entry.envelope.ttl))
            .ok_or_else(|| invalid("expiry overflow"))?;
        original_header::verify_inner_extension(&entry.envelope.ext, bytes, issued, expires)
            .map_err(|error| SdkError::GeneratedRefused {
                code: if error == EvidenceError::OriginEvidenceMissing {
                    crate::error::GeneratedRefusalCode::OriginEvidenceMissing
                } else {
                    crate::error::GeneratedRefusalCode::OriginCommitmentMismatch
                },
                reason: error.to_string(),
            })
    }

    fn project_generated_group(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        scanned: &validation::ScannedInner<'_>,
        metadata: Option<&MessageMetadata>,
        identity: Option<g::EventIdentity>,
    ) -> Result<GeneratedProjection, SdkError> {
        let wrapper =
            g::Message::decode(scanned.body).map_err(|_| invalid("group Message missing"))?;
        let sealed =
            wrapper.sealed_group.as_ref().ok_or_else(|| invalid("sealed group missing"))?;
        let native = crate::client::generated_group::to_native(sealed)?;
        let plaintext = zeroize::Zeroizing::new(self.decrypt_group_envelope_for_identity(
            &native,
            &opened.routing.message_id,
            &opened.remote_device,
        )?);
        let outcome = validation::scan_message("Message", &plaintext, scanned.layer)
            .map_err(|error| invalid(&format!("invalid group content: {error}")))?;
        if scanned.outcome == ScanOutcome::Unsupported || outcome == ScanOutcome::Unsupported {
            self.retain_generated_unsupported(opened, entry, scanned)?;
            let copy = self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?;
            self.account_db()?.put_unsupported_raw_copy(RawInnerCopyWrite {
                owner_id: &opened.routing.message_id,
                verified_source_anchor: opened.remote_device.root_commitment(),
                copy_id: &format!("{copy}/nested-group"),
                kind: RawInnerCopyKind::NestedGroup,
                bytes: &plaintext,
                bounded_metadata: &[],
            })?;
            return Ok(GeneratedProjection::Handled(None));
        }
        let message = g::Message::decode(plaintext.as_slice())
            .map_err(|_| invalid("invalid group Message"))?;
        validation::validate_message(&message).map_err(|_| invalid("invalid group content"))?;
        if message.sealed_group.is_some() {
            return Err(invalid("recursive sealed group"));
        }
        self.merge_routed_group_link(&sealed.group_id, &opened.routing.conversation_id)?;
        self.append_plaintext_projection_once(
            &opened.routing.conversation_id,
            &opened.routing.message_id,
            entry,
            scanned.exact_inner,
            metadata,
        )?;
        let db = self.account_db()?;
        db.persist_message_actor_state(
            &opened.routing.message_id,
            &format!("routed/group-projection/{}", opened.routing.message_id),
            &message,
        )?;
        db.persist_message_actor_state(
            &opened.routing.message_id,
            &format!("routed/group-content/{}", opened.routing.message_id),
            &*plaintext,
        )?;
        if let Some(identity) = identity {
            db.persist_message_actor_state(
                &opened.routing.message_id,
                &format!("routed/generated-identity/{}", opened.routing.message_id),
                &identity,
            )?;
        }
        Ok(GeneratedProjection::Handled(Some(message.text.into_bytes())))
    }

    fn project_known_generated(
        &self,
        frame: GeneratedCommit<'_>,
        content: g::Content,
    ) -> Result<GeneratedProjection, SdkError> {
        let GeneratedCommit { opened, entry, bytes, metadata, identity } = frame;
        let projected = match content.value.ok_or_else(|| invalid("generated content missing"))? {
            g::content::Value::Message(message) if message.sealed_group.is_none() => {
                self.ensure_generated_direct_conversation(opened, entry)?;
                self.append_plaintext_projection_once(
                    &opened.routing.conversation_id,
                    &opened.routing.message_id,
                    entry,
                    bytes,
                    metadata,
                )?;
                if let Some(identity) = identity {
                    self.account_db()?.persist_message_actor_state(
                        &opened.routing.message_id,
                        &format!("routed/generated-identity/{}", opened.routing.message_id),
                        &identity,
                    )?;
                }
                Some(message.text.into_bytes())
            }
            g::content::Value::Edit(_) => {
                self.apply_generated_edit_with_metadata(
                    entry,
                    &opened.routing.conversation_id,
                    bytes,
                    metadata,
                )?;
                None
            }
            g::content::Value::Delete(delete) => {
                let event = identity.as_ref().ok_or_else(|| invalid("Delete identity missing"))?;
                if delete.tombstone_id.as_slice()
                    != g::identity::delete_tombstone(&event.id)
                        .map_err(|_| invalid("Delete event id invalid"))?
                {
                    return Err(invalid("Delete tombstone id mismatch"));
                }
                self.apply_generated_delete_entry(
                    entry,
                    event,
                    &opened.routing.conversation_id,
                    &delete,
                )?;
                None
            }
            g::content::Value::Reaction(reaction) => {
                if identity.as_ref().is_none_or(|event| reaction.operation_id != event.id) {
                    return Err(invalid("Reaction operation id mismatch"));
                }
                self.apply_generated_reaction_entry(
                    entry,
                    identity.as_ref().ok_or_else(|| invalid("Reaction identity missing"))?,
                    &opened.routing.conversation_id,
                    &reaction,
                )?;
                None
            }
            g::content::Value::SelfSync(sync) => {
                let source =
                    self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
                let scanned =
                    validation::scan_inner(bytes).map_err(|_| invalid("SelfSync body missing"))?;
                self.apply_self_sync_exact(
                    &source,
                    &opened.routing.conversation_id,
                    &sync,
                    scanned.body,
                )?;
                None
            }
            g::content::Value::Call(call) => {
                let native = crate::client::generated_call::native::to_native(call)?;
                self.project_native_call_control(
                    entry,
                    &opened.routing.conversation_id,
                    opened.routing.group_id.as_deref(),
                    &native,
                    bytes,
                )?;
                None
            }
            g::content::Value::Control(control) => {
                crate::client::generated_control::validate_control_native(&control)?;
                if let Some(g::control::Payload::OwnMessageCopy(copy)) = control.payload.as_ref() {
                    self.receive_generated_own_message_copy(opened, entry, copy)?;
                } else {
                    return Err(SdkError::InboundPending(
                        "generated native control executor is not yet activated".into(),
                    ));
                }
                None
            }
            _ => return Ok(GeneratedProjection::Native),
        };
        Ok(GeneratedProjection::Handled(projected))
    }

    fn authorize_generated_origin(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        scanned: &validation::ScannedInner<'_>,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if (scanned.kind == 1 && !matches!(opened.routing.kind, Kind::Direct | Kind::GroupMessage))
            || (scanned.kind == 6 && opened.routing.kind != Kind::Receipt)
            || (scanned.kind == 12 && opened.routing.kind != Kind::Control)
        {
            return Err(SdkError::InboundRejected(
                "generated kind conflicts with authenticated route".into(),
            ));
        }
        if scanned.kind == 7 {
            return Err(SdkError::GeneratedRefused {
                code: crate::error::GeneratedRefusalCode::TypingDurable,
                reason: "known Typing requires the ephemeral channel".into(),
            });
        }
        let identity = g::Inner::decode(scanned.exact_inner)
            .map_err(|_| invalid("generated identity missing"))?
            .identity;
        if let Some(group_id) = identity.as_ref().and_then(|identity| identity.group_id.as_deref())
        {
            if Some(group_id) != opened.routing.group_id.as_deref() {
                return Err(invalid("group identity conflicts with route"));
            }
            self.require_native_operation(&source, NativeOperation::Group)?;
            self.require_routed_group_member(group_id, entry)?;
            if !self.group_state(group_id)?.members.contains(source.device_id()) {
                return Err(SdkError::InboundRejected("group author lacks a current role".into()));
            }
        }
        if matches!(opened.routing.kind, Kind::GroupMessage | Kind::GroupControl) {
            self.require_routed_group_member(
                opened.routing.group_id.as_deref().ok_or_else(|| invalid("group missing"))?,
                entry,
            )?;
            if opened.routing.kind == Kind::GroupMessage && scanned.kind == 1 {
                let message = g::Message::decode(scanned.body)
                    .map_err(|_| invalid("group Message authority fields missing"))?;
                let group =
                    message.sealed_group.as_ref().ok_or_else(|| invalid("sealed group missing"))?;
                if Some(group.group_id.as_str()) != opened.routing.group_id.as_deref() {
                    return Err(SdkError::InboundRejected(
                        "generated group routing mismatch".into(),
                    ));
                }
                let identity =
                    identity.as_ref().ok_or_else(|| invalid("group identity missing"))?;
                if identity.author != group.author
                    || identity.group_id.as_deref() != Some(group.group_id.as_str())
                    || identity.group_epoch != Some(group.key_epoch)
                {
                    return Err(invalid("sealed group and event identity disagree"));
                }
                self.check_generated_group_source(group, &opened.remote_device, entry)?;
            } else if opened.routing.kind == Kind::GroupControl {
                return Err(SdkError::InboundPending(
                    "generated group control executor is not yet activated".into(),
                ));
            } else {
                let epoch = identity
                    .as_ref()
                    .and_then(|identity| identity.group_epoch)
                    .ok_or_else(|| invalid("group epoch missing"))?;
                self.require_generated_group_epoch(
                    opened.routing.group_id.as_deref().ok_or_else(|| invalid("group missing"))?,
                    &source,
                    epoch,
                    false,
                )?;
            }
        }
        self.authorize_generated_native_fields(opened, entry, scanned)
    }

    fn authorize_generated_native_fields(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        scanned: &validation::ScannedInner<'_>,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if scanned.kind == 1 && opened.routing.kind == Kind::Direct {
            let message =
                g::Message::decode(scanned.body).map_err(|_| invalid("Message missing"))?;
            if message.sealed_group.is_some() {
                return Err(invalid("sealed group on direct route"));
            }
        }
        if scanned.kind == 4 {
            let delete = g::Delete::decode(scanned.body)
                .map_err(|_| invalid("Delete authority fields missing"))?;
            if !delete.native_group_authorization.is_empty() {
                return Err(invalid("Delete group proof forbidden in v1"));
            }
        }
        if scanned.kind == 2 {
            let service =
                g::Service::decode(scanned.body).map_err(|_| invalid("Service missing"))?;
            if !service.native_authority_proof.is_empty() {
                return Err(invalid("Service authority proof forbidden in v1"));
            }
        }
        if scanned.kind == 12 {
            if source.root_commitment() != self.own_account_anchor()? {
                return Err(SdkError::InboundRejected("self sync requires same root".into()));
            }
            self.require_native_operation(&source, NativeOperation::Sync)?;
        }
        if scanned.kind == 8 {
            let control = g::Control::decode(scanned.body)
                .map_err(|_| invalid("control authority fields missing"))?;
            if matches!(control.operation, 6 | 7 | 13 | 14 | 15) {
                if source.root_commitment() != self.own_account_anchor()? {
                    return Err(SdkError::InboundRejected("own control requires same root".into()));
                }
                self.require_native_operation(&source, NativeOperation::Sync)?;
                self.require_native_operation(
                    &self.owned_device_identity()?,
                    NativeOperation::Sync,
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn finish_generated_projection(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        if !crate::client::target_selection::schema_v1_selected() {
            return Ok(());
        }
        if matches!(opened.routing.kind, Kind::Direct | Kind::GroupMessage) {
            self.resolve_generated_pending_edit(
                &opened.routing.conversation_id,
                &opened.routing.message_id,
            )?;
            self.resolve_generated_pending_history_edit(&opened.routing.message_id)?;
        }
        self.resolve_self_sync_read_references(&opened.routing.conversation_id)?;
        self.clear_generated_capacity(entry)?;
        Ok(())
    }

    fn retain_generated_unsupported(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        scanned: &validation::ScannedInner<'_>,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let target = match scanned.kind {
            3 => g::Edit::decode(scanned.body).ok().and_then(|edit| edit.target),
            5 => g::Reaction::decode(scanned.body).ok().and_then(|reaction| reaction.target),
            _ => None,
        };
        if let Some(target) = target.as_ref() {
            if target.conversation_id != opened.routing.conversation_id {
                return Err(invalid("Unsupported mutation target conversation mismatch"));
            }
            if self
                .account_db()?
                .message_is_deleted(&ramflux_protocol::encode_base64url(&target.id))?
            {
                return Ok(());
            }
        }
        let copy_id = self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?;
        let provenance = Provenance {
            source: source.storage_key().to_owned(),
            conversation: opened.routing.conversation_id.clone(),
            message: opened.routing.message_id.clone(),
            envelope_id: entry.envelope.envelope_id.clone(),
            payload_hash: entry.envelope.payload_hash.clone(),
            expires_at: entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl)),
            original_mode: entry.envelope.delivery_mode.clone().unwrap_or_else(|| "durable".into()),
            source_epoch: self
                .account_db()?
                .client_device_record(&source)?
                .and_then(|record| record["device_epoch"].as_u64())
                .ok_or_else(|| invalid("source epoch missing"))?,
            original_route: serde_json::to_string(&opened.routing)?,
            outer_receipt_key: copy_id.clone(),
            received_erasure_generation: self.account_db()?.privacy_erasure_generation()?,
        };
        let db = self.account_db()?;
        if let Some(group) = opened.routing.group_id.as_deref() {
            self.merge_routed_group_link(group, &opened.routing.conversation_id)?;
        } else {
            self.ensure_generated_direct_conversation(opened, entry)?;
        }
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: &opened.routing.message_id,
            verified_source_anchor: source.root_commitment(),
            copy_id: &copy_id,
            kind: RawInnerCopyKind::OuterInner,
            bytes: scanned.exact_inner,
            bounded_metadata: &serde_json::to_vec(&provenance)?,
        })?;
        if let Some(target) = target {
            db.bind_raw_inner_copy(&copy_id, &ramflux_protocol::encode_base64url(target.id))?;
        }
        let raw = db
            .raw_inner_copy(&copy_id)?
            .ok_or_else(|| invalid("raw copy missing before commit"))?;
        let view = g::UnsupportedView {
            layer: scanned.layer,
            kind: scanned.kind,
            raw_digest: raw.digest.to_vec(),
            raw_length: u32::try_from(raw.bytes.len())
                .map_err(|_| invalid("raw length overflow"))?,
            raw_handle: copy_id.as_bytes().to_vec(),
            reason: "UnsupportedSchema".into(),
        };
        db.persist_message_actor_state(
            &opened.routing.message_id,
            &format!("routed/unsupported/{}", opened.routing.message_id),
            &view,
        )?;
        db.import_direct_message_projection(ramflux_storage::DirectMessageWrite {
            conversation_id: &opened.routing.conversation_id,
            message_id: &opened.routing.message_id,
            sender_id: &entry.envelope.source_principal_id,
            encrypted_body: &[],
            metadata: &MessageMetadata::default(),
            created_at: entry.envelope.created_at,
        })?;
        self.stage_delivery_receipt(
            &opened.routing.conversation_id,
            &opened.routing.message_id,
            entry,
        )?;
        Ok(())
    }

    fn ensure_generated_direct_conversation(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if db.client_record("conversation", &opened.routing.conversation_id)?.is_none() {
            let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            db.persist_client_record("conversation", &opened.routing.conversation_id, &serde_json::json!({
                "kind": "direct", "participants": [local.principal_id, entry.envelope.source_principal_id],
            }))?;
        }
        Ok(())
    }
}
