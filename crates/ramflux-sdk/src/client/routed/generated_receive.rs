// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated receive projection. Called only after source, AEAD and C verification, inside W1.
use super::{Opened, Kind, invalid};
use crate::{RamfluxClient, SdkError, GatewayInboxEntry};
use crate::client::identity_authority::{HeadUse, NativeOperation};
use prost::Message as _;
use ramflux_protocol::message::{self as g, validation::{self, ScanOutcome}};
use ramflux_storage::{MessageMetadata, RawInnerCopyKind, RawInnerCopyWrite};
use serde::{Serialize, Deserialize};

pub(super) enum GeneratedProjection {
    Native,
    Handled(Option<Vec<u8>>),
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
}

impl RamfluxClient {
    pub(super) fn project_generated_entry(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        bytes: &[u8],
        metadata: Option<&MessageMetadata>,
    ) -> Result<GeneratedProjection, SdkError> {
        // Dormant integration retains the native callers until the final codec-removal commit.
        let Ok(scanned) = validation::scan_inner(bytes) else { return Ok(GeneratedProjection::Native) };
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let inner = g::Inner::decode(bytes).ok();
        if let Some(identity) = inner.as_ref().and_then(|inner| inner.identity.as_ref())
            && (identity.conversation_id != opened.routing.conversation_id
                || identity.author.as_ref().is_none_or(|author| {
                    author.account_anchor != source.root_commitment()
                        || author.device_id != source.device_id()
                }))
            {
                return Err(SdkError::InboundRejected("generated identity differs from authenticated source or conversation".into()));
            }
        self.authorize_generated_origin(opened, entry, &scanned)?;
        if scanned.outcome == ScanOutcome::Unsupported || inner.as_ref().is_none_or(|inner| inner.identity.is_none()) {
            self.retain_generated_unsupported(opened, entry, &scanned)?;
            return Ok(GeneratedProjection::Handled(None));
        }
        let content = match g::registry::decode_body(scanned.kind, scanned.body, scanned.layer) {
            Ok(content) => content,
            Err(validation::ValidationError::Malformed | validation::ValidationError::Unsupported) => {
                self.retain_generated_unsupported(opened, entry, &scanned)?;
                return Ok(GeneratedProjection::Handled(None));
            }
            Err(error) => return Err(SdkError::InboundRejected(format!("invalid generated content: {error}"))),
        };
        let projected = match content.value.ok_or_else(|| invalid("generated content missing"))? {
            g::content::Value::Message(message) if message.sealed_group.is_none() => {
                self.ensure_generated_direct_conversation(opened, entry)?;
                self.append_plaintext_projection_once(&opened.routing.conversation_id, &opened.routing.message_id, entry, bytes, metadata)?;
                if let Some(identity) = inner.and_then(|inner| inner.identity) {
                    self.account_db()?.persist_message_actor_state(
                        &opened.routing.message_id,
                        &format!("routed/generated-identity/{}", opened.routing.message_id),
                        &identity,
                    )?;
                }
                Some(message.text.into_bytes())
            }
            g::content::Value::Edit(_) => {
                self.apply_generated_edit_entry(entry, &opened.routing.conversation_id, bytes)?;
                None
            }
            g::content::Value::Delete(delete) => {
                self.apply_generated_delete_entry(entry, &opened.routing.conversation_id, &delete)?;
                None
            }
            g::content::Value::Reaction(reaction) => {
                self.apply_generated_reaction_entry(entry, &opened.routing.conversation_id, &reaction)?;
                None
            }
            g::content::Value::SelfSync(sync) => {
                self.apply_self_sync_in(&source, &opened.routing.conversation_id, &sync)?;
                None
            }
            g::content::Value::Call(call) => {
                let native = crate::client::generated_call::native::to_native(call)?;
                self.project_native_call_control(entry, &opened.routing.conversation_id, opened.routing.group_id.as_deref(), &native, bytes)?;
                None
            }
            g::content::Value::Control(control) => {
                crate::client::generated_control::validate_control_native(&control)?;
                if let Some(g::control::Payload::OwnMessageCopy(copy)) = control.payload.as_ref() {
                    self.receive_generated_own_message_copy(opened, entry, copy)?;
                } else {
                    return Err(SdkError::InboundPending("generated native control executor is not yet activated".into()));
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
            return Err(SdkError::InboundRejected("generated kind conflicts with authenticated route".into()));
        }
        if scanned.kind == 7 {
            return Err(SdkError::InboundRejected("known Typing requires the ephemeral channel".into()));
        }
        if matches!(opened.routing.kind, Kind::GroupMessage | Kind::GroupControl) {
            self.require_routed_group_member(opened.routing.group_id.as_deref().ok_or_else(|| invalid("group missing"))?, entry)?;
            // A pair wrapper does not prove native group plaintext origin.
            // Group adapters must verify the nested author proof before raw retention.
            return Err(SdkError::InboundPending("generated group origin proof requires native group adapter".into()));
        }
        if scanned.kind == 12 {
            if source.root_commitment() != self.own_account_anchor()? {
                return Err(SdkError::InboundRejected("self sync requires same root".into()));
            }
            self.require_native_operation(&source, NativeOperation::Sync)?;
        }
        if scanned.kind == 8 {
            let control = g::Control::decode(scanned.body).map_err(|_| invalid("control authority fields missing"))?;
            if matches!(control.operation, 6 | 7 | 13 | 14 | 15) {
                if source.root_commitment() != self.own_account_anchor()? {
                    return Err(SdkError::InboundRejected("own control requires same root".into()));
                }
                self.require_native_operation(&source, NativeOperation::Sync)?;
                self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Sync)?;
            }
        }
        Ok(())
    }

    fn retain_generated_unsupported(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        scanned: &validation::ScannedInner<'_>,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let copy_id = self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?;
        let provenance = Provenance {
            source: source.storage_key().to_owned(), conversation: opened.routing.conversation_id.clone(),
            message: opened.routing.message_id.clone(), envelope_id: entry.envelope.envelope_id.clone(),
            payload_hash: entry.envelope.payload_hash.clone(),
            expires_at: entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl)),
        };
        let db = self.account_db()?;
        self.ensure_generated_direct_conversation(opened, entry)?;
        db.put_unsupported_raw_copy(RawInnerCopyWrite {
            owner_id: &opened.routing.message_id, verified_source_anchor: source.root_commitment(),
            copy_id: &copy_id, kind: RawInnerCopyKind::OuterInner, bytes: scanned.exact_inner,
            bounded_metadata: &serde_json::to_vec(&provenance)?,
        })?;
        let raw = db.raw_inner_copy(&copy_id)?.ok_or_else(|| invalid("raw copy missing before commit"))?;
        let view = g::UnsupportedView {
            layer: scanned.layer, kind: scanned.kind, raw_digest: raw.digest.to_vec(),
            raw_length: u32::try_from(raw.bytes.len()).map_err(|_| invalid("raw length overflow"))?,
            raw_handle: copy_id.as_bytes().to_vec(), reason: "UnsupportedSchema".into(),
        };
        db.persist_message_actor_state(&opened.routing.message_id, &format!("routed/unsupported/{}", opened.routing.message_id), &view)?;
        db.import_direct_message_projection(ramflux_storage::DirectMessageWrite {
            conversation_id: &opened.routing.conversation_id,
            message_id: &opened.routing.message_id,
            sender_id: &entry.envelope.source_principal_id,
            encrypted_body: &[], metadata: &MessageMetadata::default(),
            created_at: entry.envelope.created_at,
        })?;
        self.stage_delivery_receipt(&opened.routing.conversation_id, &opened.routing.message_id, entry)?;
        Ok(())
    }

    fn ensure_generated_direct_conversation(&self, opened: &Opened, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
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
