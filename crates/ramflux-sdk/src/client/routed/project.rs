// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified domain projections; called only inside the receive commit transaction.
use super::{
    GatewayInboxEntry, MessageMetadata, Opened, RamfluxClient, SdkError, invalid,
    now_unix_timestamp,
};
use crate::client::identity_authority::HeadUse;
impl RamfluxClient {
    pub(super) fn project_routed(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
        metadata: Option<&MessageMetadata>,
    ) -> Result<Option<Vec<u8>>, SdkError> {
        let super::generated_receive::GeneratedProjection::Handled(projected) =
            self.project_generated_entry(opened, entry, body, metadata)?;
        Ok(projected)
    }

    pub(crate) fn project_accepted_contact_message_at(
        &self,
        route: &super::Routing,
        entry: &GatewayInboxEntry,
        body: &[u8],
        metadata: Option<&MessageMetadata>,
        released_at: i64,
    ) -> Result<Option<Vec<u8>>, SdkError> {
        use ramflux_protocol::message as g;
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if let Some(reason) = self.friend_rejection_reason(source.root_commitment())? {
            self.account_db()?.reject_inbox_message(
                &route.conversation_id,
                &route.message_id,
                &entry.envelope.source_principal_id,
                &reason,
                now_unix_timestamp(),
            )?;
            return Ok(None);
        }
        if !self.accepted_contact_source(
            source.root_commitment(),
            &entry.envelope.source_principal_id,
        )? {
            return Err(invalid("direct message projection requires accepted source root"));
        }

        let (identity, content) = Self::decode_generated_inner(body)?;
        let author =
            identity.author.as_ref().ok_or_else(|| invalid("held message author missing"))?;
        if identity.conversation_id != route.conversation_id
            || ramflux_protocol::encode_base64url(&identity.id) != route.message_id
            || author.account_anchor != source.root_commitment()
            || author.device_id != source.device_id()
            || identity.group_id.is_some()
        {
            return Err(invalid("held generated message provenance mismatch"));
        }
        let own = self.own_account_anchor()?;
        g::dm_scope::validate_direct(&route.conversation_id, &own, source.root_commitment())
            .map_err(|_| invalid("held direct conversation root mismatch"))?;
        Self::verify_generated_message_header(entry, body)?;
        let scanned =
            g::validation::scan_inner(body).map_err(|_| invalid("held Inner malformed"))?;
        if self.prepare_generated_identity(route, entry, body, scanned.kind, Some(&identity))? {
            return Ok(None);
        }
        self.capture_generated_original_header(entry, body)?;
        let db = self.account_db()?;
        if db.client_record("conversation", &route.conversation_id)?.is_none() {
            db.persist_client_record("conversation", &route.conversation_id, &serde_json::json!({
                "kind":"direct", "group_id":null, "title":null, "direct_route":null,
                "participants":[self.device_branch.as_ref().map(|b| &b.principal_id), Some(&entry.envelope.source_principal_id)],
                "participant_roots":[own, source.root_commitment()],
            }))?;
        }
        let projected = match content.value.ok_or_else(|| invalid("held content missing"))? {
            g::content::Value::Message(message) if message.sealed_group.is_none() => {
                self.append_plaintext_projection_once(
                    &route.conversation_id,
                    &route.message_id,
                    entry,
                    body,
                    metadata,
                )?;
                Ok(Some(message.text.into_bytes()))
            }
            g::content::Value::Surface(surface) => {
                self.project_generated_surface_at(
                    route,
                    entry,
                    &surface,
                    body,
                    super::generated_applications::SurfaceProjection {
                        metadata,
                        expires_at: released_at.saturating_add(i64::from(entry.envelope.ttl)),
                    },
                )?;
                Ok(None)
            }
            g::content::Value::Task(task) => {
                self.project_generated_task(route, entry, &task, body, metadata)?;
                Ok(None)
            }
            g::content::Value::Service(_) => {
                self.append_plaintext_projection_once(
                    &route.conversation_id,
                    &route.message_id,
                    entry,
                    body,
                    metadata,
                )?;
                Ok(None)
            }
            _ => Err(invalid("held content requires its typed mutation/control owner")),
        }?;
        self.journal_generated_receive_updates(body)?;
        Ok(projected)
    }
}
