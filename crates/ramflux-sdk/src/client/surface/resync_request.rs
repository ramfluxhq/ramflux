// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Peer resync requests use authenticated controls; the original author device answers once per window.
use super::{Carrier, invalid, key};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
const KIND: &str = "surface.resync.request.v1";
const WINDOW: i64 = 60;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResyncRequest {
    #[serde(rename = "type")]
    kind: String,
    pub conversation_id: String,
    pub surface_ref: String,
    pub author: String,
    surface_id: String,
    group: Option<String>,
    epoch: Option<u64>,
}
impl RamfluxClient {
    pub(crate) fn prepare_surface_resync_request(
        &self,
        reference: &str,
    ) -> Result<Option<ResyncRequest>, SdkError> {
        let db = self.account_db()?;
        let view =
            db.client_record("surface", reference)?.ok_or_else(|| invalid("surface is unknown"))?;
        if view["out_of_sync"] != true {
            return Err(invalid("surface is not out of sync"));
        }
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let author = required(&view, "author_principal_id")?;
        if author == local.principal_id && view["author_device_id"] == local.device_id {
            return Err(invalid("the author already owns the resync state"));
        }
        let conversation = required(&view, "conversation_id")?;
        let thread = db
            .client_record("conversation", conversation)?
            .ok_or_else(|| invalid("surface conversation absent"))?;
        let group = thread["group_id"].as_str();
        let request = ResyncRequest {
            kind: KIND.into(),
            conversation_id: conversation.into(),
            surface_ref: reference.into(),
            author: author.into(),
            surface_id: required(&view, "surface_id")?.into(),
            group: group.map(str::to_owned),
            epoch: group.map(|id| self.group_state(id).map(|s| s.group_epoch)).transpose()?,
        };
        if !self.claim_resync_window(&key("resync_requested", reference))? {
            return Ok(None);
        }
        Ok(Some(request))
    }
    fn claim_resync_window(&self, id: &str) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let now = crate::prelude::now_unix_timestamp();
            if db.load_actor_state::<i64>(id)?.is_some_and(|at| now < at.saturating_add(WINDOW)) {
                return Ok(false);
            }
            db.persist_actor_state(id, &now)?;
            Ok::<_, SdkError>(true)
        })
    }
    pub(crate) fn receive_surface_resync_request(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        let Ok(value) = serde_json::from_slice::<Value>(body) else { return Ok(false) };
        if value["type"] != KIND {
            return Ok(false);
        }
        if body.len() > 4096 {
            return Err(invalid("surface resync request too large"));
        }
        let request: ResyncRequest = ramflux_protocol::parse_i_json(body)?;
        if request.conversation_id != conversation
            || request.surface_ref
                != super::scope::surface_reference(
                    conversation,
                    &request.author,
                    &request.surface_id,
                )?
        {
            return Err(invalid("surface resync request binding mismatch"));
        }
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if request.author != local.principal_id {
            return Err(invalid("surface resync request is not for the author"));
        }
        let thread = self
            .account_db()?
            .client_record("conversation", conversation)?
            .ok_or_else(|| invalid("resync conversation absent"))?;
        if thread["group_id"].as_str() != request.group.as_deref() {
            return Err(invalid("resync group context mismatch"));
        }
        let source = self.trusted_device(&entry.envelope.source_device_id)?;
        if entry.envelope.source_principal_id == local.principal_id {
            self.authorize_owned_surface_source(&source)?;
        } else {
            self.authorize_surface_peer_context(
                conversation,
                request.group.as_deref(),
                &entry.envelope.source_principal_id,
                &entry.envelope.source_device_id,
                request.epoch,
            )?;
        }
        let Some((record, _)) = self.surface_state_ref(&request.surface_ref)? else {
            return Ok(true);
        };
        // A deterministic coordinator prevents multiple devices of the author amplifying one request.
        if record.author_device_id != local.device_id {
            return Ok(true);
        }
        let root = required(&source, "principal_commitment")?;
        let rate = super::scoped_key(
            "resync_answered",
            &[&request.surface_ref, root, &entry.envelope.source_principal_id],
        )?;
        if self.claim_resync_window(&rate)? {
            let id = crate::client::routed::committed_key(entry)?;
            self.account_db()?.persist_actor_state(
                &format!("surface/resync-response/{id}"),
                &request.surface_ref,
            )?;
        }
        Ok(true)
    }
    pub(crate) fn take_surface_resync_answer(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<Carrier>, SdkError> {
        let id =
            format!("surface/resync-response/{}", crate::client::routed::committed_key(entry)?);
        let db = self.account_db()?;
        let Some(reference) = db.load_actor_state::<String>(&id)? else { return Ok(None) };
        // This is a synchronous reply, with the same send/error semantics as ordinary text.
        // Consume before sending: a crash or lost ACK cannot bypass the durable rate window.
        db.remove_actor_state(&id)?;
        self.prepare_surface_resync(&reference, &crate::new_surface_message_id()?).map(Some)
    }
}
fn required<'a>(value: &'a Value, field: &str) -> Result<&'a str, SdkError> {
    value[field].as_str().ok_or_else(|| invalid("surface resync metadata absent"))
}
