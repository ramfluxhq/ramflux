// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Peer resync requests use authenticated controls; the original author device answers once per window.
use super::{Carrier, invalid, key};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
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
#[derive(Serialize, Deserialize)]
pub(crate) struct ResyncReply {
    pub carrier: Carrier,
    #[serde(flatten)]
    pub destination: ResyncDestination,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct ResyncDestination {
    pub principal: String,
    pub root: String,
    pub device: String,
    pub target: String,
    pub group: Option<String>,
    pub epoch: Option<u64>,
    pub expires_at: i64,
}
#[derive(Serialize, Deserialize)]
struct AnswerWindow {
    answered: BTreeSet<String>,
    expires_at: i64,
}
#[derive(Serialize, Deserialize)]
struct RequesterWindow {
    surfaces: BTreeSet<String>,
    expires_at: i64,
}
const MAX_GUARDS: u32 = 2048;
const MAX_REPLIES: u32 = 256;
const MAX_SURFACE_REQUESTERS: usize = 64;
const MAX_REQUESTER_SURFACES: usize = 32;
impl RamfluxClient {
    pub(crate) fn prepare_surface_resync_request(
        &self,
        reference: &str,
    ) -> Result<Option<ResyncRequest>, SdkError> {
        let db = self.account_db()?;
        let view = db
            .client_record("surface", reference)?
            .ok_or_else(|| crate::SurfaceRefusalCode::NotFound.error("surface is unknown"))?;
        if view["out_of_sync"] != true {
            return Err(crate::SurfaceRefusalCode::NotOutOfSync.error("surface is not out of sync"));
        }
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let author = required(&view, "author_principal_id")?;
        if author == local.principal_id && view["author_device_id"] == local.device_id {
            return Err(crate::SurfaceRefusalCode::NotOutOfSync
                .error("the author already owns the resync state"));
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
            self.prune_surface_resync_state()?;
            if db
                .load_actor_state::<Value>(id)?
                .and_then(|v| v["expires_at"].as_i64())
                .is_some_and(|at| at > now)
            {
                return Ok(false);
            }
            if db.actor_state_usage("surface/resync_requested/")?.0 >= u64::from(MAX_GUARDS) {
                return Ok(false);
            }
            db.persist_actor_state(
                id,
                &serde_json::json!({"expires_at":now.saturating_add(WINDOW)}),
            )?;
            Ok::<_, SdkError>(true)
        })
    }
    pub(crate) fn prune_surface_resync_state(&self) -> Result<(), SdkError> {
        let now = crate::prelude::now_unix_timestamp();
        for prefix in [
            "surface/resync_requested/",
            "surface/resync_answered/",
            "surface/resync_requester_budget/",
        ] {
            self.account_db()?.retain_expiring_actor_states(prefix, now, MAX_GUARDS)?;
        }
        self.account_db()?.retain_expiring_actor_states(
            "surface/resync-response/",
            now,
            MAX_REPLIES,
        )?;
        Ok(())
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
        let source = self.trusted_device(&self.authenticated_device_identity(entry)?)?;
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
        if source["principal_id"] != entry.envelope.source_principal_id {
            return Err(invalid("resync requester owner mismatch"));
        }
        let root = required(&source, "principal_commitment")?;
        let target = required(&source, "target_delivery_id")?;
        let now = crate::prelude::now_unix_timestamp();
        let epoch = request
            .group
            .as_deref()
            .map(|g| self.group_state(g).map(|s| s.group_epoch))
            .transpose()?;
        let destination = ResyncDestination {
            principal: entry.envelope.source_principal_id.clone(),
            root: root.into(),
            device: entry.envelope.source_device_id.clone(),
            target: target.into(),
            group: request.group.clone(),
            epoch,
            expires_at: now.saturating_add(WINDOW),
        };
        self.queue_surface_resync_reply(entry, &request.surface_ref, destination)?;
        Ok(true)
    }
    fn queue_surface_resync_reply(
        &self,
        entry: &GatewayInboxEntry,
        reference: &str,
        destination: ResyncDestination,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            self.prune_surface_resync_state()?;
            let now = crate::prelude::now_unix_timestamp();
            if db.actor_state_usage("surface/resync-response/")?.0 >= u64::from(MAX_REPLIES) {
                return Ok(());
            }
            // One shared window and total reply budget per surface, across all requesters.
            let rate = key("resync_answered", reference);
            let old = db.load_actor_state::<AnswerWindow>(&rate)?;
            if old.is_none()
                && db.actor_state_usage("surface/resync_answered/")?.0 >= u64::from(MAX_GUARDS)
            {
                return Ok(());
            }
            let mut window = old.unwrap_or(AnswerWindow {
                answered: BTreeSet::new(),
                expires_at: now.saturating_add(WINDOW),
            });
            let requester =
                super::scoped_key("resync_requester", &[&destination.root, &destination.device])?;
            if window.answered.contains(&requester)
                || window.answered.len() >= MAX_SURFACE_REQUESTERS
            {
                return Ok(());
            }
            let budget = super::scoped_key(
                "resync_requester_budget",
                &[&destination.root, &destination.principal],
            )?;
            let old = db.load_actor_state::<RequesterWindow>(&budget)?;
            if old.is_none()
                && db.actor_state_usage("surface/resync_requester_budget/")?.0
                    >= u64::from(MAX_GUARDS)
            {
                return Ok(());
            }
            let mut peer = old.unwrap_or(RequesterWindow {
                surfaces: BTreeSet::new(),
                expires_at: now.saturating_add(WINDOW),
            });
            if !peer.surfaces.contains(reference) && peer.surfaces.len() >= MAX_REQUESTER_SURFACES {
                return Ok(());
            }
            let reply = ResyncReply {
                carrier: self
                    .prepare_surface_resync(reference, &crate::new_surface_message_id()?)?,
                destination,
            };
            peer.surfaces.insert(reference.into());
            window.answered.insert(requester);
            db.persist_actor_state(&rate, &window)?;
            db.persist_actor_state(&budget, &peer)?;
            db.persist_actor_state(
                &format!("surface/resync-response/{}", self.authenticated_committed_key(entry)?),
                &reply,
            )?;
            Ok::<_, SdkError>(())
        })
    }
    pub(crate) fn validate_surface_resync_reply(
        &self,
        reply: &ResyncReply,
    ) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if reply.carrier.author_principal_id != local.principal_id
            || reply.carrier.sender_principal_id != local.principal_id
            || reply.carrier.sender_device_id != local.device_id
        {
            return Err(invalid("resync reply requires the original author device"));
        }
        let target = &reply.destination;
        let device =
            self.trusted_device(&self.device_identity_for_root(&target.root, &target.device)?)?;
        if device["principal_id"] != target.principal
            || device["principal_commitment"] != target.root
        {
            return Err(invalid("resync reply recipient binding changed"));
        }
        if target.principal == local.principal_id {
            self.authorize_owned_surface_source(&device)?;
        } else {
            self.authorize_surface_peer_context(
                &reply.carrier.conversation_id,
                target.group.as_deref(),
                &target.principal,
                &target.device,
                target.epoch,
            )?;
        }
        Ok(())
    }
    pub(crate) fn take_surface_resync_answer(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<ResyncReply>, SdkError> {
        self.prune_surface_resync_state()?;
        let id = format!("surface/resync-response/{}", self.authenticated_committed_key(entry)?);
        let db = self.account_db()?;
        let Some(reply) = db.load_actor_state::<ResyncReply>(&id)? else { return Ok(None) };
        // Consume before submission; a lost ACK cannot bypass the shared window.
        db.remove_actor_state(&id)?;
        Ok(Some(reply))
    }
}
fn required<'a>(value: &'a Value, field: &str) -> Result<&'a str, SdkError> {
    value[field].as_str().ok_or_else(|| invalid("surface resync metadata absent"))
}
