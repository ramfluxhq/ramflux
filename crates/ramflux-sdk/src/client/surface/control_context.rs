// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-authorized conversation context and own-device membership floors.
use super::{control::OwnContext, invalid};
use crate::{RamfluxClient, SdkError};
use serde_json::{Value, json};
impl RamfluxClient {
    /// Validate namespace before friend, group, checkpoint or conversation writes.
    pub(crate) fn validate_own_context_namespace(
        &self,
        context: &OwnContext,
    ) -> Result<(), SdkError> {
        use ramflux_protocol::message::dm_scope;
        if !context.conversation_id.starts_with(dm_scope::PREFIX) {
            return Ok(());
        }
        let own = self.own_account_anchor()?;
        let old = self.account_db()?.client_record("conversation", &context.conversation_id)?;
        let peer = if let Some(friend) = &context.friend {
            if friend.requester_id == own {
                friend.target_id.clone()
            } else if friend.target_id == own {
                friend.requester_id.clone()
            } else {
                return Err(invalid("own DM roots omit local root"));
            }
        } else {
            old.as_ref()
                .and_then(|v| v["participant_roots"].as_array())
                .and_then(|roots| roots.iter().filter_map(Value::as_str).find(|root| *root != own))
                .ok_or_else(|| invalid("reserved own DM lacks root binding"))?
                .to_owned()
        };
        dm_scope::validate_direct(&context.conversation_id, &own, &peer)
            .map_err(|_| invalid("own DM root pair mismatch"))?;
        if let Some(old) =
            self.account_db()?.client_record("conversation", &context.conversation_id)?
        {
            if old["kind"] != "direct" || !old["group_id"].is_null() {
                return Err(invalid("reserved own DM conflicts with existing kind"));
            }
            let roots = old["participant_roots"]
                .as_array()
                .ok_or_else(|| invalid("reserved own DM lacks immutable roots"))?;
            let expected = std::collections::BTreeSet::from([own.as_str(), peer.as_str()]);
            if roots.len() != 2
                || roots.iter().filter_map(Value::as_str).collect::<std::collections::BTreeSet<_>>()
                    != expected
            {
                return Err(invalid("reserved own DM conflicts with bound roots"));
            }
        }
        Ok(())
    }
    pub(crate) fn surface_local_root_commitment(&self) -> Result<String, SdkError> {
        self.own_account_anchor()
    }
    pub(super) fn require_existing_own_surface_context(
        &self,
        conversation: &str,
    ) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let thread =
            self.account_db()?.client_record("conversation", conversation)?.ok_or_else(|| {
                SdkError::InboundPending("own surface context unavailable; resync required".into())
            })?;
        if thread["kind"] != "direct"
            || !thread["participants"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id == &local.principal_id))
        {
            return Err(invalid("own surface direct context mismatch"));
        }
        Ok(())
    }
    pub(crate) fn authorize_owned_surface_source(&self, source: &Value) -> Result<(), SdkError> {
        let commitment = self.surface_local_root_commitment()?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if source["principal_id"] != local.principal_id
            || source["principal_commitment"] != commitment
        {
            return Err(invalid("own surface forwarding requires the same verified identity root"));
        }
        Ok(())
    }
    pub(super) fn authorize_surface_peer_context(
        &self,
        conversation: &str,
        principal: &str,
    ) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let thread = self.account_db()?.client_record("conversation", conversation)?;
        if self.friend_rejection_reason(principal)?.is_some() {
            return Err(invalid("surface peer is blocked or revoked"));
        }
        if let Some(thread) = thread {
            let peers = thread["participants"]
                .as_array()
                .ok_or_else(|| invalid("surface direct participants absent"))?;
            if thread["kind"] != "direct"
                || !peers.iter().any(|p| p == principal)
                || !peers.iter().any(|p| p == &local.principal_id)
            {
                return Err(invalid("surface direct conversation membership mismatch"));
            }
        } else {
            if self.friend_rejection_reason(principal)?.is_some() {
                return Err(invalid("surface peer is not an accepted contact"));
            }
            let mut record = json!({"id":conversation,"kind":"direct","group_id":null,"title":null,"participants":[local.principal_id,principal]});
            if let Some(identity) = self.account_db()?.client_record("identity", principal)?
                && let Some(root) = identity["contact_identity_commitment"].as_str()
            {
                let own = self.own_account_anchor()?;
                if ramflux_protocol::message::dm_scope::derive(&own, root).ok().as_deref()
                    == Some(conversation)
                {
                    record["participant_roots"] = json!([own, root]);
                }
            }
            self.account_db()?.persist_client_record("conversation", conversation, &record)?;
        }
        Ok(())
    }
    pub(crate) fn import_surface_context(&self, context: &OwnContext) -> Result<(), SdkError> {
        self.account_db()?.write_transaction(|| self.import_surface_context_inner(context))
    }
    fn import_surface_context_inner(&self, context: &OwnContext) -> Result<(), SdkError> {
        self.validate_own_context_namespace(context)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let db = self.account_db()?;
        self.import_surface_friend(context)?;
        if context.participants.len() != 2 || !context.participants.contains(&local.principal_id) {
            return Err(invalid("own surface direct context mismatch"));
        }
        if let Some(old) = db.client_record("conversation", &context.conversation_id)? {
            if old["kind"] != "direct"
                || old["participants"].as_array().map(|ids| {
                    ids.iter().filter_map(Value::as_str).collect::<std::collections::BTreeSet<_>>()
                }) != Some(context.participants.iter().map(String::as_str).collect())
            {
                return Err(invalid("own surface direct conversation conflict"));
            }
        } else {
            db.persist_client_record("conversation",&context.conversation_id,&json!({"id":context.conversation_id,"kind":"direct","group_id":null,"title":null,"participants":context.participants}))?;
        }
        if context.conversation_id.starts_with("dm:") {
            let mut record = db
                .client_record("conversation", &context.conversation_id)?
                .ok_or_else(|| invalid("own DM binding absent"))?;
            if record["participant_roots"].is_null() {
                let own = self.own_account_anchor()?;
                let friend =
                    context.friend.as_ref().ok_or_else(|| invalid("own DM roots absent"))?;
                let peer = if friend.requester_id == own {
                    &friend.target_id
                } else {
                    &friend.requester_id
                };
                record["participant_roots"] = json!([own, peer]);
                db.persist_client_record("conversation", &context.conversation_id, &record)?;
            }
        }
        Ok(())
    }
    fn import_surface_friend(&self, context: &OwnContext) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if let Some(friend) = &context.friend {
            let own = self.surface_local_root_commitment()?;
            let valid_own = friend.requester_id == own
                || friend.target_id == own
                || friend.requester_id == local.principal_id
                || friend.target_id == local.principal_id;
            let peer = context
                .participants
                .iter()
                .find(|id| *id != &local.principal_id)
                .ok_or_else(|| invalid("own surface direct peer absent"))?;
            let identity = db.client_record("identity", peer)?;
            let commitment =
                identity.as_ref().and_then(|i| i["contact_identity_commitment"].as_str());
            let valid_peer = friend.requester_id == *peer
                || friend.target_id == *peer
                || commitment.is_some_and(|c| friend.requester_id == c || friend.target_id == c);
            let existing = db
                .friend_link_for_peer(peer)?
                .or(commitment.map(|c| db.friend_link_for_peer(c)).transpose()?.flatten());
            if existing.is_none()
                && valid_own
                && valid_peer
                && friend.requester_id != friend.target_id
                && friend.state == "accepted"
                && !friend.blocked
                && friend.capability_revoked_at.is_none()
            {
                db.establish_friend_link(&friend.link_id, &friend.requester_id, &friend.target_id)?;
            }
        }
        Ok(())
    }
}
