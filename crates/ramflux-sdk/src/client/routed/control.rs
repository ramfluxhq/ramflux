// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed control projections, with source/target ownership checked before transactional mutation.
use super::{A2iControlEvent, GatewayInboxEntry, Kind, Opened, RamfluxClient, SdkError, invalid};
use serde_json::Value;
impl RamfluxClient {
    pub(super) fn project_routed_control(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>, SdkError> {
        if self.receive_task_own(
            entry,
            &opened.routing.conversation_id,
            opened.routing.group_id.as_deref(),
            body,
        )? {
            return Ok(None);
        }
        if self.receive_surface_control(
            entry,
            &opened.routing.conversation_id,
            opened.routing.group_id.as_deref(),
            body,
        )? {
            return Ok(None);
        }
        if let Ok(mut event) = serde_json::from_slice::<A2iControlEvent>(body) {
            if event.source_device_id != opened.remote_device
                || event.target_device_id != opened.local_device
            {
                return Err(invalid("control event device binding mismatch"));
            }
            if let Some(old) = self.account_db()?.load_actor_state::<A2iControlEvent>(&a2i_key(
                &event.source_device_id,
                &event.event_id,
            )?)? {
                event.acknowledged = old.acknowledged;
                if event != old {
                    return Err(invalid(
                        "control event id reused by another authenticated delivery",
                    ));
                }
            }
            self.account_db()?.persist_actor_state(
                &super::committed_key(entry)?.replace("routed/committed/", "routed/control/"),
                &event,
            )?;
            self.account_db()?
                .persist_actor_state(&a2i_key(&event.source_device_id, &event.event_id)?, &event)?;
        } else {
            let event: Value = serde_json::from_slice(body)?;
            if matches!(
                event["type"].as_str(),
                Some("pair.session.reset.v1" | "pair.session.reset.ack.v1")
            ) {
                if self.friend_rejection_reason(&entry.envelope.source_principal_id)?.is_some() {
                    return Err(invalid("pair recovery forbidden for removed or blocked contact"));
                }
                if event["type"] == "pair.session.reset.v1"
                    && let Some(floor) = event["rejected_bootstrap_floor"].as_u64()
                {
                    self.abandon_unconfirmed_candidate(
                        &opened.local_device,
                        &opened.remote_device,
                        floor,
                    )?;
                }
                self.account_db()?.append_journal(&format!("pair-reset:{}", super::committed_key(entry)?), "session.reset", &serde_json::json!({"device_id":opened.remote_device,"reason":"authenticated_reset_request"}), super::now_unix_timestamp(), None)?;
            } else {
                self.project_contact_control(entry, &event)?;
            }
        }
        Ok(None)
    }
    fn project_contact_control(
        &self,
        entry: &GatewayInboxEntry,
        event: &Value,
    ) -> Result<(), SdkError> {
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("unknown control event type"))?;
        let device = self.trusted_device(&entry.envelope.source_device_id)?;
        let remote = [
            Some(entry.envelope.source_principal_id.as_str()),
            device.get("principal_commitment").and_then(Value::as_str),
        ];
        if kind == "object.revoke_access" {
            let id = event
                .get("object_id")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("object id missing"))?;
            let record = self.account_db()?.client_record("object", id)?;
            if !record
                .as_ref()
                .and_then(|record| record.get("owner"))
                .and_then(Value::as_str)
                .is_some_and(|owner| remote.contains(&Some(owner)))
            {
                return Err(invalid(
                    "object revocation sender does not own the received reference",
                ));
            }
            self.account_db()?.set_object_tombstoned(id)?;
            return Ok(());
        }
        if self.friend_rejection_reason(&entry.envelope.source_principal_id)?.is_some() {
            return Err(invalid("blocked peer cannot mutate local friend controls"));
        }
        let id = event
            .get("link_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("friend control link missing"))?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let account = self.account_index()?.account(&self.account_db()?.local_account_id)?;
        let own = [local.principal_id.as_str(), account.principal_commitment.as_str()];
        let existing = if matches!(kind, "friend.requested" | "friend.accepted") {
            None
        } else {
            Some(self.account_db()?.friend_link(id)?)
        };
        let requester = event
            .get("requester")
            .and_then(Value::as_str)
            .or_else(|| existing.as_ref().map(|link| link.requester_id.as_str()))
            .ok_or_else(|| invalid("friend requester missing"))?;
        let target = event
            .get("target")
            .and_then(Value::as_str)
            .or_else(|| existing.as_ref().map(|link| link.target_id.as_str()))
            .ok_or_else(|| invalid("friend target missing"))?;
        if !((own.contains(&requester) && remote.contains(&Some(target)))
            || (own.contains(&target) && remote.contains(&Some(requester))))
        {
            return Err(invalid("friend control participants differ from authenticated endpoints"));
        }
        match kind {
            "friend.requested" => {
                self.record_pending_friend_link(id, requester, target)?;
            }
            "friend.accepted" => {
                self.establish_friend_link(id, requester, target)?;
            }
            "friend.removed" => {
                self.remove_friend_link(
                    id,
                    event
                        .get("scope")
                        .or_else(|| event.get("remove_scope"))
                        .and_then(Value::as_str)
                        .unwrap_or("both"),
                )?;
            }
            "friend.blocked" => {
                self.block_friend_link(id)?;
            }
            "friend.unblocked" => {
                self.unblock_friend_link(id)?;
            }
            _ => return Err(invalid("unknown authenticated control event")),
        }
        Ok(())
    }
    pub(super) fn refresh_routed_control_cache(
        &mut self,
        opened: &Opened,
        body: &[u8],
    ) -> Result<(), SdkError> {
        if body.starts_with(crate::client::task::own_history::PREFIX) {
            return Ok(());
        }
        if opened.routing.kind == Kind::Control {
            let value: Value = serde_json::from_slice(body)?;
            if value["type"] == "object.revoke_access"
                && let Some(id) = value.get("object_id").and_then(Value::as_str)
                && self.object_store.cached_object(id).is_some()
            {
                self.object_store.tombstone(id)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn a2i_key(source: &str, event: &str) -> Result<String, SdkError> {
    Ok(format!(
        "a2i/scoped/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.a2i.sender.v2",
            &ramflux_protocol::canonical_json_bytes(&(source, event))?
        )
    ))
}
