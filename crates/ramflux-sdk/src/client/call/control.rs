// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair-control authentication and public call projection; media secrets stay in RAM.
use super::state::{LiveCall, invalid};
use crate::client::identity_authority::HeadUse;
use crate::client::identity_authority::NativeOperation;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use ramflux_protocol::{CallControl, CallEndpoint, CallRow};
use serde_json::json;
const MAX_CONTROL_RECEIPTS_PER_CALL: u64 = 128;

pub(crate) fn signing_bytes(c: &CallControl) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    Ok(zeroize::Zeroizing::new(ramflux_protocol::canonical_json_bytes(&(
        "ramflux.call.control.signature.v1",
        &c.schema,
        &c.call_id,
        &c.conversation_id,
        &c.caller,
        &c.callee,
        &c.sender,
        c.seq,
        c.created_at,
        &c.body,
        &c.call_ref,
        &c.call_start,
    ))?))
}
/// Owner terminal carried beside a callee submit. The caller cancel stays a signed intent.
pub(crate) fn resolution_terminal(control: &CallControl) -> Option<String> {
    match &control.body {
        ramflux_protocol::CallAction::Hangup
        | ramflux_protocol::CallAction::Timeout
        | ramflux_protocol::CallAction::Failed => Some("end".to_owned()),
        ramflux_protocol::CallAction::Answer { .. } if control.sender != control.caller => {
            Some("answer".to_owned())
        }
        ramflux_protocol::CallAction::Reject | ramflux_protocol::CallAction::Busy
            if control.sender != control.caller =>
        {
            Some("reject".to_owned())
        }
        _ => None,
    }
}

pub(crate) fn bytes(c: &CallControl) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    let bytes = zeroize::Zeroizing::new(
        crate::client::generated_call::native::from_native(c)?.encode_to_vec(),
    );
    if bytes.len() > 16384 {
        return Err(invalid("control byte budget"));
    }
    Ok(bytes)
}
#[cfg(test)]
fn decode(body: &[u8]) -> Result<Option<CallControl>, SdkError> {
    if body.len() > 16384 {
        return Err(invalid("control byte budget"));
    }
    if g::validation::scan_message("Call", body, g::registry::COMPILED_LAYER).is_err() {
        return Ok(None);
    }
    let call = g::Call::decode(body).map_err(|_| invalid("invalid typed Call"))?;
    crate::client::generated_call::native::to_native(call).map(Some)
}
pub(crate) fn is_call_body(body: &[u8]) -> bool {
    RamfluxClient::decode_generated_inner(body)
        .is_ok_and(|(_, content)| matches!(content.value, Some(g::content::Value::Call(_))))
}
impl RamfluxClient {
    pub(crate) fn call_device_identity(
        &self,
        endpoint: &CallEndpoint,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, SdkError> {
        self.device_identity_for_root(
            &crate::identity_root_public_key_commitment(&endpoint.root_public_key)?,
            &endpoint.device_id,
        )
    }
    pub(crate) fn call_local_endpoint(&self) -> Result<CallEndpoint, SdkError> {
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Call)?;
        Ok(CallEndpoint {
            principal_id: device.principal_id.clone(),
            device_id: device.device_id.clone(),
            root_public_key: self.own_master_public_key()?,
        })
    }
    pub(crate) fn persist_call_row(&self, row: &CallRow) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.persist_actor_state(&format!("voice/public/{}", row.call_id), row)?;
        db.append_journal(
            &format!("call:{}:{}", row.call_id, row.seq),
            "call.changed",
            &serde_json::to_value(row)?,
            crate::time::now_unix_timestamp(),
            None,
        )?;
        let duration = match (row.answered_at, row.ended_at) {
            (Some(start), Some(end)) => Some(end.saturating_sub(start)),
            _ => None,
        };
        db.persist_client_record("call",&row.call_id,&json!({"kind":"call","call":row,"duration_seconds":duration,"missed":row.end_reason.as_deref()==Some("missed")}))?;
        if row.state == "ended" {
            self.remove_call_control_receipts(&row.call_id)?;
        }
        Ok(())
    }
    pub(crate) fn persist_live_call(&self, call: &LiveCall) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.join_write(|| {
            super::history::remember(self, call)?;
            self.persist_call_row(&call.row)?;
            if call.row.state == "ended" {
                super::history::publish(self, &call.row)?;
            }
            Ok(())
        })
    }
    fn remove_call_control_receipts(&self, id: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let prefix = format!("voice/control/{id}/");
        loop {
            let keys = db.actor_state_key_page(&prefix, 128)?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                db.remove_actor_state(&key)?;
            }
        }
        Ok(())
    }
    fn verify_call(
        &self,
        c: &CallControl,
        entry: &GatewayInboxEntry,
        conversation: &str,
    ) -> Result<(), SdkError> {
        if c.conversation_id != conversation
            || c.sender.principal_id != entry.envelope.source_principal_id
            || c.sender.device_id != entry.envelope.source_device_id
        {
            return Err(invalid("envelope binding"));
        }
        let identity = self.call_device_identity(&c.sender)?;
        self.require_native_operation(&identity, NativeOperation::Call)?;
        let sender = self.trusted_device(HeadUse::NewAuthorization, &identity)?;
        if sender["principal_id"] != c.sender.principal_id {
            return Err(invalid("sender principal differs from root authority"));
        }
        let local = self.call_local_endpoint()?;
        let peer = if c.caller == local {
            &c.callee
        } else if c.callee == local {
            &c.caller
        } else {
            return Err(invalid("local endpoint binding"));
        };
        if local.principal_id == c.sender.principal_id {
            return Err(invalid("self calls are unsupported"));
        }
        let db = self.account_db()?;
        let thread = db.client_record("conversation", conversation)?;
        if thread.is_none()
            && self
                .voice_calls
                .get(&c.call_id)
                .is_none_or(|call| call.row.conversation_id != conversation)
        {
            let envelope = crate::client::routed::decode(&entry.envelope)?;
            if db.actor_state_exists(&format!(
                "dm-pair/session/{}",
                envelope.ciphertext.session_id
            ))? {
                return Err(invalid("established pair requires its existing direct conversation"));
            }
        }
        if let Some(thread) = thread {
            let expected = std::collections::BTreeSet::from([
                local.principal_id.as_str(),
                c.sender.principal_id.as_str(),
            ]);
            let participants =
                thread["participants"].as_array().filter(|ids| ids.len() == 2).map(|ids| {
                    ids.iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<std::collections::BTreeSet<_>>()
                });
            if thread["kind"] != "direct"
                || !thread["group_id"].is_null()
                || thread["removed"] == true
                || thread["deleted"] == true
                || participants != Some(expected)
            {
                return Err(invalid("direct conversation participant binding"));
            }
        }
        if peer != &c.sender {
            return Err(invalid("control source is not peer"));
        }
        let record =
            self.trusted_device(HeadUse::NewAuthorization, &self.call_device_identity(&c.sender)?)?;
        let key =
            record["signing_public_key"].as_str().ok_or_else(|| invalid("sender key missing"))?;
        ramflux_crypto::verify_canonical_signature(&signing_bytes(c)?, &c.signature, key)?;
        self.verify_invitation_start(c, entry, &record, key)?;
        if !matches!(c.body, ramflux_protocol::CallAction::Invite { .. })
            && let Some(old) = self.voice_calls.get(&c.call_id)
        {
            let stored = if old.peer_reference(&c.sender).is_none() {
                super::intent::start_for_client(self, old, &c.sender.device_id)?
            } else {
                None
            };
            let reference = old
                .peer_reference(&c.sender)
                .or_else(|| stored.as_ref().map(|start| start.body.call_ref.as_str()));
            if reference.is_none() || reference != c.call_ref.as_deref() {
                return Err(invalid("control Start reference differs from its peer"));
            }
        }
        if let Some(old) = self.voice_calls.get(&c.call_id)
            && !old.peer_key_matches(&c.sender, key)
        {
            return Err(invalid("call peer device key changed"));
        }
        let root = crate::identity_root_public_key_commitment(&c.sender.root_public_key)?;
        let own = crate::identity_root_public_key_commitment(&local.root_public_key)?;
        self.require_accepted_friend_link_for_dm_send(
            &local.principal_id,
            &own,
            Some(&c.sender.principal_id),
            &root,
        )?;
        Ok(())
    }
    fn verify_invitation_start(
        &self,
        c: &CallControl,
        entry: &GatewayInboxEntry,
        record: &serde_json::Value,
        key: &str,
    ) -> Result<(), SdkError> {
        if matches!(c.body, ramflux_protocol::CallAction::Invite { .. }) {
            match (&c.call_ref, &c.call_start) {
                (Some(call_ref), Some(start)) => {
                    start.body.validate_shape()?;
                    start.body.validate_times(crate::time::now_unix_timestamp().unsigned_abs())?;
                    let origin = self.call_device_identity(&c.caller)?;
                    let recipient = self.call_device_identity(&c.callee)?;
                    let local_record = self.trusted_device(
                        HeadUse::NewAuthorization,
                        &self.owned_device_identity()?,
                    )?;
                    if start.body.action != ramflux_protocol::CallIntentAction::Start
                        || start.body.signing_key_id != key
                        || start.body.sender_device != origin.storage_key()
                        || Some(start.body.sender_epoch)
                            != record.get("device_epoch").and_then(serde_json::Value::as_u64)
                        || start.body.target_device != recipient.storage_key()
                        || Some(start.body.target_epoch)
                            != local_record.get("device_epoch").and_then(serde_json::Value::as_u64)
                        || start.body.target_delivery_id != entry.envelope.target_delivery_id
                        || start.body.source_event_id != entry.envelope.envelope_id
                        || start.body.call_ref != *call_ref
                        || i64::try_from(start.body.created_at).ok() != Some(c.created_at)
                        || start.body.expires_at
                            > u64::try_from(entry.envelope.created_at)
                                .unwrap_or(0)
                                .saturating_add(u64::from(entry.envelope.ttl))
                    {
                        return Err(invalid("original Start binding"));
                    }
                    ramflux_crypto::verify_canonical_signature(
                        &ramflux_protocol::call_intent_signing_bytes(&start.body)?,
                        &start.signature,
                        key,
                    )?;
                }
                _ => return Err(invalid("invitation requires its signed Start")),
            }
        } else if c.call_start.is_some() {
            return Err(invalid("non-invitation Start evidence"));
        }
        Ok(())
    }
    fn plan_call(&self, c: &CallControl, now: i64) -> Result<LiveCall, SdkError> {
        if let Some(old) = self.voice_calls.get(&c.call_id) {
            let mut next = old.clone();
            next.apply(c, now)?;
            Ok(next)
        } else {
            if self.voice_calls.len() >= 8
                || self.account_db()?.actor_state_exists(&format!("voice/public/{}", c.call_id))?
            {
                return Err(invalid("call capacity or retired id"));
            }
            let mut incoming = LiveCall::incoming(c, self.call_local_endpoint()?, now)?;
            let key = self.trusted_device(
                HeadUse::NewAuthorization,
                &self.call_device_identity(&c.sender)?,
            )?["signing_public_key"]
                .as_str()
                .ok_or_else(|| invalid("peer signing key missing"))?
                .to_owned();
            incoming.pin_peer(c.sender.clone(), key)?;
            if self.voice_calls.values().any(|call| call.row.state != "ended") {
                incoming.busy(now)?;
            }
            Ok(incoming)
        }
    }
    #[cfg(test)]
    pub(crate) fn project_call_control(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        group: Option<&str>,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        let Some(c) = decode(body)? else {
            return Ok(false);
        };
        self.project_native_call_control(entry, conversation, group, &c, body)
    }

    /// A call that already ended still accepts the caller's hangup, which is the shared end.
    fn revise_ended_call(&self, control: &CallControl, body: &[u8]) -> Result<bool, SdkError> {
        let now = crate::time::now_unix_timestamp();
        let live = self.voice_calls.get(&control.call_id).cloned();
        if let Some(call) = live {
            return self.revise_live_end(&call, control, body, now);
        }
        self.revise_stored_end(control, now)?;
        Ok(true)
    }

    fn revise_live_end(
        &self,
        call: &LiveCall,
        control: &CallControl,
        body: &[u8],
        now: i64,
    ) -> Result<bool, SdkError> {
        if !call.accepts_authoritative_end(control) {
            return Ok(true);
        }
        let mut next = call.clone();
        let before = next.row.clone();
        if next.apply(control, now).is_err() || next.row == before {
            return Ok(true);
        }
        self.account_db()?.join_write(|| self.persist_live_call(&next))?;
        self.voice_transition.replace(Some((transition_key(body), Box::new(next))));
        Ok(true)
    }

    fn revise_stored_end(&self, control: &CallControl, now: i64) -> Result<(), SdkError> {
        if control.created_at > now.saturating_add(60) {
            return Ok(());
        }
        let local = self.call_local_endpoint()?;
        let key = format!("voice/public/{}", control.call_id);
        let Some(mut row) = self.account_db()?.load_actor_state::<CallRow>(&key)? else {
            return Ok(());
        };
        if !stored_accepts_end(&row, control, &local) {
            return Ok(());
        }
        if !super::state::revise_person_row(&mut row, control) {
            return Ok(());
        }
        self.account_db()?.write_transaction(|| {
            self.persist_call_row(&row)?;
            super::history::publish(self, &row)?;
            Ok(())
        })
    }

    pub(crate) fn project_native_call_control(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        group: Option<&str>,
        c: &CallControl,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        self.voice_transition.borrow_mut().take();
        let id = ramflux_protocol::decode_base64url(&c.call_id).map_err(|_| invalid("call id"))?;
        if c.schema != "ramflux.call.control.v1" || id.len() != 16 {
            return Err(invalid("control schema or id"));
        }
        if group.is_some() {
            return Err(invalid("group calls are unsupported"));
        }
        self.verify_call(c, entry, conversation)?;
        if self
            .account_db()?
            .load_actor_state::<CallRow>(&format!("voice/public/{}", c.call_id))?
            .is_some_and(|row| row.state == "ended")
        {
            return self.revise_ended_call(c, body);
        }
        let receipt = format!(
            "voice/control/{}/{}",
            c.call_id,
            ramflux_protocol::hash_base64url(
                "ramflux.call.sequence.v1",
                &ramflux_protocol::canonical_json_bytes(&(&c.sender, c.seq))?
            )
        );
        let hash =
            ramflux_protocol::hash_base64url("ramflux.call.signed-control.v1", &signing_bytes(c)?);
        if let Some(old) = self.account_db()?.load_actor_state::<String>(&receipt)? {
            if old != hash {
                return Err(invalid("signed sequence equivocation"));
            }
            return Ok(true);
        }
        let receipt_prefix = format!("voice/control/{}/", c.call_id);
        if self.account_db()?.actor_state_usage(&receipt_prefix)?.0 >= MAX_CONTROL_RECEIPTS_PER_CALL
        {
            return Err(SdkError::CallControlReceiptCapacity {
                limit: MAX_CONTROL_RECEIPTS_PER_CALL,
            });
        }
        let next = self.plan_call(c, crate::time::now_unix_timestamp())?;
        let db = self.account_db()?;
        if db.client_record("conversation", conversation)?.is_none() {
            db.persist_client_record("conversation", conversation, &json!({"kind":"direct","group_id":null,"participants":[c.caller.principal_id,c.callee.principal_id],"participant_roots":[crate::identity_root_public_key_commitment(&c.caller.root_public_key)?,crate::identity_root_public_key_commitment(&c.callee.root_public_key)?]}))?;
        }
        db.join_write(|| {
            self.persist_live_call(&next)?;
            if next.row.state != "ended" {
                db.persist_actor_state(&receipt, &hash)?;
            }
            Ok::<(), SdkError>(())
        })?;
        self.voice_transition.replace(Some((transition_key(body), Box::new(next))));
        Ok(true)
    }
    pub(crate) fn retire_call_without_keys(&self, id: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        if let Some(mut row) = db.load_actor_state::<CallRow>(&format!("voice/public/{id}"))?
            && row.state != "ended"
        {
            row.state = "ended".into();
            row.end_reason = Some("failed".into());
            row.failure_reason = Some(ramflux_protocol::VoiceCallFailureReason::DaemonRestarted);
            row.ended_at = Some(crate::time::now_unix_timestamp());
            row.seq = row.seq.checked_add(1).ok_or_else(|| invalid("sequence exhausted"))?;
            db.write_transaction(|| {
                self.persist_call_row(&row)?;
                super::history::publish(self, &row)?;
                Ok::<(), SdkError>(())
            })?;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn refresh_call_control(&mut self, body: &[u8]) -> Result<bool, SdkError> {
        let Some(c) = decode(body)? else {
            return Ok(false);
        };
        self.refresh_native_call_control(&c, body)
    }

    pub(crate) fn refresh_native_call_control(
        &mut self,
        c: &CallControl,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        if let Some((key, next)) = self.voice_transition.take()
            && key == transition_key(body)
        {
            self.voice_calls.insert(c.call_id.clone(), *next);
            return Ok(true);
        }
        // An already committed delivery can be retried after an ACK failure. Its cache refresh
        // must neither apply the signed sequence twice nor recreate lost media keys after restart.
        if self.voice_calls.get(&c.call_id).is_some_and(|old| old.has_seen(&c.sender, c.seq)) {
            return Ok(true);
        }
        self.retire_call_without_keys(&c.call_id)?;
        self.voice_calls.remove(&c.call_id);
        Ok(true)
    }
}

fn stored_accepts_end(row: &CallRow, control: &CallControl, local: &CallEndpoint) -> bool {
    row.state == "ended"
        && row.direction == "incoming"
        && control.callee == *local
        && control.sender.principal_id == row.peer_id
        && matches!(
            control.body,
            ramflux_protocol::CallAction::Hangup | ramflux_protocol::CallAction::Timeout
        )
}

pub(crate) fn transition_key(body: &[u8]) -> String {
    ramflux_protocol::hash_base64url("ramflux.call.transition.v1", body)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
