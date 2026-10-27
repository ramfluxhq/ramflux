// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair-control authentication and public call projection; media secrets stay in RAM.
mod lease;
pub(crate) mod state;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_protocol::{CallControl, CallEndpoint, CallRow};
use serde_json::json;
use state::{LiveCall, invalid};
pub(crate) const PREFIX: &[u8] = b"ramflux.call.control.v1\n";
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
    ))?))
}
pub(crate) fn bytes(c: &CallControl) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    let mut bytes = zeroize::Zeroizing::new(PREFIX.to_vec());
    bytes.extend(serde_json::to_vec(c)?);
    if bytes.len() > 16384 {
        return Err(invalid("control byte budget"));
    }
    Ok(bytes)
}
fn decode(body: &[u8]) -> Result<Option<CallControl>, SdkError> {
    let Some(body) = body.strip_prefix(PREFIX) else {
        return Ok(None);
    };
    if body.len() > 16384 {
        return Err(invalid("control byte budget"));
    }
    let control: CallControl = ramflux_protocol::parse_i_json(body)?;
    let id =
        ramflux_protocol::decode_base64url(&control.call_id).map_err(|_| invalid("call id"))?;
    if control.schema != "ramflux.call.control.v1" || id.len() != 16 {
        return Err(invalid("control schema or id"));
    }
    Ok(Some(control))
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
        let sender = self.trusted_device(&identity)?;
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
        let record = self.trusted_device(&self.call_device_identity(&c.sender)?)?;
        let key =
            record["signing_public_key"].as_str().ok_or_else(|| invalid("sender key missing"))?;
        ramflux_crypto::verify_canonical_signature(&signing_bytes(c)?, &c.signature, key)?;
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
            let key =
                self.trusted_device(&self.call_device_identity(&c.sender)?)?["signing_public_key"]
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
        self.voice_transition.borrow_mut().take();
        if group.is_some() {
            return Err(invalid("group calls are unsupported"));
        }
        self.verify_call(&c, entry, conversation)?;
        if self
            .account_db()?
            .load_actor_state::<CallRow>(&format!("voice/public/{}", c.call_id))?
            .is_some_and(|row| row.state == "ended")
        {
            return Ok(true);
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
            ramflux_protocol::hash_base64url("ramflux.call.signed-control.v1", &signing_bytes(&c)?);
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
        let next = self.plan_call(&c, crate::time::now_unix_timestamp())?;
        let db = self.account_db()?;
        if db.client_record("conversation", conversation)?.is_none() {
            db.persist_client_record("conversation", conversation, &json!({"kind":"direct","group_id":null,"participants":[c.caller.principal_id,c.callee.principal_id]}))?;
        }
        self.persist_call_row(&next.row)?;
        if next.row.state != "ended" {
            db.persist_actor_state(&receipt, &hash)?;
        }
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
            row.ended_at = Some(crate::time::now_unix_timestamp());
            row.seq = row.seq.checked_add(1).ok_or_else(|| invalid("sequence exhausted"))?;
            db.write_transaction(|| self.persist_call_row(&row))?;
        }
        Ok(())
    }
    pub(crate) fn refresh_call_control(&mut self, body: &[u8]) -> Result<bool, SdkError> {
        let Some(c) = decode(body)? else {
            return Ok(false);
        };
        if let Some((key, next)) = self.voice_transition.take()
            && key == transition_key(body)
        {
            self.voice_calls.insert(c.call_id, *next);
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

pub(crate) fn transition_key(body: &[u8]) -> String {
    ramflux_protocol::hash_base64url("ramflux.call.transition.v1", body)
}

#[cfg(test)]
mod tests;
