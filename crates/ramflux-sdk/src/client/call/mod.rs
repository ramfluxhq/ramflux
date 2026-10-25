// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pair-control authentication and public call projection; media secrets stay in RAM.
pub(crate) mod state;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_protocol::{CallControl, CallEndpoint, CallRow};
use serde_json::json;
use state::{LiveCall, invalid};
pub(crate) const PREFIX: &[u8] = b"ramflux.call.control.v1\n";

pub(crate) fn signing_bytes(c: &CallControl) -> Result<Vec<u8>, SdkError> {
    Ok(ramflux_protocol::canonical_json_bytes(&(
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
    ))?)
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
    pub(crate) fn call_local_endpoint(&self) -> Result<CallEndpoint, SdkError> {
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        Ok(CallEndpoint {
            principal_id: device.principal_id.clone(),
            device_id: device.device_id.clone(),
            root_public_key: ramflux_protocol::encode_base64url(
                root.signing_key.verifying_key().to_bytes(),
            ),
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
        let manifest = self
            .account_db()?
            .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
                "identity/manifest/{}",
                c.sender.principal_id
            ))?
            .ok_or_else(|| invalid("sender root unavailable"))?;
        if manifest.root_public_key != c.sender.root_public_key
            || !manifest.devices.iter().any(|d| d.device_id == c.sender.device_id)
        {
            return Err(invalid("sender root or membership"));
        }
        let local = self.call_local_endpoint()?;
        let peer = if c.caller == local {
            &c.callee
        } else if c.callee == local {
            &c.caller
        } else {
            return Err(invalid("local endpoint binding"));
        };
        if peer != &c.sender {
            return Err(invalid("control source is not peer"));
        }
        let record = self.trusted_device(&c.sender.device_id)?;
        let key =
            record["signing_public_key"].as_str().ok_or_else(|| invalid("sender key missing"))?;
        ramflux_crypto::verify_canonical_signature(&signing_bytes(c)?, &c.signature, key)?;
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
    fn plan_call(&self, c: &CallControl, now: i64, committed: bool) -> Result<LiveCall, SdkError> {
        if let Some(old) = self.voice_calls.get(&c.call_id) {
            let mut next = old.clone();
            next.apply(c, now)?;
            Ok(next)
        } else {
            if self.voice_calls.values().filter(|c| c.row.state != "ended").count() >= 2
                || (!committed
                    && self
                        .account_db()?
                        .actor_state_exists(&format!("voice/public/{}", c.call_id))?)
            {
                return Err(invalid("call capacity or retired id"));
            }
            LiveCall::incoming(c, self.call_local_endpoint()?, now)
        }
    }
    pub(crate) fn project_call_control(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        let Some(c) = decode(body)? else {
            return Ok(false);
        };
        self.verify_call(&c, entry, conversation)?;
        let next = self.plan_call(&c, crate::time::now_unix_timestamp(), false)?;
        self.persist_call_row(&next.row)?;
        Ok(true)
    }
    pub(crate) fn refresh_call_control(&mut self, body: &[u8]) -> Result<bool, SdkError> {
        let Some(c) = decode(body)? else {
            return Ok(false);
        };
        let next = self.plan_call(&c, crate::time::now_unix_timestamp(), true)?;
        self.voice_calls.insert(c.call_id, next);
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
