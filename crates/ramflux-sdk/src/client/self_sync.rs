// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root `SelfSync` state. Receive calls join the routed W1 transaction.
use crate::client::identity_authority::NativeOperation;
use crate::{RamfluxClient, SdkError};
use ramflux_crypto::RootQualifiedDeviceRef;
use ramflux_protocol::message::{
    self as g,
    self_sync::{self, Operation},
};
use serde::{Deserialize, Serialize};
use prost::Message as _;

pub const SELF_SYNC_MAX_PINS_PER_CONVERSATION: usize = 100;

/// Accepted state for one revision scope; includes the explicit clear operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub conversation_id: String,
    pub value: g::SelfSync,
    pub exact_body: Vec<u8>,
    pub tie_break: [u8; 32],
    pub read_marker: Option<g::MessageRef>,
    pending_read: Option<PendingRead>,
    // Named references participate in the generic erasure/backup registration.
    references: Vec<Reference>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Reference {
    message_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingRead { reference: g::MessageRef, revision: u64, tie_break: [u8; 32] }

type DisplayOrder = (u64, String, String, u64, u64, Vec<u8>);

fn refused(reason: &str) -> SdkError {
    SdkError::InboundRejected(format!("self sync: {reason}"))
}

fn key(root: &str, conversation: &str, value: &g::SelfSync) -> Result<String, SdkError> {
    let operation = self_sync::validate(value).map_err(|_| refused("invalid operation payload"))?;
    let target = value.pin.as_ref().map(|pin| (&pin.author_anchor, &pin.id));
    let scope =
        ramflux_protocol::canonical_json_bytes(&(root, conversation, operation.family(), target))?;
    Ok(format!("self-sync/state/{}", ramflux_protocol::encode_base64url(scope)))
}

fn body_hash(body: &[u8]) -> Result<[u8; 32], SdkError> {
    let mut transcript = Vec::new();
    for field in [b"ramflux.message.self_sync.tiebreak.v1".as_slice(), body] {
        transcript.extend_from_slice(&u32::try_from(field.len()).map_err(|_| refused("body too large"))?.to_be_bytes());
        transcript.extend_from_slice(field);
    }
    Ok(*blake3::hash(&transcript).as_bytes())
}

impl RamfluxClient {
    pub(crate) fn persist_self_sync_delivery(
        &self,
        conversation: &str,
        value: &g::SelfSync,
        envelope: &ramflux_protocol::Envelope,
    ) -> Result<(), SdkError> {
        self.account_db()?.persist_actor_state(
            &format!("self-sync/pending/{}", envelope.envelope_id),
            &serde_json::json!({
                "conversation_id": conversation,
                "envelope": envelope,
                "references": self.self_sync_references(conversation, value)?,
            }),
        )?;
        Ok(())
    }

    pub(crate) fn authorize_self_sync(
        &self,
        source: &RootQualifiedDeviceRef,
        conversation: &str,
    ) -> Result<(), SdkError> {
        let local = self.owned_device_identity()?;
        if source.root_commitment() != local.root_commitment() {
            return Err(refused("foreign root"));
        }
        self.require_native_operation(&local, NativeOperation::Sync)?;
        self.require_native_operation(source, NativeOperation::Sync)?;
        if conversation.is_empty() {
            return Err(refused("conversation is not authorized locally"));
        }
        Ok(())
    }

    /// Read one accepted state using an operation-shaped scope (including a pin target).
    /// # Errors
    /// Refuses malformed scopes and returns storage errors.
    pub fn self_sync_state(
        &self,
        conversation: &str,
        scope: &g::SelfSync,
    ) -> Result<Option<State>, SdkError> {
        let root = self.owned_device_identity()?;
        Ok(self.account_db()?.load_actor_state(&key(
            root.root_commitment(),
            conversation,
            scope,
        )?)?)
    }

    /// Allocate and apply a local change. The durable revision advances only on commit.
    /// # Errors
    /// Refuses invalid payloads, unauthorized conversations and counter overflow.
    pub fn change_self_sync(
        &self,
        conversation: &str,
        mut value: g::SelfSync,
    ) -> Result<g::SelfSync, SdkError> {
        let source = self.owned_device_identity()?;
        self.authorize_self_sync(&source, conversation)?;
        value.revision = 1;
        let state_key = key(source.root_commitment(), conversation, &value)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            let old = db.load_actor_state::<State>(&state_key)?;
            value.revision = old
                .as_ref()
                .map_or(0, |state| state.value.revision)
                .checked_add(1)
                .ok_or_else(|| refused("revision exhausted"))?;
            if value.revision == u64::MAX { return Err(refused("revision exhausted")); }
            if value.operation == 4 && self.self_sync_pin_overflow(conversation, &state_key)? { return Err(SdkError::PinLimitReached); }
            if !self.apply_self_sync_in(&source, conversation, &value)? {
                return Err(SdkError::ObjectErased);
            }
            Ok(value)
        })
    }

    /// Apply an authenticated sibling change in a transaction shared with receive/ACK.
    /// Equal and lower revisions are successful no-ops; neither can overwrite state.
    pub(crate) fn apply_self_sync_in(
        &self,
        source: &RootQualifiedDeviceRef,
        conversation: &str,
        value: &g::SelfSync,
    ) -> Result<bool, SdkError> {
        self.apply_self_sync_exact(source, conversation, value, &value.encode_to_vec())
    }

    pub(crate) fn apply_self_sync_exact(
        &self, source: &RootQualifiedDeviceRef, conversation: &str,
        value: &g::SelfSync, exact_body: &[u8],
    ) -> Result<bool, SdkError> {
        self.authorize_self_sync(source, conversation)?;
        let operation = self_sync::validate(value).map_err(|_| refused("invalid operation payload"))?;
        let state_key = key(source.root_commitment(), conversation, value)?;
        let db = self.account_db()?;
        let old = db.load_actor_state::<State>(&state_key)?;
        let references = self.self_sync_references(conversation, value)?;
        let tie_break = body_hash(exact_body)?;
        let wins = old.as_ref().is_none_or(|state| (value.revision, tie_break) > (state.value.revision, state.tie_break));
        if operation == Operation::PinSet && self.self_sync_pin_overflow(conversation, &state_key)? { return Ok(false); }
        let mut marker = old.as_ref().and_then(|state| state.read_marker.clone());
        let mut pending = old.as_ref().and_then(|state| state.pending_read.clone());
        if let Some(reference) = value.read_through.as_ref() {
            let id = ramflux_protocol::encode_base64url(&reference.id);
            if self.direct_message_by_id(&id)?.is_none()
                && pending.as_ref().is_none_or(|old| (value.revision, tie_break) > (old.revision, old.tie_break)) {
                pending = Some(PendingRead { reference: reference.clone(), revision: value.revision, tie_break });
            }
        }
        if operation == Operation::ReadThrough {
            self.advance_self_sync_read(conversation, value.read_through.as_ref(), &mut marker)?;
        }
        for reference in &references {
            if db.message_is_deleted(&reference.message_id)? && operation != Operation::ReadThrough { return Ok(false); }
        }
        if !wins {
            if let Some(mut state) = old {
                if value.revision < state.value.revision {
                    self.queue_self_sync_repair(source, &state_key, &state)?;
                }
                if state.read_marker != marker || state.pending_read.as_ref().map(|p| (&p.reference, p.revision, p.tie_break)) != pending.as_ref().map(|p| (&p.reference, p.revision, p.tie_break)) {
                    state.read_marker = marker;
                    state.pending_read = pending;
                    db.persist_actor_state(&state_key, &state)?;
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        db.persist_actor_state(&state_key, &State {
            conversation_id: conversation.to_owned(), value: value.clone(),
            exact_body: exact_body.to_vec(), tie_break, read_marker: marker, pending_read: pending, references,
        })?;
        Ok(true)
    }

    pub(crate) fn resolve_self_sync_read_references(&self, conversation: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for key in db.actor_state_keys("self-sync/state/")? {
            let Some(mut state) = db.load_actor_state::<State>(&key)? else { continue; };
            if state.conversation_id != conversation { continue; }
            if let Some(pending) = state.pending_read.clone() {
                self.advance_self_sync_read(conversation, Some(&pending.reference), &mut state.read_marker)?;
                let id = ramflux_protocol::encode_base64url(&pending.reference.id);
                if self.self_sync_read_order(&id)?.is_some() || db.message_is_deleted(&id)? { state.pending_read = None; }
                db.persist_actor_state(&key, &state)?;
            }
        }
        Ok(())
    }

    /// Queue the exact accepted registers for a newly enrolled or restored sibling.
    /// # Errors
    /// Requires same-root Sync authority and returns storage errors.
    pub fn bootstrap_self_sync(&self, sibling: &RootQualifiedDeviceRef) -> Result<(), SdkError> {
        if sibling.root_commitment() != self.own_account_anchor()? { return Err(refused("foreign bootstrap target")); }
        self.require_native_operation(sibling, NativeOperation::Sync)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            for scope in db.actor_state_keys("self-sync/state/")? {
                if let Some(state) = db.load_actor_state::<State>(&scope)? { self.queue_self_sync_repair(sibling, &scope, &state)?; }
            }
            Ok(())
        })
    }

    fn self_sync_pin_overflow(&self, conversation: &str, state_key: &str) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        if db.load_actor_state::<State>(state_key)?.is_some_and(|state| state.value.operation == 4) { return Ok(false); }
        let mut count = 0;
        for key in db.actor_state_keys("self-sync/state/")? {
            if db.load_actor_state::<State>(&key)?.is_some_and(|state| state.conversation_id == conversation && state.value.operation == 4) { count += 1; }
        }
        Ok(count >= SELF_SYNC_MAX_PINS_PER_CONVERSATION)
    }

    fn queue_self_sync_repair(&self, source: &RootQualifiedDeviceRef, scope: &str, state: &State) -> Result<(), SdkError> {
        let id = ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&(scope, source.storage_key(), state.value.revision))?);
        let db = self.account_db()?;
        let sent = format!("self-sync/repair-sent/{id}");
        if db.load_actor_state::<bool>(&sent)?.unwrap_or(false) { return Ok(()); }
        db.persist_actor_state(&format!("self-sync/repair/{id}"), &serde_json::json!({
            "conversation_id": state.conversation_id, "target": source.storage_key(), "exact_body": state.exact_body,
        }))?;
        db.persist_actor_state(&sent, &true)?;
        Ok(())
    }

    fn self_sync_references(
        &self,
        conversation: &str,
        value: &g::SelfSync,
    ) -> Result<Vec<Reference>, SdkError> {
        let mut references = Vec::new();
        let draft_refs = value
            .draft
            .iter()
            .flat_map(|draft| {
                [
                    draft.reply_to.as_ref(),
                    draft.forward.as_ref().and_then(|forward| forward.original.as_ref()),
                ]
            })
            .flatten();
        for reference in [value.read_through.as_ref(), value.pin.as_ref()]
            .into_iter()
            .flatten()
            .chain(draft_refs)
        {
            if reference.conversation_id != conversation {
                return Err(refused("reference belongs to another conversation"));
            }
            let id = ramflux_protocol::encode_base64url(&reference.id);
            if !self.account_db()?.message_is_deleted(&id)?
                && let Some(target) = self.direct_message_by_id(&id)?
                && target.conversation_id != conversation {
                return Err(refused("reference belongs to another conversation"));
            }
            references.push(Reference { message_id: id });
        }
        Ok(references)
    }

    fn advance_self_sync_read(
        &self, conversation: &str, incoming: Option<&g::MessageRef>, marker: &mut Option<g::MessageRef>,
    ) -> Result<(), SdkError> {
        let Some(reference) = incoming else { return Ok(()); };
        let id = ramflux_protocol::encode_base64url(&reference.id);
        if self.account_db()?.message_is_deleted(&id)? { return Ok(()); }
        let Some(order) = self.self_sync_read_order(&id)? else { return Ok(()); };
        if let Some(previous) = marker.as_ref() {
            let previous_id = ramflux_protocol::encode_base64url(&previous.id);
            if self.self_sync_read_order(&previous_id)?.is_some_and(|previous| previous >= order) { return Ok(()); }
        }
        self.account_db()?.mark_read(conversation, &self.owned_device_identity()?, &id)?;
        *marker = Some(reference.clone());
        Ok(())
    }

    fn self_sync_read_order(&self, id: &str) -> Result<Option<DisplayOrder>, SdkError> {
        let Some(identity) = self.account_db()?.load_actor_state::<g::EventIdentity>(&format!("routed/generated-identity/{id}"))? else { return Ok(None); };
        let author = identity.author.ok_or_else(|| refused("read target author missing"))?;
        Ok(Some((identity.hlc, author.account_anchor, author.device_id, author.device_epoch, identity.device_sequence, identity.id)))
    }

}

#[cfg(test)]
mod tests;
