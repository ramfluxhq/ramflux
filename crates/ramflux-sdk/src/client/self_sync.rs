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

/// Accepted state for one revision scope; includes the explicit clear operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub conversation_id: String,
    pub value: g::SelfSync,
    // Named references participate in the generic erasure/backup registration.
    references: Vec<Reference>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Reference {
    message_id: String,
}

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

    fn authorize_self_sync(
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
        if conversation.is_empty()
            || self.account_db()?.client_record("conversation", conversation)?.is_none()
        {
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
        self.authorize_self_sync(source, conversation)?;
        let operation =
            self_sync::validate(value).map_err(|_| refused("invalid operation payload"))?;
        let state_key = key(source.root_commitment(), conversation, value)?;
        let db = self.account_db()?;
        let old = db.load_actor_state::<State>(&state_key)?;
        if old.as_ref().is_some_and(|state| state.value.revision >= value.revision) {
            return Ok(false);
        }
        let references = self.self_sync_references(conversation, value)?;
        for reference in &references {
            if db.message_is_deleted(&reference.message_id)? {
                return Ok(false);
            }
        }
        let mut accepted = value.clone();
        if operation == Operation::ReadThrough {
            self.advance_self_sync_read(conversation, &mut accepted, old.as_ref())?;
        }
        let references = self.self_sync_references(conversation, &accepted)?;
        db.persist_actor_state(
            &state_key,
            &State { conversation_id: conversation.to_owned(), value: accepted, references },
        )?;
        Ok(true)
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
            let id = std::str::from_utf8(&reference.id)
                .map_err(|_| refused("reference has no local message binding"))?;
            if !self.account_db()?.message_is_deleted(id)? {
                let target = self
                    .direct_message_by_id(id)?
                    .ok_or_else(|| refused("reference has no local message binding"))?;
                if target.conversation_id != conversation {
                    return Err(refused("reference belongs to another conversation"));
                }
            }
            references.push(Reference { message_id: id.to_owned() });
        }
        Ok(references)
    }

    fn advance_self_sync_read(
        &self,
        conversation: &str,
        value: &mut g::SelfSync,
        old: Option<&State>,
    ) -> Result<(), SdkError> {
        let reference =
            value.read_through.as_ref().ok_or_else(|| refused("read target missing"))?;
        let id = std::str::from_utf8(&reference.id).map_err(|_| refused("invalid read target"))?;
        let target =
            self.direct_message_by_id(id)?.ok_or_else(|| refused("read target missing"))?;
        if let Some(previous) = old.and_then(|state| state.value.read_through.as_ref()) {
            let previous_id = std::str::from_utf8(&previous.id)
                .map_err(|_| refused("invalid stored read target"))?;
            if let Some(previous_message) = self.direct_message_by_id(previous_id)?
                && (target.created_at, id) < (previous_message.created_at, previous_id)
            {
                value.read_through = Some(previous.clone());
                return Ok(());
            }
        }
        self.account_db()?.mark_read(conversation, &self.owned_device_identity()?, id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
