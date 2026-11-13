// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SDK-owned mutation intents, durable event identity and exact retry payloads.
use crate::bindings::{AdapterError, GeneratedErrorCode as Code};
use crate::client::message_mutations::{ConversationKind, MutationActor, StoredTarget};
use crate::prelude::*;
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    conversation_id: String,
    message_id: String,
    text: Option<String>,
    token: Option<String>,
    #[serde(default)]
    remove: bool,
    scope: Option<String>,
}
impl Drop for Intent {
    fn drop(&mut self) {
        self.text.zeroize();
        self.token.zeroize();
    }
}
#[derive(Deserialize, Serialize)]
pub(crate) struct Prepared {
    fingerprint: String,
    pub(crate) identity: g::EventIdentity,
    pub(crate) exact: Vec<u8>,
    pub(crate) wire: Vec<u8>,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        self.exact.zeroize();
        self.wire.zeroize();
    }
}
fn refused(code: Code, reason: &str) -> SdkError {
    AdapterError::new(code, reason).into()
}

pub(super) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = local_bus_account_mut(state, request_account_id(request)?)?;
    Box::pin(execute(request, account))
        .await
        .map_err(|error| SdkError::from(AdapterError::from_sdk(&error)))
}

pub(in crate::bus) async fn execute(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let prepared = prepare(&account.client, request)?;
    let event = ramflux_protocol::encode_base64url(&prepared.identity.id);
    let (_, content) = RamfluxClient::decode_generated_inner(&prepared.exact)?;
    if let Some(g::content::Value::Delete(delete)) = content.value
        && delete.scope == g::DeleteScope::Local as i32
    {
        account.client.apply_generated_delete_authorized(
            &account.client.owned_device_identity()?,
            &prepared.identity,
            &prepared.identity.conversation_id,
            &delete,
        )?;
        return Ok(local_bus_ok(serde_json::json!({"event_id": event,
            "message_id": request.body["message_id"], "conversation_id": prepared.identity.conversation_id,
            "delivery_state":"local", "deliveries":[]})));
    }

    let mut response = Box::pin(super::conversation_delivery::send(account, &prepared))
        .await
        .map_err(|error| SdkError::from(AdapterError::from_sdk(&error)))?;
    response.response_body["event_id"] = serde_json::json!(event);
    response.response_body["target_message_id"] = request.body["message_id"].clone();
    Ok(response)
}

pub(crate) fn prepare(
    client: &RamfluxClient,
    request: &LocalBusFrame,
) -> Result<Prepared, SdkError> {
    // Generation zero remains inert: no counter, plaintext, ratchet or outbox allocation.
    if !crate::client::target_selection::schema_v1_selected() {
        return Err(refused(Code::PeerUpgradeRequired, "message schema v1 is not active"));
    }
    let intent: Intent = serde_json::from_value(request.body.clone())
        .map_err(|_| refused(Code::InvalidArgument, "invalid conversation mutation fields"))?;
    validate_intent(&request.method, &intent)?;
    let operation = request
        .operation_id
        .as_deref()
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| refused(Code::InvalidArgument, "operation_id is required"))?;
    let key = format!(
        "conversation-intent/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.conversation.operation.v1",
            operation.as_bytes()
        )
    );
    let fingerprint = ramflux_crypto::blake3_256_base64url(
        "ramflux.conversation.intent.v1",
        &ramflux_protocol::canonical_json_bytes(&(&request.method, &request.body))?,
    );
    let db = client.account_db()?;
    db.write_transaction(|| {
        if let Some(prepared) = db.load_actor_state::<Prepared>(&key)? {
            if prepared.fingerprint != fingerprint {
                return Err(refused(
                    Code::InvalidArgument,
                    "operation_id was reused for a different intent",
                ));
            }
            return Ok(prepared);
        }
        let Target { reference: target, stored, group } = target(client, &intent)?;
        let mut content =
            content(client, &request.method, &intent, &target, &stored, group.as_deref())?;
        RamfluxClient::prepare_generated_revision(&mut content)?;
        g::validation::validate_content(&content)
            .map_err(|_| refused(Code::InvalidArgument, "invalid generated mutation content"))?;
        let mut identity = client.allocate_generated_identity(
            &intent.conversation_id,
            u64::try_from(now_unix_timestamp()).unwrap_or(0).saturating_mul(1000),
            false,
        )?;
        if let Some(group) = group {
            let state = client.group_state(&group)?;
            identity.group_id = Some(group);
            identity.group_epoch = Some(state.group_epoch);
        }
        match content.value.as_mut() {
            Some(g::content::Value::Reaction(reaction)) => {
                reaction.operation_id.clone_from(&identity.id);
            }
            Some(g::content::Value::Delete(delete)) => {
                delete.tombstone_id = g::identity::delete_tombstone(&identity.id)
                    .map_err(|_| refused(Code::InvalidArgument, "invalid tombstone identity"))?
                    .to_vec();
            }
            _ => {}
        }
        g::validation::validate_content(&content)
            .map_err(|_| refused(Code::InvalidArgument, "invalid finalized mutation content"))?;
        let exact = RamfluxClient::encode_generated_inner(identity.clone(), &content)?;
        let wire = if identity.group_id.is_some() && request.method == "conversation.reply" {
            client.wrap_conversation_group_reply(&identity, &exact)?
        } else {
            exact.clone()
        };
        let prepared = Prepared { fingerprint: fingerprint.clone(), identity, exact, wire };
        // Private replacement text follows its target's erasure ownership.
        db.persist_message_actor_state(&intent.message_id, &key, &prepared)?;
        Ok(prepared)
    })
}

fn validate_intent(method: &str, intent: &Intent) -> Result<(), SdkError> {
    let text =
        intent.text.as_deref().is_some_and(|text| !text.is_empty() && text.len() <= 64 * 1024);
    let valid = match method {
        "conversation.edit" | "conversation.reply" => {
            text && intent.token.is_none() && intent.scope.is_none() && !intent.remove
        }
        "conversation.react" => {
            intent.text.is_none()
                && intent.scope.is_none()
                && intent
                    .token
                    .as_deref()
                    .is_some_and(|token| g::validation::validate_reaction_token(token).is_ok())
        }
        "conversation.delete" => {
            intent.text.is_none()
                && intent.token.is_none()
                && !intent.remove
                && matches!(intent.scope.as_deref(), Some("local" | "everyone"))
        }
        _ => false,
    };
    if !valid
        || intent.conversation_id.is_empty()
        || intent.conversation_id.len() > 256
        || intent.message_id.is_empty()
        || intent.message_id.len() > 256
    {
        return Err(refused(Code::InvalidArgument, "invalid conversation mutation intent"));
    }
    Ok(())
}

struct Target {
    reference: g::MessageRef,
    stored: Zeroizing<Vec<u8>>,
    group: Option<String>,
}

fn target(client: &RamfluxClient, intent: &Intent) -> Result<Target, SdkError> {
    let db = client.account_db()?;
    if db.message_is_deleted(&intent.message_id)? {
        return Err(refused(Code::TargetDeleted, "target was deleted"));
    }
    let row = client
        .direct_message_by_id(&intent.message_id)?
        .filter(|row| row.conversation_id == intent.conversation_id)
        .ok_or_else(|| refused(Code::TargetNotFound, "target is absent from conversation"))?;
    let original = db
        .load_actor_state::<g::EventIdentity>(&format!(
            "routed/generated-identity/{}",
            intent.message_id
        ))?
        .ok_or_else(|| {
            refused(Code::TargetNotFound, "authenticated target identity is unavailable")
        })?;
    g::identity::verify(&original)
        .map_err(|_| refused(Code::NotAuthorized, "invalid stored target identity"))?;
    let author = original
        .author
        .as_ref()
        .ok_or_else(|| refused(Code::NotAuthorized, "target author unavailable"))?;
    if original.conversation_id != intent.conversation_id
        || ramflux_protocol::encode_base64url(&original.id) != intent.message_id
        || (row.is_own && author.account_anchor != client.own_account_anchor()?)
    {
        return Err(refused(Code::NotAuthorized, "target identity mismatch"));
    }
    let stored = db
        .message_content(&intent.message_id)?
        .ok_or_else(|| refused(Code::TargetNotFound, "target content unavailable"))?;
    Ok(Target {
        reference: g::MessageRef {
            id: original.id,
            conversation_id: intent.conversation_id.clone(),
            author_anchor: author.account_anchor.clone(),
        },
        stored: Zeroizing::new(stored),
        group: original.group_id,
    })
}

fn content(
    client: &RamfluxClient,
    method: &str,
    intent: &Intent,
    target: &g::MessageRef,
    stored: &[u8],
    group: Option<&str>,
) -> Result<g::Content, SdkError> {
    let own = client.owned_device_identity()?;
    let (_, current) = RamfluxClient::decode_generated_inner(stored)?;
    let revision = match &current.value {
        Some(g::content::Value::Edit(edit)) => edit.revision,
        _ => 0,
    };
    let state = StoredTarget {
        author_root: target.author_anchor.clone(),
        revision,
        tombstoned: false,
        conversation: if group.is_some() {
            ConversationKind::Group
        } else {
            ConversationKind::Direct
        },
    };
    if let Some(group) = group {
        client.require_generated_group_epoch(
            group,
            &own,
            client.group_state(group)?.group_epoch,
            false,
        )?;
    }
    let text =
        || g::Message { text: intent.text.clone().unwrap_or_default(), ..Default::default() };
    let value = match method {
        "conversation.edit" => {
            RamfluxClient::authorize_generated_edit(own.root_commitment(), &state)
                .map_err(|_| refused(Code::NotAuthorized, "edit requires original author"))?;
            let revision = revision
                .checked_add(1)
                .ok_or_else(|| refused(Code::InvalidArgument, "edit revision exhausted"))?;
            let nested = client.account_db()?.load_actor_state::<Vec<u8>>(&format!(
                "routed/group-content/{}",
                intent.message_id
            ))?;
            let digest = if let Some(nested) = nested {
                crate::client::message_mutations::digest_exact_content(target, &nested)?
            } else {
                crate::client::message_mutations::previous_content_digest(target, stored)?
            };
            g::content::Value::Edit(g::Edit {
                target: Some(target.clone()),
                revision,
                previous_content_digest: digest.to_vec(),
                replacement: Some(text()),
            })
        }
        "conversation.reply" => {
            g::content::Value::Message(g::Message { reply_to: Some(target.clone()), ..text() })
        }
        "conversation.react" => {
            RamfluxClient::authorize_generated_reaction(&state)?;
            g::content::Value::Reaction(g::Reaction {
                target: Some(target.clone()),
                token: intent.token.clone().unwrap_or_default(),
                remove: intent.remove,
                operation_id: vec![1; 32],
            })
        }
        "conversation.delete" => {
            let scope = if intent.scope.as_deref() == Some("local") {
                g::DeleteScope::Local
            } else {
                g::DeleteScope::Everyone
            };
            let moderator = group.is_some_and(|group| {
                client
                    .require_generated_group_epoch(
                        group,
                        &own,
                        client.group_state(group).map_or(0, |state| state.group_epoch),
                        true,
                    )
                    .is_ok()
            });
            let actor =
                if moderator { MutationActor::GroupModerator } else { MutationActor::Recipient };
            RamfluxClient::authorize_generated_delete(own.root_commitment(), actor, &state, scope)
                .map_err(|_| refused(Code::NotAuthorized, "delete scope is not authorized"))?;
            g::content::Value::Delete(g::Delete {
                targets: vec![target.clone()],
                scope: scope as i32,
                tombstone_id: vec![1; 32],
                native_group_authorization: Vec::new(),
            })
        }
        _ => return Err(refused(Code::InvalidArgument, "unsupported conversation operation")),
    };
    Ok(g::Content { value: Some(value) })
}

#[cfg(test)]
mod tests;
