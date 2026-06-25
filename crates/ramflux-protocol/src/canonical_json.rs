// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

use crate::{
    A2iControlEvent, A2uiSurfaceEvent, Ack, BotEvent, BotInstallGrant, BotManifest, BranchProof,
    ConversationEvent, Cursor, DeviceProof, Envelope, EventId, FederationHandshake,
    FriendLinkEvent, GroupEvent, HomeNodeMigrationProof, IdentityDeletionProof, IdentityEvent,
    McpGrant, MessageEvent, Nack, NotificationWake, ObjectChunkRequest, ObjectManifest,
    SignedRequest,
};
use crate::{FixtureObject, ProtocolError, ProtocolObject, domain};

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    Ok(serde_json_canonicalizer::to_vec(value)?)
}

/// # Errors
/// Returns an error when canonical serialization fails.
pub fn canonical_json_string<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    Ok(serde_json_canonicalizer::to_string(value)?)
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn signed_value<T: Serialize>(value: &T) -> Result<Value, ProtocolError> {
    let value = serde_json::to_value(value)?;
    let Value::Object(mut object) = value else {
        return Err(ProtocolError::NotObject);
    };
    remove_signature_fields(&mut object);
    reject_unknown_critical_ext(&object)?;
    Ok(Value::Object(object))
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn signed_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    canonical_json_bytes(&signed_value(value)?)
}

#[must_use]
pub fn hash_hex(domain_tag: &str, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain_tag.as_bytes());
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

#[must_use]
pub fn hash_base64url(domain_tag: &str, bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(blake3_hash_bytes(domain_tag, bytes))
}

#[must_use]
pub fn blake3_hash_bytes(domain_tag: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain_tag.as_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[must_use]
pub fn event_id(actor_device_id: &str, device_counter: u64, random_nonce: &[u8]) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(actor_device_id.as_bytes());
    input.extend_from_slice(&device_counter.to_be_bytes());
    input.extend_from_slice(random_nonce);
    hash_base64url(domain::EVENT, &input)
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn validate_domain<T: ProtocolObject>(value: &T, actual: &str) -> Result<(), ProtocolError> {
    if actual == value.domain() {
        Ok(())
    } else {
        Err(ProtocolError::InvalidDomain { expected: value.domain(), actual: actual.to_owned() })
    }
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn validate_no_replay<T: ProtocolObject>(
    value: &T,
    seen: &mut BTreeSet<String>,
) -> Result<(), ProtocolError> {
    let replay_key = value.replay_key().ok_or(ProtocolError::MissingReplayKey)?;
    if seen.insert(replay_key.clone()) { Ok(()) } else { Err(ProtocolError::Replay(replay_key)) }
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn strip_signature_fields_from_json(value: &mut Value) -> Result<(), ProtocolError> {
    let Value::Object(object) = value else {
        return Err(ProtocolError::NotObject);
    };
    remove_signature_fields(object);
    reject_unknown_critical_ext(object)
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn parse_fixture_value(object: FixtureObject, value: Value) -> Result<(), serde_json::Error> {
    match object.dir {
        "envelope" => serde_json::from_value::<Envelope>(value).map(|_value| ()),
        "signed_request" => serde_json::from_value::<SignedRequest>(value).map(|_value| ()),
        "device_proof" => serde_json::from_value::<DeviceProof>(value).map(|_value| ()),
        "branch_proof" => serde_json::from_value::<BranchProof>(value).map(|_value| ()),
        "home_node_migration_proof" => {
            serde_json::from_value::<HomeNodeMigrationProof>(value).map(|_value| ())
        }
        "identity_deletion_proof" => {
            serde_json::from_value::<IdentityDeletionProof>(value).map(|_value| ())
        }
        "ack" => serde_json::from_value::<Ack>(value).map(|_value| ()),
        "nack" => serde_json::from_value::<Nack>(value).map(|_value| ()),
        "cursor" => serde_json::from_value::<Cursor>(value).map(|_value| ()),
        "event_id" => serde_json::from_value::<EventId>(value).map(|_value| ()),
        "identity_event" => serde_json::from_value::<IdentityEvent>(value).map(|_value| ()),
        "friend_event" => serde_json::from_value::<FriendLinkEvent>(value).map(|_value| ()),
        "group_event" => serde_json::from_value::<GroupEvent>(value).map(|_value| ()),
        "conversation_event" => serde_json::from_value::<ConversationEvent>(value).map(|_value| ()),
        "message_event" => serde_json::from_value::<MessageEvent>(value).map(|_value| ()),
        "object_manifest" => serde_json::from_value::<ObjectManifest>(value).map(|_value| ()),
        "object_chunk_request" => {
            serde_json::from_value::<ObjectChunkRequest>(value).map(|_value| ())
        }
        "a2i_control" => serde_json::from_value::<A2iControlEvent>(value).map(|_value| ()),
        "a2ui_surface" => serde_json::from_value::<A2uiSurfaceEvent>(value).map(|_value| ()),
        "mcp_grant" => serde_json::from_value::<McpGrant>(value).map(|_value| ()),
        "bot_manifest" => serde_json::from_value::<BotManifest>(value).map(|_value| ()),
        "bot_event" => serde_json::from_value::<BotEvent>(value).map(|_value| ()),
        "bot_install_grant" => serde_json::from_value::<BotInstallGrant>(value).map(|_value| ()),
        "notification_wake" => serde_json::from_value::<NotificationWake>(value).map(|_value| ()),
        "federation_handshake" => {
            serde_json::from_value::<FederationHandshake>(value).map(|_value| ())
        }
        _ => serde_json::from_value::<Value>(value).map(|_value| ()),
    }
}

fn remove_signature_fields(object: &mut Map<String, Value>) {
    object.remove("signing_key_id");
    object.remove("signature_alg");
    object.remove("signature");
}

fn reject_unknown_critical_ext(object: &Map<String, Value>) -> Result<(), ProtocolError> {
    if let Some(Value::Object(ext)) = object.get("ext") {
        for key in ext.keys() {
            if key.starts_with("critical.") {
                return Err(ProtocolError::UnknownCriticalExtension(key.clone()));
            }
        }
    }
    Ok(())
}
