// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use ramflux_core::{
    ClientEventEnvelope as CoreClientEventEnvelope, DeviceId as CoreDeviceId,
    EventId as CoreEventId, UnixMillis,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::{
    BotEventBody, ConversationEventBody, FriendLinkEventBody, GroupEventBody, IdentityEventBody,
    MessageEventBody, ProtocolError,
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlg {
    Ed25519,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedFields {
    pub signing_key_id: String,
    pub signature_alg: SignatureAlg,
    pub signature: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ext {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub envelope_id: String,
    pub source_principal_id: String,
    pub source_device_id: String,
    pub target_delivery_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_set_id: Option<String>,
    pub delivery_class: DeliveryClass,
    pub priority: Priority,
    pub ttl: u32,
    pub created_at: i64,
    pub encrypted_payload: String,
    pub payload_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryClass {
    OpaqueEvent,
    SelfDeviceControl,
    NotificationWake,
    ObjectManifest,
    ObjectChunk,
    FederationControl,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub source_device_id: String,
    pub request_id: String,
    pub method: HttpMethod,
    pub path: String,
    pub device_proof_hash: String,
    pub body_hash: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
}

impl SignedRequest {
    #[must_use]
    pub fn replay_tuple_key(&self) -> String {
        format!("{}:{}:{}", self.source_device_id, self.nonce, self.request_id)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceProof {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub principal_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub branch_proof_hash: String,
    pub capability_scope: Vec<String>,
    pub nonce: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BranchProof {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub proof_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub lineage_head: String,
    pub audience: String,
    pub capability_scope: Vec<String>,
    pub issued_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HomeNodeMigrationProof {
    pub schema: String,
    pub domain: String,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub proof_id: String,
    pub identity_commitment: String,
    pub lineage_head: String,
    pub actor_device_id: String,
    pub actor_device_epoch: u64,
    pub old_home_node: String,
    pub new_home_node: String,
    pub new_home_node_key_hash: String,
    pub route_record_hash: String,
    pub effective_at: i64,
    pub expires_at: i64,
    pub issued_at: i64,
    pub nonce: String,
    pub branch_proof_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_home_node_binding_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_home_node_handoff_signature: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityDeletionProof {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub proof_id: String,
    pub identity_commitment: String,
    pub lifecycle_epoch: u64,
    pub identity_deleted_event_id: String,
    pub identity_lifecycle_tombstone_hash: String,
    pub deletion_scope: Vec<String>,
    pub deleted_metadata_hash: String,
    pub retained_summary_hash: String,
    pub retention_policy_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legal_hold_ids: Vec<String>,
    pub node_id: String,
    pub node_epoch: u64,
    pub finalized_at: i64,
    pub completed_at: i64,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub ack_id: String,
    pub envelope_id: String,
    pub receiver_device_id: String,
    pub received_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_after: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Nack {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub nack_id: String,
    pub envelope_id: String,
    pub receiver_device_id: String,
    pub reason: NackReason,
    pub received_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_home_node_hint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NackReason {
    InvalidSignature,
    Expired,
    UnknownDevice,
    RevokedCapability,
    MissingDependency,
    UnknownGroupEpoch,
    EpochRollback,
    PayloadTooLarge,
    RateLimited,
    UnsupportedSchema,
    HomeNodeMigrated,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub cursor_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub inbox_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_envelope_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acked_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_event_ids: Vec<String>,
    pub lamport_time: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventId {
    pub domain: String,
    pub actor_device_id: String,
    pub device_counter: u64,
    pub random_nonce: String,
    pub event_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientEvent<T> {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub event_id: String,
    pub event_type: String,
    pub actor_principal_id: String,
    pub actor_device_id: String,
    pub device_counter: u64,
    pub lamport_time: u64,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_prev: Vec<String>,
    pub body: T,
}

impl<T> ClientEvent<T> {
    /// # Errors
    /// Returns an error when event metadata cannot be represented as core typed ids.
    pub fn core_envelope(&self) -> Result<CoreClientEventEnvelope, ProtocolError> {
        Ok(CoreClientEventEnvelope::new(
            CoreEventId::new(self.event_id.clone())?,
            Some(CoreDeviceId::new(self.actor_device_id.clone())?),
            UnixMillis::new(
                u64::try_from(self.created_at)
                    .map_err(|_err| ramflux_core::CoreError::ClockBeforeUnixEpoch)?,
            ),
            None,
        ))
    }
}

pub type IdentityEvent = ClientEvent<IdentityEventBody>;
pub type FriendLinkEvent = ClientEvent<FriendLinkEventBody>;
pub type GroupEvent = ClientEvent<GroupEventBody>;
pub type ConversationEvent = ClientEvent<ConversationEventBody>;
pub type MessageEvent = ClientEvent<MessageEventBody>;
pub type BotEvent = ClientEvent<BotEventBody>;
