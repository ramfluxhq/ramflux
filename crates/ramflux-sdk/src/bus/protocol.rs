// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub struct LocalBusConfig {
    pub socket_path: PathBuf,
    pub data_root: PathBuf,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalBusFrameKind {
    Request,
    Response,
    Event,
    Error,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct LocalBusFrame {
    pub bus_protocol: String,
    pub frame_id: String,
    pub kind: LocalBusFrameKind,
    pub request_id: String,
    pub account_id: Option<String>,
    pub sdk_api: String,
    pub method: String,
    pub body: serde_json::Value,
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<LocalBusErrorBody>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct LocalBusErrorBody {
    pub code: String,
    pub message: String,
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusAccountCreateRequest {
    pub local_account_id: String,
    pub principal_id: String,
    pub principal_commitment: String,
    pub device_id: String,
    pub target_delivery_id: String,
    pub account_secret: String,
    pub root_seed: [u8; 32],
    pub device_seed: [u8; 32],
    pub client_mode: LocalBusClientMode,
    pub gateway: GatewayQuicEndpointConfig,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalBusClientMode {
    AttendedCli,
    HeadlessAi,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusAccountCreateResponse {
    pub local_account_id: String,
    pub principal_id: String,
    pub principal_commitment: String,
    pub device_id: String,
    pub target_delivery_id: String,
    pub client_mode: LocalBusClientMode,
    pub session_id: String,
    pub active_transport_kind: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusAccountUnlockRequest {
    pub passphrase: String,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct LocalBusDeviceRecord {
    pub device_id: String,
    pub device_epoch: u64,
    pub target_delivery_id: String,
    pub capability_scope: Vec<String>,
    pub is_local: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusDeviceListResponse {
    pub principal_id: String,
    pub local_device_id: String,
    pub devices: Vec<LocalBusDeviceRecord>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusDeviceActivateRequest {
    pub device_id: String,
    pub target_delivery_id: String,
    pub device_seed: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_epoch: Option<u64>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusDeviceRevokeRequest {
    pub device_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusDeviceSyncExportRequest {
    pub target_device_id: String,
    pub relay_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_service_key_base64: Option<String>,
    #[serde(default)]
    pub chunk_size: Option<usize>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusDeviceSyncImportRequest {
    pub envelope: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_service_key_base64: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusDeviceActivateResponse {
    pub local_account_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub target_delivery_id: String,
    pub branch_authorized_event_id: String,
    pub session_id: String,
    pub active_transport_kind: String,
    pub devices: Vec<LocalBusDeviceRecord>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusAccountBackupExportRequest {
    pub output_path: String,
    pub passphrase: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusAccountBackupImportRequest {
    pub input_path: String,
    pub passphrase: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusAccountPassphraseRotateRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_passphrase: Option<String>,
    pub new_passphrase: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct LocalBusPersistedAccount {
    pub(crate) schema: String,
    pub(crate) local_account_id: String,
    pub(crate) principal_id: String,
    pub(crate) principal_commitment: String,
    pub(crate) device_id: String,
    pub(crate) target_delivery_id: String,
    // This manifest is local at-rest private client state. Headless daemon restart
    // needs these recovery materials before any keychain/passphrase provider exists,
    // so protect it like an SSH private key: data-root/accounts dir 0700, file 0600.
    pub(crate) account_secret: String,
    pub(crate) root_seed: [u8; 32],
    pub(crate) device_seed: [u8; 32],
    pub(crate) client_mode: LocalBusClientMode,
    pub(crate) gateway: GatewayQuicEndpointConfig,
    #[serde(default)]
    pub(crate) devices: Vec<LocalBusDeviceRecord>,
}

impl LocalBusPersistedAccount {
    pub(crate) fn from_create_request(body: &LocalBusAccountCreateRequest) -> Self {
        let devices = vec![LocalBusDeviceRecord {
            device_id: body.device_id.clone(),
            device_epoch: 1,
            target_delivery_id: body.target_delivery_id.clone(),
            capability_scope: default_device_capability_scope(),
            is_local: true,
        }];
        Self {
            schema: "ramflux.local_bus.account_manifest.v1".to_owned(),
            local_account_id: body.local_account_id.clone(),
            principal_id: body.principal_id.clone(),
            principal_commitment: body.principal_commitment.clone(),
            device_id: body.device_id.clone(),
            target_delivery_id: body.target_delivery_id.clone(),
            account_secret: body.account_secret.clone(),
            root_seed: body.root_seed,
            device_seed: body.device_seed,
            client_mode: body.client_mode.clone(),
            gateway: body.gateway.clone(),
            devices,
        }
    }
}

pub(crate) fn default_device_capability_scope() -> Vec<String> {
    vec!["device.delivery.bind".to_owned(), "own_device.sync".to_owned()]
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMessageSubmitRequest {
    pub conversation_id: String,
    pub message_id: String,
    pub envelope_id: String,
    pub source_principal_id: String,
    pub sender_id: String,
    pub recipient_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_principal_commitment: Option<String>,
    pub target_delivery_id: String,
    pub encrypted_body_base64: String,
    pub plaintext_body_base64: Option<String>,
    pub created_at: i64,
    pub ttl: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<LocalBusMessageAttachmentInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<LocalBusFederationRoute>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMessageAttachmentInput {
    pub object_id: String,
    pub plaintext_base64: String,
    pub chunk_size: usize,
    pub relay_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_home_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_audience_node_id: Option<String>,
    #[serde(default)]
    pub relay_service_key_base64: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusFederationRoute {
    pub federation_url: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub required_capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_prekey_url: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMessageReceiveRequest {
    pub limit: usize,
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub auto_fetch_attachments: bool,
    #[serde(default)]
    pub relay_service_key_base64: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMessageFrankingEvidenceRequest {
    pub conversation_id: String,
    pub message_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMessageAckRequest {
    pub envelope_id: String,
    pub receiver_device_id: String,
    pub received_at: i64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMessageDeleteRequest {
    pub conversation_id: String,
    pub message_id: String,
    #[serde(default = "default_message_delete_scope")]
    pub delete_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_id: Option<String>,
}

fn default_message_delete_scope() -> String {
    "own_devices".to_owned()
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMessageReceiptDeliveredRequest {
    pub conversation_id: String,
    pub message_id: String,
    pub receiver_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_delivery_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMessageReceiptReadRequest {
    pub conversation_id: String,
    pub message_id: String,
    pub reader_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_delivery_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<i64>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusContactAddRequest {
    pub link_id: String,
    pub requester_id: String,
    pub target_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusContactRemoveRequest {
    pub link_id: String,
    pub scope: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusContactLinkRequest {
    pub link_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusContactSafetyRequest {
    pub contact_identity_commitment: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusContactFederatedRequest {
    pub link_id: String,
    pub requester_id: String,
    pub target_id: String,
    pub conversation_id: String,
    pub message_id: String,
    pub envelope_id: String,
    pub source_principal_id: String,
    pub sender_id: String,
    pub recipient_device_id: String,
    pub target_delivery_id: String,
    pub federation: LocalBusFederationRoute,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupCreateRequest {
    pub group_id: String,
    pub creator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_signing_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_target_delivery_id: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupRequest {
    pub group_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupMemberAddRequest {
    pub group_id: String,
    pub member_id: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_signing_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_principal_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_delivery_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<LocalBusFederationRoute>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupMemberRemoveRequest {
    pub group_id: String,
    pub actor_id: String,
    pub member_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupRoleSetRequest {
    pub group_id: String,
    pub actor_id: String,
    pub member_id: String,
    pub role: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupMemberKickRequest {
    pub group_id: String,
    pub actor_id: String,
    pub member_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupMemberBanRequest {
    pub group_id: String,
    pub actor_id: String,
    pub member_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupInviteCreateRequest {
    pub group_id: String,
    pub actor_id: String,
    pub invitee_id: String,
    pub invitee_signing_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitee_principal_commitment: Option<String>,
    pub target_delivery_id: String,
    #[serde(default = "default_group_invite_role")]
    pub role: String,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<LocalBusFederationRoute>,
}

fn default_group_invite_role() -> String {
    "member".to_owned()
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupInviteAcceptRequest {
    pub group_id: String,
    pub actor_id: String,
    pub invite_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_delivery_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_principal_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<LocalBusFederationRoute>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupMessageDeleteRequest {
    pub group_id: String,
    pub actor_id: String,
    pub message_id: String,
    #[serde(default = "default_group_message_delete_scope")]
    pub delete_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn default_group_message_delete_scope() -> String {
    "group_tombstone".to_owned()
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupSendRequest {
    pub group_id: String,
    pub conversation_id: String,
    pub message_id: String,
    pub sender_id: String,
    pub encrypted_body_base64: String,
    pub plaintext_body_base64: Option<String>,
    pub envelope_id: Option<String>,
    pub source_principal_id: Option<String>,
    pub target_delivery_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<LocalBusFederationRoute>,
    pub ttl: Option<u32>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupMemberRoute {
    pub member_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_principal_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_signing_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_delivery_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<LocalBusFederationRoute>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupReceiveRequest {
    pub group_id: String,
    pub conversation_id: String,
    pub limit: usize,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupSenderKeyImportRequest {
    pub distribution_base64: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGroupSenderKeyExportRequest {
    pub group_id: String,
    pub sender_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusConversationRequest {
    pub conversation_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusConversationDisappearingSetRequest {
    pub conversation_id: String,
    pub ttl_secs: i64,
    #[serde(default = "default_disappearing_countdown_mode")]
    pub countdown_mode: String,
    #[serde(default = "default_disappearing_scope")]
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusConversationDisappearingExpireRequest {
    pub conversation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<i64>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusConversationMuteRequest {
    pub conversation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mute_until: Option<i64>,
    #[serde(default)]
    pub unmute: bool,
}

fn default_disappearing_countdown_mode() -> String {
    "on_send".to_owned()
}

fn default_disappearing_scope() -> String {
    "own_devices".to_owned()
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectPutRequest {
    pub object_id: String,
    pub plaintext_base64: String,
    pub chunk_size: usize,
    #[serde(default)]
    pub relay_endpoint: Option<String>,
    #[serde(default)]
    pub relay_service_key_base64: Option<String>,
    #[serde(default)]
    pub relay_interrupt_after_chunks: Option<u32>,
    /// T25-A2 (OBJ-IPC-01): opt-in durable reconciliation. When present, the daemon runs the
    /// `Pending → LocalCommitted → Committed` state machine, is idempotent on retry with the same
    /// id, and can be reconciled via `object.put.status`. When absent, the A1 straight-line path
    /// runs (no reconciliation guarantee) — the capability is explicit and version-gated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

/// T25-A3 (CTRL-102 / OBJ-IPC-01): open a bounded UPLOAD spool for a large `object.put`. Binds the
/// whole content-and-intent up front (`object_id`, `operation_id`, `total_len`, `plaintext_hash`,
/// relay `chunk_size`, normalized relay endpoint, protocol version); chunks then stream in bounded
/// frames and `finish` verifies hash + len before reusing the A2 durable commit. Carries NO plaintext.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectPutBeginRequest {
    pub object_id: String,
    pub operation_id: String,
    pub total_len: usize,
    pub plaintext_hash: String,
    pub chunk_size: usize,
    pub protocol_version: u32,
    #[serde(default)]
    pub relay_endpoint: Option<String>,
    #[serde(default)]
    pub relay_service_key_base64: Option<String>,
    #[serde(default)]
    pub relay_interrupt_after_chunks: Option<u32>,
}

/// T25-A3: append one bounded plaintext chunk to an open UPLOAD spool at the verified offset. The
/// daemon fails closed (and destroys the spool) on any gap / overlap / duplicate / oversize.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectPutChunkRequest {
    pub operation_id: String,
    pub offset: usize,
    pub data_base64: String,
}

/// T25-A3: finalize an UPLOAD spool — verify `total_len` + `plaintext_hash` + offset completeness,
/// then reuse the SAME A2 durable reconciliation (prepare -> atomic local commit -> relay ->
/// Committed -> compact terminal) under the shared `operation_id`. Cleans up on success AND failure.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectPutFinishRequest {
    pub object_id: String,
    pub operation_id: String,
}

/// T25-A2 (OBJ-IPC-01): read-only reconciliation status for a logical `object.put`. Returns the
/// operation `state` (`pending`/`local_committed`/`committed`/`failed`/`unknown`) and, when
/// terminal, the compact terminal result. `unknown` when no record or the `operation_id` mismatches.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectPutStatusRequest {
    pub object_id: String,
    pub operation_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectGetRequest {
    pub object_id: String,
    #[serde(default)]
    pub relay_endpoint: Option<String>,
    #[serde(default)]
    pub relay_service_key_base64: Option<String>,
    #[serde(default)]
    pub relay_ack: bool,
    #[serde(default)]
    pub relay_interrupt_after_chunks: Option<u32>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectShareRequest {
    pub object_id: String,
    pub conversation_id: String,
    pub sender_id: Option<String>,
    pub recipient_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_principal_commitment: Option<String>,
    pub target_delivery_id: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectDeleteRequest {
    pub object_id: String,
    #[serde(default)]
    pub relay_endpoint: Option<String>,
    #[serde(default)]
    pub relay_service_key_base64: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectImportRequest {
    pub package: SdkObjectSharePackage,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectTransferStatusRequest {
    pub object_id: String,
    #[serde(default)]
    pub direction: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusObjectTransferResumeRequest {
    pub object_id: String,
    pub direction: String,
    #[serde(default)]
    pub relay_endpoint: Option<String>,
    #[serde(default)]
    pub relay_service_key_base64: Option<String>,
    #[serde(default)]
    pub relay_interrupt_after_chunks: Option<u32>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusCallInviteRequest {
    pub call_id: String,
    pub target_id: String,
    pub opaque_offer_base64: String,
    pub srtp_media_key_base64: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusCallAnswerRequest {
    pub call_id: String,
    pub opaque_answer_base64: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusCallHangupRequest {
    pub call_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusBotInstallRequest {
    pub manifest: ramflux_protocol::BotManifest,
    pub install_grant: ramflux_protocol::BotInstallGrant,
    pub consent_member_ids: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusBotTrustAddRequest {
    pub bot_identity_commitment: String,
    pub bot_public_key: String,
    pub signing_key_id: String,
    #[serde(default = "default_bot_trust_source")]
    pub trust_source: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusBotRevokeRequest {
    pub bot_id: String,
}

fn default_bot_trust_source() -> String {
    "local_pin".to_owned()
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusA2iAppendRequest {
    pub event_id: String,
    pub event_type: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub control_domain: String,
    pub action: String,
    pub subject_base64: String,
    pub created_at: i64,
    #[serde(default)]
    pub target_delivery_id: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusA2iAcknowledgeRequest {
    pub event_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusA2uiRenderRequest {
    pub surface: A2uiSurface,
    pub supported_catalogs: Vec<String>,
    pub granted_permissions: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusA2uiActionRequest {
    pub surface: A2uiSurface,
    pub action: A2uiAction,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusSubscriptionOpenRequest {
    pub topics: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMcpServerAddRequest {
    pub server_id: String,
    pub command: String,
    pub tool_name: String,
    pub capability: McpCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<RiskLevel>,
    #[serde(default = "default_mcp_manifest_version")]
    pub manifest_version: u32,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMcpToolCallRequest {
    pub server_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub operation_origin: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMcpApprovalDecisionRequest {
    pub approval_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGrantRequest {
    pub grant_id: String,
    pub server_id: Option<String>,
    pub tool_name: Option<String>,
    pub capability: Option<McpCapability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_scope: Option<String>,
    pub full_delegation: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGrantRevokeRequest {
    pub grant_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGrantStandingApprovalCreateRequest {
    pub server_id: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusGrantStandingApprovalRevokeRequest {
    pub standing_approval_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalBusMcpApprovalGrantRequest {
    pub approval_id: String,
    pub signed_by_device_id: String,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalMcpGrantSigningBody {
    pub approval_id: String,
    pub grant_id: String,
    pub server_id: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_scope: Option<String>,
    pub capability: McpCapability,
    pub registry_hash: String,
    pub tool_manifest_set_hash: String,
    pub full_delegation: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub single_use: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments_hash: Option<String>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LocalMcpStandingApprovalSigningBody {
    pub standing_approval_id: String,
    pub server_id: String,
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_scope: Option<String>,
    pub capability: McpCapability,
    pub risk_level: RiskLevel,
    pub registry_hash: String,
    pub tool_manifest_set_hash: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

const fn default_mcp_manifest_version() -> u32 {
    1
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}
impl LocalBusConfig {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>, data_root: impl Into<PathBuf>) -> Self {
        Self { socket_path: socket_path.into(), data_root: data_root.into() }
    }
}

impl LocalBusFrame {
    #[must_use]
    pub fn request(
        request_id: impl Into<String>,
        account_id: Option<String>,
        sdk_api: impl Into<String>,
        method: impl Into<String>,
        body: serde_json::Value,
    ) -> Self {
        let request_id = request_id.into();
        Self {
            bus_protocol: "ramflux.local_bus.v1".to_owned(),
            frame_id: format!("frame_{request_id}"),
            kind: LocalBusFrameKind::Request,
            request_id,
            account_id,
            sdk_api: sdk_api.into(),
            method: method.into(),
            body,
            trace_id: None,
            ok: None,
            error: None,
        }
    }
}
impl LocalBusMessageSubmitRequest {
    pub(crate) fn plaintext_body(&self) -> Result<Option<Vec<u8>>, SdkError> {
        self.plaintext_body_base64
            .as_deref()
            .map(|body| {
                ramflux_protocol::decode_base64url(body)
                    .map_err(|error| SdkError::LocalBus(format!("invalid plaintext body: {error}")))
            })
            .transpose()
    }

    pub(crate) fn into_gateway_message(self) -> Result<GatewayDirectMessage, SdkError> {
        let encrypted_body = ramflux_protocol::decode_base64url(&self.encrypted_body_base64)
            .map_err(|error| SdkError::LocalBus(format!("invalid encrypted body: {error}")))?;
        Ok(self.into_gateway_message_with_body(encrypted_body))
    }

    pub(crate) fn into_gateway_message_with_body(
        self,
        encrypted_body: Vec<u8>,
    ) -> GatewayDirectMessage {
        GatewayDirectMessage {
            conversation_id: self.conversation_id,
            message_id: self.message_id,
            envelope_id: self.envelope_id,
            source_principal_id: self.source_principal_id,
            sender_id: self.sender_id,
            recipient_device_id: self.recipient_device_id,
            target_delivery_id: self.target_delivery_id,
            encrypted_body,
            created_at: self.created_at,
            ttl: self.ttl,
        }
    }
}
