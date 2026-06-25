// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Ext, SignedFields, canonical_json_bytes, domain, hash_base64url};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectManifest {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub object_id: String,
    pub encrypted_owner_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_relation_ref: Option<String>,
    pub encrypted_metadata: String,
    pub object_key_slots: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_created_group_key_epoch: Option<u64>,
    pub chunk_manifest_hash: String,
    pub chunk_count: u32,
    pub total_cipher_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_state: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectChunkRequest {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub request_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub missing_chunk_bitmap: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
    pub max_chunks: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct A2iControlEvent {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub event_type: A2iControlEventType,
    pub control_domain: ControlDomain,
    pub action: String,
    pub subject: Value,
    pub correlation_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum A2iControlEventType {
    #[serde(rename = "a2i.control")]
    Control,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlDomain {
    Message,
    Conversation,
    A2ui,
    McpTool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct A2uiSurfaceEvent {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub event_type: A2uiEventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2ui_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2ui_profile_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_a2ui_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_hash: Option<String>,
    pub source_device_id: String,
    pub target_device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_session_id: Option<String>,
    pub correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_capability: Option<String>,
    pub encrypted_surface_payload: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "camelCase")]
pub enum A2uiCommand {
    CreateSurface(CreateSurfaceCommand),
    UpdateComponents(UpdateComponentsCommand),
    UpdateDataModel(UpdateDataModelCommand),
    DeleteSurface(DeleteSurfaceCommand),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateSurfaceCommand {
    pub surface_id: String,
    pub surface_type: SurfaceType,
    pub catalog: String,
    pub catalog_version: String,
    pub fallback_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_markdown: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Value>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub data_model: serde_json::Map<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_actions: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateComponentsCommand {
    pub surface_id: String,
    pub base_surface_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove_component_ids: Vec<String>,
    pub new_surface_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateDataModelCommand {
    pub surface_id: String,
    pub base_surface_hash: String,
    pub data_patch: serde_json::Map<String, Value>,
    pub new_surface_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeleteSurfaceCommand {
    pub surface_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<DeleteSurfaceReason>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceType {
    MessageCard,
    ApprovalCard,
    FormCard,
    StatusPanel,
    TaskCard,
    FilePreview,
    CallCard,
    AgentResult,
    NotificationCard,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeleteSurfaceReason {
    Completed,
    Cancelled,
    Replaced,
    Expired,
    Error,
}

/// Computes `ramflux.a2ui.surface_hash.v1` over a renderable surface snapshot.
///
/// # Errors
/// Returns an error when canonical JSON serialization fails.
pub fn surface_hash(surface_snapshot: &Value) -> Result<String, crate::ProtocolError> {
    let mut snapshot = surface_snapshot.clone();
    if let Value::Object(object) = &mut snapshot {
        object.remove("surface_hash");
        object.remove("surfaceHash");
    }
    let canonical = canonical_json_bytes(&snapshot)?;
    Ok(hash_base64url(domain::A2UI_SURFACE_HASH, &canonical))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum A2uiEventType {
    #[serde(rename = "ramflux.a2ui.surface")]
    Surface,
    #[serde(rename = "ramflux.a2ui.updateComponents")]
    UpdateComponents,
    #[serde(rename = "ramflux.a2ui.updateDataModel")]
    UpdateDataModel,
    #[serde(rename = "ramflux.a2ui.deleteSurface")]
    DeleteSurface,
    #[serde(rename = "ramflux.a2ui.action_submitted")]
    ActionSubmitted,
    #[serde(rename = "ramflux.a2ui.action_result")]
    ActionResult,
    #[serde(rename = "ramflux.a2ui.permission_required")]
    PermissionRequired,
    #[serde(rename = "ramflux.a2ui.renderer_error")]
    RendererError,
    #[serde(rename = "ramflux.agent.action_requested")]
    AgentActionRequested,
    #[serde(rename = "ramflux.bot.action_requested")]
    BotActionRequested,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpGrant {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub grant_id: String,
    pub principal_id: String,
    pub source_app_device_id: String,
    pub target_ai_device_id: String,
    pub capability: McpCapability,
    pub risk_level: RiskLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_registry_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_manifest_set_hash: Option<String>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum McpCapability {
    ReadConversation,
    DraftMessage,
    SendMessage,
    ReadLocalFiles,
    WriteLocalFiles,
    RunShell,
    ManageContacts,
    ManageGroup,
    ManageMedia,
    ManageNode,
    ExternalToolInvoke,
}

impl McpCapability {
    #[must_use]
    pub const fn default_risk(&self) -> RiskLevel {
        match self {
            Self::ReadConversation | Self::DraftMessage | Self::ReadLocalFiles => RiskLevel::Low,
            Self::SendMessage | Self::ManageContacts | Self::ManageGroup => RiskLevel::Medium,
            Self::WriteLocalFiles
            | Self::RunShell
            | Self::ManageMedia
            | Self::ManageNode
            | Self::ExternalToolInvoke => RiskLevel::High,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BotManifest {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub bot_identity_commitment: String,
    pub actor_type: ActorType,
    pub display_name: String,
    pub manifest_version: String,
    pub home_node: String,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
    pub owner_identity_commitment: String,
    pub hosting_model: HostingModel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub a2ui_profiles: Vec<String>,
    pub safety_disclosure: SafetyDisclosure,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub signature_by_bot_identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional_signature_by_home_node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional_signature_by_directory: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    Human,
    Bot,
    Workflow,
    System,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostingModel {
    Local,
    Federated,
    OfficialHosted,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SafetyDisclosure {
    pub disclosure_version: u32,
    pub disclosure_text: String,
    pub hosting_model: HostingModel,
    pub key_custody_class: KeyCustodyClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_identity_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_display_name: Option<String>,
    pub can_read_dm_plaintext: bool,
    pub can_read_group_messages_when_member: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tee_attestation_hash: Option<String>,
    pub disclosure_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyCustodyClass {
    SelfHostedOwnerKey,
    FederatedOperatorKey,
    OfficialHostedOperatorKey,
    TeeAttestedV2,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BotEventBody {
    InstallRequested {
        bot_identity_commitment: String,
        bot_manifest_hash: String,
        requested_scope: Vec<String>,
        requested_context: Value,
    },
    InstallApproved {
        bot_identity_commitment: String,
        bot_manifest_hash: String,
        bot_install_grant_hash: String,
    },
    InstallRevoked {
        bot_identity_commitment: String,
        bot_install_grant_id: String,
        reason: String,
        effective_at: i64,
    },
    PermissionUpdated {
        bot_identity_commitment: String,
        bot_install_grant_id: String,
        new_scope: Vec<String>,
        effective_at: i64,
    },
    Revoked {
        bot_identity_commitment: String,
        bot_manifest_hash: String,
        reason: String,
        revoked_by: String,
        effective_at: i64,
        tombstone_hash: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BotInstallGrant {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub grant_id: String,
    pub bot_identity_commitment: String,
    pub bot_manifest_hash: String,
    pub installer_identity: String,
    pub installer_device_id: String,
    pub scope: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    pub expires_at: i64,
    pub signature_by_installer_device: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NotificationWake {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub wake_id: String,
    pub push_alias: String,
    pub delivery_class: NotificationDeliveryClass,
    pub priority: PushPriority,
    pub ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collapse_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_hint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationDeliveryClass {
    SelfDeviceControlNotification,
    UserContentNotification,
    AiTaskNotification,
    A2uiSurfaceNotification,
    CallWakeNotification,
    ConferenceWakeNotification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PushPriority {
    Low,
    Normal,
    High,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FederationHandshake {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub handshake_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub source_capabilities: Vec<String>,
    pub protocol_versions: Vec<String>,
    pub transport_backends: Vec<String>,
    pub trust_state_hash: String,
    pub nonce: String,
    pub created_at: i64,
}
