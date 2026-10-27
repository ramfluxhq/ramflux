// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Rust core SDK facade and stable C-ABI boundary substrate.

pub mod backup;
#[cfg(all(feature = "itest-memory-vault", not(any(test, ramflux_itest))))]
compile_error!(
    "itest-memory-vault requires cfg(test) or an explicit RAMFLUX_ITEST_BUILD=1 fixture build"
);
#[cfg(all(feature = "itest-memory-vault", ramflux_production))]
compile_error!("production builds must not enable itest-memory-vault");

mod bus;
#[cfg(feature = "c-abi")]
pub mod c_abi;
mod client;
pub mod custody;
mod surface;
pub use surface::{SurfaceSendRequest, new_surface_message_id};
mod constants;
mod contact_card;
mod contact_identity;
pub use contact_card::{
    ContactCardBody, ContactNode, ContactReason, contact_node_fingerprint, parse_contact_card,
};
pub use contact_identity::{ContactRootChange, ContactRootSource};
mod dm;
mod error;
mod error_policy;
mod federation;
mod gateway;
mod group;
#[cfg(feature = "itest-bus-fault")]
mod itest_bus_fault;
#[cfg(feature = "object-ipc-crash-seam")]
mod itest_crash_seam;
#[cfg(feature = "itest-rfd-fault")]
mod itest_rfd_fault;
mod node;
mod object;
pub use node::{
    GatewayProbe, NodeGateway, NodePinSource, NodeProfile, NodeRelay, probe_gateway_pre_account,
};
mod own_device_sync;
mod prekey;
mod prelude;
mod records;
mod time;

pub use bus::io::{
    MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES, MAX_LOCAL_BUS_OBJECT_BYTES,
    MAX_LOCAL_BUS_ONE_SHOT_OBJECT_BYTES,
};
pub use bus::{
    LocalBusA2iAcknowledgeRequest, LocalBusA2iAppendRequest, LocalBusA2uiActionRequest,
    LocalBusA2uiRenderRequest, LocalBusAccountBackupExportRequest,
    LocalBusAccountBackupImportRequest, LocalBusAccountCreateRequest,
    LocalBusAccountCreateResponse, LocalBusAccountPassphraseRotateRequest,
    LocalBusAccountUnlockRequest, LocalBusBotInstallRequest, LocalBusBotRevokeRequest,
    LocalBusBotTrustAddRequest, LocalBusCallAnswerRequest, LocalBusCallHangupRequest,
    LocalBusCallInviteRequest, LocalBusClient, LocalBusClientMode, LocalBusConfig,
    LocalBusContactAddRequest, LocalBusContactFederatedRequest, LocalBusContactLinkRequest,
    LocalBusContactRemoveRequest, LocalBusContactSafetyRequest,
    LocalBusConversationDisappearingExpireRequest, LocalBusConversationDisappearingSetRequest,
    LocalBusConversationMuteRequest, LocalBusConversationRequest, LocalBusDeviceActivateRequest,
    LocalBusDeviceActivateResponse, LocalBusDeviceListResponse, LocalBusDeviceRecord,
    LocalBusDeviceRevokeRequest, LocalBusDeviceSyncExportRequest, LocalBusDeviceSyncImportRequest,
    LocalBusErrorBody, LocalBusFederationRoute, LocalBusFrame, LocalBusFrameKind,
    LocalBusGrantRequest, LocalBusGrantRevokeRequest, LocalBusGrantStandingApprovalCreateRequest,
    LocalBusGrantStandingApprovalRevokeRequest, LocalBusGroupCreateRequest,
    LocalBusGroupInviteAcceptRequest, LocalBusGroupInviteCreateRequest,
    LocalBusGroupMemberAddRequest, LocalBusGroupMemberBanRequest, LocalBusGroupMemberKickRequest,
    LocalBusGroupMemberRemoveRequest, LocalBusGroupMemberRoute, LocalBusGroupMessageDeleteRequest,
    LocalBusGroupReceiveRequest, LocalBusGroupRequest, LocalBusGroupRoleSetRequest,
    LocalBusGroupSendRequest, LocalBusGroupSenderKeyExportRequest,
    LocalBusGroupSenderKeyImportRequest, LocalBusIoCause, LocalBusMcpApprovalDecisionRequest,
    LocalBusMcpApprovalGrantRequest, LocalBusMcpServerAddRequest, LocalBusMcpToolCallRequest,
    LocalBusMessageAckRequest, LocalBusMessageAttachmentInput, LocalBusMessageDeleteRequest,
    LocalBusMessageFrankingEvidenceRequest, LocalBusMessageReceiptDeliveredRequest,
    LocalBusMessageReceiptReadRequest, LocalBusMessageReceiveRequest, LocalBusMessageSubmitRequest,
    LocalBusObjectDeleteRequest, LocalBusObjectGetBeginRequest, LocalBusObjectGetFinishRequest,
    LocalBusObjectGetReadRequest, LocalBusObjectGetRequest, LocalBusObjectGetStatusRequest,
    LocalBusObjectImportRequest, LocalBusObjectPutBeginRequest, LocalBusObjectPutChunkRequest,
    LocalBusObjectPutFinishRequest, LocalBusObjectPutRequest, LocalBusObjectPutStatusRequest,
    LocalBusObjectShareRequest, LocalBusObjectTransferResumeRequest,
    LocalBusObjectTransferStatusRequest, LocalBusSubscriptionOpenRequest, LocalMcpGrantSigningBody,
    LocalMcpStandingApprovalSigningBody, TaskApprovalBinding, serve_local_bus,
    serve_local_bus_until,
};
pub use client::RamfluxClient;
pub use client::contact::SdkContactSafetyNumber;
pub use client::conversation::ConversationSummary;
#[cfg(feature = "itest-fingerprint")]
pub use client::dm_session::RecvCommitFingerprint;
pub use client::recovery::{
    SdkFinalizedRecovery, SdkGuardianAcceptMessage, SdkGuardianInviteMessage,
    SdkGuardianRecoveryShare, SdkPendingRecoveryState, SdkPendingRecoveryStatus,
    SdkRecoveryInitiateRequest, SdkRecoveryQuorumConfiguration, SdkRecoveryQuorumMember,
    recovery_member_public_key_base64url, verify_guardian_accept,
};
pub use constants::*;
pub use dm::{
    SdkDmAttachmentImportResult, SdkDmX3dhHeader, SdkFrankingEvidenceKind,
    SdkSelectedFrankingEvidence,
};
pub use error::SdkError;
mod surface_refusal;
pub use federation::{
    SdkFederatedEnvelopeForwardRequest, SdkFederatedEnvelopeForwardResponse,
    SdkFederatedSubmitResponse,
};
pub use gateway::{
    GatewayAuthFrame, GatewayClientFrame, GatewayCursor, GatewayDirectMessage, GatewayInboxEntry,
    GatewayOpenFrame, GatewayOwnDeviceFanoutDelivery, GatewayOwnDeviceFanoutFrame,
    GatewayOwnDeviceFanoutResponse, GatewayPlaintextDelivery, GatewayPushProvider,
    GatewayPushRouteDeregistration, GatewayPushRouteDeregistrationFrame, GatewayPushRouteFrame,
    GatewayPushRouteRefusal, GatewayPushRouteRegistration, GatewayQuicEndpointConfig,
    GatewayResumeFrame, GatewayServerFrame, GatewaySessionConfig, GatewaySessionEngine,
    GatewaySessionEstablishedFrame, GatewaySessionState, GatewaySessionTransportKind,
    GatewaySubmitFrame, GatewayTcpTlsEndpointConfig, PushRouteRetry,
};
pub use group::SdkGroupSenderKeyDistribution;
pub use object::{OBJECT_PUT_PROTOCOL_VERSION, SdkObjectKeySlot, SdkObjectSharePackage};
pub use prekey::{
    SdkIdentityRegisterRequest, SdkIdentityRegistrationResponse, SdkPrekeyPublishRequest,
    SdkPrekeyResponse, identity_root_public_key_commitment,
    identity_root_public_key_commitment_for_seed,
};
pub use records::{
    LocalBotRecord, LocalBotTrustPinRecord, LocalCallRecord, LocalMcpApprovalRecord,
    LocalMcpAuditRecord, LocalMcpGrantRecord, LocalMcpStandingApprovalRecord,
};
pub use surface_refusal::SurfaceRefusalCode;

mod task_refusal;
mod task_warnings;
pub use task_refusal::TaskRefusalCode;
