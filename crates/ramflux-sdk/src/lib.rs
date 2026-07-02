// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Rust core SDK facade and stable C-ABI boundary substrate.

mod bus;
#[cfg(feature = "c-abi")]
pub mod c_abi;
mod client;
mod constants;
mod dm;
mod error;
mod federation;
mod gateway;
mod group;
mod object;
mod own_device_sync;
mod prekey;
mod prelude;
mod records;
mod time;

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
    LocalBusGroupSenderKeyImportRequest, LocalBusMcpApprovalDecisionRequest,
    LocalBusMcpApprovalGrantRequest, LocalBusMcpServerAddRequest, LocalBusMcpToolCallRequest,
    LocalBusMessageAckRequest, LocalBusMessageAttachmentInput, LocalBusMessageDeleteRequest,
    LocalBusMessageReceiptDeliveredRequest, LocalBusMessageReceiptReadRequest,
    LocalBusMessageReceiveRequest, LocalBusMessageSubmitRequest, LocalBusObjectDeleteRequest,
    LocalBusObjectGetRequest, LocalBusObjectImportRequest, LocalBusObjectPutRequest,
    LocalBusObjectShareRequest, LocalBusObjectTransferResumeRequest,
    LocalBusObjectTransferStatusRequest, LocalBusSubscriptionOpenRequest, LocalMcpGrantSigningBody,
    LocalMcpStandingApprovalSigningBody, serve_local_bus, serve_local_bus_until,
};
pub use client::RamfluxClient;
pub use client::contact::SdkContactSafetyNumber;
pub use client::conversation::ConversationSummary;
pub use client::recovery::{
    SdkRecoveryQuorumConfiguration, SdkRecoveryQuorumMember, recovery_member_public_key_base64url,
};
pub use constants::*;
pub use dm::{SdkDmAttachmentImportResult, SdkDmX3dhHeader};
pub use error::SdkError;
pub use federation::{
    SdkFederatedEnvelopeForwardRequest, SdkFederatedEnvelopeForwardResponse,
    SdkFederatedSubmitResponse,
};
pub use gateway::{
    GatewayAuthFrame, GatewayClientFrame, GatewayCursor, GatewayDirectMessage, GatewayInboxEntry,
    GatewayOpenFrame, GatewayPlaintextDelivery, GatewayQuicEndpointConfig, GatewayResumeFrame,
    GatewayServerFrame, GatewaySessionConfig, GatewaySessionEngine, GatewaySessionEstablishedFrame,
    GatewaySessionState, GatewaySessionTransportKind, GatewaySubmitFrame,
    GatewayTcpTlsEndpointConfig,
};
pub use group::SdkGroupSenderKeyDistribution;
pub use object::{SdkObjectKeySlot, SdkObjectSharePackage};
pub use prekey::{
    SdkIdentityRegisterRequest, SdkIdentityRegistrationResponse, SdkPrekeyPublishRequest,
    SdkPrekeyResponse, identity_root_public_key_commitment,
    identity_root_public_key_commitment_for_seed,
};
pub use records::{
    LocalBotRecord, LocalBotTrustPinRecord, LocalCallRecord, LocalMcpApprovalRecord,
    LocalMcpAuditRecord, LocalMcpGrantRecord, LocalMcpStandingApprovalRecord,
};
