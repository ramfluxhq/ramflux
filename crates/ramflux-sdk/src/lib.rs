// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Rust core SDK facade and stable C-ABI boundary substrate.
//!
//! Receive-ledger authority tokens have no public constructor. The constructor
//! grep in `bus::push_receiver::guard_tests` is the privacy proof.

/// Dormant generated message schema and local request/update types.
pub use ramflux_protocol::message;
pub use ramflux_protocol::message::{MessageRequest, MessageUpdate};

#[cfg(feature = "test-support")]
pub use bus::dispatch::call::VoiceAdmissionProbe;

pub mod backup;
#[cfg(all(feature = "itest-memory-vault", not(any(test, ramflux_itest))))]
compile_error!(
    "itest-memory-vault requires cfg(test) or an explicit RAMFLUX_ITEST_BUILD=1 fixture build"
);
#[cfg(all(feature = "itest-memory-vault", ramflux_production))]
compile_error!("production builds must not enable itest-memory-vault");
#[cfg(all(feature = "itest-memory-vault", ramflux_release_profile))]
compile_error!("release profiles must not enable itest-memory-vault");

#[cfg(all(feature = "itest-legacy-accounts", not(any(test, ramflux_itest))))]
compile_error!("itest-legacy-accounts requires cfg(test) or RAMFLUX_ITEST_BUILD=1");
#[cfg(all(feature = "itest-legacy-accounts", ramflux_production))]
compile_error!("production builds must not enable itest-legacy-accounts");
#[cfg(all(feature = "itest-legacy-accounts", ramflux_release_profile))]
compile_error!("release profiles must not enable itest-legacy-accounts");

pub mod bindings;
mod bus;
#[cfg(feature = "c-abi")]
pub mod c_abi;
mod client;
mod platform;
pub use client::home_migration::{
    HomeMigrationJournal, MigrationApprovalPlan, MigrationApprovalResult, MigrationIntent,
    MigrationPhase, MigrationProgress, MigrationResumption,
};
pub mod attachment_renewal;
pub mod attachment_retirement;
pub mod custody;
mod surface;
pub use surface::{SurfaceSendRequest, new_surface_message_id};
mod constants;
mod offline_retention;
pub use offline_retention::{
    AccountConfig, DEFAULT_OFFLINE_RETENTION_SECS, MIN_OFFLINE_RETENTION_SECS,
};
mod contact_card;
mod contact_card_native;
mod contact_identity;
pub use contact_card::{
    ContactCardAuthority, ContactCardBody, ContactNode, ContactReason, contact_node_fingerprint,
    parse_contact_card,
};
pub use contact_identity::{ContactRootChange, ContactRootSource};
mod dm;
mod ephemeral;
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
    AccountNetworkingReason, LocalBusA2iAcknowledgeRequest, LocalBusA2iAppendRequest,
    LocalBusA2uiActionRequest, LocalBusA2uiRenderRequest, LocalBusAccountBackupExportRequest,
    LocalBusAccountBackupImportRequest, LocalBusAccountCreateRequest,
    LocalBusAccountCreateResponse, LocalBusAccountPassphraseRotateRequest,
    LocalBusAccountUnlockRequest, LocalBusBackupContactRestoreReport, LocalBusBackupContactSkip,
    LocalBusBackupContactSkipReason, LocalBusBotInstallRequest, LocalBusBotRevokeRequest,
    LocalBusBotTrustAddRequest, LocalBusCallAnswerRequest, LocalBusCallHangupRequest,
    LocalBusCallInviteRequest, LocalBusClient, LocalBusClientMode, LocalBusConfig,
    LocalBusContactAddRequest, LocalBusContactFederatedRequest, LocalBusContactLinkRequest,
    LocalBusContactRemoveRequest, LocalBusContactSafetyRequest,
    LocalBusConversationDisappearingExpireRequest, LocalBusConversationDisappearingSetRequest,
    LocalBusConversationMuteRequest, LocalBusConversationRequest, LocalBusCreatedAccount,
    LocalBusCreatedAccountState, LocalBusCreationClient, LocalBusDeviceActivateRequest,
    LocalBusDeviceActivateResponse, LocalBusDeviceListResponse, LocalBusDeviceRecord,
    LocalBusDeviceRevokeRequest, LocalBusDeviceSyncExportRequest, LocalBusDeviceSyncImportRequest,
    LocalBusErrorBody, LocalBusFederationRoute, LocalBusFrame, LocalBusFrameKind,
    LocalBusGrantRequest, LocalBusGrantRevokeRequest, LocalBusGrantStandingApprovalCreateRequest,
    LocalBusGrantStandingApprovalRevokeRequest, LocalBusGroupCreateRequest,
    LocalBusGroupInviteAcceptRequest, LocalBusGroupInviteCreateRequest,
    LocalBusGroupMemberAddRequest, LocalBusGroupMemberBanRequest, LocalBusGroupMemberKickRequest,
    LocalBusGroupMemberRemoveRequest, LocalBusGroupMemberRoute, LocalBusGroupMessageDeleteRequest,
    LocalBusGroupNameSetRequest, LocalBusGroupReceiveRequest, LocalBusGroupRequest,
    LocalBusGroupRoleSetRequest, LocalBusGroupSendRequest, LocalBusGroupSenderKeyExportRequest,
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
    LocalBusObjectTransferStatusRequest, LocalBusPendingCreation, LocalBusPendingRecovery,
    LocalBusRecoveryClient, LocalBusSubscriptionOpenRequest, LocalMcpGrantSigningBody,
    LocalMcpStandingApprovalSigningBody, TaskApprovalBinding, serve_local_bus,
    serve_local_bus_until,
};
#[cfg(feature = "itest-restore-state")]
#[doc(hidden)]
pub use bus::{LocalBusStartupRestoreGate, LocalBusStartupRestoreGateControl};
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
pub use client::{ReparseProgress, self_sync, typed_messages, typed_read_model, typing};
pub use constants::*;
pub use dm::{
    SdkDmAttachmentImportResult, SdkDmX3dhHeader, SdkFrankingEvidenceKind,
    SdkSelectedFrankingEvidence,
};
pub use ephemeral::{
    AuthenticatedCiphertext, EphemeralConsumer, EphemeralReceiver, EphemeralSendError,
    EphemeralSendOutcome, EphemeralSource, EphemeralWire, HoldLease, LedgerProbe,
    RECEIVER_CHANNEL_BYTES, RECEIVER_CHANNEL_FRAMES, RECEIVER_DEDUP_BOUND,
    RECEIVER_DEDUP_BUDGET_BYTES, RECEIVER_DEDUP_ENTRY_BYTES, RECEIVER_MAX_FRAME_BYTES,
    ReceiverAdmit, ReceiverClock, ReceiverDequeue, ReceiverDropReason, ReceiverHandoff,
    ReceiverLifetime, admit_authenticated_ciphertext, authenticate, decode_ephemeral_result,
    echo_holds_ephemeral_send, encode_ephemeral_submit, send_ephemeral, ttl_seconds,
};
pub use error::{GeneratedRefusalCode, GroupOperation, ReceiveEpochReconcileFailure, SdkError};
mod surface_refusal;
pub use federation::{
    SdkFederatedEnvelopeForwardRequest, SdkFederatedEnvelopeForwardResponse,
    SdkFederatedSubmitResponse,
};
pub use gateway::{
    GatewayAuthFrame, GatewayCallFuture, GatewayClientFrame, GatewayCursor, GatewayCustodyConfig,
    GatewayDirectMessage, GatewayInboxEntry, GatewayOpenFrame, GatewayOwnDeviceFanoutDelivery,
    GatewayOwnDeviceFanoutFrame, GatewayOwnDeviceFanoutResponse, GatewayPlaintextDelivery,
    GatewayPushProvider, GatewayPushRouteDeregistration, GatewayPushRouteDeregistrationFrame,
    GatewayPushRouteFrame, GatewayPushRouteRefusal, GatewayPushRouteRegistration,
    GatewayQuicEndpointConfig, GatewayResumeFrame, GatewayServerFrame, GatewaySessionAccess,
    GatewaySessionConfig, GatewaySessionEngine, GatewaySessionEstablishedFrame,
    GatewaySessionState, GatewaySessionTransportKind, GatewaySubmitFrame,
    GatewayTcpTlsEndpointConfig, PushRouteRetry,
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

pub use client::identity_authority::profile_read::VerifiedIdentityProfile;

#[cfg(test)]
mod storage_failure_fixture;

pub use object::{SdkObjectRelayCapability, SdkRelayToken};
pub use prekey::SdkDeviceManifestResponse;

#[cfg(feature = "test-support")]
pub use bus::account_runtime::testing::{AccountSessionFixture, AccountSessionHarness};

#[cfg(all(feature = "test-support", any(ramflux_production, ramflux_release_profile)))]
compile_error!("test-support is excluded from production and release builds");
