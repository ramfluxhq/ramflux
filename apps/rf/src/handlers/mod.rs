// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

pub(crate) mod a2i;
pub(crate) mod a2ui;
pub(crate) mod account;
pub(crate) mod admin;
pub(crate) mod bot;
pub(crate) mod call;
pub(crate) mod contact;
pub(crate) mod daemon;
pub(crate) mod device;
pub(crate) mod dm;
pub(crate) mod grant;
pub(crate) mod group;
pub(crate) mod keychain;
pub(crate) mod mcp;
pub(crate) mod object;

pub(crate) use crate::cli::*;
pub(crate) use crate::utils::*;
pub(crate) use crate::{DEFAULT_DATA_ROOT, RfError};
pub(crate) use ramflux_sdk::{
    GatewayQuicEndpointConfig, LocalBusA2iAcknowledgeRequest, LocalBusA2iAppendRequest,
    LocalBusA2uiActionRequest, LocalBusA2uiRenderRequest, LocalBusAccountBackupExportRequest,
    LocalBusAccountBackupImportRequest, LocalBusAccountCreateRequest,
    LocalBusAccountPassphraseRotateRequest, LocalBusAccountUnlockRequest,
    LocalBusBotInstallRequest, LocalBusBotRevokeRequest, LocalBusBotTrustAddRequest,
    LocalBusCallAnswerRequest, LocalBusCallHangupRequest, LocalBusCallInviteRequest,
    LocalBusClient, LocalBusConfig, LocalBusContactAddRequest, LocalBusContactFederatedRequest,
    LocalBusContactLinkRequest, LocalBusContactRemoveRequest, LocalBusContactSafetyRequest,
    LocalBusConversationDisappearingExpireRequest, LocalBusConversationDisappearingSetRequest,
    LocalBusConversationMuteRequest, LocalBusConversationRequest, LocalBusDeviceRevokeRequest,
    LocalBusFederationRoute, LocalBusGrantRequest, LocalBusGrantRevokeRequest,
    LocalBusGroupCreateRequest, LocalBusGroupInviteAcceptRequest, LocalBusGroupInviteCreateRequest,
    LocalBusGroupMemberAddRequest, LocalBusGroupMemberBanRequest, LocalBusGroupMemberKickRequest,
    LocalBusGroupMemberRemoveRequest, LocalBusGroupMessageDeleteRequest,
    LocalBusGroupReceiveRequest, LocalBusGroupRequest, LocalBusGroupRoleSetRequest,
    LocalBusGroupSendRequest, LocalBusMcpApprovalDecisionRequest, LocalBusMcpServerAddRequest,
    LocalBusMcpToolCallRequest, LocalBusMessageAckRequest, LocalBusMessageAttachmentInput,
    LocalBusMessageDeleteRequest, LocalBusMessageReceiptDeliveredRequest,
    LocalBusMessageReceiptReadRequest, LocalBusMessageSubmitRequest, LocalBusObjectDeleteRequest,
    LocalBusObjectGetRequest, LocalBusObjectImportRequest, LocalBusObjectPutRequest,
    LocalBusObjectPutStatusRequest, LocalBusObjectShareRequest,
    LocalBusObjectTransferResumeRequest, LocalBusObjectTransferStatusRequest,
};
pub(crate) use std::net::SocketAddr;
pub(crate) use std::path::PathBuf;
