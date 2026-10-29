// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

pub(crate) mod a2i;
pub(crate) mod a2ui;
pub(crate) mod account;
mod account_backup;
mod account_ceremony;
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
pub(crate) mod node;
pub(crate) mod object;
pub(crate) mod surface;

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
    LocalBusObjectGetBeginRequest, LocalBusObjectGetFinishRequest, LocalBusObjectGetReadRequest,
    LocalBusObjectGetRequest, LocalBusObjectImportRequest, LocalBusObjectPutBeginRequest,
    LocalBusObjectPutChunkRequest, LocalBusObjectPutFinishRequest, LocalBusObjectPutRequest,
    LocalBusObjectPutStatusRequest, LocalBusObjectShareRequest,
    LocalBusObjectTransferResumeRequest, LocalBusObjectTransferStatusRequest,
    MAX_LOCAL_BUS_CHUNK_PAYLOAD_BYTES, MAX_LOCAL_BUS_OBJECT_BYTES,
    MAX_LOCAL_BUS_ONE_SHOT_OBJECT_BYTES, OBJECT_PUT_PROTOCOL_VERSION,
};
pub(crate) use std::net::SocketAddr;
pub(crate) use std::path::PathBuf;

/// Serializes CLI request structs into the owned SDK request boundary.
async fn request_body<T: serde::Serialize>(
    bus: &mut LocalBusClient,
    account: Option<String>,
    api: &str,
    method: &str,
    body: T,
) -> Result<serde_json::Value, RfError> {
    Ok(bus.request(account, api, method, serde_json::to_value(body)?).await?)
}
