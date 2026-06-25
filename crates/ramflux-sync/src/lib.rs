//! MVP-3 sync, MCP, A2UI, franking, and WebRTC local state machines.

mod a2ui;
mod bot;
mod error;
mod federation;
mod franking_call;
mod gossip;
mod mcp;
mod object_store;

pub use a2ui::{
    A2UI_ACTION_SIGNING_BODY_SCHEMA, A2iControlEvent, A2uiAction, A2uiActionSigningBody,
    A2uiComponent, A2uiSurface, RenderedSurface, a2ui_action_signing_body, a2ui_surface_hash,
    render_a2ui_surface, verify_a2ui_action, verify_a2ui_action_signature,
};
pub use bot::{
    BotInstallGrantSigningBody, BotManifestSigningBody, BotRevocationRegistry,
    bot_install_grant_signing_body, bot_manifest_hash, bot_manifest_signing_body,
    verify_bot_install_grant, verify_bot_manifest, verify_bot_mcp_tool_capability,
};
pub use error::SyncError;
pub use federation::{
    CutoverDelivery, FederationMesh, FederationMessage, FederationNode, HomeNodeMigration,
    NodeTrustStatus,
};
pub use franking_call::{
    FrankingEvidence, OpaqueCallSignal, SignalingRelay, assert_srtp_relay_has_no_media_key,
    bot_revocation_targets, relay_opaque_call_signal, verify_franking_evidence,
};
pub use gossip::{ContactGossipExpectation, ContactGossipReport, verify_contact_gossip_checkpoint};
pub use mcp::{
    McpCapability, McpGrantState, McpRegistry, McpToolManifest, RiskLevel, grant_matches_manifest,
    mcp_capability_wire_name, parse_mcp_capability, risk_requires_explicit_approval,
    risk_wire_name,
};
#[cfg(test)]
pub use object_store::backup_manifest_signature;
pub use object_store::{
    BackupCheckpoint, BackupManifest, BackupManifestRequest, ChunkManifest, ChunkPayload,
    EncryptedObject, LanAnnounce, LanPairingRegistry, MissingChunkBitmap, ObjectAuth,
    ObjectChunkAck, ObjectChunkResponse, ObjectHello, ObjectManifestOffer, ObjectQuinnStreamLayout,
    ObjectStore, ObjectSyncControlMessage, ObjectSyncSession, ObjectTombstone,
    ObjectTransferComplete, ObjectTransferError, PeerProof, PeerProofVerifier, RelayOpaqueBundle,
    ResumeToken, SyncBatch, backup_manifest_device_signature, chunk_cipher_hash,
    chunk_manifest_for_object, chunk_payload, client_sync_path, decrypt_chunk_payload,
    encrypted_chunk_payload, object_tombstone_head, sign_lan_announce, sign_object_tombstone,
    sign_peer_proof, sync_batch_v1, verify_backup_manifest, verify_lan_announce,
    verify_object_tombstone, verify_peer_proof, verify_resume_token,
};

pub const CRATE_NAME: &str = "ramflux-sync";

#[must_use]
pub const fn crate_name() -> &'static str {
    CRATE_NAME
}
