// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub const EVENT: &str = "ramflux.event.v1";
pub const ENVELOPE: &str = "ramflux.envelope.v1";
pub const OBJECT: &str = "ramflux.object.v1";
pub const CHUNK_PLAIN: &str = "ramflux.chunk.plain.v1";
pub const CHUNK_CIPHER: &str = "ramflux.chunk.cipher.v1";
pub const OBJECT_CHUNK_ID: &str = "ramflux.object_chunk_id.v1";
pub const OBJECT_MANIFEST: &str = "ramflux.object_manifest.v1";
pub const OBJECT_CHUNK_REQUEST: &str = "ramflux.object_chunk_request.v1";
pub const SIGNED_REQUEST: &str = "ramflux.signed_request.v1";
pub const DEVICE_PROOF: &str = "ramflux.device_proof.v1";
pub const HOME_NODE_MIGRATION_PROOF: &str = "ramflux.home_node_migration_proof.v1";
pub const IDENTITY_DELETION_PROOF: &str = "ramflux.identity_deletion_proof.v1";
pub const IDENTITY_DELETION_PROOF_DELETED_METADATA_LEAF: &str =
    "ramflux.identity_deletion_proof.deleted_metadata_leaf.v1";
pub const IDENTITY_DELETION_PROOF_DELETED_METADATA_PARENT: &str =
    "ramflux.identity_deletion_proof.deleted_metadata_parent.v1";
pub const IDENTITY_DELETION_PROOF_DELETED_METADATA_EMPTY: &str =
    "ramflux.identity_deletion_proof.deleted_metadata_empty.v1";
pub const IDENTITY_DELETION_PROOF_RETAINED_SUMMARY: &str =
    "ramflux.identity_deletion_proof.retained_summary.v1";
pub const IDENTITY_DELETION_PROOF_TOMBSTONE: &str = "ramflux.identity_deletion_proof.tombstone.v1";
pub const ACK: &str = "ramflux.ack.v1";
pub const NACK: &str = "ramflux.nack.v1";
pub const CURSOR: &str = "ramflux.cursor.v1";
pub const IDENTITY_EVENT: &str = "ramflux.identity_event.v1";
pub const BRANCH_PROOF: &str = "ramflux.branch_proof.v1";
pub const FRIEND_EVENT: &str = "ramflux.friend_event.v1";
pub const GROUP_EVENT: &str = "ramflux.group_event.v1";
pub const CONVERSATION_EVENT: &str = "ramflux.conversation_event.v1";
pub const MESSAGE_EVENT: &str = "ramflux.message_event.v1";
pub const NOTIFICATION_WAKE: &str = "ramflux.notification_wake.v1";
pub const MCP_GRANT: &str = "ramflux.mcp_grant.v1";
pub const BOT_MANIFEST: &str = "ramflux.bot_manifest.v1";
pub const BOT_EVENT: &str = "ramflux.bot_event.v1";
pub const BOT_INSTALL_GRANT: &str = "ramflux.bot_install_grant.v1";
pub const A2I_CONTROL: &str = "ramflux.a2i_control.v1";
pub const A2UI_SURFACE: &str = "ramflux.a2ui_surface.v1";
pub const A2UI_SURFACE_HASH: &str = "ramflux.a2ui.surface_hash.v1";
pub const PUSH_ALIAS: &str = "ramflux.push_alias.v1";
pub const FEDERATION_HANDSHAKE: &str = "ramflux.federation_handshake.v1";
pub const X3DH_PREKEY_BUNDLE: &str = "ramflux.x3dh.prekey_bundle.v1";
pub const X3DH_INITIAL_SECRET: &str = "ramflux.x3dh.initial_secret.v1";
pub const DM_RATCHET_ROOT: &str = "ramflux.dm_ratchet.root.v1";
pub const DM_RATCHET_CHAIN: &str = "ramflux.dm_ratchet.chain.v1";
pub const DM_RATCHET_MESSAGE: &str = "ramflux.dm_ratchet.message.v1";
pub const DM_RATCHET_HEADER: &str = "ramflux.dm_ratchet.header.v1";
pub const DM_RATCHET_SKIPPED_KEY: &str = "ramflux.dm_ratchet.skipped_key.v1";
pub const GROUP_SENDER_KEY_DISTRIBUTION: &str = "ramflux.group_sender_key.distribution.v1";
pub const GROUP_SENDER_KEY_CHAIN: &str = "ramflux.group_sender_key.chain.v1";
pub const GROUP_SENDER_KEY_MESSAGE: &str = "ramflux.group_sender_key.message.v1";
pub const COMMITTING_AEAD: &str = "ramflux.committing_aead.v1";
pub const COMMITTING_AEAD_HEADER: &str = "ramflux.committing_aead.header.v1";
pub const COMMITTING_AEAD_AD: &str = "ramflux.committing_aead.ad.v1";
pub const FRANKING_OPENING: &str = "ramflux.franking_opening.v1";
pub const FRANKING_NODE_TAG: &str = "ramflux.franking.node_tag.v1";
pub const KEY_VERIFICATION_SAFETY_NUMBER: &str = "ramflux.safety_number.v1";
pub const KEY_VERIFICATION_DEVICE_SET: &str = "ramflux.device_set.v1";
pub const REGISTRATION_POW: &str = "ramflux.registration_pow.v1";
pub const REGISTRATION_TRUST_TIER: &str = "ramflux.registration_trust_tier.v1";

pub const ALL: [&str; 55] = [
    EVENT,
    ENVELOPE,
    OBJECT,
    CHUNK_PLAIN,
    CHUNK_CIPHER,
    OBJECT_CHUNK_ID,
    OBJECT_MANIFEST,
    OBJECT_CHUNK_REQUEST,
    SIGNED_REQUEST,
    DEVICE_PROOF,
    HOME_NODE_MIGRATION_PROOF,
    IDENTITY_DELETION_PROOF,
    IDENTITY_DELETION_PROOF_DELETED_METADATA_LEAF,
    IDENTITY_DELETION_PROOF_DELETED_METADATA_PARENT,
    IDENTITY_DELETION_PROOF_DELETED_METADATA_EMPTY,
    IDENTITY_DELETION_PROOF_RETAINED_SUMMARY,
    IDENTITY_DELETION_PROOF_TOMBSTONE,
    ACK,
    NACK,
    CURSOR,
    IDENTITY_EVENT,
    BRANCH_PROOF,
    FRIEND_EVENT,
    GROUP_EVENT,
    CONVERSATION_EVENT,
    MESSAGE_EVENT,
    NOTIFICATION_WAKE,
    MCP_GRANT,
    BOT_MANIFEST,
    BOT_EVENT,
    BOT_INSTALL_GRANT,
    A2I_CONTROL,
    A2UI_SURFACE,
    A2UI_SURFACE_HASH,
    PUSH_ALIAS,
    FEDERATION_HANDSHAKE,
    X3DH_PREKEY_BUNDLE,
    X3DH_INITIAL_SECRET,
    DM_RATCHET_ROOT,
    DM_RATCHET_CHAIN,
    DM_RATCHET_MESSAGE,
    DM_RATCHET_HEADER,
    DM_RATCHET_SKIPPED_KEY,
    GROUP_SENDER_KEY_DISTRIBUTION,
    GROUP_SENDER_KEY_CHAIN,
    GROUP_SENDER_KEY_MESSAGE,
    COMMITTING_AEAD,
    COMMITTING_AEAD_HEADER,
    COMMITTING_AEAD_AD,
    FRANKING_OPENING,
    FRANKING_NODE_TAG,
    KEY_VERIFICATION_SAFETY_NUMBER,
    KEY_VERIFICATION_DEVICE_SET,
    REGISTRATION_POW,
    REGISTRATION_TRUST_TIER,
];
