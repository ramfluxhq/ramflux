// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ramflux C1 protocol types, canonical JSON, and fixture helpers.

mod canonical_json;
mod core_types;
pub mod domain;
mod encoding;
mod error;
mod events;
mod fixtures;
mod header;
mod protocol_object;
mod replay;
mod signature;
mod state;
mod surfaces;

pub use canonical_json::{
    blake3_hash_bytes, canonical_json_bytes, canonical_json_string, event_id, hash_base64url,
    hash_hex, parse_fixture_value, signed_bytes, signed_value, strip_signature_fields_from_json,
    validate_domain, validate_no_replay,
};
pub use core_types::{
    Ack, BotEvent, BranchProof, ClientEvent, ConversationEvent, Cursor, DeliveryClass, DeviceProof,
    Envelope, EventId, Ext, FriendLinkEvent, GroupEvent, HomeNodeMigrationProof, HttpMethod,
    IdentityDeletionProof, IdentityEvent, MessageEvent, Nack, NackReason, Priority, SignatureAlg,
    SignedFields, SignedRequest,
};
pub use encoding::{decode_base64url, encode_base64url};
pub use error::ProtocolError;
pub use events::{
    ConversationEventBody, ForwardedFrom, FriendLinkEventBody, GroupEventBody, IdentityEventBody,
    MessageEventBody, RecoveryApproval, RecoveryApprovalContext, RecoveryQuorumConfigured,
    RecoveryQuorumMemberCommitment, RecoveryQuorumMemberKind, RecoveryQuorumProof, ReplyTo,
};
pub use fixtures::{
    FIXTURE_OBJECTS, FixtureObject, fixture_canonical_path, fixture_hash_path,
    fixture_invalid_signature_path, fixture_json_path, fixture_replay_path, fixture_sig_path,
};
pub use header::{
    HeaderField, HeaderFieldValue, HeaderKind, canonical_header_bytes, header_hash_base64url,
};
pub use protocol_object::ProtocolObject;
pub use ramflux_core::{ClientEventEnvelope as CoreClientEventEnvelope, DomainTag};
pub use replay::{
    MAX_CLOCK_SKEW_SECONDS, MAX_ENVELOPE_TTL_SECONDS, MAX_ENVELOPE_TTL_SECONDS_U32,
    REPLAY_WINDOW_SECONDS, ReplayGuard,
};
pub use signature::{verify_canonical_signature, verify_json_signature, verify_signed_fields};
pub use state::{CursorState, EventOrderingState, EventSortKey, GroupEpochState, event_sort_key};
pub use surfaces::{
    A2iControlEvent, A2uiCommand, A2uiEventType, A2uiSurfaceEvent, ActorType, BotEventBody,
    BotInstallGrant, BotManifest, ControlDomain, CreateSurfaceCommand, DeleteSurfaceCommand,
    DeleteSurfaceReason, FederationHandshake, HostingModel, KeyCustodyClass, McpCapability,
    McpGrant, NotificationDeliveryClass, NotificationWake, ObjectChunkRequest, ObjectManifest,
    PushPriority, RiskLevel, SafetyDisclosure, SurfaceType, UpdateComponentsCommand,
    UpdateDataModelCommand, surface_hash,
};

pub const CRATE_NAME: &str = "ramflux-protocol";
pub const SCHEMA_VERSION_V1: u32 = 1;

#[must_use]
pub const fn crate_name() -> &'static str {
    CRATE_NAME
}
