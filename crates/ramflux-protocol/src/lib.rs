// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ramflux C1 protocol types, canonical JSON, and fixture helpers.
pub mod agent_profile;

mod canonical_json;
pub mod client_discovery;
pub mod custody;
pub mod large_attachment;
pub mod message;
pub use client_discovery::*;
pub mod a2ui_state;
mod core_types;
mod device_address;
pub use device_address::{
    RootQualifiedDeviceIdentity, parse_qualified_device_id, qualified_device_id,
    validate_device_name,
};
pub mod dm_fs_v3;
pub mod domain;
mod encoding;
pub mod ephemeral;
mod error;
mod events;
mod group_device_roots;
pub use group_device_roots::{GROUP_DEVICE_ROOTS_EXTENSION, GroupDeviceRoots, group_event_member};
pub mod group_state;
pub use group_state::*;
mod fixtures;
pub mod group_permissions;
mod header;
pub mod home_migration;
mod home_node_migration;
mod i_json;
pub mod identity_keys;
pub use identity_keys::*;
pub mod object_relay_v3;
mod protocol_object;
mod replay;
pub mod schema_activation;
pub mod schema_profile;
mod signature;
mod state;
mod surfaces;
pub mod tasks;
pub mod text_safety;
pub use a2ui_state::*;
pub use i_json::{
    I_JSON_REJECTED, MAX_SAFE_JSON_INTEGER, decode_signed_ack_ijson, decode_signed_envelope_ijson,
    decode_signed_nack_ijson, i_json_rejection_body, is_i_json_rejection, parse_i_json,
    parse_i_json_secret, validate_i_json_bytes, validate_i_json_value,
};
pub use tasks::*;

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
pub use home_node_migration::{home_node_migration_proof_signed_bytes, migration_proof_hash};
pub use object_relay_v3::{
    GATEWAY_ISSUER_CERTIFICATE_SCHEMA, GatewayIssuerCertificate, OBJECT_ACCESS_GRANT_SCHEMA,
    OBJECT_RELAY_V3_PROOF_VERSION, OWNER_AUTHORIZATION_PROOF_SCHEMA, ObjectAccessGrant,
    ObjectRelayCapability, OwnerAuthorizationProof, RELAY_TOKEN_V3_AUDIENCE_RELAY,
    REQUESTER_POP_SCHEMA, RelayAuthorizationKind, RelayTokenV3, RequesterProofOfPossession,
    gateway_issuer_certificate_signing_bytes, object_access_grant_signing_bytes,
    owner_authorization_proof_signing_bytes, relay_token_v3_signing_bytes,
    requester_pop_signing_bytes,
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
    UpdateDataModelCommand, surface_hash, surface_snapshot_hash,
};

pub const CRATE_NAME: &str = "ramflux-protocol";
pub const SCHEMA_VERSION_V1: u32 = 1;

#[must_use]
pub const fn crate_name() -> &'static str {
    CRATE_NAME
}

/// Existing gateway rejection used by read-only pre-account probes.
pub const GATEWAY_FIRST_FRAME_NACK_REASON: &str = "first gateway frame must be open";
/// Negotiated capability for incarnation-bound durable session push.
pub const GATEWAY_SESSION_PUSH_CAPABILITY: &str = "gateway.session_push.v1";
/// Device-proof capability requesting typed forwarding acknowledgement.
pub const GATEWAY_FORWARD_ACK_CAPABILITY: &str = "gateway.forward_ack";
/// Legacy submit response emitted to clients that do not request typed forward acknowledgements.
pub const GATEWAY_FORWARDED_HOME_NODE_MIGRATED_REASON: &str = "forwarded_home_node_migrated";

pub mod principal_directory;
pub use principal_directory::{
    IdentityDirectoryReason, IdentityRegistrationFailure, IdentityRegistrationFailureBody,
    PrincipalLookupResponse,
};
mod envelope_sender;
mod sender_transcript;
pub use envelope_sender::{
    candidate_outer_sender_signed_bytes, envelope_sender_signed_bytes,
    verify_envelope_sender_signature,
};
pub use sender_transcript::{
    SENDER_TRANSCRIPT_PREFIX, SenderTranscript, SenderTranscriptMode, sender_origin_evidence,
    sender_signed_transcript, verify_sender_signature,
};

mod call;
pub use call::*;
mod call_resolution;
pub use call_resolution::*;

mod wake_v2;
pub use wake_v2::{
    CALL_MAX_LIFETIME_SECONDS, CLOCK_UNCERTAINTY_SECONDS, CallIntentAction, CallIntentKind,
    CallIntentV1, GATEWAY_CALL_INTENT_AUDIENCE, MAX_NOTIFICATION_ID_BYTES,
    MESSAGE_MAX_LIFETIME_SECONDS, NOTIFY_WAKE_AUDIENCE, SignedCallIntentV1, SignedWakeV2,
    WakeAction, WakeClass, WakeSignatureAlg, WakeV2, call_intent_digest, call_intent_signing_bytes,
    effective_expiry, parse_signed_call_intent_v1, parse_signed_wake_v2, remaining_whole_seconds,
    wake_request_digest, wake_signing_bytes,
};

mod identity_name;
mod identity_profile;
pub use identity_name::{
    DisplayNameSecurity, normalize_profile_display_name, profile_display_name_security,
    username_comparison_key,
};
pub use identity_profile::{SignedIdentityProfile, identity_profile_signing_bytes};

pub mod identity_profile_v2;
pub mod username_directory;

mod call_submission;
pub use call_submission::{CallSubmitCarrier, CallSubmitCarrierRef};
