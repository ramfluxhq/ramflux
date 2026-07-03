// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared node-service runtime helpers.

mod config;
mod error;
mod federation_crypto;
mod federation_delivery;
mod federation_state;
mod federation_store;
mod federation_types;
mod franking;
mod gateway_auth;
mod gateway_frames;
mod gateway_state;
mod home_node_migration;
mod http_support;
mod inbox;
mod lifecycle;
mod mesh_identity;
mod mvp1_registry;
mod notify;
mod notify_wal;
mod perf_metrics;
mod redb_store;
mod relay;
mod replay_guard;
mod retention;
mod router;
mod router_abuse;
mod router_lifecycle;
mod router_store;
mod service_signing;
mod session;
mod signaling;

pub use config::*;
pub use error::NodeCoreError;
pub use federation_crypto::{
    FederatedEnvelopeForwardVerifyTimings, sign_federated_envelope_forward,
    sign_federation_key_rotation, sign_federation_server_record,
    sign_federation_server_record_with_seed, verify_federated_envelope_forward,
    verify_federated_envelope_forward_with_timings, verify_federation_server_record,
};
pub(crate) use federation_crypto::{
    choose_srv_record, has_overlap, is_bootstrap_ip_literal, verify_federation_handshake,
    verify_federation_key_rotation, verify_node_invitation,
};
pub use federation_state::{BadNodeAdvisory, FederationTrustState};
pub use federation_store::{FederationOutboundSpoolEntry, FederationRedbStore};
pub use federation_types::*;
pub use franking::*;
pub use gateway_auth::{
    gateway_open_hash, validate_gateway_auth, validate_gateway_auth_with_replay,
};
pub use gateway_frames::*;
pub use gateway_state::*;
pub use home_node_migration::*;
pub use http_support::*;
pub use inbox::*;
pub use lifecycle::*;
pub use mesh_identity::*;
pub use mvp1_registry::*;
pub use notify::*;
pub use notify_wal::*;
pub use perf_metrics::{
    NodePerfSnapshot, node_perf_reset, node_perf_snapshot, record_gateway_submit_received,
    record_router_submit_decode_us, record_router_submit_dispatch_us,
    record_router_submit_lock_wait_us, record_router_submit_response_us,
    record_router_submit_save_us, record_router_submit_target_local_us,
    record_router_submit_target_remote_us, record_router_submit_total_us,
};
pub(crate) use perf_metrics::{
    record_router_ack, record_router_envelope_accepted, record_router_replay_guard_check,
    record_router_replay_guard_check_us, record_router_replay_guard_redb_write,
    record_router_save_begin_write_us, record_router_save_commit_us, record_router_save_inbox_us,
    record_router_save_mutation_us, record_router_save_replay_guard_us,
    record_router_save_total_us, record_router_snapshot_save,
};
pub(crate) use redb_store::{
    FEDERATION_BAD_NODE_ADVISORY_KEY, FEDERATION_DISCOVERY_PIN_KEY,
    FEDERATION_HANDSHAKE_REPLAY_KEY, FEDERATION_INBOUND_FORWARD_SEEN_TABLE,
    FEDERATION_INVITATION_STATE_KEY, FEDERATION_LIFECYCLE_TOMBSTONE_KEY,
    FEDERATION_NEGOTIATED_CAPABILITIES_KEY, FEDERATION_NODE_SIGNING_SEED_KEY,
    FEDERATION_OUTBOUND_SPOOL_TABLE, FEDERATION_ROUTE_STATE_KEY, FEDERATION_STATE_TABLE,
    GATEWAY_CHALLENGE_STATE_KEY, GATEWAY_DELIVERY_FRAME_QUEUE_KEY, GATEWAY_PRE_AUTH_METRICS_KEY,
    GATEWAY_PRE_AUTH_POLICY_KEY, GATEWAY_PRE_AUTH_RATE_STATE_KEY, GATEWAY_REPLAY_GUARD_STATE_KEY,
    GATEWAY_RESUME_TOKEN_INDEX_KEY, GATEWAY_SESSION_CHECKPOINT_KEY, GATEWAY_STATE_TABLE,
    NOTIFY_CREDENTIAL_TABLE, NOTIFY_PROVIDER_ATTEMPT_TABLE, NOTIFY_QUEUE_ENTRY_TABLE,
    NOTIFY_QUEUE_KEY, NOTIFY_QUEUE_TABLE, NOTIFY_ROUTE_TABLE, RELAY_CACHE_KEY, RELAY_CACHE_TABLE,
    RELAY_CHUNK_ENTRY_TABLE, RELAY_TOMBSTONE_TABLE, RETENTION_STATE_KEY, RETENTION_STATE_TABLE,
    ROUTER_ABUSE_REPORT_KEY, ROUTER_ABUSE_REPORT_TABLE, ROUTER_CURSOR_STATE_TABLE,
    ROUTER_DEACTIVATED_TARGET_TABLE, ROUTER_DEACTIVATED_TARGETS_KEY, ROUTER_DELETED_TARGET_TABLE,
    ROUTER_DELETED_TARGETS_KEY, ROUTER_HOME_NODE_MIGRATION_KEY, ROUTER_IDENTITY_LINEAGE_EVENTS_KEY,
    ROUTER_IDENTITY_LINEAGE_HEADS_KEY, ROUTER_IDENTITY_REGISTRY_KEY, ROUTER_INBOX_ENTRY_TABLE,
    ROUTER_INBOX_SLICE_KEY, ROUTER_LIFECYCLE_RECORD_TABLE, ROUTER_LIFECYCLE_STATE_KEY,
    ROUTER_LIFECYCLE_TOMBSTONE_KEY, ROUTER_LIFECYCLE_TOMBSTONE_TABLE,
    ROUTER_REPLAY_GUARD_STATE_KEY, ROUTER_REPLAY_TUPLE_TABLE, ROUTER_SESSION_CHECKPOINT_KEY,
    ROUTER_SESSION_ENTRY_TABLE, ROUTER_SNAPSHOT_TABLE, SIGNALING_STATE_KEY, SIGNALING_STATE_TABLE,
    load_snapshot, open_redb_with_table, save_snapshot, save_snapshot_batch,
    serialize_snapshot_value,
};
pub use relay::*;
pub use replay_guard::*;
pub use retention::*;
pub use router::*;
pub use router_store::RouterRedbStore;
pub use service_signing::*;
pub use session::*;
pub use signaling::*;

#[cfg(test)]
mod tests;
