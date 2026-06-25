#[derive(Debug, thiserror::Error)]
pub enum NodeCoreError {
    #[error("--config requires a path")]
    MissingConfigPath,
    #[error("cannot read config {path}: {source}")]
    ConfigRead { path: std::path::PathBuf, source: std::io::Error },
    #[error("cannot parse config {path}: {source}")]
    ConfigParse { path: std::path::PathBuf, source: toml::de::Error },
    #[error("cannot create node store directory {path}: {source}")]
    StoreDirectory { path: std::path::PathBuf, source: std::io::Error },
    #[error("redb operation failed: {0}")]
    Redb(String),
    #[error("router snapshot serialization failed: {0}")]
    SnapshotSerialization(String),
    #[error("config service_id {actual} does not match expected {expected}")]
    ServiceIdMismatch { expected: String, actual: String },
    #[error("config mesh.allowed_service_ids does not include {0}")]
    MissingAllowedServiceId(String),
    #[error("mesh peer {peer_spiffe_uri} is not authorized for local service {local_service_id}")]
    MeshPeerUnauthorized { local_service_id: String, peer_spiffe_uri: String },
    #[error("config mesh.endpoints is empty")]
    EmptyMeshEndpoints,
    #[error("stale session update for {target_delivery_id}")]
    StaleSessionUpdate { target_delivery_id: String },
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("envelope not found: {0}")]
    EnvelopeNotFound(String),
    #[error(
        "envelope target mismatch for {envelope_id}: expected {expected_target_delivery_id}, actual {actual_target_delivery_id}"
    )]
    EnvelopeTargetMismatch {
        envelope_id: String,
        expected_target_delivery_id: String,
        actual_target_delivery_id: String,
    },
    #[error("node replay guard rejected request: {0}")]
    ReplayGuard(String),
    #[error("envelope TTL expired: {envelope_id}")]
    TtlExpired { envelope_id: String },
    #[error("itest HTTP operation failed: {0}")]
    ItestHttp(String),
    #[error("itest HTTP JSON failed: {0}")]
    ItestJson(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
}
