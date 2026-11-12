// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Framed born-v3 registration/session requests; these never carry a legacy branch proof.

use super::{
    BindingMode, BranchChallenge, BranchProofV3, DeviceRef, DeviceSet, Envelope,
    NodeIdentityRecord, RelayAcceptance,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_CUSTODY_FRAME_BYTES: usize = 5 * 1024 * 1024;
pub const CUSTODY_RPC_PATH: &str = "/v3/custody/rpc";
pub const CUSTODY_REQUEST_PATH: &str = "/v3/custody/session";
/// Exact public historical authority lookup, scoped to delayed contact consent.
pub const CUSTODY_HISTORY_PATH_PREFIX: &str = "/mvp1/custody-history/";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub record: Envelope<DeviceSet>,
    pub compacted_ids: Option<Vec<String>>,
}
/// A one-use proof grants either authenticated reading or account management.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPurpose {
    Read,
    Manage,
}
impl MigrationPurpose {
    #[must_use]
    pub const fn capability(self) -> &'static str {
        match self {
            Self::Read => "message",
            Self::Manage => "register",
        }
    }
    #[must_use]
    pub const fn allows(self, action: crate::home_migration::Action) -> bool {
        match self {
            Self::Read => matches!(
                action,
                crate::home_migration::Action::Status
                    | crate::home_migration::Action::Resolve
                    | crate::home_migration::Action::Fence
            ),
            Self::Manage => true,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyProofAction {
    Publish {
        publication: Box<Publication>,
    },
    Register {
        prekey_bundle: Value,
    },
    OpenSession,
    HomeMigration {
        control_hash: String,
        publication: Box<Publication>,
        purpose: MigrationPurpose,
    },
    /// Dormant native carrier; authority/admission semantics belong to its consumer.
    PrekeyStatus {
        #[serde(
            deserialize_with = "native_carrier::query",
            serialize_with = "native_carrier::serialize_query"
        )]
        query: String,
    },
    /// Dormant native carrier, never a legacy Register prekey bundle.
    RegisterUpdate {
        #[serde(
            deserialize_with = "native_carrier::update",
            serialize_with = "native_carrier::serialize_update"
        )]
        update: String,
    },
    /// Dormant native pairing carrier (P01W).
    PairingIssue {
        request: Box<super::pairing::native::Issue>,
    },
    /// Dormant native pairing carrier (P01W).
    PairingCreate {
        request: Box<super::pairing::native::Create>,
    },
}
impl CustodyProofAction {
    #[must_use]
    pub const fn capability(&self) -> &'static str {
        match self {
            Self::Publish { .. }
            | Self::Register { .. }
            | Self::PrekeyStatus { .. }
            | Self::RegisterUpdate { .. }
            | Self::PairingIssue { .. }
            | Self::PairingCreate { .. } => "register",
            Self::HomeMigration { purpose, .. } => purpose.capability(),
            Self::OpenSession => "message",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodySessionAction {
    Lookup { device_ref: DeviceRef },
    Submit { envelope: Box<crate::Envelope> },
    Inbox { after_seq: u64, limit: u32 },
    Ack { ack: Box<crate::Ack> },
    HomeMigration { request: Box<crate::home_migration::Request> },
    Close,
}
/// Durable new-principal daily window identified by the receiving node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityScope {
    PrefixDaily,
    GlobalDaily,
}

/// Server-owned reset time; no address or other admission budget is disclosed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityHint {
    pub scope: CapacityScope,
    pub resets_at_unix: u64,
}

/// The admission resource whose server-owned retry interval must be respected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryScope {
    PreAuthSource,
    NodeCapacity,
}

/// Admission retry interval; receivers clamp untrusted values again before waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryHint {
    pub scope: RetryScope,
    pub retry_after_ms: u32,
}
impl RetryHint {
    pub const MIN_RETRY_AFTER_MS: u32 = 1_000;
    pub const MAX_RETRY_AFTER_MS: u32 = 3_600_000;

    #[must_use]
    pub const fn new(scope: RetryScope, retry_after_ms: u32) -> Self {
        Self { scope, retry_after_ms }.clamped()
    }

    #[must_use]
    pub const fn clamped(self) -> Self {
        let retry_after_ms = if self.retry_after_ms < Self::MIN_RETRY_AFTER_MS {
            Self::MIN_RETRY_AFTER_MS
        } else if self.retry_after_ms > Self::MAX_RETRY_AFTER_MS {
            Self::MAX_RETRY_AFTER_MS
        } else {
            self.retry_after_ms
        };
        Self { scope: self.scope, retry_after_ms }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyClientFrame {
    CustodyOpen {
        binding_mode: BindingMode,
    },
    NodeIdentity {
        record_hash: Option<String>,
    },
    Challenge {
        device_ref: DeviceRef,
        action: CustodyProofAction,
    },
    Prove {
        action: CustodyProofAction,
        proof: Box<Envelope<BranchProofV3>>,
    },
    Request {
        session_id: String,
        request: Box<crate::SignedRequest>,
        action: CustodySessionAction,
    },
    /// Switch this authenticated connection into the ordinary gateway session protocol.
    GatewayHandoff {
        session_id: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyRefusal {
    Unsupported,
    InvalidInput,
    AuthorityUnavailable,
    PrincipalIdTaken,
    ChallengeUnknown,
    ChallengeExpired,
    Replay,
    BindingRefused,
    SessionRequired,
    SessionExpired,
    UpdateRequired,
    Capacity,
    /// Temporary listener saturation; retry on a fresh connection after backoff.
    Busy,
    PersistenceUnavailable,
    HomeMigration {
        reason: crate::home_migration::Refusal,
        nack: Option<Box<crate::Nack>>,
    },
    // Append variants to preserve the existing postcard discriminants.
    AbortedRetrySafe,
    CapacityRetryAfter {
        retry_after_ms: u64,
    },
    IdempotencyConflict,
    PayloadTooLarge,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodySession {
    pub session_id: String,
    pub device_ref: DeviceRef,
    pub target_delivery_id: String,
    pub record_hash: String,
    pub proof_hash: String,
    pub binding_mode: BindingMode,
    pub expires_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyPeer {
    pub publication: Publication,
    pub custodian_publication: Option<Publication>,
    pub device_ref: DeviceRef,
    pub target_delivery_id: String,
    pub prekey_bundle: Value,
}
/// Signed native account evidence, independently checked against the caller's durable pins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAuthority {
    pub publication: Publication,
    pub custodian_publication: Option<Publication>,
}
/// Complete v3 directory evidence and the currently registered branch prekeys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyManifest {
    pub publication: Publication,
    pub custodian_publication: Option<Publication>,
    pub devices: Vec<CustodyManifestDevice>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyManifestDevice {
    pub device_ref: DeviceRef,
    pub target_delivery_id: String,
    pub prekey_bundle: Value,
    /// The same signed declaration endorsed by the attached custody publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_layer: Option<super::SignedLayerDeclaration>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyServerFrame {
    NodeIdentity {
        record: Box<Envelope<NodeIdentityRecord>>,
        audience: String,
        binding_mode: BindingMode,
        proxy_key_custody: Option<String>,
    },
    Challenge {
        challenge: BranchChallenge,
    },
    Published {
        record_hash: String,
    },
    Registered {
        device_ref: DeviceRef,
        target_delivery_id: String,
    },
    SessionEstablished {
        session: CustodySession,
    },
    Peer {
        peer: Box<CustodyPeer>,
    },
    Submitted {
        envelope_id: String,
        outcome: String,
    },
    Inbox {
        entries: Vec<Value>,
    },
    Acked {
        inbox_seq: u64,
    },
    HomeMigration {
        response: Box<crate::home_migration::Response>,
    },
    /// Dormant native pairing reply. Never a session, publication, or account grant.
    Pairing {
        reply: Box<super::pairing::native::PairingReply>,
    },
    Closed,
    Refused {
        code: CustodyRefusal,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capacity: Option<CapacityHint>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry: Option<RetryHint>,
    },
    /// Web listener only: the context the device must commit to in `transport_binding`.
    /// Appended last to keep the existing variant order.
    WebBinding {
        context: super::WebOriginBindingV1,
    },
}
/// Authenticated internal mesh request. Direct-exporter evidence is deliberately
/// absent: only the listener holding the actual TLS connection may supply it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyMeshRequest {
    Disconnect {
        connection_id: String,
    },
    NodeIdentity {
        record_hash: Option<String>,
    },
    Challenge {
        device_ref: DeviceRef,
        action: CustodyProofAction,
        binding_mode: BindingMode,
        client_source: String,
        connection_id: String,
    },
    Prove {
        action: CustodyProofAction,
        proof: Box<Envelope<BranchProofV3>>,
        receipt: Option<Box<Envelope<RelayAcceptance>>>,
        connection_id: String,
    },
    Request {
        connection_id: String,
        session_id: String,
        request: Box<crate::SignedRequest>,
        action: CustodySessionAction,
    },
    /// A `web_origin_bound` proof together with the context the web listener itself
    /// authored for that connection. Only the gateway's web listener may send this.
    ProveWeb {
        action: CustodyProofAction,
        proof: Box<Envelope<BranchProofV3>>,
        context: super::WebOriginBindingV1,
        connection_id: String,
    },
}

impl std::fmt::Display for CustodyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CustodyRefusal {}
/// Hash the complete operation before issuing its one-use challenge.
/// # Errors
/// Rejects canonical serialization failure.
pub fn custody_action_hash(action: &CustodyProofAction) -> Result<String, crate::ProtocolError> {
    super::framed_hash("ramflux.identity.custody_action.v1", action)
}
/// Hash the complete per-session operation for its signed request.
/// # Errors
/// Rejects canonical serialization failure.
pub fn custody_session_action_hash(
    action: &CustodySessionAction,
) -> Result<String, crate::ProtocolError> {
    super::framed_hash("ramflux.identity.custody_session_action.v1", action)
}

#[cfg(test)]
mod capacity_hint_tests {
    use super::*;
    #[test]
    fn capacity_hint_round_trips_and_old_refusal_shape_still_parses()
    -> Result<(), Box<dyn std::error::Error>> {
        let old = serde_json::json!({"frame_type":"refused", "code":"capacity"});
        let absent: CustodyServerFrame = serde_json::from_value(old.clone())?;
        assert_eq!(
            absent,
            CustodyServerFrame::Refused {
                code: CustodyRefusal::Capacity,
                capacity: None,
                retry: None,
            }
        );
        assert_eq!(serde_json::to_value(&absent)?, old);
        for scope in [CapacityScope::PrefixDaily, CapacityScope::GlobalDaily] {
            let frame = CustodyServerFrame::Refused {
                code: CustodyRefusal::Capacity,
                capacity: Some(CapacityHint { scope, resets_at_unix: 172_800 }),
                retry: None,
            };
            let bytes = serde_json::to_vec(&frame)?;
            assert_eq!(serde_json::from_slice::<CustodyServerFrame>(&bytes)?, frame);
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
            assert_eq!(value["capacity"]["resets_at_unix"], 172_800);
            assert_eq!(
                value["capacity"]["scope"],
                if scope == CapacityScope::PrefixDaily { "prefix_daily" } else { "global_daily" }
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod retry_hint_tests {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OldRefusal {
        frame_type: String,
        code: CustodyRefusal,
    }

    #[test]
    fn refused_retry_hint_roundtrip_and_strict_decode() -> Result<(), Box<dyn std::error::Error>> {
        let vector = br#"{"frame_type":"refused","code":"busy","retry":{"scope":"pre_auth_source","retry_after_ms":2000}}"#;
        let frame: CustodyServerFrame = super::super::decode(vector, 4096)?;
        assert_eq!(
            frame,
            CustodyServerFrame::Refused {
                code: CustodyRefusal::Busy,
                capacity: None,
                retry: Some(RetryHint { scope: RetryScope::PreAuthSource, retry_after_ms: 2000 }),
            }
        );
        assert_eq!(serde_json::to_value(&frame)?, serde_json::from_slice::<Value>(vector)?);
        let old = br#"{"frame_type":"refused","code":"busy"}"#;
        assert_eq!(
            super::super::decode::<CustodyServerFrame>(old, 4096)?,
            CustodyServerFrame::Refused { code: CustodyRefusal::Busy, capacity: None, retry: None }
        );
        for field in [
            serde_json::json!({"scope":"account","retry_after_ms":2000}),
            serde_json::json!({"scope":"node_capacity","retry_after_ms":2000,"unknown":true}),
        ] {
            let bytes = serde_json::to_vec(
                &serde_json::json!({"frame_type":"refused","code":"busy","retry":field}),
            )?;
            assert!(super::super::decode::<CustodyServerFrame>(&bytes, 4096).is_err());
        }
        let legacy: OldRefusal = serde_json::from_slice(old)?;
        assert_eq!(legacy.frame_type, "refused");
        assert_eq!(legacy.code, CustodyRefusal::Busy);
        assert!(serde_json::from_slice::<OldRefusal>(vector).is_err());
        Ok(())
    }
}

// Keep the enclosing action/proof in custody JCS. Only the embedded value is RFS1.
mod native_carrier {
    use crate::dm_fs_v3::{OwnerPrekeyUpdate, OwnerStatusQuery, WireType};
    use serde::{Deserialize, Deserializer, Serializer};
    fn validate(value: &str, update: bool) -> Result<(), &'static str> {
        let kind = if update { WireType::OwnerPrekeyUpdate } else { WireType::OwnerStatusQuery };
        let cap = kind.ceiling().min(65_536);
        if value.len() > (cap * 4).div_ceil(3) {
            return Err("native custody carrier byte limit");
        }
        let bytes =
            crate::decode_base64url(value).map_err(|_| "native custody carrier base64url")?;
        if bytes.len() > cap || crate::encode_base64url(&bytes) != value {
            return Err("native custody carrier encoding");
        }
        if update {
            OwnerPrekeyUpdate::from_bytes(&bytes).map(|_| ())
        } else {
            OwnerStatusQuery::from_bytes(&bytes).map(|_| ())
        }
        .map_err(|_| "native custody carrier RFS1")
    }
    pub(super) fn query<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        let value = String::deserialize(d)?;
        validate(&value, false).map_err(serde::de::Error::custom)?;
        Ok(value)
    }
    pub(super) fn update<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        let value = String::deserialize(d)?;
        validate(&value, true).map_err(serde::de::Error::custom)?;
        Ok(value)
    }
    pub(super) fn serialize_query<S: Serializer>(value: &str, s: S) -> Result<S::Ok, S::Error> {
        validate(value, false).map_err(serde::ser::Error::custom)?;
        s.serialize_str(value)
    }
    pub(super) fn serialize_update<S: Serializer>(value: &str, s: S) -> Result<S::Ok, S::Error> {
        validate(value, true).map_err(serde::ser::Error::custom)?;
        s.serialize_str(value)
    }
}
