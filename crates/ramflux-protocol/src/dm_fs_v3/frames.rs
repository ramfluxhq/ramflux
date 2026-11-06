// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant canonical public service documents; authentication belongs to consumers.
use super::lease::encode_fields;
use super::publication::{field, fixed, owned_text as text, scan_publication};
use super::{
    DecodeError, DmFsV3Refusal, NativePrekeyAction, NativePrekeyRequest, OwnerPrekeyStatus,
    OwnerPrekeyUpdate, OwnerStatusQuery, PrekeyLeaseIntent, PrekeyLeaseResult, WireType,
};
use crate::custody::{RetryHint, RetryScope};
/// Closed stable wire values for `NativePrekeyResultKind`; unknown and empty codes reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePrekeyResultKind {
    /// Wire code `lease`.
    Lease,
    /// Wire code `publish`.
    Publish,
    /// Wire code `status`.
    Status,
    /// Wire code `refusal`.
    Refusal,
}
impl NativePrekeyResultKind {
    /// Stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lease => "lease",
            Self::Publish => "publish",
            Self::Status => "status",
            Self::Refusal => "refusal",
        }
    }
}
impl TryFrom<&str> for NativePrekeyResultKind {
    type Error = DecodeError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "lease" => Ok(Self::Lease),
            "publish" => Ok(Self::Publish),
            "status" => Ok(Self::Status),
            "refusal" => Ok(Self::Refusal),
            _ => Err(DecodeError::Value),
        }
    }
}
/// Canonical `NativePrekeyLease` public fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrekeyLease {
    pub correlation_id: [u8; 32],
    pub request: NativePrekeyRequest,
    pub intent: PrekeyLeaseIntent,
}
impl NativePrekeyLease {
    /// Encode canonical bytes.
    /// # Errors
    /// Rejects sizes, invalid values and incompatible field combinations.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        encode_fields(
            WireType::NativePrekeyLease,
            &[&self.correlation_id, &self.request.to_bytes()?, &self.intent.to_bytes()?],
        )
    }
    /// Decode bounded canonical bytes before allocation.
    /// # Errors
    /// Rejects malformed framing, counts, codes and incompatible fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let view = scan_publication(WireType::NativePrekeyLease, bytes)?;
        let value = Self {
            correlation_id: fixed(field(view, 1)?)?,
            request: NativePrekeyRequest::from_bytes(field(view, 2)?)?,
            intent: PrekeyLeaseIntent::from_bytes(field(view, 3)?)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), DecodeError> {
        if self.request.action != NativePrekeyAction::Lease {
            return Err(DecodeError::Value);
        }
        Ok(())
    }
}
/// Canonical `NativePrekeyPublish` public fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrekeyPublish {
    pub correlation_id: [u8; 32],
    pub request: NativePrekeyRequest,
    pub update: OwnerPrekeyUpdate,
}
impl NativePrekeyPublish {
    /// Encode canonical bytes.
    /// # Errors
    /// Rejects sizes, invalid values and incompatible field combinations.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        encode_fields(
            WireType::NativePrekeyPublish,
            &[&self.correlation_id, &self.request.to_bytes()?, &self.update.to_bytes()?],
        )
    }
    /// Decode bounded canonical bytes before allocation.
    /// # Errors
    /// Rejects malformed framing, counts, codes and incompatible fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let view = scan_publication(WireType::NativePrekeyPublish, bytes)?;
        let value = Self {
            correlation_id: fixed(field(view, 1)?)?,
            request: NativePrekeyRequest::from_bytes(field(view, 2)?)?,
            update: OwnerPrekeyUpdate::from_bytes(field(view, 3)?)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), DecodeError> {
        if self.request.action != NativePrekeyAction::Publish {
            return Err(DecodeError::Value);
        }
        Ok(())
    }
}
/// Canonical `NativePrekeyStatus` public fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrekeyStatus {
    pub correlation_id: [u8; 32],
    pub request: NativePrekeyRequest,
    pub query: OwnerStatusQuery,
}
impl NativePrekeyStatus {
    /// Encode canonical bytes.
    /// # Errors
    /// Rejects sizes, invalid values and incompatible field combinations.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        encode_fields(
            WireType::NativePrekeyStatus,
            &[&self.correlation_id, &self.request.to_bytes()?, &self.query.to_bytes()?],
        )
    }
    /// Decode bounded canonical bytes before allocation.
    /// # Errors
    /// Rejects malformed framing, counts, codes and incompatible fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let view = scan_publication(WireType::NativePrekeyStatus, bytes)?;
        let value = Self {
            correlation_id: fixed(field(view, 1)?)?,
            request: NativePrekeyRequest::from_bytes(field(view, 2)?)?,
            query: OwnerStatusQuery::from_bytes(field(view, 3)?)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), DecodeError> {
        if self.request.action != NativePrekeyAction::Status {
            return Err(DecodeError::Value);
        }
        Ok(())
    }
}
/// Canonical `NativePrekeyResult` public fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePrekeyResult {
    pub correlation_id: [u8; 32],
    pub request_hash: [u8; 32],
    pub result_kind: NativePrekeyResultKind,
    pub lease: Option<PrekeyLeaseResult>,
    pub status: Option<OwnerPrekeyStatus>,
    pub refusal: Option<DmFsV3Refusal>,
    pub retry: Option<RetryHint>,
    pub node_id: String,
    pub session_id: String,
}
impl NativePrekeyResult {
    /// Encode canonical bytes.
    /// # Errors
    /// Rejects sizes, invalid values and incompatible field combinations.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        encode_fields(
            WireType::NativePrekeyResult,
            &[
                &self.correlation_id,
                &self.request_hash,
                self.result_kind.as_str().as_bytes(),
                &encode_optional(self.lease.as_ref(), PrekeyLeaseResult::to_bytes)?,
                &encode_optional(self.status.as_ref(), OwnerPrekeyStatus::to_bytes)?,
                self.refusal.map_or("", DmFsV3Refusal::as_str).as_bytes(),
                retry_scope(self.retry).as_bytes(),
                &self.retry.map_or(0, |hint| hint.clamped().retry_after_ms).to_be_bytes(),
                self.node_id.as_bytes(),
                self.session_id.as_bytes(),
            ],
        )
    }
    /// Decode bounded canonical bytes before allocation.
    /// # Errors
    /// Rejects malformed framing, counts, codes and incompatible fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let view = scan_publication(WireType::NativePrekeyResult, bytes)?;
        let value = Self {
            correlation_id: fixed(field(view, 1)?)?,
            request_hash: fixed(field(view, 2)?)?,
            result_kind: NativePrekeyResultKind::try_from(text(field(view, 3)?)?.as_str())?,
            lease: decode_optional(field(view, 4)?, PrekeyLeaseResult::from_bytes)?,
            status: decode_optional(field(view, 5)?, OwnerPrekeyStatus::from_bytes)?,
            refusal: match text(field(view, 6)?)?.as_str() {
                "" => None,
                code => Some(DmFsV3Refusal::try_from(code)?),
            },
            retry: decode_retry(field(view, 7)?, field(view, 8)?)?,
            node_id: text(field(view, 9)?)?,
            session_id: text(field(view, 10)?)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), DecodeError> {
        validate_result(self)
    }
}

pub(super) fn encode_optional<T>(
    value: Option<&T>,
    encode: impl FnOnce(&T) -> Result<Vec<u8>, DecodeError>,
) -> Result<Vec<u8>, DecodeError> {
    let mut bytes = vec![u8::from(value.is_some())];
    if let Some(value) = value {
        bytes.extend_from_slice(&encode(value)?);
    }
    Ok(bytes)
}
pub(super) fn decode_optional<T>(
    bytes: &[u8],
    decode: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
) -> Result<Option<T>, DecodeError> {
    match bytes.split_first() {
        Some((0, [])) => Ok(None),
        Some((1, body)) => Ok(Some(decode(body)?)),
        _ => Err(DecodeError::Value),
    }
}

fn retry_scope(retry: Option<RetryHint>) -> &'static str {
    match retry.map(|hint| hint.scope) {
        None => "",
        Some(RetryScope::PreAuthSource) => "pre_auth_source",
        Some(RetryScope::NodeCapacity) => "node_capacity",
    }
}
fn decode_retry(scope: &[u8], after: &[u8]) -> Result<Option<RetryHint>, DecodeError> {
    let after = u32::from_be_bytes(fixed(after)?);
    let scope = match scope {
        b"" if after == 0 => return Ok(None),
        b"pre_auth_source" => RetryScope::PreAuthSource,
        b"node_capacity" => RetryScope::NodeCapacity,
        _ => return Err(DecodeError::Value),
    };
    Ok(Some(RetryHint::new(scope, after)))
}
fn validate_result(value: &NativePrekeyResult) -> Result<(), DecodeError> {
    let valid = match value.result_kind {
        NativePrekeyResultKind::Lease => {
            value.lease.is_some() && value.status.is_none() && value.refusal.is_none()
        }
        NativePrekeyResultKind::Status => {
            value.lease.is_none() && value.status.is_some() && value.refusal.is_none()
        }
        NativePrekeyResultKind::Publish => {
            value.lease.is_none() && value.status.is_none() && value.refusal.is_none()
        }
        NativePrekeyResultKind::Refusal => {
            value.lease.is_none() && value.status.is_none() && value.refusal.is_some()
        }
    };
    if !valid || (value.retry.is_some() && value.refusal != Some(DmFsV3Refusal::Busy)) {
        return Err(DecodeError::Value);
    }
    Ok(())
}
impl NativePrekeyResult {
    /// Check a decoded result against the authenticated outstanding request context.
    /// The caller supplies the verified request hash; this method does not authenticate it.
    /// # Errors
    /// Rejects a mismatched correlation, request hash, audience, session or success kind.
    pub fn validate_for(
        &self,
        correlation_id: &[u8; 32],
        request_hash: &[u8; 32],
        request: &NativePrekeyRequest,
    ) -> Result<Option<RetryHint>, DecodeError> {
        self.validate()?;
        let kind_matches = matches!(
            (request.action, self.result_kind),
            (_, NativePrekeyResultKind::Refusal)
                | (NativePrekeyAction::Lease, NativePrekeyResultKind::Lease)
                | (NativePrekeyAction::Publish, NativePrekeyResultKind::Publish)
                | (NativePrekeyAction::Status, NativePrekeyResultKind::Status)
        );
        if self.correlation_id != *correlation_id
            || self.request_hash != *request_hash
            || self.node_id != request.node_id
            || self.session_id != request.session_id
            || !kind_matches
        {
            return Err(DecodeError::Value);
        }
        Ok(self.retry.map(RetryHint::clamped))
    }
}

/// Standalone JSON service carrier; no production gateway enum attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativePrekeyFrame {
    /// Signed lease request.
    Lease(Box<NativePrekeyLease>),
    /// Signed publication request.
    Publish(Box<NativePrekeyPublish>),
    /// Signed owner status query.
    Status(Box<NativePrekeyStatus>),
    /// Correlated reply.
    Result(Box<NativePrekeyResult>),
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonCarrier {
    frame_type: String,
    payload: String,
}
impl NativePrekeyFrame {
    /// Canonical JSON/base64url carrier bytes.
    /// # Errors
    /// Rejects invalid canonical payloads or JSON serialization failure.
    pub fn to_json(&self) -> Result<Vec<u8>, DecodeError> {
        use base64::Engine;
        let (frame_type, raw) = match self {
            Self::Lease(value) => ("native_prekey_lease", value.to_bytes()?),
            Self::Publish(value) => ("native_prekey_publish", value.to_bytes()?),
            Self::Status(value) => ("native_prekey_status", value.to_bytes()?),
            Self::Result(value) => ("native_prekey_result", value.to_bytes()?),
        };
        let carrier = JsonCarrier {
            frame_type: frame_type.to_owned(),
            payload: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
        };
        serde_json::to_vec(&carrier).map_err(|_| DecodeError::Value)
    }
    /// Strict bounded JSON with canonical unpadded base64url payload.
    /// # Errors
    /// Rejects unknown/empty labels, duplicate/unknown fields, bad base64 and oversized frames.
    pub fn from_json(bytes: &[u8]) -> Result<Self, DecodeError> {
        use base64::Engine;
        // Largest binary carrier is publication; add exact compact-JSON overhead.
        const MAX_JSON: usize = 70_656;
        if bytes.len() > MAX_JSON {
            return Err(DecodeError::TypeCeiling);
        }
        let carrier: JsonCarrier = serde_json::from_slice(bytes).map_err(|_| DecodeError::Value)?;
        let (kind, json_ceiling) = match carrier.frame_type.as_str() {
            "native_prekey_lease" => (WireType::NativePrekeyLease, 6_144),
            "native_prekey_publish" => (WireType::NativePrekeyPublish, 70_656),
            "native_prekey_status" => (WireType::NativePrekeyStatus, 26_624),
            "native_prekey_result" => (WireType::NativePrekeyResult, 55_296),
            _ => return Err(DecodeError::Value),
        };
        if bytes.len() > json_ceiling {
            return Err(DecodeError::TypeCeiling);
        }
        if carrier.payload.len() > kind.ceiling().div_ceil(3) * 4 {
            return Err(DecodeError::TypeCeiling);
        }
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&carrier.payload)
            .map_err(|_| DecodeError::Value)?;
        if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw) != carrier.payload {
            return Err(DecodeError::Value);
        }
        match kind {
            WireType::NativePrekeyLease => {
                Ok(Self::Lease(Box::new(NativePrekeyLease::from_bytes(&raw)?)))
            }
            WireType::NativePrekeyPublish => {
                Ok(Self::Publish(Box::new(NativePrekeyPublish::from_bytes(&raw)?)))
            }
            WireType::NativePrekeyStatus => {
                Ok(Self::Status(Box::new(NativePrekeyStatus::from_bytes(&raw)?)))
            }
            WireType::NativePrekeyResult => {
                Ok(Self::Result(Box::new(NativePrekeyResult::from_bytes(&raw)?)))
            }
            _ => Err(DecodeError::Header),
        }
    }
}
