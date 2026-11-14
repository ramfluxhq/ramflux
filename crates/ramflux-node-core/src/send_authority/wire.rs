// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed internal schemas. Callers authenticate service/node roles before decoding.

use super::{AuthorityMutation, SendAuthorityError, storage};
use serde::{Deserialize, Serialize};

pub const MAX_AUTHORITY_GENERATION: u64 = 9_007_199_254_740_991;
pub const SEND_AUTHORITY_BOOT_PATH: &str = "/internal/notify/send-authority/boot/v1";
pub const SEND_AUTHORITY_STATE_PATH: &str = "/internal/notify/send-authority/state/v1";
pub const SEND_AUTHORITY_PATH: &str = "/internal/notify/send-authority/v1";
pub const NOTIFY_OWNER_READ_PATH: &str = "/internal/router/notify-owner/v1";
pub const NOTIFY_CALL_READ_PATH: &str = "/internal/gateway/notify-call/v1";

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityScope {
    Owner { target_delivery_id: String },
    Call { start_digest: String },
    TargetRoutes { target_delivery_id: String },
    Credential { credential_id: String },
}

impl AuthorityScope {
    pub(super) fn key(&self) -> Result<String, SendAuthorityError> {
        match self {
            Self::Call { start_digest } => validate_digest(start_digest)?,
            Self::Owner { target_delivery_id } | Self::TargetRoutes { target_delivery_id } => {
                validate_id(target_delivery_id)?;
            }
            Self::Credential { credential_id } => validate_id(credential_id)?,
        }
        String::from_utf8(ramflux_protocol::canonical_json_bytes(self).map_err(storage)?)
            .map_err(storage)
    }

    #[must_use]
    pub const fn origin_service(&self) -> Option<&'static str> {
        match self {
            Self::Owner { .. } => Some("ramflux-router"),
            Self::Call { .. } => Some("ramflux-gateway"),
            Self::TargetRoutes { .. } | Self::Credential { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityPhase {
    Stable,
    Closing,
    Committed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityControlPhase {
    Fence,
    ResyncFence,
    Publish,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityReadPurpose {
    Current,
    FenceCheck,
    PublishCheck,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityState {
    pub generation: u64,
    #[serde(deserialize_with = "required_nullable")]
    pub operation_id: Option<String>,
    pub phase: AuthorityPhase,
    #[serde(deserialize_with = "required_nullable")]
    pub record_hash: Option<String>,
}

impl AuthorityState {
    pub(super) fn is_empty(&self) -> bool {
        self.generation == 0
            && self.operation_id.is_none()
            && self.record_hash.is_none()
            && self.phase == AuthorityPhase::Stable
    }
    pub(super) fn matches(&self, row: &AuthorityMutation) -> bool {
        self.generation == row.generation
            && self.operation_id.as_ref() == Some(&row.operation_id)
            && self.phase == row.phase
            && self.record_hash.as_ref() == Some(&row.desired_record_hash)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPin {
    pub scope: AuthorityScope,
    pub generation: u64,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityRecord {
    Owner {
        version: u32,
        target_delivery_id: String,
        #[serde(deserialize_with = "required_nullable")]
        owner: Option<ramflux_protocol::custody::DeviceRef>,
        #[serde(deserialize_with = "required_nullable")]
        branch_public_key: Option<String>,
        #[serde(deserialize_with = "required_nullable")]
        custody_authority: Option<Box<ramflux_protocol::custody::CustodyAuthority>>,
        revoked: bool,
    },
    Call {
        version: u32,
        start_digest: String,
        recipient_root: String,
        #[serde(deserialize_with = "required_nullable")]
        signed_start: Option<Box<ramflux_protocol::SignedCallIntentV1>>,
        #[serde(deserialize_with = "required_nullable")]
        pending_cancel: Option<Box<ramflux_protocol::SignedCallIntentV1>>,
        state: AuthorityCallState,
        #[serde(deserialize_with = "required_nullable")]
        invite_hash: Option<String>,
        #[serde(deserialize_with = "required_nullable")]
        terminal_at: Option<u64>,
    },
    LocalRows {
        version: u32,
        resource: LocalAuthorityResource,
        scope_key: String,
        rows: Vec<LocalAuthorityRow>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCallState {
    Ringing,
    Answered,
    Rejected,
    Ended,
    Cancelled,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAuthorityResource {
    TargetRoutes,
    Credential,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAuthorityRow {
    pub key: String,
    #[serde(deserialize_with = "required_nullable")]
    pub value: Option<String>,
}

impl AuthorityRecord {
    /// Validate the proof carried by a remote authority record before gate publication.
    /// # Errors
    /// Refuses substituted devices, forged call intents and oversized original evidence.
    pub fn verify_evidence(&self, now: u64) -> Result<(), SendAuthorityError> {
        self.scope()?;
        match self {
            Self::Owner {
                target_delivery_id,
                owner: Some(owner),
                branch_public_key,
                custody_authority: Some(evidence),
                revoked,
                ..
            } => {
                let verified =
                    ramflux_crypto::custody::verify_publication(evidence, now).map_err(storage)?;
                if verified.envelope().body.account_anchor != owner.account_anchor {
                    return Err(SendAuthorityError::Invalid);
                }
                if !revoked {
                    let branch = verified.authorize(owner, "register", now).map_err(storage)?;
                    let identity = ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(
                        &verified,
                        &owner.device_id,
                    )
                    .map_err(storage)?;
                    if branch_public_key.as_ref() != Some(&branch.branch_signing_public_key)
                        || target_delivery_id != identity.storage_key()
                    {
                        return Err(SendAuthorityError::Invalid);
                    }
                }
            }
            Self::Owner { owner: None, revoked: true, .. } => {}
            Self::Owner { .. } | Self::LocalRows { .. } => return Err(SendAuthorityError::Invalid),
            Self::Call { start_digest, recipient_root, signed_start, pending_cancel, .. } => {
                if let Some(start) = signed_start {
                    verify_intent(start)?;
                    if start.body.action != ramflux_protocol::CallIntentAction::Start
                        || ramflux_protocol::call_intent_digest(start).map_err(storage)?
                            != *start_digest
                    {
                        return Err(SendAuthorityError::Invalid);
                    }
                }
                let intent = signed_start
                    .as_ref()
                    .or(pending_cancel.as_ref())
                    .ok_or(SendAuthorityError::Invalid)?;
                let target_root =
                    ramflux_protocol::parse_qualified_device_id(&intent.body.target_device)
                        .map_err(storage)?
                        .map(|(root, _)| root)
                        .ok_or(SendAuthorityError::Invalid)?;
                if target_root != *recipient_root {
                    return Err(SendAuthorityError::Invalid);
                }
                if let Some(cancel) = pending_cancel {
                    verify_intent(cancel)?;
                    if signed_start
                        .as_ref()
                        .is_some_and(|start| !cancel.body.matches_start(&start.body, start_digest))
                    {
                        return Err(SendAuthorityError::Invalid);
                    }
                    if cancel.body.action != ramflux_protocol::CallIntentAction::Cancel
                        || cancel.body.start_digest.as_ref() != Some(start_digest)
                    {
                        return Err(SendAuthorityError::Invalid);
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn scope(&self) -> Result<AuthorityScope, SendAuthorityError> {
        let scope = match self {
            Self::Owner {
                version,
                target_delivery_id,
                owner,
                branch_public_key,
                custody_authority,
                revoked,
            } => {
                if *version != 1
                    || (owner.is_none()
                        && (branch_public_key.is_some() || custody_authority.is_some() || !revoked))
                {
                    return Err(SendAuthorityError::Invalid);
                }
                AuthorityScope::Owner { target_delivery_id: target_delivery_id.clone() }
            }
            Self::Call {
                version,
                start_digest,
                recipient_root,
                signed_start,
                pending_cancel,
                state,
                invite_hash,
                terminal_at,
            } => {
                validate_digest(recipient_root)?;
                if *version != 1
                    || (signed_start.is_none() && pending_cancel.is_none())
                    || signed_start.is_some() != invite_hash.is_some()
                    || terminal_at.is_none()
                        != matches!(
                            state,
                            AuthorityCallState::Ringing | AuthorityCallState::Answered
                        )
                {
                    return Err(SendAuthorityError::Invalid);
                }
                if let Some(hash) = invite_hash {
                    validate_digest(hash)?;
                }
                AuthorityScope::Call { start_digest: start_digest.clone() }
            }
            Self::LocalRows { version, resource, scope_key, rows } => {
                if *version != 1
                    || rows.len() > 32
                    || rows.windows(2).any(|pair| match pair {
                        [a, b] => a.key >= b.key,
                        _ => true,
                    })
                {
                    return Err(SendAuthorityError::Invalid);
                }
                match resource {
                    LocalAuthorityResource::TargetRoutes => {
                        AuthorityScope::TargetRoutes { target_delivery_id: scope_key.clone() }
                    }
                    LocalAuthorityResource::Credential => {
                        AuthorityScope::Credential { credential_id: scope_key.clone() }
                    }
                }
            }
        };
        scope.key()?;
        Ok(scope)
    }

    /// # Errors
    /// Refuses malformed or oversized records; hashes all authoritative fields.
    pub fn record_hash(&self) -> Result<String, SendAuthorityError> {
        self.scope()?;
        let bytes = ramflux_protocol::canonical_json_bytes(self).map_err(storage)?;
        if bytes.len() > 64 * 1024 {
            return Err(SendAuthorityError::Capacity);
        }
        Ok(ramflux_crypto::blake3_256_base64url(
            "ramflux.notification.send_authority_record.v1\0",
            &bytes,
        ))
    }
}

fn verify_intent(signed: &ramflux_protocol::SignedCallIntentV1) -> Result<(), SendAuthorityError> {
    signed.body.validate_shape().map_err(storage)?;
    if ramflux_protocol::canonical_json_bytes(signed).map_err(storage)?.len() > 8192 {
        return Err(SendAuthorityError::Capacity);
    }
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::call_intent_signing_bytes(&signed.body).map_err(storage)?,
        &signed.signature,
        &signed.body.signing_key_id,
    )
    .map_err(storage)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBootRequest {
    pub version: u32,
    pub request_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBootReply {
    pub version: u32,
    pub request_id: String,
    pub notify_boot: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityControlRequest {
    pub reservation_id: String,
    pub reservation_generation: u64,
    pub origin_incarnation: String,
    pub version: u32,
    pub request_id: String,
    pub operation_id: String,
    pub notify_boot: String,
    pub scope: AuthorityScope,
    pub expected_generation: u64,
    pub generation: u64,
    pub phase: AuthorityControlPhase,
    pub record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityControlReply {
    pub version: u32,
    pub request_id: String,
    pub operation_id: String,
    pub notify_boot: String,
    pub generation: u64,
    pub outcome: AuthorityControlOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityControlOutcome {
    Applied,
    Duplicate,
    Refused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityReadRequest {
    pub version: u32,
    pub request_id: String,
    pub notify_boot: String,
    pub scope: AuthorityScope,
    pub purpose: AuthorityReadPurpose,
    #[serde(deserialize_with = "required_nullable")]
    pub operation_id: Option<String>,
}

impl AuthorityReadRequest {
    /// # Errors
    /// Refuses malformed correlation, missing explicit operation and oversized requests.
    pub fn validate(&self) -> Result<(), SendAuthorityError> {
        validate_digest(&self.request_id)?;
        validate_digest(&self.notify_boot)?;
        self.scope.key()?;
        match self.purpose {
            AuthorityReadPurpose::Current if self.operation_id.is_none() => {}
            AuthorityReadPurpose::FenceCheck | AuthorityReadPurpose::PublishCheck => {
                validate_digest(self.operation_id.as_deref().ok_or(SendAuthorityError::Invalid)?)?;
            }
            AuthorityReadPurpose::Current => return Err(SendAuthorityError::Invalid),
        }
        if self.version != 1
            || ramflux_protocol::canonical_json_bytes(self).map_err(storage)?.len() > 8192
        {
            return Err(SendAuthorityError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityReadReply {
    pub version: u32,
    pub request_id: String,
    pub notify_boot: String,
    pub scope: AuthorityScope,
    pub result: AuthorityReadResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityReadResult {
    Record {
        reservation_id: String,
        reservation_generation: u64,
        origin_incarnation: String,
        operation_id: String,
        phase: AuthorityPhase,
        expected_generation: u64,
        generation: u64,
        record_hash: String,
        record: Box<AuthorityRecord>,
    },
    Refused {
        reason: AuthorityReadRefusal,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityReadRefusal {
    Missing,
    Closing,
    ResyncRequired,
    WrongBoot,
    Conflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityStateRequest {
    pub version: u32,
    pub request_id: String,
    pub notify_boot: String,
    pub scope: AuthorityScope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityStateReply {
    pub version: u32,
    pub request_id: String,
    pub notify_boot: String,
    pub scope: AuthorityScope,
    pub generation: u64,
    #[serde(deserialize_with = "required_nullable")]
    pub operation_id: Option<String>,
    pub phase: AuthorityPhase,
    #[serde(deserialize_with = "required_nullable")]
    pub record_hash: Option<String>,
}

impl AuthorityStateReply {
    #[must_use]
    pub fn state(&self) -> AuthorityState {
        AuthorityState {
            generation: self.generation,
            operation_id: self.operation_id.clone(),
            phase: self.phase,
            record_hash: self.record_hash.clone(),
        }
    }
}

pub(super) fn validate_digest(value: &str) -> Result<(), SendAuthorityError> {
    if value.len() != 43
        || !ramflux_protocol::decode_base64url(value).is_ok_and(|bytes| {
            bytes.len() == 32 && ramflux_protocol::encode_base64url(&bytes) == value
        })
    {
        return Err(SendAuthorityError::Invalid);
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), SendAuthorityError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(SendAuthorityError::Invalid);
    }
    Ok(())
}

/// # Errors
/// Returns the typed nullable member's deserialization error.
pub fn required_nullable<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(decoder)
}
